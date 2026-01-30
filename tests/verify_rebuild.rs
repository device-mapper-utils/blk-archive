use anyhow::Result;

mod common;

use blk_stash::config;
use blk_stash::stream_archive::StreamArchive;
use common::fixture::*;
use common::random::Pattern;
use common::test_dir::*;

/// Test that verify --repair correctly updates stream metadata when removing corrupted streams
#[test]
fn test_verify_rebuild_with_corrupted_middle_stream() -> Result<()> {
    let mut td = TestDir::new()?;
    let archive = create_archive(&mut td, false)?;

    // Create 3 input files
    let file_size = 4 * 1024 * 1024; // 4 MB
    let input1 = create_input_file(&mut td, file_size, 1, Pattern::Lcg)?;
    let input2 = create_input_file(&mut td, file_size, 2, Pattern::Lcg)?;
    let input3 = create_input_file(&mut td, file_size, 3, Pattern::Lcg)?;

    // Pack all three files
    let response1 = archive.pack(&input1)?;
    let response2 = archive.pack(&input2)?;
    let response3 = archive.pack(&input3)?;

    eprintln!("Stream 1: {}", response1.stream_id);
    eprintln!("Stream 2: {}", response2.stream_id);
    eprintln!("Stream 3: {}", response3.stream_id);

    // Verify all streams work before corruption
    archive.verify(&input1, &response1.stream_id)?;
    archive.verify(&input2, &response2.stream_id)?;
    archive.verify(&input3, &response3.stream_id)?;

    // Get stream metadata before corruption
    let dummy_matches = clap::ArgMatches::default();
    let _ = config::read_config(archive.archive_path(), &dummy_matches)?;

    let stream_archive = StreamArchive::open_read(archive.archive_path())?;
    assert_eq!(stream_archive.stream_count(), 3, "Should have 3 streams");

    let config0_before = stream_archive.read_config(0)?;
    let config1_before = stream_archive.read_config(1)?;
    let config2_before = stream_archive.read_config(2)?;

    eprintln!(
        "Stream 0 before: first_mapping_slab={}, num={}",
        config0_before.first_mapping_slab, config0_before.num_mapping_slabs
    );
    eprintln!(
        "Stream 1 before: first_mapping_slab={}, num={}",
        config1_before.first_mapping_slab, config1_before.num_mapping_slabs
    );
    eprintln!(
        "Stream 2 before: first_mapping_slab={}, num={}",
        config2_before.first_mapping_slab, config2_before.num_mapping_slabs
    );

    drop(stream_archive);

    // Corrupt the middle stream (stream 1) by modifying its checksum in metadata
    use blk_stash::slab::builder::SlabFileBuilder;
    use blk_stash::stream_metadata::serialize_stream_config;
    use std::fs;

    // Read all three stream configs
    let configs = {
        let sa = StreamArchive::open_read(archive.archive_path())?;
        let c0 = sa.read_config(0)?;
        let mut c1 = sa.read_config(1)?;
        let c2 = sa.read_config(2)?;

        // Corrupt stream 1's checksum
        c1.source_sig =
            Some("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".to_string());

        vec![c0, c1, c2]
    };

    // Delete and recreate the metadata file with corrupted stream 1
    let metadata_path = archive.archive_path().join("streams/metadata");
    fs::remove_file(&metadata_path)?;

    {
        let mut metadata_file = SlabFileBuilder::create(&metadata_path)
            .write(true)
            .queue_depth(16)
            .build()?;

        for config in &configs {
            let data = serialize_stream_config(config)?;
            metadata_file.write_slab(&data)?;
        }

        metadata_file.sync_all()?;
        metadata_file.close()?;
    }

    // Run verify --repair to rebuild and remove corrupted streams
    archive.verify_all_with_repair()?;

    // Open the rebuilt archive and verify structure
    let rebuilt_archive = StreamArchive::open_read(archive.archive_path())?;

    // We should now have 2 streams (stream 0 and stream 2, with stream 1 removed)
    assert_eq!(
        rebuilt_archive.stream_count(),
        2,
        "Rebuilt archive should have 2 streams (corrupted middle stream removed)"
    );

    // Verify the first stream (was stream 0, still stream 0)
    let config0_after = rebuilt_archive.read_config(0)?;
    assert_eq!(
        config0_after.source_path, config0_before.source_path,
        "Stream 0 should be the same file"
    );
    assert_eq!(
        config0_after.first_mapping_slab, 0,
        "Stream 0 should still start at slab 0"
    );

    // Verify the second stream (was stream 2, now stream 1)
    let config1_after = rebuilt_archive.read_config(1)?;
    assert_eq!(
        config1_after.source_path, config2_before.source_path,
        "Stream 1 (after rebuild) should be what was stream 2"
    );

    // This is the critical test: stream 1's first_mapping_slab should be recalculated
    // It should start immediately after stream 0's mappings
    let expected_slab = config0_after.first_mapping_slab + config0_after.num_mapping_slabs;
    assert_eq!(
        config1_after.first_mapping_slab, expected_slab,
        "Stream 1's mapping slabs should be recalculated to start at slab {}",
        expected_slab
    );

    // Verify both streams can be opened (mappings are accessible)
    let stream0 = rebuilt_archive.get_stream(0);
    assert!(stream0.is_ok(), "Should be able to open stream 0");

    let stream1 = rebuilt_archive.get_stream(1);
    assert!(stream1.is_ok(), "Should be able to open stream 1");

    Ok(())
}
