use super::regenerate_index;
use super::*;
use anyhow::{ensure, Result};
use std::time::Duration;
use tempfile::*;

use crate::archive::SLAB_SIZE_TARGET;
use crate::hash::{hash_64, Hash64};
use crate::slab::file::{FILE_MAGIC, FORMAT_VERSION, SLAB_FILE_HDR_LEN, SLAB_MAGIC};
use crate::slab::SlabFileBuilder;
use byteorder::{LittleEndian, WriteBytesExt};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

//-----------------------------------------
// Helper functions
//-----------------------------------------

fn create_file(path: &PathBuf) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
}

fn write_valid_header(f: &mut File) -> std::io::Result<()> {
    f.write_u64::<LittleEndian>(FILE_MAGIC)?;
    f.write_u32::<LittleEndian>(FORMAT_VERSION)?;
    f.write_u32::<LittleEndian>(0)?;
    Ok(())
}

fn write_slab(f: &mut File, payload: &[u8]) -> std::io::Result<()> {
    f.write_u64::<LittleEndian>(SLAB_MAGIC)?;
    f.write_u64::<LittleEndian>(payload.len() as u64)?;
    let csum: Hash64 = hash_64(payload);
    f.write_all(&csum)?;
    f.write_all(payload)?;
    Ok(())
}

fn pad_bytes(f: &mut File, n: usize) -> std::io::Result<()> {
    let zeros = vec![0u8; n];
    f.write_all(&zeros)
}

//-----------------------------------------
// Tests
//-----------------------------------------

// ensure the writer could handle unordered writes from the compressors
#[test]
fn write_unordered() -> Result<()> {
    let td = tempdir()?;
    let path = td.path().join("slab_file");
    let mut slab = SlabFileBuilder::create(path.clone()).build()?;

    let (_, tx0) = slab.reserve_slab();
    let (_, tx1) = slab.reserve_slab();
    let (_, tx2) = slab.reserve_slab();

    tx2.send(SlabData {
        index: 2,
        data: vec![2; 1536],
    })?;
    drop(tx2);

    tx0.send(SlabData {
        index: 0,
        data: vec![0; 512],
    })?;
    drop(tx0);

    tx1.send(SlabData {
        index: 1,
        data: vec![1; 1024],
    })?;
    drop(tx1);

    slab.close()?;
    drop(slab);

    let mut slab = SlabFileBuilder::open(path).build()?;

    for i in 0..3u8 {
        let data = slab.read(i as u32)?;
        ensure!(data.len() == (i as usize + 1) * 512);
        ensure!(data.iter().all(|&v| v == i));
    }

    Ok(())
}

//-----------------------------------------

// Test that sync_all doesn't hang when opening for write but not writing anything
#[test]
fn sync_all_no_writes() -> Result<()> {
    let td = tempdir()?;
    let path = td.path().join("slab_file");

    // Create a slab file with some initial data
    {
        let mut slab = SlabFileBuilder::create(path.clone()).build()?;
        slab.write_slab(&vec![1; 512])?;
        slab.write_slab(&vec![2; 1024])?;
        slab.close()?;
    }

    // Open for write but don't write anything - run with timeout to catch hangs
    let path_clone = path.clone();
    let handle = std::thread::spawn(move || -> Result<()> {
        let mut slab = SlabFileBuilder::open(path_clone)
            .write(true)
            .queue_depth(16)
            .build()
            .context("couldn't open test slab file")?;

        // This should not hang
        slab.sync_all()?;
        slab.close()?;
        Ok(())
    });

    // Wait up to 10 seconds for the test to complete
    let _ = std::thread::sleep(Duration::from_secs(10));
    if !handle.is_finished() {
        panic!("sync_all() hung when opening for write with no writes!");
    }
    handle.join().unwrap()?;

    // Verify data is still intact
    {
        let mut slab = SlabFileBuilder::open(path).build()?;
        ensure!(slab.get_nr_slabs() == 2);
        let data0 = slab.read(0)?;
        let data1 = slab.read(1)?;
        ensure!(data0.len() == 512 && data0.iter().all(|&v| v == 1));
        ensure!(data1.len() == 1024 && data1.iter().all(|&v| v == 2));
    }

    Ok(())
}

//-----------------------------------------

// Test that sync_all actually persists data when writing to a new file
// This test catches the bug where last_written was initialized to 0 instead of u64::MAX
#[test]
fn sync_all_first_write() -> Result<()> {
    let td = tempdir()?;
    let path = td.path().join("slab_file");

    // Create new file and write first slab using sync_all (not close)
    {
        let mut slab = SlabFileBuilder::create(path.clone()).build()?;
        slab.write_slab(&vec![42; 1024])?;

        // This is the critical path that was broken: sync_all on first write
        // to a new file (nr_existing_slabs = 0)
        slab.sync_all()?;

        // Immediately after sync_all, the slab count should reflect the write
        // With the bug, this would return 0 because sync_all didn't wait
        ensure!(
            slab.get_nr_slabs() == 1,
            "Expected 1 slab immediately after sync_all (bug: sync didn't wait for write)"
        );

        // Close to ensure offsets file is written
        slab.close()?;
    }

    // Reopen and verify the slab was actually persisted to disk
    {
        let mut slab = SlabFileBuilder::open(path).build()?;
        ensure!(slab.get_nr_slabs() == 1, "Expected 1 slab after reopen");
        let data = slab.read(0)?;
        ensure!(data.len() == 1024, "Expected 1024 bytes");
        ensure!(data.iter().all(|&v| v == 42), "Expected all bytes to be 42");
    }

    Ok(())
}

//-----------------------------------------

// Test that sync_all works correctly when writing multiple slabs to a new file
#[test]
fn sync_all_multiple_writes() -> Result<()> {
    let td = tempdir()?;
    let path = td.path().join("slab_file");

    // Create new file, write multiple slabs, and sync after each
    {
        let mut slab = SlabFileBuilder::create(path.clone()).build()?;

        // Write and sync first slab
        slab.write_slab(&vec![1; 512])?;
        slab.sync_all()?;
        ensure!(slab.get_nr_slabs() == 1, "Expected 1 slab after first sync");

        // Write and sync second slab
        slab.write_slab(&vec![2; 1024])?;
        slab.sync_all()?;
        ensure!(
            slab.get_nr_slabs() == 2,
            "Expected 2 slabs after second sync"
        );

        // Write and sync third slab
        slab.write_slab(&vec![3; 2048])?;
        slab.sync_all()?;
        ensure!(
            slab.get_nr_slabs() == 3,
            "Expected 3 slabs after third sync"
        );

        slab.close()?;
    }

    // Verify all slabs were persisted
    {
        let mut slab = SlabFileBuilder::open(path).build()?;
        ensure!(slab.get_nr_slabs() == 3, "Expected 3 slabs after reopen");

        let data0 = slab.read(0)?;
        ensure!(data0.len() == 512 && data0.iter().all(|&v| v == 1));

        let data1 = slab.read(1)?;
        ensure!(data1.len() == 1024 && data1.iter().all(|&v| v == 2));

        let data2 = slab.read(2)?;
        ensure!(data2.len() == 2048 && data2.iter().all(|&v| v == 3));
    }

    Ok(())
}

//-----------------------------------------
#[test]
fn too_small_for_header_errors() {
    let td = tempdir().unwrap();
    let path = td.path().join("tiny.slab");

    // Create file smaller than SLAB_FILE_HDR_LEN
    let mut f = create_file(&path).unwrap();
    pad_bytes(&mut f, (SLAB_FILE_HDR_LEN as usize).saturating_sub(1)).unwrap();

    let res = regenerate_index(&path);
    assert!(res.is_err(), "expected error for file smaller than header");
}

#[test]
fn empty_archive_ok() {
    let td = tempdir().unwrap();
    let path = td.path().join("empty.slab");

    let mut f = create_file(&path).unwrap();
    write_valid_header(&mut f).unwrap();
    f.flush().unwrap();

    let res = regenerate_index(&path);
    assert!(res.is_ok(), "empty archive (header only) should be OK");
    assert_eq!(res.unwrap().len(), 0);
}

#[test]
fn single_slab_ok() {
    let td = tempdir().unwrap();
    let path = td.path().join("single-ok.slab");

    let mut f = create_file(&path).unwrap();
    write_valid_header(&mut f).unwrap();
    write_slab(&mut f, b"hello world").unwrap();
    f.flush().unwrap();

    let res = regenerate_index(&path);
    assert!(res.is_ok(), "single valid slab should parse");
    assert_eq!(res.unwrap().len(), 1);
}

#[test]
fn multiple_slabs_ok() {
    let td = tempdir().unwrap();
    let path = td.path().join("multi-ok.slab");

    let mut f = create_file(&path).unwrap();
    write_valid_header(&mut f).unwrap();
    write_slab(&mut f, b"slab-0").unwrap();
    write_slab(&mut f, b"slab-1-longer").unwrap();
    write_slab(&mut f, &[42u8; 1024]).unwrap();
    f.flush().unwrap();

    let res = regenerate_index(&path);
    assert!(res.is_ok(), "multiple valid slabs should parse");
    assert_eq!(res.unwrap().len(), 3);
}

#[test]
fn bad_magic_errors() {
    let td = tempdir().unwrap();
    let path = td.path().join("bad-magic.slab");

    let mut f = create_file(&path).unwrap();
    write_valid_header(&mut f).unwrap();

    // Write a bad magic followed by a minimal valid-looking header/payload
    f.write_u64::<LittleEndian>(0xDEAD_BEEF_DEAD_BEEFu64)
        .unwrap();
    f.write_u64::<LittleEndian>(5u64).unwrap();
    let bogus: Hash64 = Hash64::default();
    f.write_all(&bogus).unwrap();
    f.write_all(&[0u8; 5]).unwrap();
    f.flush().unwrap();

    let err = regenerate_index(&path).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("magic incorrect"),
        "expected magic error, got: {msg}"
    );
}

#[test]
fn excessive_length_errors() {
    let td = tempdir().unwrap();
    let path = td.path().join("excess-len.slab");

    let mut f = create_file(&path).unwrap();
    write_valid_header(&mut f).unwrap();

    // Write header with slab_len > SLAB_SIZE_TARGET * 2
    let len = (SLAB_SIZE_TARGET as u64) * 2 + 1;
    f.write_u64::<LittleEndian>(SLAB_MAGIC).unwrap();
    f.write_u64::<LittleEndian>(len).unwrap();
    let bogus: Hash64 = Hash64::default();
    f.write_all(&bogus).unwrap();
    // Don't need to write payload; function should reject length before reading.
    f.flush().unwrap();

    let err = regenerate_index(&path).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("length too large"),
        "expected length too large error, got: {msg}"
    );
}

#[test]
fn truncated_payload_errors() {
    let td = tempdir().unwrap();
    let path = td.path().join("truncated-payload.slab");

    let mut f = create_file(&path).unwrap();
    write_valid_header(&mut f).unwrap();

    // Write header that claims len = 100, but provide fewer than 100 bytes.
    let claimed_len = 100u64;
    f.write_u64::<LittleEndian>(SLAB_MAGIC).unwrap();
    f.write_u64::<LittleEndian>(claimed_len).unwrap();

    // Compute checksum for a 100-byte payload of zeros (just to have *some* checksum)
    let full_payload = vec![0u8; claimed_len as usize];
    let csum = hash_64(&full_payload);
    f.write_all(&csum).unwrap();

    // Actually write only 20 bytes -> truncated payload
    f.write_all(&full_payload[..20]).unwrap();
    f.flush().unwrap();

    let err = regenerate_index(&path).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("truncated") || msg.contains("incomplete"),
        "expected truncated payload error, got: {msg}"
    );
}

#[test]
fn checksum_mismatch_errors() {
    let td = tempdir().unwrap();
    let path = td.path().join("bad-checksum.slab");

    let mut f = create_file(&path).unwrap();
    write_valid_header(&mut f).unwrap();

    let payload = b"good-bytes";
    f.write_u64::<LittleEndian>(SLAB_MAGIC).unwrap();
    f.write_u64::<LittleEndian>(payload.len() as u64).unwrap();

    // Put a wrong checksum
    let wrong: Hash64 = Hash64::default();
    f.write_all(&wrong).unwrap();

    // Write the actual payload
    f.write_all(payload).unwrap();
    f.flush().unwrap();

    let err = regenerate_index(&path).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("checksum"),
        "expected checksum error, got: {msg}"
    );
}

#[test]
fn zero_length_slab_errors() {
    let td = tempdir().unwrap();
    let path = td.path().join("zero-len.slab");

    let mut f = create_file(&path).unwrap();
    write_valid_header(&mut f).unwrap();

    f.write_u64::<LittleEndian>(SLAB_MAGIC).unwrap();
    f.write_u64::<LittleEndian>(0u64).unwrap(); // zero length
    let bogus: Hash64 = Hash64::default();
    f.write_all(&bogus).unwrap();
    f.flush().unwrap();

    let err = regenerate_index(&path).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("zero-length"),
        "expected zero-length error, got: {msg}"
    );
}
