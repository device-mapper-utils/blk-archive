use anyhow::Result;

mod common;

use crate::common::random::Pattern;
use common::fixture::*;
use common::process::*;
use common::test_dir::*;

//-----------------------------------------

#[test]
#[ignore]
fn verify_incompleted_archive_should_fail() -> Result<()> {
    let mut td = TestDir::new()?;
    let archive = create_archive(&mut td, true)?;

    let file_size = 16 * 1024 * 1024;
    let seed = 1;
    let input = create_input_file(&mut td, file_size, seed, Pattern::Lcg)?;
    let input_short = create_input_file(&mut td, file_size - 1, seed, Pattern::Lcg)?;
    let stream = archive.pack(&input_short)?.stream_id;
    run_fail(archive.verify_cmd(&input, &stream))?;
    Ok(())
}

#[test]
#[ignore]
fn verify_incompleted_file_should_fail() -> Result<()> {
    let mut td = TestDir::new()?;
    let archive = create_archive(&mut td, true)?;

    let file_size = 16 * 1024 * 1024;
    let seed = 1;
    let input = create_input_file(&mut td, file_size, seed, Pattern::Lcg)?;
    let input_short = create_input_file(&mut td, file_size - 1, seed, Pattern::Lcg)?;
    let stream = archive.pack(&input)?.stream_id;
    run_fail(archive.verify_cmd(&input_short, &stream))?;
    Ok(())
}

#[test]
#[ignore]
fn verify_all_should_succeed() -> Result<()> {
    let mut td = TestDir::new()?;
    let archive = create_archive(&mut td, true)?;

    let file_size = 16 * 1024 * 1024;

    // Pack multiple streams
    let input1 = create_input_file(&mut td, file_size, 1, Pattern::Lcg)?;
    archive.pack(&input1)?;

    let input2 = create_input_file(&mut td, file_size, 2, Pattern::Lcg)?;
    archive.pack(&input2)?;

    let input3 = create_input_file(&mut td, file_size, 3, Pattern::Lcg)?;
    archive.pack(&input3)?;

    // Verify all streams
    archive.verify_all()?;
    Ok(())
}

#[test]
#[ignore]
fn verify_all_with_repair_should_succeed() -> Result<()> {
    let mut td = TestDir::new()?;
    let archive = create_archive(&mut td, true)?;

    let file_size = 8 * 1024 * 1024;

    // Pack a couple of streams
    let input1 = create_input_file(&mut td, file_size, 1, Pattern::Lcg)?;
    archive.pack(&input1)?;

    let input2 = create_input_file(&mut td, file_size, 2, Pattern::Lcg)?;
    archive.pack(&input2)?;

    // Verify all streams with repair flag
    archive.verify_all_with_repair()?;
    Ok(())
}

#[test]
#[ignore]
fn verify_all_json_output_should_be_valid() -> Result<()> {
    use common::targets::*;
    use serde_json::Value;

    let mut td = TestDir::new()?;
    let archive = create_archive(&mut td, true)?;

    let file_size = 8 * 1024 * 1024;

    // Pack multiple streams
    let input1 = create_input_file(&mut td, file_size, 1, Pattern::Lcg)?;
    archive.pack(&input1)?;

    let input2 = create_input_file(&mut td, file_size, 2, Pattern::Lcg)?;
    archive.pack(&input2)?;

    let input3 = create_input_file(&mut td, file_size, 3, Pattern::Lcg)?;
    archive.pack(&input3)?;

    // Verify all streams with JSON output
    let json_output = run_ok(verify_cmd(args![
        "-a",
        archive.archive_path(),
        "--all",
        "-j"
    ]))?;

    // Parse and validate JSON
    let results: Value = serde_json::from_str(&json_output)?;

    // Should be an array
    assert!(results.is_array());
    let arr = results.as_array().unwrap();
    assert_eq!(arr.len(), 3);

    // Check each result has required fields
    for result in arr {
        assert!(result.get("stream_id").is_some());
        assert!(result.get("source_path").is_some());
        assert!(result.get("status").is_some());
        assert_eq!(result["status"], "success");
        assert!(result.get("error").is_some());
        assert_eq!(result["error"], serde_json::Value::Null);
    }

    Ok(())
}

//-----------------------------------------
