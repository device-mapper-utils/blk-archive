use anyhow::Result;
use std::path::PathBuf;
use std::process::{Command as StdCommand, Stdio};
use std::time::Duration;

mod common;
use common::blk_stash::*;
use common::fixture::*;
use common::random::Pattern;
use common::test_dir::*;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::process::Child;

fn blk_stash_pack(archive: &BlkArchive, input: PathBuf) -> Result<Child> {
    const BLK_STASH_BIN: &str = env!("CARGO_BIN_EXE_blk-stash");
    Ok(StdCommand::new(BLK_STASH_BIN)
        .arg("pack")
        .arg("-a")
        .arg(archive.archive_path())
        .arg(&input)
        .arg("--sync-point-secs")
        .arg("1")
        .arg("-j")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?)
}

fn kill_process(pid: i32) {
    signal::kill(Pid::from_raw(pid), Signal::SIGKILL).unwrap();
}

#[test]
fn test_interrupt_after_checkpoint() -> Result<()> {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let mut td = TestDir::new()?;
    let file_size = 1024 * 1024 * 1024u64;

    let archive = create_archive(&mut td, false)?;
    let input = create_input_file(&mut td, file_size, 1, Pattern::Lcg)?;

    let checkpoint_path = archive.archive_path().join("recovery.checkpoint");
    let checkpoint_start = std::fs::metadata(&checkpoint_path)?.modified().unwrap();

    let child = blk_stash_pack(&archive, input.clone())?;

    // Spin waiting for the checkpoint file to get updated then hit it with a signal, then
    // let it complete

    loop {
        let current = std::fs::metadata(&checkpoint_path)?.modified().unwrap();
        if current != checkpoint_start {
            eprintln!("check point modified");
            break;
        }
    }

    // The pack operation is creating a checkpoint ~ every 1 sec
    let delay = rng.gen_range(100..=500);
    eprintln!("delaying {delay} ms");
    std::thread::sleep(Duration::from_millis(delay));

    kill_process(child.id() as i32);

    let output = child.wait_with_output()?;

    let checkpoint_after_signal = std::fs::metadata(&checkpoint_path)?.modified().unwrap();

    // Maybe we should dump stdout & stderr?

    assert!(!output.status.success());

    // Now, lets make sure we can handle whatever corruption may have been done to archive
    let child = blk_stash_pack(&archive, input)?;
    let output = child.wait_with_output()?;

    if !output.status.success() {
        eprintln!("pack did not completes successfully! {}", output.status);
        eprintln!("stdout = {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr = {}", String::from_utf8_lossy(&output.stderr));

        assert!(output.status.success());
    } else {
        let checkpoint_after_complete = std::fs::metadata(&checkpoint_path)?.modified().unwrap();
        assert!(checkpoint_after_signal < checkpoint_after_complete);

        eprintln!("SUCCESS - debug data");
        eprintln!("stdout = {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr = {}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}

#[test]
fn test_interrupt_before_checkpoint() -> Result<()> {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    let mut td = TestDir::new()?;
    let file_size = 1024 * 1024 * 1024u64;

    let archive = create_archive(&mut td, false)?;
    let input = create_input_file(&mut td, file_size, 1, Pattern::Lcg)?;

    let checkpoint_path = archive.archive_path().join("recovery.checkpoint");
    let checkpoint_start = std::fs::metadata(&checkpoint_path)?.modified().unwrap();

    let child = blk_stash_pack(&archive, input.clone())?;

    // The pack operation is creating a checkpoint ~ every 1 sec
    let delay = rng.gen_range(200..800);
    eprintln!("delaying {delay} ms");
    std::thread::sleep(Duration::from_millis(delay));

    kill_process(child.id() as i32);

    let output = child.wait_with_output()?;

    let checkpoint_after_signal = std::fs::metadata(&checkpoint_path)?.modified().unwrap();

    // Maybe we should dump stdout & stderr?

    assert!(!output.status.success());
    assert_eq!(checkpoint_start, checkpoint_after_signal);

    // Now, lets make sure we can handle whatever corruption may have been done to archive
    let child = blk_stash_pack(&archive, input)?;
    let output = child.wait_with_output()?;

    if !output.status.success() {
        eprintln!("pack did not completes successfully! {}", output.status);
        eprintln!("stdout = {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr = {}", String::from_utf8_lossy(&output.stderr));

        assert!(output.status.success());
    } else {
        let checkpoint_after_complete = std::fs::metadata(&checkpoint_path)?.modified().unwrap();
        assert!(checkpoint_after_signal < checkpoint_after_complete);

        eprintln!("SUCCESS - debug data");
        eprintln!("stdout = {}", String::from_utf8_lossy(&output.stdout));
        eprintln!("stderr = {}", String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}

/// Test that checkpoint files are created and updated
#[test]
fn test_checkpoint_file_creation() -> Result<()> {
    let mut td = TestDir::new()?;
    let file_size = 64 * 1024 * 1024u64; // 64 MiB

    // Create archive
    let archive = create_archive(&mut td, false)?;

    // Check that initial checkpoint was created
    let checkpoint_path = archive.archive_path().join("recovery.checkpoint");
    assert!(
        checkpoint_path.exists(),
        "Initial checkpoint should be created"
    );

    let initial_metadata = std::fs::metadata(&checkpoint_path)?;
    let initial_modified = initial_metadata.modified()?;

    eprintln!("Initial checkpoint created at: {:?}", initial_modified);

    // Wait a moment to ensure timestamps differ
    std::thread::sleep(Duration::from_millis(100));

    // Pack a file (should update checkpoint at end)
    let input = create_input_file(&mut td, file_size, 1, Pattern::Lcg)?;
    let response = archive.pack(&input)?;

    eprintln!("Packed file, stream ID: {}", response.stream_id);

    // Check that checkpoint was updated
    let final_metadata = std::fs::metadata(&checkpoint_path)?;
    let final_modified = final_metadata.modified()?;

    eprintln!("Final checkpoint modified at: {:?}", final_modified);

    assert!(
        final_modified > initial_modified,
        "Checkpoint should be updated after pack"
    );

    Ok(())
}
