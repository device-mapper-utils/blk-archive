use super::*;
use anyhow::{ensure, Result};
use std::time::Duration;
use tempfile::*;

use crate::slab::SlabFileBuilder;

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
