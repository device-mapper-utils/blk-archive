use anyhow::{anyhow, Context, Result};
use clap::ArgMatches;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thinp::report::*;

use crate::cuckoo_filter::*;
use crate::paths;
use crate::paths::*;
use crate::recovery;
use crate::slab::{builder::*, MultiFile};
use crate::{config::*, cuckoo_filter};

//-----------------------------------------

fn create_sub_dir(root: &Path, sub: &str) -> Result<()> {
    let mut p = PathBuf::new();
    p.push(root);
    p.push(sub);
    fs::create_dir(&p)
        .with_context(|| format!("Failed to create subdirectory '{}' in {:?}", sub, root))?;
    Ok(())
}

fn write_config(
    root: &Path,
    block_size: usize,
    hash_cache_size_meg: usize,
    data_cache_size_meg: usize,
) -> Result<()> {
    let mut p = PathBuf::new();
    p.push(root);
    p.push("dm-archive.yaml");

    let mut output = OpenOptions::new()
        .read(false)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&p)
        .with_context(|| format!("Failed to create config file at {:?}", p))?;

    let config = Config {
        block_size,
        splitter_alg: "RollingHashV0".to_string(),
        hash_cache_size_meg,
        data_cache_size_meg,
    };

    write!(output, "{}", &serde_yaml_ng::to_string(&config).unwrap())
        .with_context(|| format!("Failed to write config to {:?}", p))?;
    Ok(())
}

fn adjust_block_size(n: usize) -> usize {
    // We have a max block size of 1M currently
    let max_bs = 1024 * 1024;
    if n > max_bs {
        return max_bs;
    }

    let mut p = 1;
    while p < n {
        p *= 2;
    }

    p
}

fn numeric_option<T: std::str::FromStr>(matches: &ArgMatches, name: &str, dflt: T) -> Result<T> {
    match matches.try_get_one::<String>(name) {
        Ok(Some(s)) => s
            .parse::<T>()
            .map_err(|_| anyhow!("could not parse {} argument", name)),
        Ok(None) => Ok(dflt),
        Err(_) => Err(anyhow!("Error retrieving {} argument", name)),
    }
}

/*
fn numeric_option<T: std::str::FromStr>(matches: &ArgMatches, name: &str, dflt: T) -> Result<T> {
    matches
        .value_of(name)
        .map(|s| s.parse::<T>())
        .unwrap_or(Ok(dflt))
        .map_err(|_| anyhow!(format!("could not parse {} argument", name)))
}
*/

fn create(
    archive_dir: &Path,
    data_compression: bool,
    block_size: usize,
    hash_cache_size_meg: usize,
    data_cache_size_meg: usize,
) -> Result<()> {
    fs::create_dir_all(archive_dir)
        .with_context(|| format!("Unable to create archive {:?}", archive_dir))?;

    write_config(
        archive_dir,
        block_size,
        hash_cache_size_meg,
        data_cache_size_meg,
    )?;
    create_sub_dir(archive_dir, "data")?;
    create_sub_dir(archive_dir, "streams")?;
    create_sub_dir(archive_dir, "indexes")?;

    // Create empty data and hash slab files
    let mut data_file = MultiFile::create(archive_dir, 1, data_compression, 1)?;
    data_file
        .close()
        .with_context(|| format!("Failed to close data file in {:?}", archive_dir))?;

    let hashes_path = hashes_path(archive_dir);
    let mut hashes_file = SlabFileBuilder::create(&hashes_path)
        .queue_depth(1)
        .compressed(false)
        .build()?;
    hashes_file
        .close()
        .with_context(|| format!("Failed to close hashes file at {:?}", hashes_path))?;

    // Create empty stream metadata slab file
    let streams_metadata_path = paths::streams_metadata_path(archive_dir);
    let mut metadata_file = SlabFileBuilder::create(&streams_metadata_path)
        .queue_depth(1)
        .compressed(false)
        .build()?;
    metadata_file.close().with_context(|| {
        format!(
            "Failed to close stream metadata file at {:?}",
            streams_metadata_path
        )
    })?;

    // Create empty stream mappings slab file
    let streams_mappings_path = paths::stream_mappings_path(archive_dir);
    let mut mappings_file = SlabFileBuilder::create(&streams_mappings_path)
        .queue_depth(1)
        .compressed(true)
        .build()?;
    mappings_file.close().with_context(|| {
        format!(
            "Failed to close stream mappings file at {:?}",
            streams_mappings_path
        )
    })?;

    // Write empty index
    let index_path = paths::index_path(archive_dir);
    let index = CuckooFilter::with_capacity(cuckoo_filter::INITIAL_SIZE);
    index
        .write(&index_path)
        .with_context(|| format!("Failed to write initial index to {:?}", index_path))?;

    // Create initial recovery checkpoint
    let checkpoint_path = archive_dir.join(recovery::check_point_file());
    let checkpoint = recovery::create_checkpoint_from_files(archive_dir, 0)?;
    checkpoint.write(&checkpoint_path).with_context(|| {
        format!(
            "Failed to write initial checkpoint to {:?}",
            checkpoint_path
        )
    })?;

    Ok(())
}

pub struct CreateParmeters {
    pub data_compression: bool,
    pub block_size: usize,
    pub hash_cache_size_meg: usize,
    pub data_cache_size_meg: usize,
}

pub fn default(dir: &Path) -> Result<CreateParmeters> {
    create(dir, true, 4096, 1024, 1024)?;
    Ok(CreateParmeters {
        data_compression: true,
        block_size: 4096,
        hash_cache_size_meg: 1024,
        data_cache_size_meg: 1024,
    })
}

pub fn run(matches: &ArgMatches, report: Arc<Report>) -> Result<()> {
    let archive_dir = Path::new(matches.get_one::<String>("ARCHIVE").unwrap());
    let data_compression = matches.get_one::<String>("DATA_COMPRESSION").unwrap() == "y";

    let mut block_size = numeric_option::<usize>(matches, "BLOCK_SIZE", 4096)?;
    let new_block_size = adjust_block_size(block_size);
    if new_block_size != block_size {
        report.info(&format!("adjusting block size to {}", new_block_size));
        block_size = new_block_size;
    }
    let hash_cache_size_meg = numeric_option::<usize>(matches, "HASH_CACHE_SIZE_MEG", 1024)?;
    let data_cache_size_meg = numeric_option::<usize>(matches, "DATA_CACHE_SIZE_MEG", 1024)?;

    create(
        archive_dir,
        data_compression,
        block_size,
        hash_cache_size_meg,
        data_cache_size_meg,
    )
}

//-----------------------------------------
