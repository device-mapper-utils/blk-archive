use anyhow::{anyhow, Context, Result};
use clap::ArgMatches;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thinp::report::*;

use crate::hash::{BlockHash, StreamHash};
use crate::paths;
use crate::paths::*;
use crate::recovery;
use crate::slab::{builder::*, data_cache::DEFAULT_DATA_CACHE_SIZE_MEG, MultiFile};
use crate::stream_archive;
use crate::{config::*, cuckoo_filter};
use crate::{cuckoo_filter::*, hash};

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
    block_hash: BlockHash,
    stream_hash: StreamHash,
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
        block_hash,
        stream_hash,
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
    block_hash: BlockHash,
    stream_hash: StreamHash,
) -> Result<()> {
    // We need to initialize the hash functions as soon as we know them
    hash::init_block_hashes(block_hash);

    fs::create_dir_all(archive_dir)
        .with_context(|| format!("Unable to create archive {:?}", archive_dir))?;

    write_config(
        archive_dir,
        block_size,
        hash_cache_size_meg,
        data_cache_size_meg,
        block_hash,
        stream_hash,
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

    // Create the empty stream archive
    stream_archive::StreamArchive::create(archive_dir, 1)?.close()?;

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
    pub block_hash: BlockHash,
    pub stream_hash: StreamHash,
}

pub fn default(dir: &Path) -> Result<CreateParmeters> {
    let block_hash = BlockHash::default();
    let stream_hash = StreamHash::default();
    create(
        dir,
        true,
        4096,
        DEFAULT_DATA_CACHE_SIZE_MEG,
        DEFAULT_DATA_CACHE_SIZE_MEG,
        block_hash,
        stream_hash,
    )?;
    Ok(CreateParmeters {
        data_compression: true,
        block_size: 4096,
        hash_cache_size_meg: DEFAULT_DATA_CACHE_SIZE_MEG,
        data_cache_size_meg: DEFAULT_DATA_CACHE_SIZE_MEG,
        block_hash,
        stream_hash,
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
    let hash_cache_size_meg =
        numeric_option::<usize>(matches, "HASH_CACHE_SIZE_MEG", DEFAULT_DATA_CACHE_SIZE_MEG)?;
    let data_cache_size_meg =
        numeric_option::<usize>(matches, "DATA_CACHE_SIZE_MEG", DEFAULT_DATA_CACHE_SIZE_MEG)?;

    // Parse hash algorithm selections
    let block_hash_str = matches.get_one::<String>("BLOCK_HASH").unwrap();
    let block_hash = block_hash_str
        .parse::<BlockHash>()
        .map_err(|e| anyhow!("Invalid block hash: {}", e))?;

    let stream_hash_str = matches.get_one::<String>("STREAM_HASH").unwrap();
    let stream_hash = stream_hash_str
        .parse::<StreamHash>()
        .map_err(|e| anyhow!("Invalid stream hash: {}", e))?;

    create(
        archive_dir,
        data_compression,
        block_size,
        hash_cache_size_meg,
        data_cache_size_meg,
        block_hash,
        stream_hash,
    )
}

//-----------------------------------------
