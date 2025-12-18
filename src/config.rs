use anyhow::{Context, Result};
use chrono::prelude::*;
use clap::ArgMatches;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use crate::hash::{self, BlockHash, StreamHash};
use crate::slab::data_cache::DEFAULT_DATA_CACHE_SIZE_MEG;

//-----------------------------------------

#[derive(Deserialize, Serialize, Debug)]
pub struct Config {
    pub block_size: usize,
    pub splitter_alg: String,
    pub hash_cache_size_meg: usize,
    pub data_cache_size_meg: usize,
    #[serde(default)]
    pub block_hash: BlockHash,
    #[serde(default)]
    pub stream_hash: StreamHash,
}

fn numeric_override<T>(matches: &ArgMatches, name: &str, default: T) -> T
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match matches.try_get_one::<String>(name) {
        Ok(Some(s)) => match s.parse::<T>() {
            Ok(v) => v,
            Err(_) => {
                // Parsing failed – fall back to default.
                default
            }
        },
        Ok(None) => {
            // Argument not supplied.
            default
        }
        Err(_) => {
            // Retrieval error (unlikely with clap, but handled for completeness).
            default
        }
    }
}

pub fn read_config<P>(root: P, overrides: &ArgMatches) -> Result<Config>
where
    P: AsRef<Path>,
{
    // Build the full path to the yaml file.
    let config_path = root.as_ref().join("dm-archive.yaml");

    // Read and deserialize the file.
    let input = fs::read_to_string(&config_path)
        .with_context(|| format!("couldn't read config file `{}`", config_path.display()))?;
    let mut config: Config =
        serde_yaml_ng::from_str(&input).context("couldn't parse config file")?;

    // Initialise hash functions, we need to do this as soon as we know what they are
    // as we have lots of code that needs the hashing functions.
    hash::init_block_hashes(config.block_hash);

    let cache_size = numeric_override::<usize>(
        overrides,
        "DATA_CACHE_SIZE_MEG",
        DEFAULT_DATA_CACHE_SIZE_MEG,
    );
    config.data_cache_size_meg = cache_size;

    Ok(config)
}

//-----------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct StreamConfig {
    pub name: Option<String>,
    pub source_path: String,
    pub pack_time: String,
    pub size: u64,
    pub mapped_size: u64,
    pub packed_size: u64,
    pub thin_id: Option<u32>,
    pub source_sig: Option<String>,

    // Stream mapping location in binary format
    #[serde(default)]
    pub first_mapping_slab: u32,
    #[serde(default)]
    pub num_mapping_slabs: u32,
}

pub fn now() -> String {
    let dt = Utc::now();
    dt.to_rfc3339()
}

pub fn to_date_time(t: &str) -> chrono::DateTime<FixedOffset> {
    DateTime::parse_from_rfc3339(t).unwrap()
}

//-----------------------------------------

#[cfg(test)]
mod config_tests {

    use super::*;

    #[test]
    fn test_simple() {
        let config = StreamConfig {
            name: Some(String::from("test_file")),
            source_path: String::from("/home/some_user/test_file"),
            pack_time: String::from("2023-11-14T22:06:02.101221624+00:00"),
            size: u64::MAX,
            mapped_size: u64::MAX,
            packed_size: u64::MAX,
            thin_id: None,
            source_sig: None,
            first_mapping_slab: 0,
            num_mapping_slabs: 0,
        };

        let ser = serde_yaml_ng::to_string(&config).unwrap();
        let des_config: StreamConfig = serde_yaml_ng::from_str(&ser).unwrap();
        assert!(config == des_config);
    }
}
