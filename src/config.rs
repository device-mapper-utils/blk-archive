use anyhow::{anyhow, Context, Result};
use clap::ArgMatches;

use std::fs;
use std::path::{Path, PathBuf};

use rkyv::{Archive, Deserialize, Serialize};

use serde_derive::Deserialize as SDeserialize;
use serde_derive::Serialize as SSerialize;

//-----------------------------------------

#[derive(SDeserialize, SSerialize, Deserialize, Archive, Serialize, Debug, PartialEq)]
#[rkyv(
    // This will generate a PartialEq impl between our unarchived
    // and archived types
    compare(PartialEq),
    // Derives can be passed through to the generated type:
    derive(Debug),
)]
pub struct Config {
    pub block_size: u64,
    pub splitter_alg: String,
    pub hash_cache_size_meg: u64,
    pub data_cache_size_meg: u64,
}

fn numeric_override<T: std::str::FromStr>(matches: &ArgMatches, name: &str) -> Result<Option<T>> {
    match matches.try_get_one::<String>(name) {
        Ok(Some(s)) => s
            .parse::<T>()
            .map_err(|_| anyhow!("could not parse {} argument", name))
            .map(|n| Some(n)),
        Ok(None) => Ok(None),
        Err(_) => Err(anyhow!("Error retrieving {} argument", name)),
    }
}

pub fn read_config<P: AsRef<Path>>(root: P, overrides: &ArgMatches) -> Result<Config> {
    let mut p = PathBuf::new();
    p.push(root);
    p.push("dm-archive.yaml");
    let input = fs::read_to_string(p).context("couldn't read config file")?;
    let mut config: Config =
        serde_yaml_ng::from_str(&input).context("couldn't parse config file")?;

    if let Some(data_cache_meg) = numeric_override::<u64>(overrides, "DATA_CACHE_SIZE_MEG")? {
        config.data_cache_size_meg = data_cache_meg;
    }
    Ok(config)
}
