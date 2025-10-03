use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

//------------------------------

pub fn index_path() -> PathBuf {
    ["indexes", "seen"].iter().collect()
}

pub fn data_path() -> PathBuf {
    ["data", "data"].iter().collect()
}

pub fn hashes_path() -> PathBuf {
    ["data", "hashes"].iter().collect()
}

pub fn stream_path(stream: &str) -> PathBuf {
    ["streams", stream, "stream"].iter().collect()
}

pub fn stream_config(stream: &str) -> PathBuf {
    ["streams", stream, "config.yaml"].iter().collect()
}

/// Clean up all temporary stream directories
///
/// This removes any `.tmp_*` directories in the streams directory.
/// These are uncommitted pack operations that were interrupted.
/// This should be called by any command that accesses the archive.
pub fn cleanup_temp_streams(streams_dir: &Path) -> Result<()> {
    if !streams_dir.exists() {
        return Ok(());
    }

    let paths = fs::read_dir(streams_dir)?;

    for entry in paths {
        let entry = entry?;
        let file_name = entry.file_name();
        let name = file_name.to_str().unwrap_or("");

        if name.starts_with(".tmp_") {
            if let Err(e) = fs::remove_dir_all(entry.path()) {
                eprintln!("Warning: Failed to remove temp directory {}: {}", name, e);
            }
        }
    }
    Ok(())
}

//------------------------------
