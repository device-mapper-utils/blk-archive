use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

//------------------------------

fn make<P, I, S>(base: P, parts: I) -> PathBuf
where
    P: AsRef<Path>,
    I: IntoIterator<Item = S>,
    S: AsRef<Path>,
{
    parts
        .into_iter()
        .fold(base.as_ref().to_path_buf(), |p, s| p.join(s))
}

pub fn index_path<P: AsRef<std::path::Path>>(base: P) -> PathBuf {
    make(&base, ["indexes", "seen"])
}

pub fn data_path<P: AsRef<std::path::Path>>(base: P) -> PathBuf {
    make(&base, ["data", "data"])
}

pub fn hashes_path<P: AsRef<std::path::Path>>(base: P) -> PathBuf {
    make(&base, ["data", "hashes"])
}

pub fn stream_path<P: AsRef<std::path::Path>>(base: P, stream: &str) -> PathBuf {
    make(&base, ["streams", stream, "stream"])
}

pub fn stream_config<P: AsRef<std::path::Path>>(base: P, stream: &str) -> PathBuf {
    make(&base, ["streams", stream, "config.yaml"])
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

    let paths = fs::read_dir(streams_dir).with_context(|| {
        format!(
            "cleanup_temp_streams:failed to read streams directory {:?}",
            streams_dir
        )
    })?;

    for entry in paths {
        let entry = entry.with_context(|| {
            format!(
                "cleanup_temp_streams:failed to read directory entry in {:?}",
                streams_dir
            )
        })?;
        let file_name = entry.file_name();
        let name = file_name.to_str().unwrap_or("");

        if name.starts_with(".tmp_") {
            if let Err(e) = fs::remove_dir_all(entry.path()) {
                eprintln!(
                    "cleanup_temp_streams:: Warning: Failed to remove temp directory {}: {}",
                    name, e
                );
            }
        }
    }
    Ok(())
}

//------------------------------
