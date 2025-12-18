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

pub fn streams_metadata_path<P: AsRef<std::path::Path>>(base: P) -> PathBuf {
    make(&base, ["streams", "metadata"])
}

pub fn stream_mappings_path<P: AsRef<std::path::Path>>(base: P) -> PathBuf {
    make(&base, ["streams", "mappings"])
}

pub fn append_to_filename(mut path: PathBuf, suffix: &str) -> PathBuf {
    // Get the file name (without directories)
    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
        // Split into stem + extension
        let (stem, ext) = match Path::new(file_name).file_stem().and_then(|s| s.to_str()) {
            Some(stem) => {
                let ext = Path::new(file_name).extension().and_then(|e| e.to_str());
                (stem, ext)
            }
            None => (file_name, None),
        };

        // Build new filename with suffix
        let new_name = if let Some(ext) = ext {
            format!("{stem}{suffix}.{ext}")
        } else {
            format!("{stem}{suffix}")
        };

        // Replace the file name in the path
        path.set_file_name(new_name);
    }

    path
}
