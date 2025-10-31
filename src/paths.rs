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
