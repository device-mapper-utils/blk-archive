use anyhow::Result;

use crate::iovec::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::archive::file_based::Data;
use crate::archive::redb_based::DedupStore;
use crate::hash::*;
use crate::slab::SlabFile;

pub trait Store {
    fn data_add(&mut self, h: Hash256, iov: &IoVec, len: u64) -> Result<((u32, u32), u64)>;
    fn is_known(&mut self, h: &Hash256) -> Result<Option<(u32, u32)>>;
    fn data_get(
        &mut self,
        slab: u32,
        offset: u32,
        nr_entries: u32,
        partial: Option<(u32, u32)>,
    ) -> Result<(Arc<Vec<u8>>, usize, usize)>;

    fn flush(&mut self) -> Result<()>;
    fn ensure_extra_capacity(&mut self, blocks: usize) -> Result<()>;
}
pub enum Backend {
    File(Box<SlabFile>, Arc<Mutex<SlabFile>>, usize),
    Redb(PathBuf),
}

pub fn make_store(cfg: Backend) -> anyhow::Result<Box<dyn Store>> {
    Ok(match cfg {
        Backend::File(slab_file, hashes_file, slab_capacity) => {
            Box::new(Data::new(slab_file, hashes_file, slab_capacity)?)
        }
        Backend::Redb(path_buf) => Box::new(DedupStore::new(&path_buf)?),
    })
}

pub fn complete_slab_(slab: &mut SlabFile, buf: &mut Vec<u8>) -> Result<()> {
    slab.write_slab(buf)?;
    buf.clear();
    Ok(())
}

pub fn complete_slab(slab: &mut SlabFile, buf: &mut Vec<u8>, threshold: usize) -> Result<bool> {
    if buf.len() > threshold {
        complete_slab_(slab, buf)?;
        Ok(true)
    } else {
        Ok(false)
    }
}
