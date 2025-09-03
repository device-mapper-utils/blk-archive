use anyhow::{Context, Result};

use crate::config::read_config;
use crate::cuckoo_filter::*;
use crate::hash::*;
use crate::hash_index::*;
use crate::iovec::*;
use crate::paths;
use crate::slab::*;
use crate::stream::{DataFields, MapEntry};
use crate::threaded_hasher::*;
use clap::ArgMatches;
use parking_lot::Mutex;
use std::io::Write;
use std::num::NonZeroUsize;
use std::sync::Arc;

pub const SLAB_SIZE_TARGET: u64 = 4 * 1024 * 1024;

pub struct Data {
    seen: CuckooFilter,
    hashes: lru::LruCache<u32, ByHash>,

    data_file: SlabFile,
    hashes_file: Arc<Mutex<SlabFile>>,

    current_slab: u32,
    current_entries: usize,
    current_index: IndexBuilder,

    data_buf: Vec<u8>,
    hashes_buf: Vec<u8>,

    slabs: lru::LruCache<u32, ByIndex>,
}

fn complete_slab_(slab: &mut SlabFile, buf: &mut Vec<u8>) -> Result<()> {
    slab.write_slab(buf)?;
    buf.clear();
    Ok(())
}

pub fn complete_slab(slab: &mut SlabFile, buf: &mut Vec<u8>, threshold: u64) -> Result<bool> {
    if buf.len() > threshold as usize {
        complete_slab_(slab, buf)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

impl Data {
    fn get_config_slab_cap(matches: &ArgMatches) -> Result<u64> {
        let config = read_config(".", matches)?;

        let hashes_per_slab = std::cmp::max(SLAB_SIZE_TARGET / config.block_size, 1);
        let slab_capacity = ((config.hash_cache_size_meg * 1024 * 1024)
            / std::mem::size_of::<Hash256>() as u64)
            / hashes_per_slab as u64;
        Ok(slab_capacity)
    }

    pub fn new(
        cache_entries: Option<u64>,
        data_file: Option<SlabFile>,
        hashes_file: Option<Arc<Mutex<SlabFile>>>,
        matches: &ArgMatches,
    ) -> Result<Self> {
        let seen = CuckooFilter::read(paths::index_path())?;
        let mut slab_capacity = Self::get_config_slab_cap(matches)?;

        if let Some(cache_entries) = cache_entries {
            slab_capacity = cache_entries;
        }

        let hashes = lru::LruCache::new(NonZeroUsize::new(slab_capacity as usize).unwrap());
        let slabs: lru::LruCache<u32, ByIndex> =
            lru::LruCache::new(NonZeroUsize::new(slab_capacity as usize).unwrap());

        let data_file = data_file.unwrap_or(
            SlabFileBuilder::open(paths::data_path())
                .write(true)
                .queue_depth(128)
                .build()
                .context("couldn't open data slab file")?,
        );

        let nr_slabs = data_file.get_nr_slabs() as u32;

        let hashes_file: Arc<parking_lot::lock_api::Mutex<parking_lot::RawMutex, SlabFile>> =
            hashes_file.unwrap_or(Arc::new(Mutex::new(
                SlabFileBuilder::open(paths::hashes_path())
                    .write(true)
                    .queue_depth(16)
                    .build()
                    .context("couldn't open hashes slab file")?,
            )));

        {
            let hashes_file = hashes_file.lock();
            assert_eq!(data_file.get_nr_slabs(), hashes_file.get_nr_slabs());
        }

        let mut s = Self {
            seen,
            hashes,
            data_file,
            hashes_file,
            current_slab: nr_slabs,
            current_index: IndexBuilder::with_capacity(1024), // FIXME: estimate
            current_entries: 0,
            data_buf: Vec::new(),
            hashes_buf: Vec::new(),
            slabs,
        };

        // TODO make this more dynamic as needed that will work in multi-client env.
        s.rebuild_index(262144)?;

        Ok(s)
    }

    fn _get_info<'a>(
        slabs: &'a mut lru::LruCache<u32, ByIndex>,
        hashes_file: &mut Arc<Mutex<SlabFile>>,
        slab: u32,
    ) -> Result<&'a ByIndex> {
        slabs.try_get_or_insert(slab, || {
            let mut hf = hashes_file.lock();
            let hashes = hf.read(slab)?;
            ByIndex::new(hashes)
        })
    }

    pub fn calculate_entry_len(&mut self, d: &DataFields) -> Result<u64> {
        Self::_calculate_entry_len(&mut self.slabs, &mut self.hashes_file, d)
    }

    pub fn _calculate_entry_len(
        slabs: &mut lru::LruCache<u32, ByIndex>,
        hashes_file: &mut Arc<Mutex<SlabFile>>,
        d: &DataFields,
    ) -> Result<u64> {
        let index = Self::_get_info(slabs, hashes_file, d.slab)?;
        let mut total_len = 0;
        for i in d.offset..(d.offset + d.nr_entries) {
            let (data_begin, data_end, _) = index.get(i as usize).unwrap();
            total_len += data_end - data_begin;
        }
        Ok(total_len as u64)
    }

    fn get_map_entry_lengths(
        slabs: &mut lru::LruCache<u32, ByIndex>,
        hashes_file: &mut Arc<Mutex<SlabFile>>,
        map_entries: &mut [MapEntry],
    ) -> Result<()> {
        for e in map_entries.iter_mut() {
            if let MapEntry::Data(d) = e {
                let len = Self::_calculate_entry_len(slabs, hashes_file, d)?;
                *e = MapEntry::DataWithLen { d: *d, len };
            }
        }
        Ok(())
    }

    pub fn calculate_stream_map_entry_lengths(
        matches: &ArgMatches,
        map_entries: &mut [MapEntry],
    ) -> Result<()> {
        // create a LRU and load hashes file and rip through the entries
        let slab_capacity = Self::get_config_slab_cap(matches)?;

        let mut slabs: lru::LruCache<u32, ByIndex> =
            lru::LruCache::new(NonZeroUsize::new(slab_capacity as usize).unwrap());

        let mut hashes_file = Arc::new(Mutex::new(
            SlabFileBuilder::open(paths::hashes_path())
                .write(true)
                .queue_depth(16)
                .build()
                .context("couldn't open hashes slab file")?,
        ));

        Self::get_map_entry_lengths(&mut slabs, &mut hashes_file, map_entries)?;

        Ok(())
    }

    pub fn calculate_stream_map_entry_lengths_m(
        &mut self,
        map_entries: &mut [MapEntry],
    ) -> Result<()> {
        Self::get_map_entry_lengths(&mut self.slabs, &mut self.hashes_file, map_entries)
    }

    pub fn ensure_extra_capacity(&mut self, blocks: usize) -> Result<()> {
        if self.seen.capacity() < self.seen.len() + blocks {
            self.rebuild_index(self.seen.len() + blocks)?;
            eprintln!("resized index to {}", self.seen.capacity());
        }

        Ok(())
    }

    fn get_hash_index(&mut self, slab: u32) -> Result<&ByHash> {
        // the current slab is not inserted into the self.hashes
        assert!(slab != self.current_slab);

        self.hashes.try_get_or_insert(slab, || {
            let mut hashes_file = self.hashes_file.lock();
            let buf = hashes_file.read(slab)?;
            ByHash::new(buf)
        })
    }

    fn rebuild_index(&mut self, mut new_capacity: usize) -> Result<()> {
        loop {
            let mut seen = CuckooFilter::with_capacity(new_capacity);
            let mut resize_needed = false;

            // Lock the hashes file and iterate through slabs.
            let mut hashes_file = self.hashes_file.lock();
            for s in 0..hashes_file.get_nr_slabs() {
                let buf = hashes_file.read(s as u32)?;
                let hi = ByHash::new(buf)?;

                for i in 0..hi.len() {
                    let h = hi.get(i);
                    let mini_hash = hash_le_u64(h);
                    if seen.test_and_set(mini_hash, s as u32).is_err() {
                        new_capacity *= 2;
                        resize_needed = true;
                        break;
                    }
                }

                if resize_needed {
                    break;
                }
            }

            if !resize_needed {
                std::mem::swap(&mut seen, &mut self.seen);
                return Ok(());
            }
        }
    }

    fn complete_data_slab(&mut self) -> Result<()> {
        if complete_slab(&mut self.data_file, &mut self.data_buf, 0)? {
            let mut builder = IndexBuilder::with_capacity(1024); // FIXME: estimate properly
            std::mem::swap(&mut builder, &mut self.current_index);
            let buffer = builder.build()?;
            self.hashes_buf.write_all(&buffer[..])?;
            let index = ByHash::new(buffer)?;
            self.hashes.put(self.current_slab, index);

            let mut hashes_file = self.hashes_file.lock();
            complete_slab_(&mut hashes_file, &mut self.hashes_buf)?;
            self.current_slab += 1;
            self.current_entries = 0;
        }
        Ok(())
    }

    fn data_add_common<'a>(
        &mut self,
        h: Hash256,
        data: impl IntoIterator<Item = &'a [u8]>,
        len: u64,
    ) -> Result<((u32, u32), u64)> {
        if let Some(location) = self.is_known(&h)? {
            return Ok((location, 0));
        }

        let h64 = hash_le_u64(&h);
        if self.seen.test_and_set(h64, self.current_slab).is_err() {
            let s = self.seen.capacity() * 2;
            self.rebuild_index(s)?;
        }

        if self.data_buf.len() as u64 + len > SLAB_SIZE_TARGET {
            self.complete_data_slab()?;
        }

        let r = (self.current_slab, self.current_entries as u32);
        for chunk in data {
            self.data_buf.extend_from_slice(chunk);
        }
        self.current_entries += 1;
        self.current_index.insert(h, len as usize);
        Ok((r, len))
    }

    pub fn data_add(&mut self, h: HashedData, len: u64) -> Result<((u32, u32), u64)> {
        self.data_add_common(h.h256, std::iter::once(&h.data[..]), len)
    }

    pub fn data_add_iov(&mut self, h: Hash256, iov: &IoVec, len: u64) -> Result<((u32, u32), u64)> {
        self.data_add_common(h, iov.iter().map(|v| &v[..]), len)
    }

    // Have we seen this hash before, if we have we will return the slab and offset
    // Note: This function does not modify any state
    pub fn is_known(&mut self, h: &Hash256) -> Result<Option<(u32, u32)>> {
        let mini_hash = hash_le_u64(h);
        let rc = match self.seen.test(mini_hash)? {
            // This is a possibly in set
            InsertResult::PossiblyPresent(s) => {
                if self.current_slab == s {
                    if let Some(offset) = self.current_index.lookup(h) {
                        Some((self.current_slab, offset))
                    } else {
                        None
                    }
                } else {
                    let hi = self.get_hash_index(s)?;
                    hi.lookup(h).map(|offset| (s, offset as u32))
                }
            }
            _ => None,
        };
        Ok(rc)
    }

    fn calculate_offsets(
        offset: u32,
        nr_entries: u32,
        info: &ByIndex,
        partial: Option<(u32, u32)>,
    ) -> (usize, usize) {
        let (data_begin, data_end) = if nr_entries == 1 {
            let (data_begin, data_end, _expected_hash) = info.get(offset as usize).unwrap();
            (*data_begin as usize, *data_end as usize)
        } else {
            let (data_begin, _data_end, _expected_hash) = info.get(offset as usize).unwrap();
            let (_data_begin, data_end, _expected_hash) = info
                .get((offset as usize) + (nr_entries as usize) - 1)
                .unwrap();
            (*data_begin as usize, *data_end as usize)
        };

        if let Some((begin, end)) = partial {
            let data_end = data_begin + end as usize;
            let data_begin = data_begin + begin as usize;
            (data_begin, data_end)
        } else {
            (data_begin, data_end)
        }
    }

    pub fn data_get(
        &mut self,
        slab: u32,
        offset: u32,
        nr_entries: u32,
        partial: Option<(u32, u32)>,
    ) -> Result<(Arc<Vec<u8>>, usize, usize)> {
        let info = Self::_get_info(&mut self.slabs, &mut self.hashes_file, slab)?;
        let (data_begin, data_end) = Self::calculate_offsets(offset, nr_entries, info, partial);
        let data = self.data_file.read(slab)?;

        Ok((data, data_begin, data_end))
    }

    // Not used at the moment, but was used for the send/receive POC.  This was being called after
    // we received the newly created stream file for a pack operation.  The reason this is done is
    // until you complete a slab, you cannot locate it in the data_get path for unpack operation.
    pub fn flush(&mut self) -> Result<()> {
        self.complete_data_slab()
    }

    pub fn get_seen(&mut self) -> CuckooFilterSerialized {
        self.seen.to_rpc()
    }

    fn sync_and_close(&mut self) {
        self.complete_data_slab()
            .expect("Data.drop: complete_data_slab error!");
        let mut hashes_file = self.hashes_file.lock();
        hashes_file
            .close()
            .expect("Data.drop: hashes_file.close() error!");
        self.data_file
            .close()
            .expect("Data.drop: data_file.close() error!");
        self.seen
            .write(paths::index_path())
            .expect("Data.drop: seen.write() error!");
    }
}

impl Drop for Data {
    fn drop(&mut self) {
        self.sync_and_close();
    }
}
