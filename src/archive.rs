use anyhow::{anyhow, Result};

use crate::cuckoo_filter::*;
use crate::hash::*;
use crate::hash_index::*;
use crate::iovec::*;
use crate::paths;
use crate::paths::*;
use crate::recovery::*;
use crate::slab::MultiFile;
use crate::slab::*;
use std::io::Write;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

pub const SLAB_SIZE_TARGET: usize = 4 * 1024 * 1024;

pub struct Data<'a, S: SlabStorage = MultiFile> {
    seen: CuckooFilter,
    hashes: lru::LruCache<u32, ByHash>,

    data_file: S,
    hashes_file: Arc<Mutex<SlabFile<'a>>>,

    current_slab: u32,
    current_entries: usize,
    current_index: IndexBuilder,

    data_buf: Vec<u8>,
    hashes_buf: Vec<u8>,

    slabs: lru::LruCache<u32, ByIndex>,
    last_slab_completed: bool,
}

fn complete_slab_<S: SlabStorage>(slab: &mut S, buf: &mut Vec<u8>) -> Result<()> {
    slab.write_slab(buf)?;
    buf.clear();
    Ok(())
}

pub fn complete_slab<S: SlabStorage>(
    slab: &mut S,
    buf: &mut Vec<u8>,
    threshold: usize,
) -> Result<bool> {
    if buf.len() > threshold {
        complete_slab_(slab, buf)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Build a cuckoo filter by scanning the hashes file.
///
/// - `hashes_slab` : mutable reference to hashes slab file
/// - `capacity` : starting capacity to use when creating the filter.
///
/// Returns `seen`.
fn build_cuckoo_from_hashes(
    hashes_slab: &Arc<Mutex<SlabFile>>,
    start_cap: usize,
) -> Result<CuckooFilter> {
    let mut capacity = start_cap;

    loop {
        let mut seen = CuckooFilter::with_capacity(capacity);
        let mut resize_needed = false;

        let mut hashes_file = hashes_slab.lock().unwrap();

        for s in 0..hashes_file.get_nr_slabs() {
            let buf = hashes_file.read(s as u32)?;
            let hi = ByHash::new(buf)?;

            for i in 0..hi.len() {
                let h = hi.get(i);
                let mini_hash = hash_le_u64(h);
                if seen.test_and_set(mini_hash, s as u32).is_err() {
                    // insertion failed -> need to grow capacity
                    capacity *= 2;
                    resize_needed = true;
                    break;
                }
            }
        }

        if !resize_needed {
            return Ok(seen);
        }
    }
}

impl<'a, S: SlabStorage> Data<'a, S> {
    pub fn new(
        data_file: S,
        hashes_file: Arc<Mutex<SlabFile<'a>>>,
        slab_capacity: usize,
    ) -> Result<Self> {
        let hashes = lru::LruCache::new(NonZeroUsize::new(slab_capacity).unwrap());
        let nr_slabs = data_file.get_nr_slabs();

        {
            let hashes_file = hashes_file.lock().unwrap();
            assert_eq!(
                data_file.get_nr_slabs() as usize,
                hashes_file.get_nr_slabs()
            );
        }

        let slabs = lru::LruCache::new(NonZeroUsize::new(slab_capacity).unwrap());

        // Read this last. If we get an error reading up the file, we
        // can re-build it from the hashes file.
        let seen = {
            match CuckooFilter::read(paths::index_path()) {
                Ok(c) => c,
                Err(_) => build_cuckoo_from_hashes(&hashes_file, INITIAL_SIZE)?,
            }
        };

        Ok(Self {
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
            last_slab_completed: false,
        })
    }

    fn get_info(&mut self, slab: u32) -> Result<&ByIndex> {
        self.slabs.try_get_or_insert(slab, || {
            let mut hf = self.hashes_file.lock().unwrap();
            let hashes = hf.read(slab)?;
            ByIndex::new(hashes)
        })
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
            let mut hashes_file = self.hashes_file.lock().unwrap();
            let buf = hashes_file.read(slab)?;
            ByHash::new(buf)
        })
    }

    fn rebuild_index(&mut self, new_capacity: usize) -> Result<()> {
        let mut seen = build_cuckoo_from_hashes(&self.hashes_file, new_capacity)?;
        std::mem::swap(&mut seen, &mut self.seen);
        Ok(())
    }

    fn complete_data_slab(&mut self) -> Result<bool> {
        if complete_slab(&mut self.data_file, &mut self.data_buf, 0)? {
            let mut builder = IndexBuilder::with_capacity(1024); // FIXME: estimate properly
            std::mem::swap(&mut builder, &mut self.current_index);
            let buffer = builder.build()?;
            self.hashes_buf.write_all(&buffer[..])?;
            let index = ByHash::new(buffer)?;
            self.hashes.put(self.current_slab, index);

            let mut hashes_file = self.hashes_file.lock().unwrap();
            hashes_file.write_slab(&self.hashes_buf)?;
            self.hashes_buf.clear();
            self.current_slab += 1;
            self.current_entries = 0;
            Ok(true) // Slab was completed
        } else {
            Ok(false) // Slab not complete yet
        }
    }

    // Returns the (slab, entry) for the IoVec which may/may not already exist.
    pub fn data_add(&mut self, h: Hash256, iov: &IoVec, len: u64) -> Result<((u32, u32), u64)> {
        // There is an inherent race condition between checking if we have it and adding it,
        // check before we add when this functionality ends up on a server side.
        if let Some(location) = self.is_known(&h)? {
            return Ok((location, 0));
        }

        // Add entry to cuckoo filter, not checking return value as we could get indication that
        // it's "PossiblyPresent" when our logical expectation is "Inserted".
        let key = hash_le_u64(&h);
        self.seen
            .test_and_set(key, self.current_slab)
            .or_else(|_| {
                let new_cap = self.seen.capacity() * 2;
                self.rebuild_index(new_cap)?;
                self.seen.test_and_set(key, self.current_slab)
            })?;

        if self.data_buf.len() as u64 + len > SLAB_SIZE_TARGET as u64
            && self.complete_data_slab()?
        {
            self.last_slab_completed = true;
        }

        let r = (self.current_slab, self.current_entries as u32);
        for v in iov {
            self.data_buf.extend_from_slice(v);
        }
        self.current_entries += 1;
        self.current_index.insert(h, len as usize);
        Ok((r, len))
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

    // NOTE: This won't work for multiple clients and one server!
    pub fn file_sizes(&mut self) -> (u64, u64) {
        let hashes_written = {
            let hashes_file = self.hashes_file.lock().unwrap();
            hashes_file.get_file_size()
        };

        (self.data_file.get_file_size(), hashes_written)
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
        let info = self.get_info(slab)?;
        let (data_begin, data_end) = Self::calculate_offsets(offset, nr_entries, info, partial);
        let data = self.data_file.read(slab)?;

        Ok((data, data_begin, data_end))
    }

    // TODO: Now that we've fixed the issue preventing us from reading slab data that hasn't been written to
    // a slab, do we need to keep this?
    pub fn flush(&mut self) -> Result<()> {
        self.complete_data_slab()?;
        Ok(())
    }

    // Returns true if a slab was just completed, and resets the flag
    pub fn slab_just_completed(&mut self) -> bool {
        let result = self.last_slab_completed;
        self.last_slab_completed = false;
        result
    }

    // Get the total number of data slabs
    pub fn get_nr_data_slabs(&self) -> u32 {
        self.data_file.get_nr_slabs()
    }

    // Sync all archive files without closing them
    pub fn sync_checkpoint(&mut self) -> Result<()> {
        // Complete current data slab if needed
        self.complete_data_slab()?;

        // Sync hashes file
        let mut hashes_file = self.hashes_file.lock().unwrap();
        hashes_file.sync_all()?;
        drop(hashes_file);

        // Sync data file
        self.data_file.sync_all()?;

        // Write cuckoo filter
        self.seen.write(paths::index_path())?;

        // Sync the directory that is holding the cuckoo filter
        // Note: The offsets file could be re-built if needed.
        let index = paths::index_path();
        let cuckoo_parent = index.parent().unwrap();
        crate::recovery::sync_directory(cuckoo_parent)?;

        Ok(())
    }

    fn sync_and_close(&mut self) {
        self.sync_checkpoint()
            .expect("Data.drop: sync_checkpoint error!");
        let mut hashes_file = self.hashes_file.lock().unwrap();
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

impl<'a, S: SlabStorage> Drop for Data<'a, S> {
    fn drop(&mut self) {
        self.sync_and_close();
    }
}

/// Performs a flight check on data and hashes slab files
///
/// Verifies that both files have the same number of slabs. If they don't match,
/// regenerates the index files and checks again. Returns an error if they still
/// don't match after regeneration.
///
/// # Arguments
///
/// * `archive_path`  Path to archive
///
/// # Returns
///
/// * `Ok(())` if files have matching slab counts
/// * `Err` if slab counts don't match after regeneration
pub fn flight_check<P: AsRef<std::path::Path>>(archive_path: P) -> Result<()> {
    use std::path::Path;

    // Make sure the archive directory actually exists
    if !RecoveryCheckpoint::exists(&archive_path) {
        return Err(anyhow!(format!(
            "archive {:?} does not exist!",
            archive_path.as_ref()
        )));
    }

    let data_base_path = archive_path.as_ref().iter().as_path().join(data_path());
    let data_file = current_active_data_slab(&data_base_path)?;

    let hashes_file = archive_path.as_ref().iter().as_path().join(hashes_path());
    let data_path = data_file.as_ref();
    let hashes_path = hashes_file.as_ref();

    // Helper to get offsets file path
    fn offsets_path(p: &Path) -> std::path::PathBuf {
        let mut offsets_path = std::path::PathBuf::new();
        offsets_path.push(p);
        offsets_path.set_extension("offsets");
        offsets_path
    }

    // Helper to get slab offsets or regenerate if needed
    fn get_or_regenerate_slab_offsets<'a>(
        slab_path: &Path,
        offsets_path: &Path,
    ) -> Result<(crate::slab::offsets::SlabOffsets<'a>, bool)> {
        let offsets = if offsets_path.exists() {
            match crate::slab::offsets::SlabOffsets::open(offsets_path, false) {
                Ok(offsets) => offsets,
                Err(_) => {
                    // Failed to read, regenerate
                    crate::slab::regenerate_index(slab_path, None)?
                }
            }
        } else {
            // No offsets file, regenerate
            crate::slab::regenerate_index(slab_path, None)?
        };

        Ok((offsets, false))
    }

    let data_offsets_path = offsets_path(data_path);
    let hashes_offsets_path = offsets_path(hashes_path);

    // Get initial slab counts
    let (mut data_offsets, data_regen) =
        get_or_regenerate_slab_offsets(data_path, &data_offsets_path)?;
    let (mut hashes_offsets, hashes_regen) =
        get_or_regenerate_slab_offsets(hashes_path, &hashes_offsets_path)?;

    if data_regen {
        data_offsets.write_offset_file(true)?;
    }

    if hashes_regen {
        hashes_offsets.write_offset_file(true)?;
    }

    // Check if counts match bettween the data and hashes slab
    if data_offsets.len() != hashes_offsets.len() {
        // Close the offsets
        drop(data_offsets);
        drop(hashes_offsets);

        // Try regenerating both to be sure, regenerating index files is safe.
        let mut data_offsets = crate::slab::regenerate_index(data_path, None)?;
        let mut hashes_offsets = crate::slab::regenerate_index(hashes_path, None)?;

        let hashes_count = hashes_offsets.len();

        data_offsets.write_offset_file(true)?;
        hashes_offsets.write_offset_file(true)?;

        // We need to compare the count of all slabs across all the data files to the hashes file
        //
        // TODO: We may also have to go back through the slab files fixing up the index files.
        // because if the error exists in anyone of them, our numbers won't match
        let base_path = archive_path
            .as_ref()
            .iter()
            .as_path()
            .join(paths::data_path());
        let data_mf = MultiFile::open_for_read(base_path.clone(), 0)?;
        let data_count = data_mf.get_nr_slabs();
        drop(data_mf);

        if data_count as usize != hashes_count {
            // if we get here, we need to walk all the data slab files and regen all of the index
            // files.  When that is done we will fetch the number of data slabs and if it doesn't
            // match the hash slab count, the archive is in a bad state.
            MultiFile::fix_data_file_slab_indexes(&base_path)?;

            let data_mf = MultiFile::open_for_read(base_path.clone(), 0)?;
            let data_count = data_mf.get_nr_slabs();

            if data_count as usize != hashes_count {
                return Err(anyhow::anyhow!(
                "Slab count mismatch after offsets for all slab files regenerated: data file has {} slabs, hashes file has {} slabs",
                data_count,
                hashes_count
            ));
            }
        }
    }

    // Lastly, remove any in-progress streams file

    if let Err(e) = crate::paths::cleanup_temp_streams(
        archive_path
            .as_ref()
            .to_path_buf()
            .join("streams")
            .as_path(),
    ) {
        eprintln!("Warning: Failed to cleanup temp directories: {}", e);
    }

    Ok(())
}
