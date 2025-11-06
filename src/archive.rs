use anyhow::{Context, Result};

use crate::cuckoo_filter::*;
use crate::hash::*;
use crate::hash_index::*;
use crate::iovec::*;
use crate::paths;
use crate::recovery::*;
use crate::slab::MultiFile;
use crate::slab::*;
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub const SLAB_SIZE_TARGET: usize = 4 * 1024 * 1024;

pub struct Data<'a, S: SlabStorage = MultiFile> {
    archive_dir: PathBuf,
    skip_data: bool,
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
    fake_write: bool,
) -> Result<bool> {
    if buf.len() > threshold {
        if fake_write {
            buf.clear();
        } else {
            complete_slab_(slab, buf)?;
        }
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
pub fn build_cuckoo_from_hashes(
    hashes_slab: &Arc<Mutex<SlabFile>>,
    start_cap: usize,
) -> Result<CuckooFilter> {
    let mut capacity = start_cap;

    loop {
        let mut seen = CuckooFilter::with_capacity(capacity);
        let mut resize_needed = false;

        let mut hashes_file = hashes_slab.lock().unwrap();

        for s in 0..hashes_file.get_nr_slabs() {
            let buf = hashes_file.read(s as u32).with_context(|| {
                format!("build_cuckoo_from_hashes:failed to read hashes slab {}", s)
            })?;
            let hi = ByHash::new(buf).with_context(|| {
                format!(
                    "build_cuckoo_from_hashes: failed to parse hash index for slab {}",
                    s
                )
            })?;

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

            if resize_needed {
                break;
            }
        }
        if !resize_needed {
            return Ok(seen);
        }
    }
}

impl<'a, S: SlabStorage> Data<'a, S> {
    pub fn new(
        archive_dir: &Path,
        data_file: S,
        hashes_file: Arc<Mutex<SlabFile<'a>>>,
        slab_capacity: usize,
    ) -> Result<Self> {
        let hashes = lru::LruCache::new(NonZeroUsize::new(slab_capacity).unwrap());
        let nr_slabs = data_file.get_nr_slabs();
        let skip_data = std::env::var("BLK_ARCHIVE_DEVEL_SKIP_DATA").is_ok();

        {
            if !skip_data {
                let hashes_file = hashes_file.lock().unwrap();
                assert_eq!(
                    data_file.get_nr_slabs() as usize,
                    hashes_file.get_nr_slabs()
                );
            }
        }

        let slabs = lru::LruCache::new(NonZeroUsize::new(slab_capacity).unwrap());

        // Read this last. If we get an error reading up the file, we
        // can re-build it from the hashes file.
        let seen = {
            match CuckooFilter::read(paths::index_path(archive_dir)) {
                Ok(c) => c,
                Err(_) => build_cuckoo_from_hashes(&hashes_file, INITIAL_SIZE)?,
            }
        };

        Ok(Self {
            archive_dir: archive_dir.to_path_buf(),
            skip_data,
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
            let hashes = hf
                .read(slab)
                .with_context(|| format!("Failed to read hashes for slab {}", slab))?;
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
            let buf = hashes_file
                .read(slab)
                .with_context(|| format!("get_hash_index: read error for slab idx {}", slab))?;
            ByHash::new(buf)
        })
    }

    fn rebuild_index(&mut self, new_capacity: usize) -> Result<()> {
        let mut seen = build_cuckoo_from_hashes(&self.hashes_file, new_capacity)?;
        std::mem::swap(&mut seen, &mut self.seen);
        Ok(())
    }

    fn complete_data_slab(&mut self) -> Result<bool> {
        if complete_slab(&mut self.data_file, &mut self.data_buf, 0, self.skip_data)? {
            let mut builder = IndexBuilder::with_capacity(1024); // FIXME: estimate properly
            std::mem::swap(&mut builder, &mut self.current_index);
            let buffer = builder.build()?;
            self.hashes_buf.write_all(&buffer[..])?;
            let index = ByHash::new(buffer)?;
            self.hashes.put(self.current_slab, index);

            let mut hashes_file = self.hashes_file.lock().unwrap();
            hashes_file.write_slab(&self.hashes_buf).with_context(|| {
                format!(
                    "complete_data_slab: write error hashes slab idx {}",
                    self.current_slab
                )
            })?;
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

    // Sync all archive files without closing them (does NOT write checkpoint file for MultiFile)
    // This is the internal implementation used by both the generic Drop and MultiFile::sync_checkpoint
    pub(crate) fn sync_internal(&mut self) -> Result<()> {
        // Check if completing the slab will cross a file boundary
        // For SlabFile, will_cross_boundary_on_next_write() always returns false
        // For MultiFile, we need to handle the boundary before completing the slab
        if self.data_file.will_cross_boundary_on_next_write() {
            // Sync archive state for the boundary crossing
            self.sync_for_file_boundary()?;

            // Cross the boundary (no-op for SlabFile, creates new file for MultiFile)
            // Note: For MultiFile, this should ideally create a checkpoint first,
            // but we can't do that here without access to MultiFile-specific methods.
            // The caller (drop or explicit sync) should handle this properly.
            self.data_file.cross_file_boundary()?;
        }

        // Complete current data slab if needed
        self.complete_data_slab()
            .with_context(|| "Failed to complete data slab during sync checkpoint")?;

        // Sync hashes file
        let mut hashes_file = self.hashes_file.lock().unwrap();
        hashes_file
            .sync_all()
            .with_context(|| "Failed to sync hashes file")?;
        drop(hashes_file);

        // Sync data file
        self.data_file
            .sync_all()
            .with_context(|| "Failed to sync data file")?;

        // Write cuckoo filter
        let index_path = paths::index_path(&self.archive_dir);
        self.seen
            .write(&index_path)
            .with_context(|| format!("Failed to write cuckoo filter to {:?}", index_path))?;

        // Sync the directory that is holding the cuckoo filter
        // Note: The offsets file could be re-built if needed.
        index_path
            .sync_parent()
            .with_context(|| format!("Failed to sync parent directory of {:?}", index_path))?;

        Ok(())
    }

    /// Sync archive state for file boundary crossing
    ///
    /// This is called when MultiFile is about to create a new slab file.
    /// Unlike sync_checkpoint(), this does NOT complete the current data slab
    /// or sync the data file, since we're in the middle of a write_slab() operation.
    pub fn sync_for_file_boundary(&mut self) -> Result<()> {
        // Sync hashes file before creating checkpoint
        // Note: While MultiFile::write_slab syncs the data file when writing the last slab,
        // it does NOT sync the hashes file, which is a separate SlabFile. We must sync it
        // here to ensure the checkpoint captures the correct file size.
        let mut hashes_file = self.hashes_file.lock().unwrap();
        hashes_file
            .sync_all()
            .with_context(|| "Failed to sync hashes file before boundary crossing")?;
        drop(hashes_file);

        // Write cuckoo filter
        let index_path = paths::index_path(&self.archive_dir);
        self.seen
            .write(&index_path)
            .with_context(|| format!("Failed to write cuckoo filter to {:?}", index_path))?;

        // Sync the directory holding the cuckoo filter
        index_path
            .sync_parent()
            .with_context(|| format!("Failed to sync parent directory of {:?}", index_path))?;

        Ok(())
    }

    fn sync_and_close(&mut self) {
        self.sync_internal()
            .expect("Data.drop: sync_internal error!");
        let mut hashes_file = self.hashes_file.lock().unwrap();
        hashes_file
            .close()
            .expect("Data.drop: hashes_file.close() error!");
        self.data_file
            .close()
            .expect("Data.drop: data_file.close() error!");
        let index_path = paths::index_path(&self.archive_dir);
        self.seen
            .write(&index_path)
            .expect("Data.drop: seen.write() error!");
    }
}

impl<'a, S: SlabStorage> Drop for Data<'a, S> {
    fn drop(&mut self) {
        self.sync_and_close();
    }
}

pub fn calculate_slab_capacity(block_size: usize, hash_cache_size_meg: usize) -> usize {
    let hashes_per_slab = std::cmp::max(SLAB_SIZE_TARGET / block_size, 1);
    ((hash_cache_size_meg * 1024 * 1024) / std::mem::size_of::<Hash256>()) / hashes_per_slab
}

// Specialized methods for Data<MultiFile>
impl<'a> Data<'a, MultiFile> {
    /// Sync all archive files and write checkpoint
    ///
    /// This method syncs all archive state and writes a checkpoint file
    /// that can be used for crash recovery. The checkpoint captures the
    /// current write file ID to ensure recovery knows which files are valid.
    pub fn sync_checkpoint(&mut self) -> Result<()> {
        // First do the standard sync (complete slab, sync files, write cuckoo filter)
        self.sync_internal()?;

        // Now write the checkpoint file with the current write file ID
        let data_slab_file_id = self.data_file.get_current_write_file_id();
        let checkpoint_path = self.archive_dir.join(crate::recovery::check_point_file());
        let checkpoint =
            crate::recovery::create_checkpoint_from_files(&self.archive_dir, data_slab_file_id)?;
        checkpoint.write(&checkpoint_path).with_context(|| {
            format!(
                "MultiFile:sync_checkpoint: failed to write checkpoint to {:?}",
                checkpoint_path
            )
        })?;

        Ok(())
    }

    /// Check if the next slab write will cross a file boundary
    pub fn will_cross_file_boundary(&self) -> bool {
        self.data_file.will_cross_boundary_on_next_write()
    }

    /// Handle file boundary crossing with proper checkpointing
    ///
    /// This method:
    /// 1. Syncs all archive state (hashes, cuckoo filter, directories)
    /// 2. Creates a checkpoint with the current file ID
    /// 3. Crosses the file boundary (closes old file, creates new one)
    ///
    /// CRITICAL: This ensures crash consistency by checkpointing BEFORE
    /// creating the new file. If we crash after the new file is created
    /// but before the next checkpoint, recovery will delete the new file.
    pub fn handle_file_boundary_crossing(&mut self) -> Result<()> {
        if !self.will_cross_file_boundary() {
            return Err(anyhow::anyhow!(
                "handle_file_boundary_crossing called when not at boundary"
            ));
        }

        let current_file_id = self.data_file.get_current_write_file_id();

        // Sync archive state (hashes, cuckoo filter, directories)
        self.sync_for_file_boundary()?;

        // Create checkpoint with current file_id BEFORE crossing boundary
        let checkpoint_path = self.archive_dir.join(crate::recovery::check_point_file());
        let checkpoint =
            crate::recovery::create_checkpoint_from_files(&self.archive_dir, current_file_id)?;
        checkpoint
            .write(&checkpoint_path)
            .with_context(|| format!("Failed to write checkpoint to {:?}", checkpoint_path))?;

        // Now it's safe to cross the boundary
        self.data_file.cross_file_boundary().with_context(|| {
            format!(
                "Failed to cross file boundary:current file {:?}",
                current_file_id
            )
        })?;

        Ok(())
    }

    /// Complete data slab with file boundary handling
    ///
    /// This wraps the generic complete_data_slab() to handle MultiFile-specific
    /// file boundary crossings with proper checkpointing.
    pub fn complete_data_slab_with_boundary_check(&mut self) -> Result<bool> {
        // Check if we're at a file boundary BEFORE completing the slab
        if self.will_cross_file_boundary() {
            self.handle_file_boundary_crossing()?;
        }

        // Now safe to complete the slab
        self.complete_data_slab()
    }

    /// Data add with file boundary handling
    ///
    /// This wraps the generic data_add() to handle MultiFile-specific
    /// file boundary crossings. When data_add() encounters a file boundary
    /// (MultiFile returns FileBoundaryError from write_slab()), this method:
    ///
    /// 1. Detects the FileBoundaryError via downcast
    /// 2. Syncs archive state and creates a checkpoint
    /// 3. Crosses the file boundary (close old file, create new one)
    /// 4. Retries the data_add() operation
    ///
    /// This ensures crash consistency by checkpointing BEFORE creating new files.
    pub fn data_add_with_boundary_check(
        &mut self,
        h: Hash256,
        iov: &IoVec,
        len: u64,
    ) -> Result<((u32, u32), u64)> {
        // The generic data_add() may call complete_data_slab() which writes a slab
        // If we hit a file boundary, handle it and retry
        match self.data_add(h, iov, len) {
            Err(e) => {
                // Use downcast to check for the specific FileBoundaryError type
                if let Some(_boundary_err) = e.downcast_ref::<crate::slab::FileBoundaryError>() {
                    // Hit file boundary during data_add
                    // Sync, checkpoint, cross boundary, then retry
                    self.handle_file_boundary_crossing()?;
                    self.data_add(h, iov, len)
                } else {
                    // Some other error, propagate it
                    Err(e)
                }
            }
            result => result,
        }
    }

    /// Get the current write file ID from the underlying MultiFile storage
    pub fn get_current_write_file_id(&self) -> u32 {
        self.data_file.get_current_write_file_id()
    }
}

pub fn archive_data_slab_count<P: AsRef<std::path::Path>>(archive_path: P) -> Result<(u32, bool)> {
    let mut regen = false;
    let count = match MultiFile::total_number_slabs(&archive_path) {
        Ok(len) => len.1,
        Err(_) => {
            // We got an error going through all the slab index files, try to fix
            MultiFile::fix_data_file_slab_indexes(&archive_path, false).with_context(|| {
                format!(
                    "Failed to fix data file slab indexes at {:?}",
                    archive_path.as_ref()
                )
            })?;
            regen = true;
            // This should work without errors!
            MultiFile::total_number_slabs(&archive_path)?.1
        }
    };
    Ok((count, regen))
}

pub fn archive_hashes_slab_count<P: AsRef<std::path::Path>>(
    archive_path: P,
) -> Result<(u32, bool)> {
    let mut regen = false;
    let hashes_path = paths::hashes_path(&archive_path);
    let count = match file::number_of_slabs(&hashes_path) {
        Ok(len) => len,
        Err(_) => {
            // hashes index file has an error, fix
            let mut hash_index =
                crate::slab::regenerate_index(&hashes_path, false).with_context(|| {
                    format!("Failed to regenerate hashes index for {:?}", hashes_path)
                })?;
            regen = true;
            hash_index.write_offset_file(true)?;
            file::number_of_slabs(&hashes_path)?
        }
    };
    Ok((count, regen))
}

// The tests below verify the crash-consistency guarantees of the file boundary
// crossing implementation.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::default;
    use crate::recovery;
    use crate::slab::multi_file::{MultiFile, SLABS_PER_FILE};
    use crate::slab::SlabFileBuilder;
    use rand::Rng;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    fn fill_random(vec: &mut Vec<u8>) {
        let mut rng = rand::thread_rng();
        for byte in vec.iter_mut() {
            *byte = rng.gen();
        }
    }

    /// Test that file boundary crossing creates checkpoints correctly
    ///
    /// This test verifies the critical crash-consistency guarantee:
    /// - Checkpoint is created BEFORE new file is created
    /// - If interrupted after checkpoint, new file can be created on recovery
    /// - If interrupted before checkpoint, state rolls back to previous file
    #[test]
    #[ignore]
    fn test_file_boundary_checkpoint_on_interruption() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path();

        std::fs::create_dir_all(archive_path)
            .with_context(|| format!("Unable to create archive {:?}", archive_path))?;

        // This will create an empty archive with defaults
        let values = default(archive_path).with_context(|| {
            format!(
                "Error while creating default directory in {:?}",
                archive_path
            )
        })?;
        let slab_capacity = calculate_slab_capacity(values.block_size, values.hash_cache_size_meg);

        let data_file = MultiFile::open_for_write(archive_path, 10, slab_capacity)?;
        let hashes_file = Arc::new(Mutex::new(
            SlabFileBuilder::open(paths::hashes_path(&archive_path))
                .write(true)
                .queue_depth(16)
                .build()
                .context("couldn't open hashes slab file")?,
        ));

        let mut archive = Data::new(archive_path, data_file, hashes_file.clone(), 10)?;

        // Check initial state - should not be at boundary with empty archive
        assert!(
            !archive.will_cross_file_boundary(),
            "Empty archive should not be at boundary"
        );

        println!("Writing {} slabs to reach file boundary...", SLABS_PER_FILE);

        // Write SLABS_PER_FILE slabs to reach the boundary
        // Each slab needs to exceed SLAB_SIZE_TARGET to trigger completion
        // and the data needs to be random to prevent it from being de-duplicated
        let block_size = 4096;
        let blocks_per_slab = (SLAB_SIZE_TARGET / block_size) + 1;
        let mut test_data = vec![0u8; block_size];

        for slab_idx in 0..SLABS_PER_FILE {
            for _ in 0..blocks_per_slab {
                // We need to data random so it doesn't get de-duped
                fill_random(&mut test_data);
                let mut iov = IoVec::new();
                iov.push(&test_data);
                let h = crate::hash::hash_256(&test_data);
                archive.data_add_with_boundary_check(h, &iov, test_data.len() as u64)?;
            }

            if slab_idx % 100 == 0 {
                println!("Written {} slabs...", slab_idx + 1);
            }
        }

        // Now we should be at the boundary
        assert!(
            archive.will_cross_file_boundary(),
            "After writing {} slabs, should be at file boundary",
            SLABS_PER_FILE
        );

        // Test boundary crossing with checkpoint
        archive.handle_file_boundary_crossing()?;

        // After crossing, should not be at boundary anymore
        assert!(
            !archive.will_cross_file_boundary(),
            "After crossing boundary, should not be at boundary"
        );

        // Verify checkpoint was created with file_id=0 (before crossing to file 1)
        let checkpoint_path = archive_path.join(recovery::check_point_file());
        assert!(checkpoint_path.exists(), "Checkpoint file should exist");

        let checkpoint = recovery::RecoveryCheckpoint::read(&checkpoint_path)?;
        assert_eq!(
            checkpoint.data_slab_file_id, 0,
            "Checkpoint should have file_id=0 (created before crossing to file 1)"
        );

        // Check for the existence of the new data file and index
        let new_file_path = file_id_to_path(archive_path, 1);

        assert!(
            new_file_path.exists(),
            "New data file should exist after crossing file boundary!"
        );

        drop(archive);

        // Check the archive, fix up as needed, this should remove the new data file and index
        flight_check(archive_path).unwrap();

        // Check that the new data file and index are gone
        assert!(
            !new_file_path.exists(),
            "New data file should NOT exist after flight_check()"
        );

        Ok(())
    }

    /// Test that interruption BEFORE checkpoint at boundary loses uncommitted data
    ///
    /// This test verifies that if we crash BEFORE the checkpoint is created,
    /// the new file gets deleted during recovery.
    #[test]
    #[ignore]
    fn test_file_boundary_interruption_before_checkpoint() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path();

        std::fs::create_dir_all(archive_path)
            .with_context(|| format!("Unable to create archive {:?}", archive_path))?;

        // Create data and hashes files
        // This will create an empty archive with defaults
        let values = default(archive_path).with_context(|| {
            format!(
                "Error while trying to create a 'default' archive in {:?}",
                archive_path
            )
        })?;
        let slab_capacity = calculate_slab_capacity(values.block_size, values.hash_cache_size_meg);

        let data_file = MultiFile::open_for_write(archive_path, 10, slab_capacity)?;
        let hashes_file = Arc::new(Mutex::new(
            SlabFileBuilder::open(paths::hashes_path(&archive_path))
                .write(true)
                .queue_depth(16)
                .build()
                .context("couldn't open hashes slab file")?,
        ));

        let archive = Data::new(archive_path, data_file, hashes_file.clone(), 10)?;

        // Create a checkpoint pointing to file 0 only
        let checkpoint_path = archive_path.join(recovery::check_point_file());
        let checkpoint = recovery::create_checkpoint_from_files(archive_path, 0)?;
        checkpoint.write(&checkpoint_path)?;

        // Now manually create file 1 without checkpointing (simulating crash during boundary cross)
        // This simulates the scenario where:
        // 1. handle_file_boundary_crossing starts
        // 2. New file gets created
        // 3. CRASH occurs before checkpoint is written

        let file1_path = file_id_to_path(&archive_path, 1);
        std::fs::write(&file1_path, b"corrupt data that should be deleted")?;
        let mut file1_offsets = file1_path.clone();
        file1_offsets.set_extension("offsets");

        std::fs::write(file1_offsets.clone(), b"index")?;

        // Drop archive without syncing
        std::mem::forget(archive);
        std::mem::forget(hashes_file);

        // Apply recovery - this should DELETE file 1 as it's not in the checkpoint
        let checkpoint_for_recovery = recovery::RecoveryCheckpoint::read(&checkpoint_path)?;
        checkpoint_for_recovery.apply(archive_path)?;

        // Verify file 1 data file was deleted (recovery removes .data and .offsets files
        assert!(
            !file1_path.exists(),
            "File 1 {:?} should have been deleted during recovery (not in checkpoint)",
            file1_path
        );

        // Verify offsets file was also deleted
        assert!(
            !file1_offsets.exists(),
            "File 1 offsets {:?} should have been deleted during recovery (not in checkpoint)",
            file1_offsets
        );

        // Verify file 0 still exists
        let file0_path = file_id_to_path(archive_path, 0);
        let mut file0_index_path = file0_path.clone();
        file0_index_path.set_extension("offsets");

        assert!(
            file0_path.exists(),
            "File 0 should still exist {:?}",
            file0_path
        );

        // Verify offsets file was also deleted
        assert!(
            file0_index_path.exists(),
            "File 0 index should still exist {:?}",
            file0_path
        );

        Ok(())
    }

    /// Test build_cuckoo_from_hashes function
    ///
    /// This test verifies that:
    /// 1. A cuckoo filter can be built from a hashes slab file
    /// 2. The filter contains all the hashes that were added
    /// 3. The filter correctly handles capacity resizing
    #[test]
    fn test_build_cuckoo_from_hashes() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let archive_path = temp_dir.path();

        // Create archive directory
        std::fs::create_dir_all(archive_path)
            .with_context(|| format!("Unable to create archive {:?}", archive_path))?;

        // Create a default archive
        let values = default(archive_path).with_context(|| {
            format!("Error while creating default archive in {:?}", archive_path)
        })?;
        let slab_capacity = calculate_slab_capacity(values.block_size, values.hash_cache_size_meg);

        // Create the data and hashes files
        let data_file = MultiFile::open_for_write(archive_path, 10, slab_capacity)?;
        let hashes_file = Arc::new(Mutex::new(
            SlabFileBuilder::open(paths::hashes_path(&archive_path))
                .write(true)
                .queue_depth(16)
                .build()
                .context("couldn't open hashes slab file")?,
        ));

        // Create the Data structure to add entries
        let mut archive = Data::new(archive_path, data_file, hashes_file.clone(), 10)?;

        // Add some test data with known hashes
        let test_blocks = 100;
        let block_size = 4096;
        let mut test_hashes = Vec::new();

        for i in 0..test_blocks {
            let mut data = vec![0u8; block_size];
            // Fill with unique deterministic pattern based on index to avoid deduplication
            // Write the index number repeatedly throughout the block
            for j in 0..block_size / 4 {
                data[j * 4] = (i & 0xff) as u8;
                data[j * 4 + 1] = ((i >> 8) & 0xff) as u8;
                data[j * 4 + 2] = (j & 0xff) as u8;
                data[j * 4 + 3] = ((j >> 8) & 0xff) as u8;
            }

            let hash = crate::hash::hash_256(&data);
            test_hashes.push(hash);

            let mut iov = IoVec::new();
            iov.push(&data);
            archive.data_add(hash, &iov, data.len() as u64)?;
        }

        // Flush to ensure all data is written to hashes file
        archive.flush()?;

        // Explicitly sync to make sure everything is written
        drop(archive);

        // Get the number of slabs in the hashes file
        let nr_slabs = {
            let hf = hashes_file.lock().unwrap();
            hf.get_nr_slabs()
        };

        assert!(
            nr_slabs > 0,
            "Should have created at least one hash index slab"
        );

        // Test 1: Build cuckoo filter with sufficient capacity
        let sufficient_capacity = test_blocks * 2;
        let mut filter = build_cuckoo_from_hashes(&hashes_file, sufficient_capacity)?;

        assert!(
            filter.capacity() >= sufficient_capacity,
            "Filter capacity should be at least {}",
            sufficient_capacity
        );

        // Test 2: Verify all hashes are in the filter
        for (i, hash) in test_hashes.iter().enumerate() {
            let mini_hash = hash_le_u64(hash);
            let result = filter.test(mini_hash)?;
            assert!(
                matches!(
                    result,
                    crate::cuckoo_filter::InsertResult::PossiblyPresent(_)
                ),
                "Hash {} should be in the filter",
                i
            );
        }

        // Test 3: Build with very small capacity to trigger resizing
        let small_capacity = 10; // Much smaller than needed
        let mut filter_resized = build_cuckoo_from_hashes(&hashes_file, small_capacity)?;

        // Should have automatically resized to fit all entries
        assert!(
            filter_resized.capacity() > small_capacity,
            "Filter should have been resized from {} to {}",
            small_capacity,
            filter_resized.capacity()
        );

        // All hashes should still be present after resizing
        for (i, hash) in test_hashes.iter().enumerate() {
            let mini_hash = hash_le_u64(hash);
            let result = filter_resized.test(mini_hash)?;
            assert!(
                matches!(
                    result,
                    crate::cuckoo_filter::InsertResult::PossiblyPresent(_)
                ),
                "Hash {} should be in the resized filter",
                i
            );
        }

        // Test 4: Empty hashes file
        let empty_dir = temp_dir.path().join("empty");
        std::fs::create_dir_all(&empty_dir)?;
        default(&empty_dir)?;

        let empty_hashes_file = Arc::new(Mutex::new(
            SlabFileBuilder::open(paths::hashes_path(&empty_dir))
                .write(true)
                .queue_depth(16)
                .build()
                .context("couldn't open empty hashes slab file")?,
        ));

        let empty_filter = build_cuckoo_from_hashes(&empty_hashes_file, 100)?;
        assert_eq!(
            empty_filter.len(),
            0,
            "Empty hashes file should produce empty filter"
        );

        Ok(())
    }
}
