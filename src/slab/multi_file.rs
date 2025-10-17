use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::archive::SLAB_SIZE_TARGET;
use crate::slab::file::*;
use crate::slab::storage::*;

/// Error returned when attempting to write a slab at a file boundary
///
/// This is a recoverable error that signals the caller to checkpoint
/// and then call cross_file_boundary() before retrying the write.
#[derive(Debug, Clone)]
pub struct FileBoundaryError {
    pub current_file_id: u32,
    pub next_file_id: u32,
}

impl std::fmt::Display for FileBoundaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "File boundary reached at file {} (next file will be {}). Caller must checkpoint and call cross_file_boundary().",
            self.current_file_id, self.next_file_id
        )
    }
}

impl std::error::Error for FileBoundaryError {}

//------------------------------------------------
// Multi-file configuration constants

pub const MAX_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024 - 1; // 4GB - 1 byte (FAT32 limit)
pub const SLABS_PER_FILE: u32 = (MAX_FILE_SIZE / SLAB_SIZE_TARGET as u64) as u32; // 1023 slabs per file
pub const FILES_PER_SUBDIR: u32 = 100; // 100 files per leaf directory
pub const SUBDIRS_PER_DIR: u32 = 100; // 100 subdirs per directory

pub const MAX_OPEN_FILES: usize = 10; // Maximum files open at the same time, current guess, make better or dynamic

//------------------------------------------------
// Multi-file utility functions

pub fn file_id_from_global_slab(global_slab: u32) -> u32 {
    global_slab / SLABS_PER_FILE
}

pub fn local_slab_from_global(global_slab: u32) -> u32 {
    global_slab % SLABS_PER_FILE
}

pub fn file_id_to_path<P: AsRef<std::path::Path>>(base_path: P, file_id: u32) -> PathBuf {
    let level0 = file_id / (SUBDIRS_PER_DIR * FILES_PER_SUBDIR);
    let level1 = (file_id / FILES_PER_SUBDIR) % SUBDIRS_PER_DIR;

    base_path.as_ref().join(format!(
        "data/data/slabs/{:03}/{:03}/file_{:010}",
        level0, level1, file_id
    ))
}

pub fn path_for_global_slab(base_path: &Path, global_slab: u32) -> PathBuf {
    let file_id: u32 = file_id_from_global_slab(global_slab);
    file_id_to_path(base_path, file_id)
}

//------------------------------------------------
// FileHandleCache - LRU cache for open file handles

struct FileHandleCache {
    handles: HashMap<u32, SlabFile<'static>>,
    access_order: Vec<u32>,
    max_open_files: usize,
    base_path: PathBuf,
    cache_nr_entries: usize,
}

impl FileHandleCache {
    fn new(base_path: PathBuf, max_open_files: usize, cache_nr_entries: usize) -> Self {
        Self {
            handles: HashMap::new(),
            access_order: Vec::new(),
            max_open_files,
            base_path,
            cache_nr_entries: cache_nr_entries / max_open_files, // TODO: Can we make better?
        }
    }

    fn get_file(&mut self, file_id: u32) -> Result<&mut SlabFile<'static>> {
        // Update access order for LRU
        if let Some(pos) = self.access_order.iter().position(|&x| x == file_id) {
            self.access_order.remove(pos);
        }
        self.access_order.push(file_id);

        // If file not in cache, open it
        if !self.handles.contains_key(&file_id) {
            // Evict oldest file if cache is full
            if self.handles.len() >= self.max_open_files {
                if let Some(&oldest) = self.access_order.first() {
                    self.access_order.remove(0);
                    if let Some(mut old_file) = self.handles.remove(&oldest) {
                        old_file.close()?;
                    }
                }
            }

            // Open the file for reading
            let file_path = file_id_to_path(&self.base_path, file_id);
            let slab_file = SlabFile::open_for_read(file_path, self.cache_nr_entries)
                .with_context(|| format!("Failed to open slab file {}", file_id))?;

            self.handles.insert(file_id, slab_file);
        }

        Ok(self.handles.get_mut(&file_id).unwrap())
    }

    fn close_all(&mut self) -> Result<()> {
        for (_, mut file) in self.handles.drain() {
            file.close()?;
        }
        self.access_order.clear();
        Ok(())
    }
}

//------------------------------------------------
// Helper function to discover existing files

fn discover_existing_files<P: AsRef<std::path::Path>>(archive_dir: P) -> Result<(u32, u32)> {
    let mut file_id = 0;
    let mut total_slabs = 0;

    loop {
        let file_path = file_id_to_path(&archive_dir, file_id);
        if !file_path.exists() {
            break;
        }
        total_slabs += count_slabs_in_file(&file_path)?;
        file_id += 1;
    }

    Ok((file_id, total_slabs))
}

pub fn current_active_data_slab<P: AsRef<std::path::Path>>(base_path: P) -> Result<PathBuf> {
    let mut file_id = 0;
    let mut last_data_file = PathBuf::new();
    loop {
        let file_path = file_id_to_path(&base_path, file_id);
        if !file_path.exists() {
            break;
        }
        last_data_file = file_path;
        file_id += 1;
    }

    Ok(last_data_file)
}

fn count_slabs_in_file(file_path: &Path) -> Result<u32> {
    let slab_file = SlabFile::open_for_read(file_path, 1)?;
    Ok(slab_file.get_nr_slabs() as u32)
}

//------------------------------------------------
// MultiFile - Manages multiple slab files

pub struct MultiFile {
    base_path: PathBuf,

    // Current file being written to
    write_file: Option<SlabFile<'static>>,
    write_file_id: u32,
    write_file_slab_count: u32,

    // For reading from any file
    file_cache: FileHandleCache,

    // Global state
    total_slabs: u32,
    queue_depth: usize,
    compressed: bool,
    cache_nr_entries: usize,
}

impl MultiFile {
    pub fn fix_data_file_slab_indexes<P: AsRef<Path>>(base_path: P) -> Result<()> {
        let mut file_id = 0;

        loop {
            let file_path = file_id_to_path(&base_path, file_id);
            if !file_path.exists() {
                break;
            }

            // Lets just re-generate and move on...
            let mut slab_offsets = regenerate_index(file_path, None)?;
            slab_offsets.write_offset_file(true)?;
            drop(slab_offsets);

            file_id += 1;
        }

        Ok(())
    }

    pub fn create<P: AsRef<Path>>(
        base_path: P,
        queue_depth: usize,
        compressed: bool,
        cache_nr_entries: usize,
    ) -> Result<Self> {
        let base_path = base_path.as_ref().to_path_buf();

        // Create initial file (file_id = 0)
        let initial_file_path = file_id_to_path(&base_path, 0);
        if let Some(parent) = initial_file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let current_write_file =
            SlabFile::create(initial_file_path, queue_depth, compressed, cache_nr_entries)?;

        Ok(Self {
            base_path: base_path.clone(),
            write_file: Some(current_write_file),
            write_file_id: 0,
            write_file_slab_count: 0,
            file_cache: FileHandleCache::new(base_path, MAX_OPEN_FILES, cache_nr_entries),
            total_slabs: 0,
            queue_depth,
            compressed,
            cache_nr_entries,
        })
    }

    pub fn open_for_write<P: AsRef<Path>>(
        base_path: P,
        queue_depth: usize,
        cache_nr_entries: usize,
    ) -> Result<Self> {
        //let base_path = paths::data_path(base_path.as_ref().to_path_buf());
        let base_path = base_path.as_ref();

        // Discover existing files
        let (num_files, total_slabs) = discover_existing_files(base_path)?;
        if num_files == 0 {
            return Err(anyhow::anyhow!(
                "No existing slab files found in {:?}",
                base_path
            ));
        }

        let current_file_id = num_files - 1;
        let current_file_path = file_id_to_path(base_path, current_file_id);

        // Open the last file for writing
        let current_write_file =
            SlabFile::open_for_write(&current_file_path, queue_depth, cache_nr_entries)?;

        let current_file_slab_count = current_write_file.get_nr_slabs() as u32;

        // Determine compression from first file, currently they're all compressed or none of them
        // are.
        let compressed = {
            let sf = SlabFile::open_for_read(file_id_to_path(base_path, 0), 1)?;
            sf.compressed
        };

        Ok(Self {
            base_path: base_path.to_path_buf(),
            write_file: Some(current_write_file),
            write_file_id: current_file_id,
            write_file_slab_count: current_file_slab_count,
            file_cache: FileHandleCache::new(
                base_path.to_path_buf(),
                MAX_OPEN_FILES,
                cache_nr_entries,
            ),
            total_slabs,
            queue_depth,
            compressed,
            cache_nr_entries,
        })
    }

    pub fn open_for_read<P: AsRef<Path>>(archive_dir: P, cache_nr_entries: usize) -> Result<Self> {
        // Discover existing files
        let (num_files, total_slabs) = discover_existing_files(&archive_dir)?;
        if num_files == 0 {
            return Err(anyhow::anyhow!(
                "No existing slab files found in {:?}",
                archive_dir.as_ref()
            ));
        }

        Ok(Self {
            base_path: archive_dir.as_ref().to_path_buf(),
            write_file: None,
            write_file_id: 0,
            write_file_slab_count: 0,
            file_cache: FileHandleCache::new(
                archive_dir.as_ref().to_path_buf(),
                10,
                cache_nr_entries,
            ),
            total_slabs,
            queue_depth: 1,
            compressed: false,
            cache_nr_entries,
        })
    }

    fn will_cross(current: u32) -> bool {
        current >= SLABS_PER_FILE
    }

    /// Returns true if the next write_slab() will trigger a file boundary crossing
    pub fn will_cross_boundary_on_next_write(&self) -> bool {
        MultiFile::will_cross(self.write_file_slab_count)
    }

    /// Get the current write file ID
    pub fn get_current_write_file_id(&self) -> u32 {
        self.write_file_id
    }

    /// Perform file boundary crossing: close current file and create next one
    ///
    /// IMPORTANT: Caller MUST sync all archive state and create a checkpoint
    /// BEFORE calling this method to ensure crash consistency.
    ///
    /// This method should only be called when will_cross_boundary_on_next_write() returns true.
    pub fn cross_file_boundary(&mut self) -> Result<()> {
        if self.write_file_slab_count < SLABS_PER_FILE {
            return Err(anyhow::anyhow!(
                "cross_file_boundary called when not at boundary (count={}, limit={})",
                self.write_file_slab_count,
                SLABS_PER_FILE
            ));
        }

        // Close current file
        if let Some(mut file) = self.write_file.take() {
            file.close()?;
        }

        // Move to next file
        self.write_file_id += 1;
        self.write_file_slab_count = 0;

        // Create new file
        let new_file_path = file_id_to_path(&self.base_path, self.write_file_id);
        if let Some(parent) = new_file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        self.write_file = Some(SlabFile::create(
            new_file_path,
            self.queue_depth,
            self.compressed,
            self.cache_nr_entries,
        )?);

        Ok(())
    }

    pub fn write_slab(&mut self, data: &[u8]) -> Result<()> {
        if self.will_cross_boundary_on_next_write() {
            return Err(FileBoundaryError {
                current_file_id: self.write_file_id,
                next_file_id: self.write_file_id + 1,
            }
            .into());
        }

        // Write to current file
        if let Some(ref mut file) = self.write_file {
            file.write_slab(data)?;
            self.write_file_slab_count += 1;
            self.total_slabs += 1;

            // If this is the last slab in this file, sync it!
            if MultiFile::will_cross(self.write_file_slab_count) {
                file.sync_all()?;
            }
        }

        Ok(())
    }

    pub fn read(&mut self, global_slab: u32) -> Result<std::sync::Arc<Vec<u8>>> {
        let file_id = file_id_from_global_slab(global_slab);
        let local_slab = local_slab_from_global(global_slab);

        // Check if reading from current write file
        if file_id == self.write_file_id {
            if let Some(ref mut file) = self.write_file {
                return file.read(local_slab);
            }
        }

        // Read from cache
        let file = self.file_cache.get_file(file_id)?;
        file.read(local_slab)
    }

    /// Sync all pending writes to disk without closing
    pub fn sync_all(&mut self) -> Result<()> {
        // Sync current write file if it exists
        if let Some(ref mut file) = self.write_file {
            file.sync_all()?;
        }
        Ok(())
    }

    pub fn close(&mut self) -> Result<()> {
        // Close current write file
        if let Some(mut file) = self.write_file.take() {
            file.close()?;
        }

        // Close all cached files
        self.file_cache.close_all()?;

        Ok(())
    }

    pub fn get_nr_slabs(&self) -> u32 {
        self.total_slabs
    }

    pub fn index(&self) -> u32 {
        self.total_slabs
    }

    pub fn get_file_size(&self) -> u64 {
        let mut total_size = 0u64;

        // Iterate through all files and sum their sizes
        for file_id in 0..=self.write_file_id {
            let file_path = file_id_to_path(&self.base_path, file_id);
            if let Ok(metadata) = std::fs::metadata(&file_path) {
                total_size += metadata.len();
            }
        }

        total_size
    }
}

impl SlabStorage for MultiFile {
    fn write_slab(&mut self, data: &[u8]) -> Result<()> {
        self.write_slab(data)
    }

    fn read(&mut self, slab: u32) -> Result<std::sync::Arc<Vec<u8>>> {
        self.read(slab)
    }

    fn sync_all(&mut self) -> Result<()> {
        self.sync_all()
    }

    fn close(&mut self) -> Result<()> {
        self.close()
    }

    fn get_nr_slabs(&self) -> u32 {
        self.get_nr_slabs()
    }

    fn index(&self) -> u32 {
        self.index()
    }

    fn get_file_size(&self) -> u64 {
        self.get_file_size()
    }

    fn will_cross_boundary_on_next_write(&self) -> bool {
        self.will_cross_boundary_on_next_write()
    }

    fn cross_file_boundary(&mut self) -> Result<()> {
        self.cross_file_boundary()
    }
}

impl Drop for MultiFile {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_file_id_from_global_slab() {
        // SLABS_PER_FILE = (4GB - 1) / 8KB = 524287
        assert_eq!(file_id_from_global_slab(0), 0);
        assert_eq!(file_id_from_global_slab(SLABS_PER_FILE - 1), 0);
        assert_eq!(file_id_from_global_slab(SLABS_PER_FILE), 1);
        assert_eq!(file_id_from_global_slab(2 * SLABS_PER_FILE - 1), 1);
        assert_eq!(file_id_from_global_slab(2 * SLABS_PER_FILE), 2);
    }

    #[test]
    fn test_constants() {
        assert_eq!(1023, SLABS_PER_FILE);
    }

    #[test]
    fn test_local_slab_from_global() {
        // SLABS_PER_FILE = 524287
        assert_eq!(local_slab_from_global(0), 0);
        assert_eq!(
            local_slab_from_global(SLABS_PER_FILE - 1),
            SLABS_PER_FILE - 1
        );
        assert_eq!(local_slab_from_global(SLABS_PER_FILE), 0);
        assert_eq!(
            local_slab_from_global(2 * SLABS_PER_FILE - 1),
            SLABS_PER_FILE - 1
        );
        assert_eq!(local_slab_from_global(2 * SLABS_PER_FILE), 0);
    }

    #[test]
    fn test_file_id_to_path() {
        let base = PathBuf::from("/tmp/test");

        // File 0: level0=0, level1=0
        assert_eq!(
            file_id_to_path(&base, 0),
            PathBuf::from("/tmp/test/data/data/slabs/000/000/file_0000000000")
        );

        // File 99: level0=0, level1=0 (still in first subdir)
        assert_eq!(
            file_id_to_path(&base, 99),
            PathBuf::from("/tmp/test/data/data/slabs/000/000/file_0000000099")
        );

        // File 100: level0=0, level1=1 (second subdir)
        assert_eq!(
            file_id_to_path(&base, 100),
            PathBuf::from("/tmp/test/data/data/slabs/000/001/file_0000000100")
        );

        // File 9999: level0=0, level1=99
        assert_eq!(
            file_id_to_path(&base, 9999),
            PathBuf::from("/tmp/test/data/data/slabs/000/099/file_0000009999")
        );

        // File 10000: level0=1, level1=0
        assert_eq!(
            file_id_to_path(&base, 10000),
            PathBuf::from("/tmp/test/data/data/slabs/001/000/file_0000010000")
        );

        // File u32::MAX: maximum possible file_id
        // level0 = 4294967295 / 10000 = 429496
        // level1 = (4294967295 / 100) % 100 = 72
        assert_eq!(
            file_id_to_path(&base, u32::MAX),
            PathBuf::from("/tmp/test/data/data/slabs/429496/072/file_4294967295")
        );
    }

    #[test]
    fn test_path_for_global_slab() {
        let base = PathBuf::from("/tmp/test");

        // Slab 0 is in file 0
        assert_eq!(
            path_for_global_slab(&base, 0),
            PathBuf::from("/tmp/test/data/data/slabs/000/000/file_0000000000")
        );

        // Slab SLABS_PER_FILE is in file 1
        assert_eq!(
            path_for_global_slab(&base, SLABS_PER_FILE),
            PathBuf::from("/tmp/test/data/data/slabs/000/000/file_0000000001")
        );

        // Slab 100 * SLABS_PER_FILE is in file 100
        assert_eq!(
            path_for_global_slab(&base, 100 * SLABS_PER_FILE),
            PathBuf::from("/tmp/test/data/data/slabs/000/001/file_0000000100")
        );

        // Slab u32::MAX: maximum possible global_slab
        // SLABS_PER_FILE = (4GB-1) / 4MB = 1023
        // file_id = 4294967295 / 1023 = 4198404
        // level0 = 4198404 / 10000 = 419
        // level1 = (4198404 / 100) % 100 = 84
        assert_eq!(
            path_for_global_slab(&base, u32::MAX),
            PathBuf::from("/tmp/test/data/data/slabs/419/084/file_0004198404")
        );
    }

    #[test]
    fn test_multifile_create_write_read() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        // Create a MultiFile with queue_depth=4 for async writes
        let mut mf = MultiFile::create(&base_path, 4, false, 10).unwrap();

        // Write some slabs
        let data1 = vec![1u8; SLAB_SIZE_TARGET];
        let data2 = vec![2u8; SLAB_SIZE_TARGET];
        let data3 = vec![3u8; SLAB_SIZE_TARGET];

        mf.write_slab(&data1).unwrap();
        mf.write_slab(&data2).unwrap();
        mf.write_slab(&data3).unwrap();

        assert_eq!(mf.get_nr_slabs(), 3);

        // Read back immediately without close - this now works!
        let read1 = mf.read(0).unwrap();
        let read2 = mf.read(1).unwrap();
        let read3 = mf.read(2).unwrap();

        assert_eq!(*read1, data1);
        assert_eq!(*read2, data2);
        assert_eq!(*read3, data3);

        mf.close().unwrap();
    }

    #[test]
    fn test_multifile_compressed() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        // Create a compressed MultiFile with queue_depth=4
        let mut mf = MultiFile::create(&base_path, 4, true, 10).unwrap();

        // Write a compressible slab (all zeros)
        let data = vec![0u8; SLAB_SIZE_TARGET];
        mf.write_slab(&data).unwrap();

        // Read it back immediately - works due to pending_writes cache
        let read_data = mf.read(0).unwrap();
        assert_eq!(*read_data, data);

        mf.close().unwrap();
    }

    #[test]
    fn test_multifile_open_for_write() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        // Create and write some data
        {
            let mut mf = MultiFile::create(&base_path, 4, false, 10).unwrap();
            let data = vec![42u8; SLAB_SIZE_TARGET];
            mf.write_slab(&data).unwrap();
            mf.write_slab(&data).unwrap();
            mf.close().unwrap();
        }

        // Reopen for writing
        let mut mf = MultiFile::open_for_write(&base_path, 4, 10).unwrap();
        assert_eq!(mf.get_nr_slabs(), 2);

        // Write more data
        let data = vec![99u8; SLAB_SIZE_TARGET];
        mf.write_slab(&data).unwrap();
        assert_eq!(mf.get_nr_slabs(), 3);

        // Verify we can read all slabs immediately
        let read1 = mf.read(0).unwrap();
        assert_eq!(read1[0], 42);
        let read3 = mf.read(2).unwrap();
        assert_eq!(read3[0], 99);

        mf.close().unwrap();
    }

    #[test]
    fn test_multifile_open_for_read() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Create and write data
        {
            let mut mf = MultiFile::create(base_path, 1, false, 10).unwrap();
            for i in 0..5 {
                let data = vec![i as u8; SLAB_SIZE_TARGET];
                mf.write_slab(&data).unwrap();
            }
            mf.close().unwrap();
        }

        // Open for reading
        let mut mf = MultiFile::open_for_read(base_path, 10).unwrap();
        assert_eq!(mf.get_nr_slabs(), 5);

        // Read slabs
        for i in 0..5 {
            let data = mf.read(i).unwrap();
            assert_eq!(data[0], i as u8);
        }

        mf.close().unwrap();
    }

    #[test]
    fn test_multifile_multiple_files() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        let num_slabs = 100u32;

        let mut mf = MultiFile::create(&base_path, 4, false, 10).unwrap();

        // Write enough slabs to span multiple files
        // SLABS_PER_FILE is 1023 with current constants (4GB / 4MB)
        // Writing that many would be too slow, so write just enough to test the logic

        for i in 0..num_slabs {
            let data = vec![(i % 256) as u8; SLAB_SIZE_TARGET];
            mf.write_slab(&data).unwrap();
        }

        assert_eq!(mf.get_nr_slabs(), num_slabs);

        // Verify file was created
        let file0_path = file_id_to_path(&base_path, 0);
        assert!(file0_path.exists());

        // Read slabs immediately - works with pending_writes
        let data_from_file0 = mf.read(0).unwrap();
        assert_eq!(data_from_file0[0], 0);

        let data_from_file0_end = mf.read(num_slabs - 1).unwrap();
        assert_eq!(data_from_file0_end[0], ((num_slabs - 1) % 256) as u8);

        mf.close().unwrap();
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_multifile_crosses_file_boundary() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        let slabs_in_file0 = SLABS_PER_FILE;
        let slabs_in_file1 = 512u32;
        let total_slabs = slabs_in_file0 + slabs_in_file1;

        let mut mf = MultiFile::create(&base_path, 4, false, 10).unwrap();

        // Write slabs that will span two files
        for i in 0..total_slabs {
            // Check if we need to cross file boundary
            if mf.will_cross_boundary_on_next_write() {
                mf.cross_file_boundary().unwrap();
            }
            let data = vec![(i % 256) as u8; SLAB_SIZE_TARGET];
            mf.write_slab(&data).unwrap();
        }

        assert_eq!(mf.get_nr_slabs(), total_slabs);
        assert_eq!(mf.write_file_id, 1); // Should be on second file now

        // Verify both files exist
        let file0_path = file_id_to_path(&base_path, 0);
        let file1_path = file_id_to_path(&base_path, 1);
        assert!(file0_path.exists(), "First file should exist");
        assert!(file1_path.exists(), "Second file should exist");

        // Read from first file (last slab in file 0)
        let last_in_file0 = mf.read(slabs_in_file0 - 1).unwrap();
        assert_eq!(last_in_file0[0], ((slabs_in_file0 - 1) % 256) as u8);

        // Read from second file (first slab in file 1)
        let first_in_file1 = mf.read(slabs_in_file0).unwrap();
        assert_eq!(first_in_file1[0], (slabs_in_file0 % 256) as u8);

        // Read from second file (last slab)
        let last_in_file1 = mf.read(total_slabs - 1).unwrap();
        assert_eq!(last_in_file1[0], ((total_slabs - 1) % 256) as u8);

        // Verify file IDs are correct
        assert_eq!(file_id_from_global_slab(0), 0);
        assert_eq!(file_id_from_global_slab(slabs_in_file0 - 1), 0);
        assert_eq!(file_id_from_global_slab(slabs_in_file0), 1);
        assert_eq!(file_id_from_global_slab(total_slabs - 1), 1);

        mf.close().unwrap();

        // Reopen for reading and verify we can still read across boundaries
        let mut mf = MultiFile::open_for_read(&base_path, 10).unwrap();
        assert_eq!(mf.get_nr_slabs(), total_slabs);

        let last_in_file0_reopened = mf.read(slabs_in_file0 - 1).unwrap();
        assert_eq!(
            last_in_file0_reopened[0],
            ((slabs_in_file0 - 1) % 256) as u8
        );

        let first_in_file1_reopened = mf.read(slabs_in_file0).unwrap();
        assert_eq!(first_in_file1_reopened[0], (slabs_in_file0 % 256) as u8);

        mf.close().unwrap();
    }

    #[test]
    fn test_multifile_get_file_size() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let mut mf = MultiFile::create(base_path, 1, false, 10).unwrap();

        let initial_size = mf.get_file_size();
        assert!(initial_size > 0);

        // Write a slab
        let data = vec![1u8; SLAB_SIZE_TARGET];
        mf.write_slab(&data).unwrap();

        // Close to flush writes
        mf.close().unwrap();

        // Check final size
        let final_size = std::fs::metadata(file_id_to_path(base_path, 0))
            .unwrap()
            .len();
        assert!(final_size > initial_size);
    }

    #[test]
    fn test_multifile_index() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        let mut mf = MultiFile::create(base_path, 1, false, 10).unwrap();

        assert_eq!(mf.index(), 0);

        let data = vec![1u8; SLAB_SIZE_TARGET];
        mf.write_slab(&data).unwrap();
        assert_eq!(mf.index(), 1);

        mf.write_slab(&data).unwrap();
        assert_eq!(mf.index(), 2);

        mf.close().unwrap();
    }

    #[test]
    fn test_open_for_write_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Try to open nonexistent archive for writing
        let result = MultiFile::open_for_write(base_path, 4, 10);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("No existing slab files found"));
        }
    }

    #[test]
    fn test_open_for_read_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path();

        // Try to open nonexistent archive for reading
        let result = MultiFile::open_for_read(base_path, 10);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("No existing slab files found"));
        }
    }

    #[test]
    fn test_slab_storage_trait() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        {
            let mut mf: Box<dyn SlabStorage> =
                Box::new(MultiFile::create(&base_path, 1, false, 10).unwrap());

            // Test trait methods
            let data = vec![7u8; SLAB_SIZE_TARGET];
            mf.write_slab(&data).unwrap();

            assert_eq!(mf.get_nr_slabs(), 1);
            assert_eq!(mf.index(), 1);

            // Close before reading to ensure all writes are flushed
            mf.close().unwrap();
        }

        // Reopen and verify the data was written
        {
            let mut mf: Box<dyn SlabStorage> =
                Box::new(MultiFile::open_for_read(&base_path, 10).unwrap());

            let data = vec![7u8; SLAB_SIZE_TARGET];
            let read_data = mf.read(0).unwrap();
            assert_eq!(*read_data, data);
        }
    }

    // ===== Race Condition Tests =====
    // These tests verify the fixes in commit 5db2a22 and subsequent fixes

    /// Test: Read immediately after write without close
    ///
    /// This is the core use case for pending_writes - ensuring reads
    /// work before the writer thread has committed data to disk.
    #[test]
    fn test_read_uncommitted_data() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        let mut mf = MultiFile::create(&base_path, 8, false, 10).unwrap();

        // Write and immediately read without close
        for i in 0..20 {
            let data = vec![i as u8; SLAB_SIZE_TARGET];
            mf.write_slab(&data).unwrap();

            // Read immediately - should work via pending_writes
            let read_data = mf.read(i).unwrap();
            assert_eq!(*read_data, data, "Slab {} data mismatch", i);
        }
    }

    /// Test: Reopen file and ensure pending_index is correct
    ///
    /// Tests the fix where open_for_write must set pending_index to
    /// nr_existing_slabs, not 0.
    #[test]
    fn test_reopen_pending_index_correctness() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        // Create and write initial data
        {
            let mut mf = MultiFile::create(&base_path, 4, false, 10).unwrap();
            for i in 0..3 {
                let data = vec![i as u8; SLAB_SIZE_TARGET];
                mf.write_slab(&data).unwrap();
            }
            mf.close().unwrap();
        }

        // Reopen and write more
        {
            let mut mf = MultiFile::open_for_write(&base_path, 4, 10).unwrap();
            assert_eq!(mf.get_nr_slabs(), 3);

            // Write new slab - should get index 3, not overwrite index 0
            let data = vec![99u8; SLAB_SIZE_TARGET];
            mf.write_slab(&data).unwrap();

            // Read original slab 0 - should be unchanged
            let read0 = mf.read(0).unwrap();
            assert_eq!(read0[0], 0, "Slab 0 was overwritten!");

            // Read new slab 3
            let read3 = mf.read(3).unwrap();
            assert_eq!(read3[0], 99, "New slab not written correctly");

            mf.close().unwrap();
        }

        // Reopen for read and verify all data
        {
            let mut mf = MultiFile::open_for_read(&base_path, 10).unwrap();
            assert_eq!(mf.get_nr_slabs(), 4);

            for i in 0..3 {
                let data = mf.read(i).unwrap();
                assert_eq!(data[0], i as u8);
            }
            let data = mf.read(3).unwrap();
            assert_eq!(data[0], 99);
        }
    }

    /// Test: Rapid write-read cycles
    ///
    /// Stress test the pending_writes cache with rapid alternating
    /// writes and reads to expose any race conditions.
    #[test]
    fn test_rapid_write_read_cycles() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        let mut mf = MultiFile::create(&base_path, 8, false, 10).unwrap();

        // Rapid write-read cycles
        for cycle in 0..50 {
            let data = vec![cycle as u8; SLAB_SIZE_TARGET];
            mf.write_slab(&data).unwrap();

            // Immediately read it back
            let read_data = mf.read(cycle).unwrap();
            assert_eq!(*read_data, data, "Cycle {} failed", cycle);

            // Also read a previous slab to ensure cache coherency
            if cycle > 0 {
                let prev_data = mf.read(cycle - 1).unwrap();
                assert_eq!(prev_data[0], (cycle - 1) as u8);
            }
        }
    }

    /// Test: Writer thread ordering
    ///
    /// Tests that the writer thread processes slabs in order even if
    /// they arrive out of order on the channel.
    #[test]
    fn test_writer_thread_ordering() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        // Use small queue to potentially expose ordering issues
        let mut mf = MultiFile::create(&base_path, 2, false, 10).unwrap();

        // Write many slabs quickly
        for i in 0..100 {
            let data = vec![i as u8; SLAB_SIZE_TARGET];
            mf.write_slab(&data).unwrap();
        }

        // Close to ensure all writes complete
        mf.close().unwrap();

        // Reopen and verify all slabs are in correct order
        let mut mf = MultiFile::open_for_read(&base_path, 10).unwrap();
        for i in 0..100 {
            let data = mf.read(i).unwrap();
            assert_eq!(data[0], i as u8, "Slab {} out of order", i);
        }
    }

    /// Test: Close clears pending_writes
    ///
    /// Verifies that close() properly clears pending_writes after
    /// committing all data.
    #[test]
    fn test_close_clears_pending() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        {
            let mut mf = MultiFile::create(&base_path, 4, false, 10).unwrap();

            // Write data (goes to pending_writes)
            for i in 0..5 {
                let data = vec![i as u8; SLAB_SIZE_TARGET];
                mf.write_slab(&data).unwrap();
            }

            // Close should sync and clear pending_writes
            mf.close().unwrap();
        }

        // Reopen - all data should be on disk, not in pending_writes
        let mut mf = MultiFile::open_for_read(&base_path, 10).unwrap();
        assert_eq!(mf.get_nr_slabs(), 5);

        for i in 0..5 {
            let data = mf.read(i).unwrap();
            assert_eq!(data[0], i as u8);
        }
    }

    /// Test: Compressed slabs with pending_writes
    ///
    /// Ensures pending_writes works correctly with compressed data.
    #[test]
    fn test_compressed_pending_writes() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        let mut mf = MultiFile::create(&base_path, 4, true, 10).unwrap();

        // Write compressible data
        for i in 0..10 {
            let data = vec![i as u8; SLAB_SIZE_TARGET];
            mf.write_slab(&data).unwrap();

            // Read immediately (before compression completes)
            let read_data = mf.read(i).unwrap();
            assert_eq!(*read_data, data);
        }

        mf.close().unwrap();

        // Reopen and verify compressed data persisted correctly
        let mut mf = MultiFile::open_for_read(&base_path, 10).unwrap();
        for i in 0..10 {
            let data = mf.read(i).unwrap();
            assert_eq!(data[0], i as u8);
        }
    }

    /// Test: Concurrent writes and reads from multiple threads
    ///
    /// This tests that the pending_writes cache correctly handles:
    /// - Multiple threads writing concurrently
    /// - Reads happening before writes are committed
    /// - No lost writes or corrupted data
    #[test]
    fn test_concurrent_write_read() {
        use std::sync::{Arc, Barrier, Mutex};
        use std::thread;

        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        let mf = Arc::new(Mutex::new(
            MultiFile::create(&base_path, 16, false, 10).unwrap(),
        ));

        let num_threads = 4;
        let slabs_per_thread = 10;
        let barrier = Arc::new(Barrier::new(num_threads));

        let mut handles = vec![];

        // Spawn writer threads
        for thread_id in 0..num_threads {
            let mf_clone = Arc::clone(&mf);
            let barrier_clone = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier_clone.wait(); // Synchronize start

                for i in 0..slabs_per_thread {
                    let data = vec![(thread_id * 100 + i) as u8; SLAB_SIZE_TARGET];
                    let mut mf = mf_clone.lock().unwrap();
                    mf.write_slab(&data).unwrap();
                }
            });
            handles.push(handle);
        }

        // Wait for all writes to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Now read all slabs and verify
        let mut mf = mf.lock().unwrap();
        let total_slabs = num_threads * slabs_per_thread;
        assert_eq!(mf.get_nr_slabs(), total_slabs as u32);

        // Verify we can read all slabs (tests pending_writes)
        for slab_id in 0..total_slabs {
            let data = mf.read(slab_id as u32).unwrap();
            assert_eq!(data.len(), SLAB_SIZE_TARGET);
        }
    }

    /// Test: Write, sync, read pattern
    ///
    /// Ensures sync_all() properly commits data and clears pending_writes,
    /// and reads still work after sync.
    #[test]
    fn test_sync_and_read() {
        let num_slabs = 10;
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        let mut mf = MultiFile::create(&base_path, 10, true, 10).unwrap();

        // Write some slabs
        for i in 0..num_slabs {
            let data = vec![i as u8; SLAB_SIZE_TARGET];
            mf.write_slab(&data).unwrap();
        }

        // Read before sync (uses pending_writes)
        for i in 0..num_slabs {
            let data = mf.read(i).unwrap();
            assert_eq!(data[0], i as u8);
        }

        // Sync to commit
        mf.sync_all().unwrap();

        // Read after sync (should read from disk)
        for i in 0..num_slabs {
            let data = mf.read(i).unwrap();
            assert_eq!(data[0], i as u8);
        }

        // Write more and read (uses pending_writes again)
        for i in num_slabs..num_slabs * 2 {
            let data = vec![i as u8; SLAB_SIZE_TARGET];
            mf.write_slab(&data).unwrap();
            let read_data = mf.read(i).unwrap();
            assert_eq!(read_data[0], i as u8);
        }
    }

    /// Test: Sync atomicity
    ///
    /// Ensures that sync_all() atomically syncs data and offsets under lock,
    /// preventing the race where offsets include slabs whose data isn't synced.
    #[test]
    fn test_sync_atomicity() {
        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().to_path_buf();

        let mut mf = MultiFile::create(&base_path, 4, false, 10).unwrap();

        // Write some data
        for i in 0..5 {
            let data = vec![i as u8; SLAB_SIZE_TARGET];
            mf.write_slab(&data).unwrap();
        }

        // First sync
        mf.sync_all().unwrap();

        // Write more
        for i in 5..10 {
            let data = vec![i as u8; SLAB_SIZE_TARGET];
            mf.write_slab(&data).unwrap();
        }

        // Second sync
        mf.sync_all().unwrap();

        // Close and reopen
        mf.close().unwrap();
        let mut mf = MultiFile::open_for_read(&base_path, 10).unwrap();

        // All 10 slabs should be readable
        assert_eq!(mf.get_nr_slabs(), 10);
        for i in 0..10 {
            let data = mf.read(i).unwrap();
            assert_eq!(data[0], i as u8, "Slab {} not persisted correctly", i);
        }
    }
}
