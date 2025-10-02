use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::archive::SLAB_SIZE_TARGET;
use crate::slab::file::*;
use crate::slab::storage::*;

//------------------------------------------------
// Multi-file configuration constants

//pub const MAX_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024 - 1; // 4GB - 1 byte (FAT32 limit)

pub const MAX_FILE_SIZE: u64 = 8 * 1024 * 1024;
pub const SLABS_PER_FILE: u32 = (MAX_FILE_SIZE / SLAB_SIZE_TARGET as u64) as u32; // 1024 slabs per file
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

pub fn file_id_to_path(base_path: &Path, file_id: u32) -> PathBuf {
    let level0 = file_id / (SUBDIRS_PER_DIR * FILES_PER_SUBDIR);
    let level1 = (file_id / FILES_PER_SUBDIR) % SUBDIRS_PER_DIR;

    base_path.join(format!(
        "slabs/{:03}/{:03}/file_{:010}",
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
    handles: HashMap<u32, SlabFile>,
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

    fn get_file(&mut self, file_id: u32) -> Result<&mut SlabFile> {
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

fn discover_existing_files(base_path: &Path) -> Result<(u32, u32)> {
    let mut file_id = 0;
    let mut total_slabs = 0;

    loop {
        let file_path = file_id_to_path(base_path, file_id);
        if !file_path.exists() {
            break;
        }
        total_slabs += count_slabs_in_file(&file_path)?;
        file_id += 1;
    }

    Ok((file_id, total_slabs))
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
    write_file: Option<SlabFile>,
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
    pub fn create<P: AsRef<Path>>(
        base_path: P,
        queue_depth: usize,
        compressed: bool,
        cache_nr_entries: usize,
    ) -> Result<Self> {
        let base_path = base_path.as_ref().to_path_buf();

        println!("debug base_path = {:?}", base_path);

        // Create initial file (file_id = 0)
        let initial_file_path = file_id_to_path(&base_path, 0);
        if let Some(parent) = initial_file_path.parent() {
            println!("DEBUG: {:?}", parent);
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
        let base_path = base_path.as_ref().to_path_buf();

        // Discover existing files
        let (num_files, total_slabs) = discover_existing_files(&base_path)?;
        if num_files == 0 {
            return Err(anyhow::anyhow!("No existing slab files found"));
        }

        let current_file_id = num_files - 1;
        let current_file_path = file_id_to_path(&base_path, current_file_id);

        // Open the last file for writing
        let current_write_file =
            SlabFile::open_for_write(&current_file_path, queue_depth, cache_nr_entries)?;

        let current_file_slab_count = current_write_file.get_nr_slabs() as u32;

        // Determine compression from first file, currently they're all compressed or none of them
        // are.
        let compressed = {
            let sf = SlabFile::open_for_read(file_id_to_path(&base_path, 0), 1)?;
            sf.compressed
        };

        Ok(Self {
            base_path: base_path.clone(),
            write_file: Some(current_write_file),
            write_file_id: current_file_id,
            write_file_slab_count: current_file_slab_count,
            file_cache: FileHandleCache::new(base_path, MAX_OPEN_FILES, cache_nr_entries),
            total_slabs,
            queue_depth,
            compressed,
            cache_nr_entries,
        })
    }

    pub fn open_for_read<P: AsRef<Path>>(base_path: P, cache_nr_entries: usize) -> Result<Self> {
        let base_path = base_path.as_ref().to_path_buf();

        // Discover existing files
        let (num_files, total_slabs) = discover_existing_files(&base_path)?;
        if num_files == 0 {
            return Err(anyhow::anyhow!("No existing slab files found"));
        }

        Ok(Self {
            base_path: base_path.clone(),
            write_file: None,
            write_file_id: 0,
            write_file_slab_count: 0,
            file_cache: FileHandleCache::new(base_path, 10, cache_nr_entries),
            total_slabs,
            queue_depth: 1,
            compressed: false,
            cache_nr_entries,
        })
    }

    pub fn write_slab(&mut self, data: &[u8]) -> Result<()> {
        // Check if current file is full
        if self.write_file_slab_count >= SLABS_PER_FILE {
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
        }

        // Write to current file
        if let Some(ref mut file) = self.write_file {
            file.write_slab(data)?;
            self.write_file_slab_count += 1;
            self.total_slabs += 1;
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
}

impl Drop for MultiFile {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
