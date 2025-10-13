use anyhow::{anyhow, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use crate::hash::*;
use crate::slab::compression_service::*;
use crate::slab::data_cache::*;
use crate::slab::offsets::*;
use crate::slab::storage::*;

#[cfg(test)]
mod tests;

//------------------------------------------------
// Slab files are used to store 'slabs' of data.  You
// may only append to a slab file, or read an existing
// slab.
//
// Along side the slab an 'index' file will be written
// that contains the offsets of all the slabs.  This is
// derived data, and can be rebuilt with the repair fn.
//
// file := <header> <slab>*
// header := <magic nr> <slab format version> <flags>
// slab := <magic nr> <len> <checksum> <compressed data>

const FILE_MAGIC: u64 = 0xb927f96a6b611180;
const SLAB_MAGIC: u64 = 0x20565137a3100a7c;

const FORMAT_VERSION: u32 = 0;

pub type SlabIndex = u64;
type Shared = Arc<(Mutex<SlabShared>, Condvar)>;

pub const SLAB_META_SIZE: u64 = 24; // Slab magic + length + check sum, each of which is 8 bytes

struct Progress {
    last_submitted: u64, // highest seq handed out (pending_index - 1)
    last_written: u64,   // highest seq actually appended by writer
}

// Clone should only be used in tests
#[derive(Clone)]
pub struct SlabData {
    pub index: SlabIndex,
    pub data: Vec<u8>,
}

struct SlabShared {
    data: File,
    offsets: SlabOffsets,
    file_size: u64,

    progress: Progress,

    // move here so writer thread can erase entries once committed
    pending_writes: HashMap<SlabIndex, Arc<Vec<u8>>>,
}

// FIXME: add index file
pub struct SlabFile {
    pub compressed: bool,
    compressor: Option<CompressionService>,
    offsets_path: PathBuf,
    pending_index: u64,

    shared: Shared,

    tx: Option<SyncSender<SlabData>>,
    tid: Option<thread::JoinHandle<()>>,

    data_cache: DataCache,
}

impl Drop for SlabFile {
    fn drop(&mut self) {
        let mut tx = None;
        std::mem::swap(&mut tx, &mut self.tx);
        drop(tx);

        let mut compressor = None;
        std::mem::swap(&mut compressor, &mut self.compressor);
        if let Some(mut c) = compressor {
            c.join();
        }
    }
}

fn write_slab(shared: &Mutex<SlabShared>, data: &[u8]) -> Result<()> {
    assert!(!data.is_empty());

    let mut shared = shared.lock().unwrap();

    let offset = shared.file_size;
    shared.offsets.offsets.push(offset);
    shared.file_size += 8 + 8 + 8 + data.len() as u64;

    shared.data.seek(SeekFrom::End(0))?;
    shared.data.write_u64::<LittleEndian>(SLAB_MAGIC)?;
    shared.data.write_u64::<LittleEndian>(data.len() as u64)?;
    let csum = hash_64(data);
    shared.data.write_all(&csum)?;
    shared.data.write_all(data)?;

    Ok(())
}

fn writer_(shared: &Shared, rx: Receiver<SlabData>, start_index: u64) -> Result<()> {
    let (slab_shared, cv) = &**shared;
    let mut write_index = start_index;
    let mut queued: BTreeMap<u64, SlabData> = BTreeMap::new();

    while let Ok(buf) = rx.recv() {
        // Always insert into queue
        queued.insert(buf.index, buf);

        // Drain all consecutive items starting from write_index
        while let Some(buf) = queued.remove(&write_index) {
            write_slab(slab_shared, &buf.data)?;
            {
                let mut sh = slab_shared.lock().unwrap();
                sh.pending_writes.remove(&buf.index);
                sh.progress.last_written = buf.index;
                cv.notify_all();
            }
            write_index += 1;
        }
    }
    assert!(queued.is_empty());
    Ok(())
}

fn writer(shared: &Shared, rx: Receiver<SlabData>, start_index: u64) {
    // FIXME: pass on error
    writer_(shared, rx, start_index).expect("write of slab failed");
}

fn offsets_path<P: AsRef<Path>>(p: P) -> PathBuf {
    let mut offsets_path = PathBuf::new();
    offsets_path.push(p);
    offsets_path.set_extension("offsets");
    offsets_path
}

fn read_slab_header(data: &mut std::fs::File) -> Result<u32> {
    let magic = data
        .read_u64::<LittleEndian>()
        .context("couldn't read magic")?;
    let version = data
        .read_u32::<LittleEndian>()
        .context("couldn't read version")?;
    let flags = data
        .read_u32::<LittleEndian>()
        .context("couldn't read flags")?;

    if magic != FILE_MAGIC {
        return Err(anyhow!(
            "slab file magic is invalid or corrupt, actual {} != {} expected",
            magic,
            FILE_MAGIC
        ));
    }

    if version != FORMAT_VERSION {
        return Err(anyhow!(
            "slab file version actual {} != {} expected",
            version,
            FORMAT_VERSION
        ));
    }

    if !(flags == 0 || flags == 1) {
        return Err(anyhow!(
            "slab file flag value unexpected {} != 0 or 1",
            flags
        ));
    }
    Ok(flags)
}

impl SlabFile {
    pub(crate) fn create<P: AsRef<Path>>(
        data_path: P,
        queue_depth: usize,
        compressed: bool,
        cache_nr_entries: usize,
    ) -> Result<Self> {
        let offsets_path = offsets_path(&data_path);

        let mut data = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(data_path)?;

        let (tx, rx) = sync_channel(queue_depth);
        let flags = if compressed { 1 } else { 0 };
        data.write_u64::<LittleEndian>(FILE_MAGIC)?;
        data.write_u32::<LittleEndian>(FORMAT_VERSION)?;
        data.write_u32::<LittleEndian>(flags)?;

        let offsets = SlabOffsets::default();
        let file_size = data.metadata()?.len();
        let shared: Shared = Arc::new((
            Mutex::new(SlabShared {
                data,
                offsets,
                file_size,
                progress: Progress {
                    last_submitted: 0, // or 0 on create
                    last_written: 0,
                },
                pending_writes: std::collections::HashMap::new(),
            }),
            Condvar::new(),
        ));

        let (compressor, tx) = if flags == 1 {
            let (c, tx) = CompressionService::new(1, tx, ZstdCompressor::new(0));
            (Some(c), tx)
        } else {
            (None, tx)
        };

        let tid = {
            let shared = shared.clone();
            thread::spawn(move || writer(&shared, rx, 0))
        };

        Ok(Self {
            compressed,
            compressor,
            offsets_path,
            pending_index: 0,
            shared,
            tx: Some(tx),
            tid: Some(tid),
            data_cache: DataCache::new(cache_nr_entries),
        })
    }

    pub(crate) fn open_for_write<P: AsRef<Path>>(
        data_path: P,
        queue_depth: usize,
        cache_nr_entries: usize,
    ) -> Result<Self> {
        let offsets_path = offsets_path(&data_path);

        let mut data = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(data_path)
            .context("open offsets")?;

        let flags = read_slab_header(&mut data)?;

        let compressed = flags == 1;
        let (tx, rx) = sync_channel(queue_depth);
        let (compressor, tx) = if flags == 1 {
            let (c, tx) = CompressionService::new(4, tx, ZstdCompressor::new(0));
            (Some(c), tx)
        } else {
            (None, tx)
        };

        let offsets = SlabOffsets::read_offset_file(&offsets_path)?;
        let file_size = data.metadata()?.len();
        let nr_existing_slabs = offsets.offsets.len() as u64;

        let shared: Shared = Arc::new((
            Mutex::new(SlabShared {
                data,
                offsets,
                file_size,
                progress: Progress {
                    last_submitted: nr_existing_slabs, // or 0 on create
                    last_written: nr_existing_slabs.saturating_sub(1),
                },
                pending_writes: std::collections::HashMap::new(),
            }),
            Condvar::new(),
        ));

        let tid = {
            let shared = shared.clone();
            thread::spawn(move || writer(&shared, rx, nr_existing_slabs))
        };

        Ok(Self {
            compressed,
            compressor,
            offsets_path,
            pending_index: nr_existing_slabs, // Start from number of existing slabs
            shared,
            tx: Some(tx),
            tid: Some(tid),
            data_cache: DataCache::new(cache_nr_entries),
        })
    }

    pub(crate) fn open_for_read<P: AsRef<Path>>(
        data_path: P,
        cache_nr_entries: usize,
    ) -> Result<Self> {
        let offsets_path = offsets_path(&data_path);

        let mut data = OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(data_path)?;

        let flags = read_slab_header(&mut data)?;
        let compressed = flags == 1;
        let compressor = None;

        let offsets = SlabOffsets::read_offset_file(&offsets_path)?;
        let nr_existing_slabs = offsets.offsets.len() as u64;
        let file_size = data.metadata()?.len();
        let shared: Shared = Arc::new((
            Mutex::new(SlabShared {
                data,
                offsets,
                file_size,
                progress: Progress {
                    last_submitted: nr_existing_slabs,
                    last_written: nr_existing_slabs.saturating_sub(1),
                },
                pending_writes: std::collections::HashMap::new(),
            }),
            Condvar::new(),
        ));

        Ok(Self {
            compressed,
            compressor,
            offsets_path,
            pending_index: 0,
            shared,
            tx: None,
            tid: None,
            data_cache: DataCache::new(cache_nr_entries),
        })
    }

    /// Sync all pending writes to disk without closing
    ///
    /// Ensures the file and offsets are synced to persistent storage.
    /// Writer thread remains alive for future writes.
    pub fn sync_all(&mut self) -> Result<()> {
        // If no writer thread (read-only mode), nothing to sync
        if self.tx.is_none() {
            return Ok(());
        }

        let target = {
            let (lock, _) = &*self.shared;
            let sh = lock.lock().unwrap();
            // Skip sync if nothing new has been written since opening
            // This happens when we open_for_write but don't actually write any new slabs
            if self.pending_index == sh.progress.last_submitted {
                None
            } else {
                Some(sh.progress.last_submitted)
            }
        };

        if let Some(target) = target {
            let (lock, cv) = &*self.shared;
            let mut sh = lock.lock().unwrap();
            // No borrow from `sh` while moving `sh`
            sh = cv
                .wait_while(sh, |sh| sh.progress.last_written < target)
                .unwrap();

            sh.data.sync_all()?;
            sh.offsets.write_offset_file(&self.offsets_path)?;
            drop(sh);

            let f = OpenOptions::new().write(true).open(&self.offsets_path)?;
            f.sync_all()?;
        }
        Ok(())
    }

    pub fn close(&mut self) -> Result<()> {
        // Close the channel to signal writer thread to stop
        self.tx = None;

        // Wait for writer thread to finish all pending writes
        let mut tid = None;
        std::mem::swap(&mut tid, &mut self.tid);
        if let Some(tid) = tid {
            tid.join().expect("join failed");
        }

        // Sync data and write offsets file atomically
        {
            let (lock, _) = &*self.shared;
            let shared = lock.lock().unwrap();

            // Sync the data file to ensure all writes are persisted
            shared.data.sync_all()?;

            // Write offsets file while holding the lock
            shared.offsets.write_offset_file(&self.offsets_path)?;
        }

        Ok(())
    }

    pub fn read_(&mut self, slab: u32) -> Result<Vec<u8>> {
        let (lock, _) = &*self.shared;

        let mut shared = lock.lock().unwrap();

        // Check if slab index is within bounds
        let slab_idx = slab as usize;
        if slab_idx >= shared.offsets.offsets.len() {
            return Err(anyhow::anyhow!(
                "Slab index {} out of bounds (have {} slabs committed to disk)",
                slab,
                shared.offsets.offsets.len()
            ));
        }

        let offset = shared.offsets.offsets[slab_idx];
        shared.data.seek(SeekFrom::Start(offset))?;

        let magic = shared.data.read_u64::<LittleEndian>()?;
        let len = shared.data.read_u64::<LittleEndian>()?;
        assert_eq!(magic, SLAB_MAGIC);

        let mut expected_csum: Hash64 = Hash64::default();
        shared.data.read_exact(&mut expected_csum)?;

        let mut buf = vec![0; len as usize];
        shared.data.read_exact(&mut buf)?;

        let actual_csum = hash_64(&buf);
        assert_eq!(actual_csum, expected_csum);

        if self.compressed {
            let decompress_buff_size_mb: usize = env::var("BLK_ARCHIVE_DECOMPRESS_BUFF_SIZE_MB")
                .unwrap_or(String::from("4"))
                .parse::<usize>()
                .unwrap_or(4);
            let mut z = zstd::Decoder::new(&buf[..])?;
            let mut buffer = Vec::with_capacity(decompress_buff_size_mb * 1024 * 1024);
            z.read_to_end(&mut buffer)?;
            Ok(buffer)
        } else {
            Ok(buf)
        }
    }

    pub fn read(&mut self, slab: u32) -> Result<Arc<Vec<u8>>> {
        // Check pending writes first (uncommitted data)
        {
            let (lock, _) = &*self.shared;
            let sh = lock.lock().unwrap();
            if let Some(data) = sh.pending_writes.get(&(slab as u64)) {
                return Ok(data.clone());
            }
        }

        // Check cache
        if let Some(data) = self.data_cache.find(slab) {
            Ok(data)
        } else {
            // Read from disk
            let data = Arc::new(self.read_(slab)?);
            self.data_cache.insert(slab, data.clone());
            Ok(data)
        }
    }

    fn reserve_slab(&mut self) -> (SlabIndex, SyncSender<SlabData>) {
        let index = self.pending_index;
        self.pending_index += 1;

        // Make it visible to flushers what the current high-water mark is
        {
            let (lock, _) = &*self.shared;
            let mut sh = lock.lock().unwrap();
            sh.progress.last_submitted = index;
        }

        let tx = self.tx.as_ref().unwrap().clone();
        (index, tx)
    }

    pub fn write_slab(&mut self, data: &[u8]) -> Result<()> {
        let (index, tx) = self.reserve_slab();

        // make data available for immediate reads before durability
        {
            let (lock, _) = &*self.shared;
            let mut sh = lock.lock().unwrap();
            sh.pending_writes.insert(index, Arc::new(data.to_vec()));
        }

        tx.send(SlabData {
            index,
            data: data.to_vec(),
        })?;

        Ok(())
    }

    pub fn index(&self) -> SlabIndex {
        self.pending_index
    }

    pub fn get_nr_slabs(&self) -> usize {
        let (lock, _) = &*self.shared;
        let shared = lock.lock().unwrap();
        shared.offsets.offsets.len()
    }

    pub fn get_file_size(&self) -> u64 {
        let (lock, _) = &*self.shared;
        let shared = lock.lock().unwrap();
        shared.file_size
    }

    pub fn hits(&self) -> u64 {
        self.data_cache.hits
    }

    pub fn misses(&self) -> u64 {
        self.data_cache.misses
    }
}

impl SlabStorage for SlabFile {
    fn write_slab(&mut self, data: &[u8]) -> Result<()> {
        self.write_slab(data)
    }

    fn read(&mut self, slab: u32) -> Result<Arc<Vec<u8>>> {
        self.read(slab)
    }

    fn close(&mut self) -> Result<()> {
        self.close()
    }

    fn get_nr_slabs(&self) -> u32 {
        self.get_nr_slabs() as u32
    }

    fn index(&self) -> u32 {
        self.index() as u32
    }

    fn get_file_size(&self) -> u64 {
        self.get_file_size()
    }
}

//-----------------------------------------
