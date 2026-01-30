use anyhow::{anyhow, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
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
pub const SLAB_FILE_HDR_LEN: u64 = 16;
const SLAB_HDR_LEN: u64 = 24;

const FORMAT_VERSION: u32 = 0;

pub type SlabIndex = u64;
type Shared<'a> = Arc<(Mutex<SlabShared<'a>>, Condvar)>;

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

struct SlabShared<'a> {
    data: File,
    offsets: SlabOffsets<'a>,
    file_size: u64,

    progress: Progress,

    // move here so writer thread can erase entries once committed
    pending_writes: HashMap<SlabIndex, Arc<Vec<u8>>>,
}

// FIXME: add index file
pub struct SlabFile<'a> {
    pub compressed: bool,
    compressor: Option<CompressionService>,
    offsets_path: PathBuf,
    pending_index: u64,
    slab_path: PathBuf,

    shared: Shared<'a>,

    tx: Option<SyncSender<SlabData>>,
    tid: Option<thread::JoinHandle<()>>,

    data_cache: DataCache,
}

impl<'a> Drop for SlabFile<'a> {
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
    shared.offsets.append(offset);
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

// Retrieve the number of slabs in a slab file by using the index file count
// This should not be considered an absolute truth as the index file may not match the
// data slab.  It's a quick check to be used when we're doing simple checks when we start up.
pub fn number_of_slabs<P: AsRef<Path>>(data_slab: P) -> Result<u32> {
    let slab_offsets_name = offsets_path(&data_slab);
    let (valid, count, context) = validate_slab_offsets_file(&slab_offsets_name, false);

    if valid {
        Ok(count)
    } else {
        Err(anyhow!(context.unwrap()))
    }
}

/// Verify the checksum of the last slab in a slab file
///
/// This function reads the last slab (based on the last offset in the index file)
/// and verifies its checksum matches. This is a quick way to detect if the slab
/// file and index file are out of sync.
///
/// # Arguments
///
/// * `data_slab` - Path to the slab data file
/// * `offsets` - SlabOffsets containing the index information
/// * `count` - Number of slabs (from index file)
///
/// # Returns
///
/// * `Ok(())` if the last slab's checksum is valid
/// * `Err` if the checksum is invalid or if there's an I/O error
pub fn verify_last_slab_checksum<P: AsRef<Path>>(
    data_slab: P,
    offsets: &SlabOffsets,
    count: u32,
) -> Result<()> {
    if count == 0 {
        return Ok(()); // Empty file is trivially valid
    }

    let slab_path = data_slab.as_ref();
    let last_offset = offsets
        .get_slab_offset((count - 1) as usize)
        .ok_or_else(|| anyhow!("Failed to read last offset from index"))?;

    let mut data = OpenOptions::new()
        .read(true)
        .create(false)
        .open(slab_path)
        .with_context(|| format!("Failed to open slab file {:?}", slab_path))?;

    // Seek to the last slab
    data.seek(SeekFrom::Start(last_offset)).with_context(|| {
        format!(
            "Failed to seek to offset {} in {:?}",
            last_offset, slab_path
        )
    })?;

    // Read slab header
    let slab_magic = data
        .read_u64::<LittleEndian>()
        .with_context(|| format!("Failed to read magic for last slab in {:?}", slab_path))?;

    if slab_magic != SLAB_MAGIC {
        return Err(anyhow!(
            "Last slab in {:?} has incorrect magic: expected 0x{:016x}, got 0x{:016x}",
            slab_path,
            SLAB_MAGIC,
            slab_magic
        ));
    }

    let slab_len = data
        .read_u64::<LittleEndian>()
        .with_context(|| format!("Failed to read length for last slab in {:?}", slab_path))?;

    if slab_len == 0 {
        return Err(anyhow!(
            "Last slab in {:?} has zero length (invalid)",
            slab_path
        ));
    }

    let mut expected_csum: Hash64 = Hash64::default();
    data.read_exact(&mut expected_csum)
        .with_context(|| format!("Failed to read checksum for last slab in {:?}", slab_path))?;

    // Read the slab data
    let mut buf = vec![0u8; slab_len as usize];
    data.read_exact(&mut buf).with_context(|| {
        format!(
            "Failed to read {} bytes for last slab in {:?}",
            slab_len, slab_path
        )
    })?;

    // Verify checksum
    let actual_csum = hash_64(&buf);
    if actual_csum != expected_csum {
        return Err(anyhow!(
            "Checksum mismatch for last slab in {:?}: expected {:?}, got {:?}",
            slab_path,
            expected_csum,
            actual_csum
        ));
    }

    Ok(())
}

/// Perform a quick consistency check between a slab file and its index file
///
/// This function performs multiple checks to ensure the slab file and index file are consistent:
/// 1. Validates the index file's internal CRC64 checksum
/// 2. Checks that the last offset is within the slab file size bounds
/// 3. Verifies the last slab's checksum matches
///
/// This is much faster than regenerating the entire index, while still catching
/// most common corruption scenarios.
///
/// # Arguments
///
/// * `data_slab` - Path to the slab data file
///
/// # Returns
///
/// * `Ok(())` if all consistency checks pass
/// * `Err` with a descriptive message if any check fails
pub fn quick_consistency_check<P: AsRef<Path>>(data_slab: P) -> Result<()> {
    let slab_path = data_slab.as_ref();
    let offsets_path = offsets_path(slab_path);

    // Check 1: Validate index file CRC64
    let (valid, count, error) = validate_slab_offsets_file(&offsets_path, true);
    if !valid {
        return Err(anyhow!(
            "Index file CRC validation failed for {:?}: {}",
            offsets_path,
            error.unwrap_or_else(|| "unknown error".to_string())
        ));
    }

    // If empty, we're done
    if count == 0 {
        return Ok(());
    }

    // Check 2: Verify last offset is within file bounds
    let offsets = SlabOffsets::open(&offsets_path, false)
        .with_context(|| format!("Failed to open index file {:?}", offsets_path))?;

    let last_offset = offsets
        .get_slab_offset((count - 1) as usize)
        .ok_or_else(|| anyhow!("Failed to read last offset from {:?}", offsets_path))?;

    let file_size = std::fs::metadata(slab_path)
        .with_context(|| format!("Failed to get metadata for {:?}", slab_path))?
        .len();

    // Last offset should be less than file size and should have room for at least
    // the slab header (magic + length + checksum = 24 bytes)
    if last_offset >= file_size {
        return Err(anyhow!(
            "Index/slab mismatch for {:?}: last offset {} >= file size {} - index file is out of sync",
            slab_path,
            last_offset,
            file_size
        ));
    }

    if last_offset + SLAB_HDR_LEN > file_size {
        return Err(anyhow!(
            "Index/slab mismatch for {:?}: last offset {} + header {} > file size {} - slab file may be truncated",
            slab_path,
            last_offset,
            SLAB_HDR_LEN,
            file_size
        ));
    }

    // Check 3: Verify the last slab's checksum
    verify_last_slab_checksum(slab_path, &offsets, count)
        .with_context(|| format!("Last slab checksum verification failed for {:?}", slab_path))?;

    Ok(())
}

fn writer(shared: &Shared, rx: Receiver<SlabData>, start_index: u64) {
    // FIXME: pass on error
    writer_(shared, rx, start_index).expect("write of slab failed");
}

pub fn regenerate_index<'a, P: AsRef<Path>>(
    data_path: P,
    truncate: bool,
) -> Result<SlabOffsets<'a>> {
    let slab_name = data_path.as_ref().to_path_buf();
    let slab_display = slab_name.display();
    let slab_offsets_name = offsets_path(slab_name.clone());

    let data = OpenOptions::new()
        .read(true)
        .write(truncate) // Need write permission if we might truncate
        .create(false)
        .open(&slab_name)?;

    let file_size = data.metadata()?.len();

    if file_size < crate::slab::file::SLAB_FILE_HDR_LEN {
        return Err(anyhow!(
            "{slab_display} isn't large enough to be a slab file, size = {file_size} bytes."
        ));
    }

    // Use buffered reader for efficient small reads
    let mut data = BufReader::new(data);

    let _flags = read_slab_header(&mut data)?; // This validates the slab header

    // We don't have any additional data in an empty archive
    let mut curr_offset = data.stream_position()?;
    if curr_offset != SLAB_FILE_HDR_LEN {
        return Err(anyhow!(
            "For slab {}, after reading header, position={} but expected {}",
            slab_display,
            curr_offset,
            SLAB_FILE_HDR_LEN
        ));
    }

    // Only after we know we have a valid slab header will we muck with the index file.
    let mut so = SlabOffsets::open(slab_offsets_name.clone(), true)?;

    if curr_offset == file_size {
        return Ok(so);
    }
    //so.append(SLAB_FILE_HDR_LEN); // The first offset for slab 0 starts at the size of the hdr
    let mut slab_index: u32 = 0;
    let mut last_good_offset = curr_offset;

    loop {
        // Closure to handle slab reading which we'll call with error handling
        let read_result = (|| -> Result<bool> {
            let remaining = file_size
                .checked_sub(curr_offset)
                .ok_or_else(|| anyhow!("position {} beyond end {}", curr_offset, file_size))?;

            if remaining < SLAB_HDR_LEN {
                return Err(anyhow!(
                    "{slab_display}[{slab_index}] is incomplete, not enough remaining for header, \
                    {remaining} remaining bytes, need {SLAB_HDR_LEN}",
                ));
            }

            let slab_magic = data.read_u64::<LittleEndian>()?;
            let slab_len = data.read_u64::<LittleEndian>()?;

            if slab_magic != SLAB_MAGIC {
                return Err(anyhow!("{slab_display}[{slab_index}] magic incorrect"));
            }

            if slab_len == 0 {
                return Err(anyhow!(
                    "{slab_display}[{slab_index}] zero-length slab not allowed"
                ));
            }

            if slab_len > (crate::archive::SLAB_SIZE_TARGET * 2) as u64 {
                return Err(anyhow!(
                    "{slab_display}[{slab_index}] length too large: {slab_len}"
                ));
            }

            let mut expected_csum: Hash64 = Hash64::default();
            data.read_exact(&mut expected_csum)
                .with_context(|| format!("{slab_display}[{slab_index}] failed to read checksum"))?;

            if remaining < SLAB_HDR_LEN + slab_len {
                return Err(anyhow!(
                    "{slab_display}[{slab_index}] is incomplete, payload is truncated, \
                    needing {}, remaining {remaining}",
                    SLAB_HDR_LEN + slab_len
                ));
            }

            let mut buf = vec![0; slab_len as usize];
            data.read_exact(&mut buf).with_context(|| {
                format!(
                    "{slab_display}[{slab_index}] error while trying to read ({slab_len} bytes)",
                )
            })?;

            let actual_csum = hash_64(&buf);
            if actual_csum != expected_csum {
                return Err(anyhow!("{slab_display}[{slab_index}] checksum incorrect!"));
            }

            Ok(false) // Successfully read slab, not at EOF
        })();

        match read_result {
            Ok(_) => {
                so.append(curr_offset); // Append offset for next slab after successfully reading current one

                curr_offset = data.stream_position()?;
                last_good_offset = curr_offset;

                if curr_offset == file_size {
                    break;
                }
                slab_index += 1;
            }
            Err(e) => {
                if truncate {
                    // Truncate the file to the end of the last good slab
                    eprintln!(
                        "Warning: {slab_display}[{slab_index}] encountered error: {e}\n\
                        Truncating file to {last_good_offset} bytes (end of slab {})",
                        slab_index.saturating_sub(1)
                    );

                    // Drop buffered reader to release file handle
                    drop(data);

                    // Reopen slab file with write permission and truncate
                    let file = OpenOptions::new()
                        .write(true)
                        .open(&slab_name)
                        .with_context(|| {
                            format!("Failed to open {} for truncation", slab_display)
                        })?;

                    file.set_len(last_good_offset).with_context(|| {
                        format!(
                            "Failed to truncate {} to {}",
                            slab_display, last_good_offset
                        )
                    })?;

                    // so already contains the correct offsets (only good slabs)
                    // Just break and return it
                    break;
                } else {
                    // Re-throw the error if not in truncate mode
                    return Err(e);
                }
            }
        }
    }

    Ok(so)
}

/// Truncate a slab file to contain exactly `slab_num` slabs and rebuild its index
///
/// This function:
/// 1. Validates the slab file header
/// 2. Reads through slabs until reaching `slab_num`
/// 3. Truncates the file at the offset after the last desired slab
/// 4. Rebuilds the index file (.offsets)
///
/// # Arguments
/// * `data_slab` - Path to the slab data file
/// * `slab_num` - Number of slabs to keep (0 = truncate to header only)
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(...)` if:
///   - The file doesn't exist or has invalid format
///   - `slab_num` exceeds the current number of slabs
///   - Any I/O errors occur
pub fn truncate_to_slab_count(data_slab: &Path, slab_num: u32) -> Result<()> {
    let slab_display = data_slab.display();

    // Open file for reading to determine truncation point
    let data = OpenOptions::new()
        .read(true)
        .create(false)
        .open(data_slab)?;

    let file_size = data.metadata()?.len();

    if file_size < SLAB_FILE_HDR_LEN {
        return Err(anyhow!(
            "{slab_display} isn't large enough to be a slab file, size = {file_size} bytes."
        ));
    }

    let mut data = BufReader::new(data);

    // Validate the slab header
    let _flags = read_slab_header(&mut data)?;

    let mut curr_offset = data.stream_position()?;
    if curr_offset != SLAB_FILE_HDR_LEN {
        return Err(anyhow!(
            "For slab {}, after reading header, position={} but expected {}",
            slab_display,
            curr_offset,
            SLAB_FILE_HDR_LEN
        ));
    }

    // Special case: truncate to header only (0 slabs)
    if slab_num == 0 {
        drop(data); // Close the reader before truncating
        let file = OpenOptions::new()
            .write(true)
            .open(data_slab)
            .with_context(|| format!("Failed to open {} for truncation", slab_display))?;

        file.set_len(SLAB_FILE_HDR_LEN).with_context(|| {
            format!(
                "Failed to truncate {} to header size ({})",
                slab_display, SLAB_FILE_HDR_LEN
            )
        })?;

        // Rebuild index for empty file
        let mut slab_offsets = regenerate_index(data_slab, false)?;
        slab_offsets.write_offset_file(true)?;
        return Ok(());
    }

    // Read through slabs to find truncation point
    let mut slab_index: u32 = 0;
    let truncate_offset: u64;

    loop {
        if slab_index >= slab_num {
            // Found our truncation point
            truncate_offset = curr_offset;
            break;
        }

        let remaining = file_size
            .checked_sub(curr_offset)
            .ok_or_else(|| anyhow!("position {} beyond end {}", curr_offset, file_size))?;

        if remaining == 0 {
            return Err(anyhow!(
                "{slab_display}: requested {} slabs but file only contains {}",
                slab_num,
                slab_index
            ));
        }

        if remaining < SLAB_HDR_LEN {
            return Err(anyhow!(
                "{slab_display}[{slab_index}] is incomplete, not enough remaining for header"
            ));
        }

        // Read slab header
        let slab_magic = data.read_u64::<LittleEndian>()?;
        let slab_len = data.read_u64::<LittleEndian>()?;

        if slab_magic != SLAB_MAGIC {
            return Err(anyhow!("{slab_display}[{slab_index}] magic incorrect"));
        }

        if slab_len == 0 {
            return Err(anyhow!(
                "{slab_display}[{slab_index}] zero-length slab not allowed"
            ));
        }

        if slab_len > (crate::archive::SLAB_SIZE_TARGET * 2) as u64 {
            return Err(anyhow!(
                "{slab_display}[{slab_index}] length too large: {slab_len}"
            ));
        }

        // Skip checksum (8 bytes)
        data.seek(SeekFrom::Current(8))?;

        if remaining < SLAB_HDR_LEN + slab_len {
            return Err(anyhow!(
                "{slab_display}[{slab_index}] is incomplete, payload is truncated"
            ));
        }

        // Skip slab data
        data.seek(SeekFrom::Current(slab_len as i64))?;

        curr_offset = data.stream_position()?;
        slab_index += 1;
    }

    // Close the reader before truncating
    drop(data);

    // Truncate the file
    let file = OpenOptions::new()
        .write(true)
        .open(data_slab)
        .with_context(|| format!("Failed to open {} for truncation", slab_display))?;

    file.set_len(truncate_offset).with_context(|| {
        format!(
            "Failed to truncate {} to {} bytes ({} slabs)",
            slab_display, truncate_offset, slab_num
        )
    })?;

    drop(file);

    // Rebuild the index
    let mut slab_offsets = regenerate_index(data_slab, false)?;
    slab_offsets.write_offset_file(true)?;

    Ok(())
}

fn offsets_path<P: AsRef<Path>>(p: P) -> PathBuf {
    let mut offsets_path = PathBuf::new();
    offsets_path.push(p);
    offsets_path.set_extension("offsets");
    offsets_path
}

fn read_slab_header<R: Read + Seek>(data: &mut R) -> Result<u32> {
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

impl<'a> SlabFile<'a> {
    pub(crate) fn create<P: AsRef<Path>>(
        data_path: P,
        queue_depth: usize,
        compressed: bool,
        cache_nr_entries: usize,
    ) -> Result<Self>
    where
        'a: 'static,
    {
        let offsets_path = offsets_path(&data_path);
        let slab_path = data_path.as_ref().to_path_buf();

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

        let offsets = SlabOffsets::open(offsets_path.clone(), true)?; // Truncate to match data file
        let file_size = data.metadata()?.len();
        let shared: Shared = Arc::new((
            Mutex::new(SlabShared {
                data,
                offsets,
                file_size,
                progress: Progress {
                    last_submitted: 0,
                    // Initialize to wrapping -1 so first write (index 0) will update last_written
                    last_written: 0u64.wrapping_sub(1),
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
            slab_path,
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
    ) -> Result<Self>
    where
        'a: 'static,
    {
        let offsets_path = offsets_path(&data_path);
        let slab_path = data_path.as_ref().to_path_buf();

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

        let offsets = SlabOffsets::open(&offsets_path, false)?;
        let file_size = data.metadata()?.len();
        let nr_existing_slabs = offsets.len() as u64;

        let shared: Shared = Arc::new((
            Mutex::new(SlabShared {
                data,
                offsets,
                file_size,
                progress: Progress {
                    last_submitted: nr_existing_slabs, // or 0 on create
                    // Use wrapping_sub so that 0 - 1 = u64::MAX (not 0 from saturating)
                    // This ensures the first write (index 0) will update last_written
                    last_written: nr_existing_slabs.wrapping_sub(1),
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
            pending_index: nr_existing_slabs as u64, // Start from number of existing slabs
            slab_path,
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
        let slab_path = data_path.as_ref().to_path_buf();

        let mut data = OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(data_path)?;

        let flags = read_slab_header(&mut data)?;
        let compressed = flags == 1;
        let compressor = None;

        let offsets = SlabOffsets::open(&offsets_path, false)?;
        let nr_existing_slabs = offsets.len() as u64;
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
            slab_path,
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
            sh = cv
                .wait_while(sh, |sh| {
                    // Handle wraparound: u64::MAX means "not yet written"
                    sh.progress.last_written == u64::MAX || sh.progress.last_written < target
                })
                .unwrap();

            sh.data.sync_all()?;
            sh.offsets.write_offset_file(true)?;
            drop(sh);

            // Sync the directory that is holding the offsets file which also includes the data file
            // Note: The offsets file could be re-built if needed.
            use crate::recovery::SyncParentExt;
            self.offsets_path.sync_parent()?;
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
            let mut shared = lock.lock().unwrap();

            // Sync the data file to ensure all writes are persisted
            shared.data.sync_all()?;

            // Write offsets file while holding the lock
            shared.offsets.write_offset_file(true)?;
        }

        Ok(())
    }

    pub fn read_(&mut self, slab: u32) -> Result<Vec<u8>> {
        let (lock, _) = &*self.shared;

        let mut shared = lock.lock().unwrap();

        // Check if slab index is within bounds
        let slab_idx = slab as usize;
        if slab_idx >= shared.offsets.len() {
            return Err(anyhow::anyhow!(
                "Slab {:?} index {} out of bounds (have {} slabs committed to disk)",
                self.slab_path,
                slab,
                shared.offsets.len()
            ));
        }

        let offset = shared
            .offsets
            .get_slab_offset(slab_idx)
            .ok_or_else(|| anyhow::anyhow!("Failed to get offset for slab {}", slab))?;
        shared.data.seek(SeekFrom::Start(offset))?;

        // Use buffered reader for efficient small reads
        let mut reader = BufReader::new(&mut shared.data);

        let magic = reader.read_u64::<LittleEndian>()?;
        let len = reader.read_u64::<LittleEndian>()?;

        if magic != SLAB_MAGIC {
            return Err(anyhow!(format!(
                "While trying to read the slab {:?} index {} with len {} we got error a slab magic missmatch! expected = {:016x} actual {:016x}",
                self.slab_path, slab, len, SLAB_MAGIC, magic
            )));
        }

        let mut expected_csum: Hash64 = Hash64::default();
        reader.read_exact(&mut expected_csum).with_context(|| {
            format!(
                "Failed to read checksum for slab {} in {:?}",
                slab, self.slab_path
            )
        })?;

        let mut buf = vec![0; len as usize];
        let slab_read_result = reader.read_exact(&mut buf);
        if let Err(e) = slab_read_result {
            return Err(anyhow!(format!(
                "While trying to read the slab {:?} index {} with len {} we got error '{:#}'",
                self.slab_path, slab, len, e
            )));
        }

        let actual_csum = hash_64(&buf);
        if actual_csum != expected_csum {
            return Err(anyhow!("Slab {slab} has a checksum error!"));
        }

        if self.compressed {
            let decompress_buff_size_mb: usize = env::var("BLK_STASH_DECOMPRESS_BUFF_SIZE_MB")
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
        shared.offsets.len()
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

impl<'a> SlabStorage for SlabFile<'a> {
    fn write_slab(&mut self, data: &[u8]) -> Result<()> {
        self.write_slab(data)
    }

    fn read(&mut self, slab: u32) -> Result<Arc<Vec<u8>>> {
        self.read(slab)
    }

    fn sync_all(&mut self) -> Result<()> {
        self.sync_all()
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

/// Trait for types that can provide stream data for iteration
pub trait StreamData {
    /// Read a slab by its index
    fn read(&mut self, slab: u32) -> Result<Arc<Vec<u8>>>;

    /// Get the total number of slabs available
    fn get_nr_slabs(&self) -> usize;
}

impl<'a> StreamData for SlabFile<'a> {
    fn read(&mut self, slab: u32) -> Result<Arc<Vec<u8>>> {
        self.read(slab)
    }

    fn get_nr_slabs(&self) -> usize {
        self.get_nr_slabs()
    }
}

impl<'a> StreamData for Box<dyn StreamData + Send + Sync + 'a> {
    fn read(&mut self, slab: u32) -> Result<Arc<Vec<u8>>> {
        (**self).read(slab)
    }

    fn get_nr_slabs(&self) -> usize {
        (**self).get_nr_slabs()
    }
}

//-----------------------------------------
