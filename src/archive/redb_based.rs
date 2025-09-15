// redb-backed dedup with database-only metadata, slab files contain only raw chunk data
// ------------------------------------------------------------------
// In this design, redb stores all metadata: index, directory, offsets, lengths, hashes, etc.
// The slab files only contain concatenated raw data chunks (without headers).

use anyhow::{Context, Result};
use indexmap::IndexMap;
use redb::ReadableDatabase;
use redb::{Database, ReadableTable, TableDefinition};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{error::Error, fmt};

use crate::archive::data::Store;
use crate::hash::{hash_256, Hash256};
use crate::iovec::IoVec;

static HASH_TO_INDEX: TableDefinition<&Hash256, &[u8; 12]> = TableDefinition::new("index");
static SLABMETA: TableDefinition<u64, u64> = TableDefinition::new("slab_meta");
static META: TableDefinition<&str, u64> = TableDefinition::new("meta");
static INDEX_TO_OFFSET_LEN_HASH: TableDefinition<(u32, u32), Vec<u8>> =
    TableDefinition::new("slab_index");

pub struct DedupStore {
    db: Database,
    root: PathBuf,
    slab_id: u32,
    slab_fd: File,
    frontier: u64,
    cursor: u64,
    max_slab_bytes: u64,
    staged: IndexMap<Hash256, (u32, u32)>,
    staged_bytes: u64,
    flush_threshold_bytes: u64,
    entries_in_slab: u32,
    get_index: HashMap<(u32, u32), (u32, u32, Hash256)>,
}

#[inline]
fn enc_index(out: &mut [u8; 12], slab: u32, off: u32, len: u32) {
    out[0..4].copy_from_slice(&slab.to_le_bytes());
    out[4..8].copy_from_slice(&off.to_le_bytes());
    out[8..12].copy_from_slice(&len.to_le_bytes());
}

#[inline]
fn dec_index(v: &[u8]) -> Option<(u32, u32, u32)> {
    if v.len() < 12 {
        return None;
    }
    Some((
        u32::from_le_bytes(v[0..4].try_into().ok()?),
        u32::from_le_bytes(v[4..8].try_into().ok()?),
        u32::from_le_bytes(v[8..12].try_into().ok()?),
    ))
}

impl Store for DedupStore {
    fn ensure_extra_capacity(&mut self, _blocks: usize) -> Result<()> {
        Ok(())
    }

    fn data_add(&mut self, h: Hash256, iov: &IoVec, len: u64) -> Result<((u32, u32), u64)> {
        // 0) Return early if we already have this chunk (staged or in the db)
        if let Some(&(off, l)) = self.staged.get(&h) {
            return Ok(((self.slab_id, off), l as u64));
        }

        if let Some(loc) = self.already_indexed(&h)? {
            return Ok(loc);
        }

        // 1) Make sure there is room in the current slab (roll if needed)
        self.ensure_room(len)?;

        // 2) Append raw bytes to the slab and stage metadata (no fsync here)
        let off_u32 = self.append_to_slab(iov)?;
        let len_u32 = u32::try_from(len).context("len > u32::MAX not supported")?;
        self.stage_entry(h, off_u32, len_u32);

        // 3) Auto-publish on threshold; caller can also call publish() explicitly
        if self.staged_bytes >= self.flush_threshold_bytes {
            self.publish()?;
        }

        let ordinal_offset = self.entries_in_slab + self.staged.len() as u32;

        self.get_index
            .insert((self.slab_id, ordinal_offset - 1), (off_u32, len_u32, h));

        Ok(((self.slab_id, ordinal_offset - 1), len))
    }

    fn data_get(
        &mut self,
        slab: u32,
        offset: u32,
        nr_entries: u32,
        partial: Option<(u32, u32)>,
    ) -> Result<(Arc<Vec<u8>>, usize, usize)> {
        if nr_entries == 0 {
            return Ok((Arc::new(Vec::new()), 0, 0));
        }

        let rtxn = self.db.begin_read()?;
        let idx_lookup = rtxn.open_table(INDEX_TO_OFFSET_LEN_HASH)?;
        let mut offsets = Vec::with_capacity(nr_entries as usize);
        let mut lengths: Vec<usize> = Vec::with_capacity(nr_entries as usize);
        let mut hashes = Vec::with_capacity(nr_entries as usize);
        for ord in offset..offset + nr_entries {
            // Check the db, else check the in memory
            let g = idx_lookup.get((slab, ord))?;

            if let Some(g) = g {
                let block = g.value();
                let (offset, len, hash) = DedupStore::parse_dir_record(&block)?;
                offsets.push(offset);
                lengths.push(len as usize);
                hashes.push(hash);
            } else if let Some((offset, len, h)) = self.get_index.get(&(slab, ord)) {
                offsets.push(*offset);
                lengths.push(*len as usize);
                hashes.push(*h)
            } else {
                anyhow::bail!(
                    "data not found {}, {}, {}, {:?}",
                    slab,
                    offset,
                    nr_entries,
                    partial
                );
            }
        }
        // Since the file stores raw chunks back-to-back, these entries are contiguous.
        let region_start = offsets[0] as u64;
        let region_len: u64 = lengths.iter().map(|&l| l as u64).sum();

        let fd = OpenOptions::new()
            .read(true)
            .open(self.root.join(format!("slab-{slab:04}.bin")))?;
        let mut out = vec![0u8; region_len as usize];
        fd.read_exact_at(&mut out, region_start)?;

        //Validate that the data is correct by verifying the blake hash is the same as stored
        validate_data(&out, &lengths, &hashes)?;

        let mut data_begin = 0usize;
        let mut data_end = region_len as usize;

        // Handle partial
        (data_begin, data_end) = if let Some((begin, end)) = partial {
            let data_end = data_begin + end as usize;
            let data_begin = data_begin + begin as usize;
            (data_begin, data_end)
        } else {
            (data_begin, data_end)
        };

        Ok((Arc::new(out), data_begin, data_end))
    }

    fn flush(&mut self) -> Result<()> {
        self.publish()
    }

    fn is_known(&mut self, h: &Hash256) -> Result<Option<(u32, u32)>> {
        if let Some(&(off, _l)) = self.staged.get(h) {
            return Ok(Some((self.slab_id, off)));
        }

        if let Some(((slab, offset), _len)) = self.already_indexed(h)? {
            return Ok(Some((slab, offset)));
        }

        Ok(None)
    }
}

impl DedupStore {
    // ---------- small helpers to keep data_add clean ----------
    #[inline]
    fn already_indexed(&self, h: &Hash256) -> Result<Option<((u32, u32), u64)>> {
        let rtxn = self.db.begin_read()?;
        let idx = rtxn.open_table(HASH_TO_INDEX)?;
        if let Some(g) = idx.get(&h)? {
            if let Some((slab, off, l)) = dec_index(g.value()) {
                return Ok(Some(((slab, off), l as u64)));
            }
        }

        Ok(None)
    }

    #[inline]
    fn ensure_room(&mut self, need: u64) -> Result<()> {
        if self.cursor + need <= self.max_slab_bytes {
            return Ok(());
        }
        // publish current staged set and roll to a new slab
        self.publish()?;
        self.roll_slab()?;
        Ok(())
    }

    #[inline]
    fn append_to_slab(&mut self, iov: &IoVec) -> Result<u32> {
        let start = self.cursor;
        let mut off = start;

        for chunk in iov {
            // write this chunk at the current offset
            self.slab_fd.write_all_at(chunk, off)?;
            // advance by chunk length (checked to avoid u64 overflow on pathological input)
            off = off
                .checked_add(chunk.len() as u64)
                .context("offset overflow while appending iov")?;
        }

        // update the slab cursor to the end of the appended region
        self.cursor = off;

        // return starting offset as u32 (match original API)
        u32::try_from(start).context("offset exceeds u32::MAX")
    }

    #[inline]
    fn stage_entry(&mut self, h: Hash256, off: u32, len: u32) {
        self.staged.insert(h, (off, len));
        self.staged_bytes += len as u64;
    }

    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self> {
        DedupStore::open(root)
    }

    pub fn open<P: AsRef<Path>>(root: P) -> Result<Self> {
        const ONE_GIB: u64 = 1u64 << 30;
        const DEFAULT_FLUSH: u64 = 128u64 << 20;

        let frontier: u64;
        let active_id: u32;

        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let db = Database::create(root.join("index.redb"))?;

        let write = db.begin_write()?;
        {
            let mut meta = write.open_table(META)?;
            let next = meta.get("next_slab_id")?.map(|g| g.value()).unwrap_or(0);
            active_id = next.saturating_sub(1) as u32;
            if next == 0 {
                meta.insert("next_slab_id", 1)?;
            }
            let mut smeta = write.open_table(SLABMETA)?;
            frontier = smeta.get(active_id as u64)?.map(|g| g.value()).unwrap_or(0);
            if next == 0 {
                smeta.insert(active_id as u64, 0)?;
            }
            // ensure directory table exists
            let _ = write.open_table(INDEX_TO_OFFSET_LEN_HASH)?;
            let _ = write.open_table(HASH_TO_INDEX)?;
        }
        write.commit()?;

        let slab_path = root.join(format!("slab-{active_id:04}.bin"));
        let fd = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&slab_path)?;
        let len = fd.metadata()?.len();
        if len > frontier {
            fd.set_len(frontier)?;
        }

        Ok(Self {
            db,
            root,
            slab_id: active_id,
            slab_fd: fd,
            frontier,
            cursor: frontier,
            max_slab_bytes: ONE_GIB,
            staged: IndexMap::new(),
            staged_bytes: 0,
            flush_threshold_bytes: DEFAULT_FLUSH,
            entries_in_slab: 0,
            get_index: HashMap::new(),
        })
    }

    fn current_slab_path(&self) -> PathBuf {
        self.root.join(format!("slab-{:04}.bin", self.slab_id))
    }

    #[inline]
    fn fdatasync(fd: &File) -> Result<()> {
        fd.sync_data()?;
        Ok(())
    }

    fn parse_dir_record(bytes: &[u8]) -> Result<(u32, u32, Hash256)> {
        if bytes.len() < 4 + 4 + 32 {
            anyhow::bail!("dir record too short: {} bytes", bytes.len());
        }
        let off = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let mut h: Hash256 = [0u8; 32];
        h.copy_from_slice(&bytes[8..40]);
        Ok((off, len, h))
    }

    pub fn publish(&mut self) -> Result<()> {
        if self.staged.is_empty() {
            return Ok(());
        }

        // 1) Make slab durable up to cursor
        Self::fdatasync(&self.slab_fd)?;

        // 2) Atomically publish index + frontier
        let wtxn = self.db.begin_write()?;
        {
            let mut idx = wtxn.open_table(HASH_TO_INDEX)?;
            let mut dir = wtxn.open_table(INDEX_TO_OFFSET_LEN_HASH)?;
            for (i, (h, (off, len))) in self.staged.iter().enumerate() {
                if idx.get(&h)?.is_none() {
                    let mut encoded = [0u8; 12];
                    enc_index(&mut encoded, self.slab_id, *off, *len);
                    idx.insert(&h, &encoded)?;
                }
                let ord = self.entries_in_slab + i as u32;
                let mut rec = Vec::with_capacity(4 + 4 + 32);
                rec.extend_from_slice(&off.to_le_bytes());
                rec.extend_from_slice(&len.to_le_bytes());
                rec.extend_from_slice(h);
                dir.insert((self.slab_id, ord), &rec)?;
            }
            wtxn.open_table(SLABMETA)?
                .insert(self.slab_id as u64, self.cursor)?;
        }
        wtxn.commit()?;

        self.frontier = self.cursor;
        self.entries_in_slab += self.staged.len() as u32;
        self.staged.clear();
        self.staged_bytes = 0;
        self.get_index.clear();
        Ok(())
    }

    fn roll_slab(&mut self) -> Result<()> {
        if !self.staged.is_empty() {
            self.publish()?;
        }

        let new_id: u32;

        let w = self.db.begin_write()?;
        {
            let mut meta = w.open_table(META)?;
            let next = meta
                .get("next_slab_id")?
                .map(|g| g.value())
                .unwrap_or(self.slab_id as u64 + 1);
            new_id = next as u32;
            meta.insert("next_slab_id", next + 1)?;
            w.open_table(SLABMETA)?.insert(new_id as u64, 0)?;
        }
        w.commit()?;

        self.slab_id = new_id;
        self.slab_fd = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(self.current_slab_path())?;
        self.frontier = 0;
        self.cursor = 0;
        self.entries_in_slab = 0;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidateError {
    /// lengths.len() != expected_hashes.len()
    CountMismatch { lengths: usize, hashes: usize },
    /// Sum(lengths) != buf.len()
    LengthSumMismatch { sum: usize, buf: usize },
    /// Hash mismatch at chunk index
    HashMismatch {
        index: usize,
        expected: [u8; 32],
        actual: [u8; 32],
    },
}

impl fmt::Display for ValidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CountMismatch { lengths, hashes } => {
                write!(f, "count mismatch: {lengths} lengths vs {hashes} hashes")
            }
            Self::LengthSumMismatch { sum, buf } => {
                write!(f, "total length mismatch: sum({sum}) != buf({buf})")
            }
            Self::HashMismatch { index, .. } => write!(f, "hash mismatch at index {index}"),
        }
    }
}
impl Error for ValidateError {}

/// Validate that `buf` is the concatenation of `lengths` chunks whose
/// BLAKE3 hashes match `expected_hashes` (32-byte digests).
pub fn validate_data(
    buf: &[u8],
    lengths: &[usize],
    expected_hashes: &[[u8; 32]],
) -> Result<(), ValidateError> {
    // 1) Same number of lengths and hashes?
    if lengths.len() != expected_hashes.len() {
        return Err(ValidateError::CountMismatch {
            lengths: lengths.len(),
            hashes: expected_hashes.len(),
        });
    }

    // 2) Do the lengths cover the buffer exactly?
    let mut sum: usize = 0;
    for &len in lengths {
        // checked add to guard against overflow on pathological inputs
        sum = sum.checked_add(len).expect("length sum overflow");
    }
    if sum != buf.len() {
        return Err(ValidateError::LengthSumMismatch {
            sum,
            buf: buf.len(),
        });
    }

    // 3) Hash each chunk and compare
    let mut off = 0usize;
    for (i, (&len, expected)) in lengths.iter().zip(expected_hashes).enumerate() {
        let end = off + len; // safe: we already checked the total equals buf.len()
        let chunk = &buf[off..end];

        let actual = hash_256(chunk); // [u8; 32]
        if &actual != expected {
            return Err(ValidateError::HashMismatch {
                index: i,
                expected: *expected,
                actual,
            });
        }

        off = end;
    }

    Ok(())
}

#[cfg(test)]
mod test_data_store {
    use super::*;
    use crate::hash::hash_256_iov;
    use crate::iovec::to_iovec;
    use chrono::prelude::*;
    use rand::seq::SliceRandom;
    use size_display::Size;
    use std::collections::HashSet;
    use std::fs;
    use std::io;
    use std::path::Path;
    use std::sync::Mutex;

    use crate::archive::data::Store;
    use crate::archive::file_based::{Data, SLAB_SIZE_TARGET};
    use crate::create::{archive_create, CreateArgs};
    use crate::paths::*;
    use crate::slab::SlabFileBuilder;

    fn dir_size(path: &Path) -> io::Result<u64> {
        let mut size = 0;

        if path.is_dir() {
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let metadata = entry.metadata()?;

                if metadata.is_file() {
                    size += metadata.len();
                } else if metadata.is_dir() {
                    size += dir_size(&entry.path())?;
                }
            }
        } else if path.is_file() {
            size += fs::metadata(path)?.len();
        }

        Ok(size)
    }

    fn dedup_keep_order(vec: Vec<((u32, u32), u64)>) -> Vec<((u32, u32), u64)> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();

        for item in vec {
            if seen.insert(item.clone()) {
                result.push(item);
            }
        }

        result
    }

    fn shuffle_vec(mut vec: Vec<((u32, u32), u64)>) -> Vec<((u32, u32), u64)> {
        let mut rng = rand::thread_rng();
        vec.shuffle(&mut rng);
        vec
    }

    #[test]
    fn roundtrip_meta_in_db() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let mut store = DedupStore::open(tmp.path())?;
        store.flush_threshold_bytes = 32 * 1024;

        for idx in 0..2 {
            let mut data: Vec<u8> = vec![1u8; 4096];
            fastrand::Rng::new().fill(&mut data);
            let iov = to_iovec(&data);
            let h = hash_256_iov(&iov);

            let ((slab, returned_off), len) = store.data_add(h, &iov, iov.len() as u64)?;
            assert_eq!(slab, 0);
            assert_eq!(idx, returned_off);
            assert_eq!(data.len(), len as usize);
            store.publish()?;

            let (arc, start, end) = store.data_get(slab, idx, 1, None)?;
            assert_eq!(&arc[start..end], &data[..]);
        }
        Ok(())
    }

    #[test]
    fn more_than_one_entry() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let mut store = DedupStore::open(tmp.path())?;

        let mut buf = vec![0u8; 64 * 1024];
        fastrand::Rng::new().fill(&mut buf);

        let mid = 32 * 1024 as usize;
        let first_half = &buf[0..mid];
        let second_half = &buf[mid..];

        let f_iov = to_iovec(&first_half);
        let h = hash_256_iov(&f_iov);
        let ((slab, off), len) = store.data_add(h, &f_iov, f_iov.len() as u64)?;
        eprintln!("data_add {slab}, {off}, {len}");

        let s_iov = to_iovec(&second_half);
        let h = hash_256_iov(&s_iov);

        let ((slab2, off2), len2) = store.data_add(h, &s_iov, s_iov.len() as u64)?;
        eprintln!("data_add {slab2}, {off2}, {len2}");

        // Check before and after publish, to ensure we are handling entries in flight that haven't made it
        // to the db, and then after everything has been flushed to persistent storage.
        let (arc, start, end) = store.data_get(slab, off, 2, None)?;
        assert_eq!(&arc[start..end], &buf[..]);

        store.publish()?;

        let (arc, start, end) = store.data_get(slab, off, 2, None)?;
        assert_eq!(&arc[start..end], &buf[..]);

        Ok(())
    }

    #[test]
    fn test_partial_db() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let mut store = DedupStore::open(tmp.path())?;
        store.flush_threshold_bytes = 32 * 1024;

        let mut buf = vec![0u8; 64 * 1024];
        fastrand::Rng::new().fill(&mut buf);

        let mid = 32 * 1024 as usize;
        let first_half = &buf[0..mid];
        let second_half = &buf[mid..];

        let f_iov = to_iovec(&first_half);

        let h = hash_256_iov(&f_iov);
        let ((slab, off), len) = store.data_add(h, &f_iov, f_iov.len() as u64)?;
        eprintln!("data_add {slab}, {off}, {len}");

        let s_iov = to_iovec(&second_half);
        let h = hash_256_iov(&s_iov);

        let ((_slab2, _off2), _len2) = store.data_add(h, &s_iov, s_iov.len() as u64)?;
        eprintln!("data_add {slab}, {off}, {len}");

        // Check before and after publish, to ensure we are handling entries in flight that haven't made it
        // to the db, and then after everything has been flushed to persistent storage.
        let (arc, start, end) = store.data_get(slab, off, 2, Some((10, 20)))?;
        assert_eq!(&arc[start..end], &buf[10..20]);

        store.publish()?;

        let (arc, start, end) = store.data_get(slab, off, 2, Some((10, 20)))?;
        assert_eq!(&arc[start..end], &buf[10..20]);

        Ok(())
    }

    #[test]
    fn roundtrip_and_group_commit() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let mut store = DedupStore::open(tmp.path())?;
        // make it easy to trigger auto-publish quickly
        store.flush_threshold_bytes = 32 * 1024; // 32 KiB

        // add a block and confirm it dedups on second add without publishing
        let data = vec![7u8; 20 * 1024];
        let len = data.len();

        let iov = to_iovec(&data);
        let h = hash_256_iov(&iov);
        let ((slab, off), _len) = store.data_add(h, &iov, len as u64)?;
        let ((slab2, off2), _len2) = store.data_add(h, &iov, len as u64)?;

        assert_eq!((slab, off), (slab2, off2));

        // force publish and read back
        store.publish()?;
        let (arc, _, _) = store.data_get(slab, off, 1, None)?;
        assert_eq!(&arc[..], &data[..]);
        Ok(())
    }

    #[test]
    fn rollover_at_boundary() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let mut store = DedupStore::open(tmp.path())?;
        // tiny limit to trigger roll quickly in test
        store.max_slab_bytes = 64 * 1024; // 64 KiB
        store.flush_threshold_bytes = u64::MAX; // manual publish only

        let chunk = vec![0u8; 16 * 1024];

        let iov = to_iovec(&chunk);
        let h = hash_256_iov(&iov);

        let ((slab0, _), _) = store.data_add(h, &iov, iov.len() as u64)?;
        // write more to exceed slab size, should auto-publish+roll
        for i in 0..4 {
            let chunk = vec![i as u8; 16 * 1024];
            let iov = to_iovec(&chunk);
            let h = hash_256_iov(&iov);

            let _ = store.data_add(h, &iov, iov.len() as u64)?;
        }
        // ensure a publish happens so frontier == cursor and then roll
        store.publish()?;

        let chunk = vec![5 as u8; 16 * 1024];
        let iov = to_iovec(&chunk);
        let h = hash_256_iov(&iov);
        let ((slab1, _), _) = store.data_add(h, &iov, iov.len() as u64)?;
        assert!(slab1 >= slab0);
        Ok(())
    }

    const NUM_WRITES: usize = 89292;

    #[test]
    fn database_backend_speed() -> Result<()> {
        let tmp = tempfile::tempdir()?;

        let mut buf = vec![0u8; 32 * 1024];

        let total_read = NUM_WRITES * buf.len();
        let mut inserts: Vec<((u32, u32), u64)> = Vec::new();

        let mut start: DateTime<Utc> = Utc::now();
        {
            let mut store = DedupStore::open(tmp.path())?;
            for _ in 0..NUM_WRITES {
                fastrand::Rng::new().fill(&mut buf);
                let iov = to_iovec(&buf);
                let h = hash_256_iov(&iov);
                inserts.push(store.data_add(h, &iov, iov.len() as u64)?);
            }
            store.publish()?;
        }
        let mut end: DateTime<Utc> = Utc::now();
        let elapsed = end - start;
        let elapsed = elapsed.num_milliseconds() as f64 / 1000.0;
        eprintln!(
            "database backend speed: {:.2}/s",
            Size((total_read as f64 / elapsed) as u64)
        );
        let total_bytes = dir_size(tmp.path())?;
        eprintln!("total bytes on disk = {total_bytes}");

        let total_inserts = inserts.len();

        // Lets test read speed
        let dedup = dedup_keep_order(inserts);

        eprintln!("The number of dups found = {}", total_inserts - dedup.len());
        {
            let mut store = DedupStore::open(tmp.path())?;
            start = Utc::now();
            for ((slab_id, slab_offset), _len) in &dedup {
                let (_buffer, _start, _len) = store.data_get(*slab_id, *slab_offset, 1, None)?;
            }
        }
        end = Utc::now();

        let elapsed = end - start;
        let elapsed_seconds = elapsed.num_milliseconds() as f64 / 1000.0;
        eprintln!(
            "database backend read speed sequential: {:.2}/s",
            Size((total_read as f64 / elapsed_seconds) as u64)
        );

        let random = shuffle_vec(dedup);
        {
            let mut store = DedupStore::open(tmp.path())?;
            start = Utc::now();
            for ((slab_id, slab_offset), _len) in random {
                let (_buffer, _start, _len) = store.data_get(slab_id, slab_offset, 1, None)?;
            }
            end = Utc::now();
        }

        let elapsed = end - start;
        let elapsed_seconds = elapsed.num_milliseconds() as f64 / 1000.0;
        eprintln!(
            "database backend read speed random: {:.2}/s",
            Size((total_read as f64 / elapsed_seconds) as u64)
        );

        Ok(())
    }

    fn open_blk_archive(args: &CreateArgs) -> Result<Data> {
        let data_file = SlabFileBuilder::open(data_path())
            .write(true)
            .queue_depth(128)
            .build()
            .context("couldn't open data slab file")?;

        let hashes_inner = SlabFileBuilder::open(hashes_path())
            .write(true)
            .queue_depth(128)
            .build()
            .context("couldn't open hashes file")?;

        let hashes_file = Arc::new(Mutex::new(hashes_inner));

        let hashes_per_slab = std::cmp::max(SLAB_SIZE_TARGET / args.block_size, 1);
        let slab_capacity = ((args.hash_cache_size_meg * 1024 * 1024)
            / std::mem::size_of::<Hash256>())
            / hashes_per_slab;

        Data::new(Box::new(data_file), hashes_file, slab_capacity)
    }

    #[test]
    fn zblk_archive_backend_speed() -> Result<()> {
        let tmp = tempfile::tempdir()?;

        let mut start: DateTime<Utc>;

        let path_ref = tmp.path();
        let path_buf: PathBuf = path_ref.to_path_buf();

        let args = CreateArgs {
            dir: path_buf,
            data_compression: false,
            block_size: 4096,
            hash_cache_size_meg: 1024,
            data_cache_size_meg: 1024,
        };

        archive_create(&args)?;

        let mut buf = vec![0u8; 32 * 1024];

        let mut inserts: Vec<((u32, u32), u64)> = Vec::new();

        {
            let mut ad = open_blk_archive(&args)?;
            start = Utc::now();
            for _ in 0..NUM_WRITES {
                fastrand::Rng::new().fill(&mut buf);
                {
                    let mut iv = IoVec::new();
                    iv.push(&buf[..]);
                    let h = hash_256_iov(&iv);
                    inserts.push(ad.data_add(h, &iv, buf.len() as u64)?);
                }
            }
        }

        let total_read = NUM_WRITES * buf.len();
        let mut end: DateTime<Utc> = Utc::now();
        let elapsed = end - start;
        let elapsed_seconds = elapsed.num_milliseconds() as f64 / 1000.0;
        eprintln!(
            "blk-archive backend write speed: {:.2}/s",
            Size((total_read as f64 / elapsed_seconds) as u64)
        );
        let total_bytes = dir_size(tmp.path())?;
        eprintln!("total bytes on disk = {total_bytes}");

        // Lets test read speed
        let total_inserts = inserts.len();
        let dedup = dedup_keep_order(inserts);
        eprintln!("The number of dups found = {}", total_inserts - dedup.len());

        /*
        for d in &dedup {
            eprintln!("{:?}", d);
        }
        */

        {
            let mut ad = open_blk_archive(&args)?;
            start = Utc::now();
            for ((slab_id, slab_offset), _len) in &dedup {
                let (_buffer, _start, _len) = ad.data_get(*slab_id, *slab_offset, 1, None)?;
            }
        }
        end = Utc::now();

        let elapsed = end - start;
        let elapsed_seconds = elapsed.num_milliseconds() as f64 / 1000.0;
        eprintln!(
            "blk-archive backend read speed sequential: {:.2}/s",
            Size((total_read as f64 / elapsed_seconds) as u64)
        );

        // random read speed
        if true {
            let random = shuffle_vec(dedup);
            {
                let mut ad = open_blk_archive(&args)?;
                start = Utc::now();
                for ((slab_id, slab_offset), _len) in random {
                    let (_buffer, _start, _len) = ad.data_get(slab_id, slab_offset, 1, None)?;
                }
            }
            end = Utc::now();

            let elapsed = end - start;
            let elapsed_seconds = elapsed.num_milliseconds() as f64 / 1000.0;
            eprintln!(
                "blk-archive backend read speed random: {:.2}/s",
                Size((total_read as f64 / elapsed_seconds) as u64)
            );
        } else {
            eprintln!("skipping random read test...");
        }

        Ok(())
    }

    #[test]
    fn test_partial_existing() -> Result<()> {
        let tmp = tempfile::tempdir()?;

        let path_ref = tmp.path();
        let path_buf: PathBuf = path_ref.to_path_buf();

        let args = CreateArgs {
            dir: path_buf,
            data_compression: false,
            block_size: 4096,
            hash_cache_size_meg: 1024,
            data_cache_size_meg: 1024,
        };

        archive_create(&args)?;

        let mut buf = vec![0u8; 64 * 1024];
        fastrand::Rng::new().fill(&mut buf);

        let mid = 32 * 1024 as usize;
        let first_half = &buf[0..mid];
        let second_half = &buf[mid..];
        let returned_data: (Arc<Vec<u8>>, usize, usize);

        {
            let mut ad = open_blk_archive(&args)?;

            let mut iv = IoVec::new();
            iv.push(&first_half);
            let h = hash_256_iov(&iv);
            let ((slab, off), len) = ad.data_add(h, &iv, first_half.len() as u64)?;
            eprintln!("data_add 1 {slab}, {off}, {len}");

            let mut iv = IoVec::new();
            iv.push(&second_half);
            let h = hash_256_iov(&iv);

            let ((slab2, off2), len2) = ad.data_add(h, &iv, second_half.len() as u64)?;
            eprintln!("data_add 2 {slab2}, {off2}, {len2}");

            ad.flush()?;

            // We have a race condition in droping the backend and having the write treads finish.
            std::thread::sleep(std::time::Duration::from_millis(5000));

            returned_data = ad.data_get(slab, off, 2, Some((10, 20)))?;
        }

        let (arc, start, end) = (returned_data.0, returned_data.1, returned_data.2);

        assert_eq!(&arc[start..end], &buf[10..20]);
        Ok(())
    }
}

pub fn main() {}
