use anyhow::{anyhow, Context, Result};
use crc::Crc;
use memmap2::Mmap;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const FOOT_MAGIC_CRC64: u64 = 0x7C0A_10A3_3751_5620; // "seal w/ crc64" marker

const SLAB_OFFSET_CRC: Crc<u64> = Crc::<u64>::new(&crc::CRC_64_ECMA_182);
const SLAB_OFFSET_FOOTER_SIZE: u64 = 24;

// If the archive resides on FAT32, a single file can be at most 4 GiB − 1 byte (2^32 − 1).
// With a 24-byte header and 8 bytes per slab index, that file can store
// (((2^32 − 1) − 24) / 8) = 536,870,908 slab indices.
// At ~4 MiB per slab, that corresponds to ~2 PiB of addressable data in a single archive.
// For large offset files (>= 33,554,432 offsets, ~256 MiB), we use memory-mapped I/O.
// For smaller files, we keep offsets in RAM for simplicity and better performance.

const MMAP_THRESHOLD: usize = 33_554_432; // ~256 MiB when loaded into RAM (8 bytes per offset)

pub struct SlabOffsets<'a> {
    // Backing file path (for writes)
    path: PathBuf,

    // Existing on-disk offsets - either mmapped or loaded into RAM
    map: Option<Mmap>,
    map_file: Option<std::fs::File>, // Keep file handle alive for mmap
    existing_offsets: Vec<u64>,      // RAM copy for small files
    existing_count: usize,           // number of existing offsets

    // Newly appended offsets (not yet written to disk)
    new_offsets: Vec<u64>,

    // Rolling CRC64 over data region:
    //   after open: seeded with CRC of existing region (from footer)
    //   on append: update with LE bytes of new u64s
    //   on seal: finalize -> CRC of (existing || new)
    digest: crc::Digest<'a, u64>,
}

impl<'a> std::fmt::Debug for SlabOffsets<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let alt = f.alternate();

        const PREVIEW: usize = 8;
        let existing_preview = &self.existing_offsets[..self.existing_offsets.len().min(PREVIEW)];
        let new_preview = &self.new_offsets[..self.new_offsets.len().min(PREVIEW)];

        let map_present = self.map.is_some();
        let map_len = self.map.as_ref().map(|m| m.len()).unwrap_or(0);
        let map_file_present = self.map_file.is_some();

        let crc_now = self.digest.clone().finalize(); // need to clone so we don't disturb running calculation

        let mut ds = f.debug_struct("SlabOffsets");
        ds.field("path", &self.path)
            .field("existing_count", &self.existing_count)
            .field("map_present", &map_present)
            .field("map_len", &map_len)
            .field("map_file_present", &map_file_present)
            .field("crc64", &format_args!("0x{:016x}", crc_now));

        if alt {
            ds.field("existing_offsets", &self.existing_offsets)
                .field("new_offsets", &self.new_offsets);
        } else {
            ds.field("existing_offsets_len", &self.existing_offsets.len())
                .field("existing_offsets_preview", &existing_preview)
                .field("new_offsets_len", &self.new_offsets.len())
                .field("new_offsets_preview", &new_preview);
        }

        ds.finish()
    }
}

impl SlabOffsets<'_> {
    /// Open an offsets file. Valid states:
    /// - size == 0: empty, no seal; existing_count=0, crc64 seeded to initial.
    /// - sealed: [u64..]*  | FOOT_MAGIC | COUNT | CRC64
    ///
    ///  Note: We mmap only the data region and seed CRC from footer (no re-scan).
    pub fn open<P: AsRef<Path>>(p: P, truncate: bool) -> Result<Self> {
        let path = p.as_ref().to_path_buf();
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true) // create if missing
            .truncate(truncate)
            .open(&path)
            .with_context(|| format!("open {:?}", path))?;

        let len = f.metadata()?.len();

        // Only if we were asked to truncate will be return a new instance, else we bail
        if len == 0 && truncate {
            return Ok(Self {
                path,
                map: None,
                map_file: None,
                existing_offsets: Vec::new(),
                existing_count: 0,
                new_offsets: Vec::new(),
                digest: SLAB_OFFSET_CRC.digest(),
            });
        }

        if len < SLAB_OFFSET_FOOTER_SIZE {
            return Err(anyhow!("offset file too small (< 24 B) to contain footer"));
        }

        let pathbuf: PathBuf = p.as_ref().to_path_buf();

        // Read last 24 bytes: FOOT_MAGIC | COUNT | CRC64
        let mut footer = [0u8; 24];
        (&f).seek(SeekFrom::End(-(SLAB_OFFSET_FOOTER_SIZE as i64)))
            .with_context(|| {
                format!(
                    "SlabOffsets:seek to end -24 on slab index footer for file {:?}",
                    pathbuf
                )
            })?;
        (&f).read_exact(&mut footer).with_context(|| {
            format!(
                "SlabOffsets:read_exact on slab index footer for file {:?}",
                pathbuf
            )
        })?;

        let magic = u64::from_le_bytes(footer[0..8].try_into().unwrap());
        let count = u64::from_le_bytes(footer[8..16].try_into().unwrap());
        let crc = u64::from_le_bytes(footer[16..24].try_into().unwrap());

        // Verify magic
        if magic != FOOT_MAGIC_CRC64 {
            return Err(anyhow!(
                "SlabOffsets::unrecognized footer magic 0x{magic:016x}"
            ));
        }

        let data_end = len - SLAB_OFFSET_FOOTER_SIZE;
        let crc_seed = crc;

        let required = count
            .checked_mul(8)
            .ok_or_else(|| anyhow!("SlabOffsets::COUNT overflow"))?;
        if required != data_end {
            return Err(anyhow!(
                "SlabOffsets:: footer COUNT mismatch: expected data {} B, found {} B before footer",
                required,
                data_end
            ));
        }

        // Seed rolling CRC with prior CRC so we can continue with new bytes only.
        let digest = SLAB_OFFSET_CRC.digest_with_initial(crc_seed);

        // Use mmap for large files, RAM for small files
        let (map, map_file, existing_offsets) = if count as usize >= MMAP_THRESHOLD {
            // Large file: use mmap
            let mmap = unsafe { Mmap::map(&f)? };
            (Some(mmap), Some(f), Vec::new())
        } else {
            // Small file: load into RAM
            let mut offsets = Vec::with_capacity(count as usize);
            (&f).seek(SeekFrom::Start(0)).with_context(|| {
                format!("SlabOffsets:: Failed to seek to start of {:?}", pathbuf)
            })?;
            for i in 0..count {
                let mut buf = [0u8; 8];
                (&f).read_exact(&mut buf).with_context(|| {
                    format!("SlabOffsets:Failed to read offset {} from {:?}", i, pathbuf)
                })?;
                offsets.push(u64::from_le_bytes(buf));
            }
            drop(f);
            (None, None, offsets)
        };

        Ok(Self {
            path,
            map,
            map_file,
            existing_offsets,
            existing_count: count as usize,
            new_offsets: Vec::new(),
            digest,
        })
    }

    /// Number of offsets currently visible (existing + new, in memory).
    #[inline]
    pub fn len(&self) -> usize {
        self.existing_count + self.new_offsets.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Random access by index. Uses mmap or RAM for existing, Vec for new.
    pub fn get_slab_offset(&self, idx: usize) -> Option<u64> {
        if idx < self.existing_count {
            // Check RAM first
            if !self.existing_offsets.is_empty() {
                return self.existing_offsets.get(idx).copied();
            }
            // Fall back to mmap
            let start = idx * 8;
            let end = start + 8;
            let map = self.map.as_ref()?;
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&map[start..end]);
            Some(u64::from_le_bytes(arr))
        } else {
            let j = idx - self.existing_count;
            self.new_offsets.get(j).copied()
        }
    }

    /// Append a new offset (kept only in memory until `write_offset_file`).
    /// Updates rolling CRC64 so we won’t need to re-scan when sealing.
    pub fn append(&mut self, off: u64) {
        self.new_offsets.push(off);
        self.digest.update(&off.to_le_bytes());
    }

    /// Write combined (existing + new entries) to disk:
    ///
    ///  Close file handle and mmap.
    ///  Seek to end, back up footer size, write new entries and
    ///  - write EOF seal: FOOT_MAGIC | COUNT | CRC64
    ///
    ///     If `sync` is true, fsync the file.
    ///
    /// Reopen file and either mmap or load into RAM based on size
    pub fn write_offset_file(&mut self, sync: bool) -> Result<()> {
        let total_count = self.len();

        if let Some(map) = self.map.take() {
            drop(map);
        }
        if let Some(file) = self.map_file.take() {
            drop(file);
        }

        // Re-open RW, backup a footer size, write over the footer with new data and add new footer
        // we can do this because if the file gets partially written we can re-generate the entire
        // file from the slab
        let mut w = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)
            .with_context(|| format!("open for write {:?}", self.path))?;

        // If we had previous existing bytes we will seek to just before the footer
        if self.existing_count > 0 {
            w.seek(SeekFrom::End(-24))?;
        }

        // Stream write new entries
        for &o in &self.new_offsets {
            w.write_all(&o.to_le_bytes())?;
        }

        // Finalize CRC (over existing||new).
        let final_crc = self.digest.clone().finalize();

        // EOF seal
        w.write_all(&FOOT_MAGIC_CRC64.to_le_bytes())?;
        w.write_all(&(total_count as u64).to_le_bytes())?;
        w.write_all(&final_crc.to_le_bytes())?;

        if sync {
            w.sync_all()?;
        }

        // Explicitly close the write handle before reopening
        drop(w);

        // Determine whether to use mmap or RAM based on size
        if total_count >= MMAP_THRESHOLD {
            // Large file: use mmap
            let f_ro = OpenOptions::new().read(true).open(&self.path)?;
            let mm = unsafe { Mmap::map(&f_ro)? };
            self.map = Some(mm);
            self.map_file = Some(f_ro);
            self.existing_offsets.clear();
        } else {
            // Small file: load into RAM
            let f_ro = OpenOptions::new()
                .read(true)
                .open(&self.path)
                .with_context(|| format!("Failed to open {:?} for reading", self.path))?;
            let mut offsets = Vec::with_capacity(total_count);
            (&f_ro)
                .seek(SeekFrom::Start(0))
                .with_context(|| format!("Failed to seek to start of {:?}", self.path))?;
            for i in 0..total_count {
                let mut buf = [0u8; 8];
                (&f_ro)
                    .read_exact(&mut buf)
                    .with_context(|| format!("Failed to read offset {} from {:?}", i, self.path))?;
                offsets.push(u64::from_le_bytes(buf));
            }
            drop(f_ro);
            self.map = None;
            self.map_file = None;
            self.existing_offsets = offsets;
        }

        self.existing_count = total_count;
        self.new_offsets.clear();
        // Re-seed crc64 with the new CRC so further appends can continue without re-scan.
        self.digest = SLAB_OFFSET_CRC.digest_with_initial(final_crc);

        Ok(())
    }
}

impl Drop for SlabOffsets<'_> {
    fn drop(&mut self) {
        // Explicitly drop the memory map and file handle
        // The Mmap will be automatically unmapped when dropped,
        // but we make it explicit here for clarity
        if let Some(map) = self.map.take() {
            drop(map);
        }
        if let Some(file) = self.map_file.take() {
            drop(file);
        }
    }
}

/// Validate a slab-offsets file.
/// Returns: (is_valid, count, error_context)
///
/// - If `verify_crc` is false: only structural checks are performed.
/// - If `verify_crc` is true: structural checks + CRC64 over [0 .. len-24).
/// - Empty file is considered a valid empty table: (true, 0, None).
pub fn validate_slab_offsets_file<P: AsRef<Path>>(
    p: P,
    verify_crc: bool,
) -> (bool, u32, Option<String>) {
    let path = p.as_ref();

    // Open read-only without creating.
    let f = match OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
            return (false, 0, Some(format!("open {:?}: {}", path, e)));
        }
    };

    let len = match f.metadata() {
        Ok(md) => md.len(),
        Err(e) => {
            return (false, 0, Some(format!("metadata {:?}: {}", path, e)));
        }
    };

    // Empty file is considered a valid empty table.
    if len == 0 {
        return (true, 0, None);
    }

    // Must be at least big enough to hold FOOT_MAGIC + COUNT + CRC64.
    if len < 24 {
        return (
            false,
            0,
            Some(format!(
                "file too small (<24 bytes): len={} for {:?}",
                len, path
            )),
        );
    }

    // Read 24-byte footer.
    let mut f = f; // make mutable
    if let Err(e) = f.seek(SeekFrom::End(-24)) {
        return (false, 0, Some(format!("seek footer {:?}: {}", path, e)));
    }
    let mut tail = [0u8; 24];
    if let Err(e) = f.read_exact(&mut tail) {
        return (false, 0, Some(format!("read footer {:?}: {}", path, e)));
    }

    let magic = match <[u8; 8]>::try_from(&tail[0..8]) {
        Ok(a) => u64::from_le_bytes(a),
        Err(_) => return (false, 0, Some("footer magic slice parse failed".into())),
    };
    let count = match <[u8; 8]>::try_from(&tail[8..16]) {
        Ok(a) => u64::from_le_bytes(a),
        Err(_) => return (false, 0, Some("footer count slice parse failed".into())),
    };
    let crc_stored = match <[u8; 8]>::try_from(&tail[16..24]) {
        Ok(a) => u64::from_le_bytes(a),
        Err(_) => return (false, 0, Some("footer CRC slice parse failed".into())),
    };

    if magic != FOOT_MAGIC_CRC64 {
        return (
            false,
            0,
            Some(format!("bad footer magic: got=0x{:016x}", magic)),
        );
    }

    // Data region length must equal count * 8 bytes.
    let data_end = len - 24;
    let required = match count.checked_mul(8) {
        Some(v) => v,
        None => return (false, 0, Some("count * 8 overflow".into())),
    };
    if required != data_end {
        return (
            false,
            0,
            Some(format!(
                "size/count mismatch: required={} (count*8) != data_end={} (len-24)",
                required, data_end
            )),
        );
    }

    if !verify_crc {
        // Structural checks passed.
        return (true, count as u32, None);
    }

    // Recompute CRC64 over the data region [0 .. data_end).
    let mut crc = SLAB_OFFSET_CRC.digest();
    let mut buf = vec![0u8; 1 << 20]; // 1 MiB buffer
    if let Err(e) = f.seek(SeekFrom::Start(0)) {
        return (
            false,
            0,
            Some(format!("seek start for CRC {:?}: {}", path, e)),
        );
    }
    let mut remaining = data_end;
    while remaining > 0 {
        let to_read = std::cmp::min(remaining as usize, buf.len());
        if let Err(e) = f.read_exact(&mut buf[..to_read]) {
            return (
                false,
                0,
                Some(format!(
                    "read {} bytes for CRC {:?} failed: {} (remaining={})",
                    to_read, path, e, remaining
                )),
            );
        }
        crc.update(&buf[..to_read]);
        remaining -= to_read as u64;
    }
    let crc_computed = crc.finalize();

    if crc_computed == crc_stored {
        (true, count as u32, None)
    } else {
        (
            false,
            0,
            Some(format!(
                "CRC mismatch: computed=0x{:016x}, stored=0x{:016x}",
                crc_computed, crc_stored
            )),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::TempDir;

    #[test]
    fn test_create_empty_offsets() {
        let temp_dir = TempDir::new().unwrap();
        let offsets_path = temp_dir.path().join("test.offsets");

        let offsets = SlabOffsets::open(&offsets_path, true).unwrap();

        assert_eq!(offsets.len(), 0);
        assert!(offsets.is_empty());
    }

    #[test]
    fn test_append_and_get_offsets() {
        let temp_dir = TempDir::new().unwrap();
        let offsets_path = temp_dir.path().join("test.offsets");

        let mut offsets = SlabOffsets::open(&offsets_path, true).unwrap();

        // Append some offsets
        offsets.append(100);
        offsets.append(200);
        offsets.append(300);

        assert_eq!(offsets.len(), 3);
        assert!(!offsets.is_empty());

        // Get offsets back
        assert_eq!(offsets.get_slab_offset(0), Some(100));
        assert_eq!(offsets.get_slab_offset(1), Some(200));
        assert_eq!(offsets.get_slab_offset(2), Some(300));
        assert_eq!(offsets.get_slab_offset(3), None);
    }

    #[test]
    fn test_write_and_reload() {
        let temp_dir = TempDir::new().unwrap();
        let offsets_path = temp_dir.path().join("test.offsets");

        // Create and write offsets
        {
            let mut offsets = SlabOffsets::open(&offsets_path, true).unwrap();
            offsets.append(1024);
            offsets.append(2048);
            offsets.append(4096);
            offsets.write_offset_file(true).unwrap();
        }

        // Reload and verify
        {
            let offsets = SlabOffsets::open(&offsets_path, false).unwrap();
            assert_eq!(offsets.len(), 3);
            assert_eq!(offsets.get_slab_offset(0), Some(1024));
            assert_eq!(offsets.get_slab_offset(1), Some(2048));
            assert_eq!(offsets.get_slab_offset(2), Some(4096));
        }
    }

    #[test]
    fn test_append_after_reload() {
        let temp_dir = TempDir::new().unwrap();
        let offsets_path = temp_dir.path().join("test.offsets");

        // Create initial offsets
        {
            let mut offsets = SlabOffsets::open(&offsets_path, true).unwrap();
            offsets.append(100);
            offsets.append(200);
            offsets.write_offset_file(true).unwrap();
        }

        // Reload and append more
        {
            let mut offsets = SlabOffsets::open(&offsets_path, false).unwrap();
            assert_eq!(offsets.len(), 2);

            offsets.append(300);
            offsets.append(400);
            assert_eq!(offsets.len(), 4);

            offsets.write_offset_file(true).unwrap();
        }

        // Verify final state
        {
            let offsets = SlabOffsets::open(&offsets_path, false).unwrap();
            assert_eq!(offsets.len(), 4);
            assert_eq!(offsets.get_slab_offset(0), Some(100));
            assert_eq!(offsets.get_slab_offset(1), Some(200));
            assert_eq!(offsets.get_slab_offset(2), Some(300));
            assert_eq!(offsets.get_slab_offset(3), Some(400));
        }
    }

    #[test]
    fn test_truncate_recreates_file() {
        let temp_dir = TempDir::new().unwrap();
        let offsets_path = temp_dir.path().join("test.offsets");

        // Create initial offsets
        {
            let mut offsets = SlabOffsets::open(&offsets_path, true).unwrap();
            offsets.append(100);
            offsets.append(200);
            offsets.write_offset_file(true).unwrap();
        }

        // Open with truncate
        {
            let offsets = SlabOffsets::open(&offsets_path, true).unwrap();
            assert_eq!(offsets.len(), 0);
            assert!(offsets.is_empty());
        }
    }

    #[test]
    fn test_multiple_appends_before_write() {
        let temp_dir = TempDir::new().unwrap();
        let offsets_path = temp_dir.path().join("test.offsets");

        let mut offsets = SlabOffsets::open(&offsets_path, true).unwrap();

        // Append many offsets without writing
        for i in 0..100 {
            offsets.append(i * 1024);
        }

        assert_eq!(offsets.len(), 100);

        // Verify all offsets are accessible
        for i in 0..100 {
            assert_eq!(offsets.get_slab_offset(i), Some(i as u64 * 1024));
        }

        // Write and reload
        offsets.write_offset_file(true).unwrap();
        drop(offsets);

        let offsets = SlabOffsets::open(&offsets_path, false).unwrap();
        assert_eq!(offsets.len(), 100);
        for i in 0..100 {
            assert_eq!(offsets.get_slab_offset(i), Some(i as u64 * 1024));
        }
    }

    #[test]
    fn test_checksum_validation() {
        let temp_dir = TempDir::new().unwrap();
        let offsets_path = temp_dir.path().join("test.offsets");

        // Create and write valid offsets
        {
            let mut offsets = SlabOffsets::open(&offsets_path, true).unwrap();
            offsets.append(1000);
            offsets.append(2000);
            offsets.write_offset_file(true).unwrap();
        }

        // Corrupt the file by changing a byte in the data section
        {
            use std::fs::OpenOptions;
            use std::io::{Seek, SeekFrom, Write};

            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&offsets_path)
                .unwrap();

            // Corrupt some data
            file.seek(SeekFrom::Start(0)).unwrap();
            file.write_all(&[0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
        }

        // Try to open - should pass as we don't check crc on open
        let result = SlabOffsets::open(&offsets_path, false);
        assert!(
            result.is_ok(),
            "Shouldn't fail as we don't check crc on open"
        );

        drop(result.unwrap());

        let verifies = validate_slab_offsets_file(offsets_path, true);
        // This should return false
        assert_ne!(verifies.0, true);
        assert_eq!(verifies.1, 0);
        assert!(verifies.2.is_some());
    }

    /// Compare two files byte-for-byte.
    /// Returns Ok(true) if identical, Ok(false) if differ, Err(_) on I/O error.
    fn files_are_identical<P: AsRef<std::path::Path>>(a: P, b: P) -> Result<bool> {
        let mut file_a = File::open(&a).with_context(|| format!("open {:?}", a.as_ref()))?;
        let mut file_b = File::open(&b).with_context(|| format!("open {:?}", b.as_ref()))?;

        let meta_a = file_a.metadata()?;
        let meta_b = file_b.metadata()?;

        // Quick size check before reading
        if meta_a.len() != meta_b.len() {
            return Ok(false);
        }

        let mut buf_a = vec![0u8; meta_a.len() as usize];
        let mut buf_b = vec![0u8; meta_a.len() as usize];

        let na = file_a.read_exact(&mut buf_a)?;
        let nb = file_b.read_exact(&mut buf_b)?;

        // Check read lengths (this should never be different)
        if na != nb {
            return Ok(false);
        }

        if buf_a != buf_b {
            return Ok(false);
        }

        return Ok(true);
    }

    #[test]
    fn test_checksum_continuation() {
        let temp_dir = TempDir::new().unwrap();
        let offsets_path_reference = temp_dir.path().join("test.offsets.reference");
        let offsets_path_expected_match = temp_dir.path().join("test.offsets.match");

        // Create and write valid offsets
        {
            let mut offsets = SlabOffsets::open(&offsets_path_reference, true).unwrap();
            offsets.append(1000);
            offsets.append(2000);
            offsets.append(3000);
            offsets.append(4000);
            offsets.write_offset_file(true).unwrap();
        }

        {
            let mut offsets = SlabOffsets::open(&offsets_path_expected_match, true).unwrap();
            offsets.append(1000);
            offsets.append(2000);
            offsets.write_offset_file(false).unwrap();
            offsets.append(3000);
            offsets.write_offset_file(true).unwrap();
            offsets.append(4000);
            offsets.write_offset_file(true).unwrap();
        }

        // Now compare the two files
        let result =
            files_are_identical(offsets_path_reference, offsets_path_expected_match).unwrap();
        assert!(result);
    }
}
