//! Recovery and crash-safety for blk-archive
//!
//! This module provides crash-safe checkpoint/recovery functionality to protect
//! against data corruption when pack operations are interrupted by panics or signals.

use anyhow::{anyhow, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};

use crate::archive;
use crate::paths;
use crate::slab;

/// Extension trait for syncing the parent directory of a path
///
/// This trait provides a method to sync the parent directory to ensure
/// directory metadata changes (like file creation or removal) are persisted.
pub trait SyncParentExt {
    /// Sync the parent directory of this path
    ///
    /// The path must be a directory, and it must have a parent directory.
    /// This method will open the parent directory read-only and call sync_all on it.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path does not exist or is not a directory
    /// - The path has no parent directory
    /// - The parent directory cannot be opened
    /// - The sync operation fails
    fn sync_parent(&self) -> io::Result<()>;
}

impl SyncParentExt for Path {
    fn sync_parent(&self) -> io::Result<()> {
        // Ensure the path has a parent directory
        let parent = self.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("sync_parent: path has no parent directory: {:?}", self),
            )
        })?;

        // Open the parent directory read-only and sync it
        let dir = File::open(parent)?;
        dir.sync_all()?;
        Ok(())
    }
}

/// Magic number to identify recovery checkpoint files
const RECOVERY_MAGIC: u64 = 0x52435652594d4147; // "RCVRYMA" + "G"

/// Version for recovery file format
const RECOVERY_VERSION: u32 = 2;

/// Recovery checkpoint file format:
///
/// ```text
/// +--------------------------+
/// | Magic (8 bytes)          |  0x52435652594d4147 ("RCVRYMA" + "G")
/// +--------------------------+
/// | Version (4 bytes)        |  1
/// +--------------------------+
/// | Checksum (8 bytes)       |  Blake2b-64 hash of data section
/// +--------------------------+
/// | Data (36 bytes)          |  All checkpoint fields (little-endian):
/// |   hashes_file_size (8)   |  Size of hashes slab file
/// |   data_slab_file_id (4)  |  Current data slab file ID
/// |   data_slab_file_size (8)|  Size of current data slab file
/// |   stream_metadata_size (8)| Size of stream metadata slab file
/// |   stream_mappings_size (8)| Size of stream mappings slab file
/// +--------------------------+
/// Total: 56 bytes (8 + 4 + 8 + 36)
/// ```
///
/// Recovery checkpoint structure containing all sync point information
///
/// This structure tracks the last known good state of all archive files.
/// On startup after a crash, all files are truncated to these sizes to
/// ensure consistency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCheckpoint {
    /// Last sync'd size of the hashes file (in bytes)
    pub hashes_file_size: u64,

    /// Data slab file ID currently being written to (for MultiFile)
    pub data_slab_file_id: u32,

    /// Last sync'd size of the current data slab file (in bytes)
    pub data_slab_file_size: u64,

    /// Last sync'd size of the stream metadata file (in bytes)
    pub stream_metadata_size: u64,

    /// Last sync'd size of the stream mappings file (in bytes)
    pub stream_mappings_size: u64,
}

impl RecoveryCheckpoint {
    /// Create a new recovery checkpoint with all fields set to zero
    pub fn new() -> Self {
        Self {
            hashes_file_size: 0,
            data_slab_file_id: 0,
            data_slab_file_size: 0,
            stream_metadata_size: 0,
            stream_mappings_size: 0,
        }
    }

    /// Write checkpoint to a file atomically
    ///
    /// This implements the atomic checkpoint workflow:
    /// 1. Write to temporary file
    /// 2. Sync the temporary file
    /// 3. Sync the parent directory
    /// 4. Rename to final location (atomic operation on POSIX)
    ///
    /// This ensures we either have the old checkpoint or the new checkpoint,
    /// never a partial/corrupted one.
    pub fn write<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();
        let tmp_path = path.with_extension("tmp");

        // Write to temporary file
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .with_context(|| format!("Failed to create temporary recovery file: {:?}", tmp_path))?;

        // Write header
        file.write_u64::<LittleEndian>(RECOVERY_MAGIC)?;
        file.write_u32::<LittleEndian>(RECOVERY_VERSION)?;

        // Write checkpoint data (we'll compute checksum over this)
        let mut data_buf = Vec::new();
        data_buf.write_u64::<LittleEndian>(self.hashes_file_size)?;
        data_buf.write_u32::<LittleEndian>(self.data_slab_file_id)?;
        data_buf.write_u64::<LittleEndian>(self.data_slab_file_size)?;
        data_buf.write_u64::<LittleEndian>(self.stream_metadata_size)?;
        data_buf.write_u64::<LittleEndian>(self.stream_mappings_size)?;

        // Compute checksum over the data
        let checksum = crate::hash::hash_64(&data_buf);

        // Write checksum first, then data
        file.write_all(&checksum)?;
        file.write_all(&data_buf)?;

        // Ensure all data is written to disk
        file.sync_all()?;
        drop(file);

        // Sync the parent directory to ensure the temp file is visible
        path.sync_parent()?;

        // Atomically replace the old checkpoint file (POSIX atomic operation)
        std::fs::rename(&tmp_path, path)
            .with_context(|| format!("Failed to rename recovery file: {:?}", tmp_path))?;

        // Sync parent directory again to ensure rename is visible
        path.sync_parent()?;
        Ok(())
    }

    /// Read checkpoint from a file
    pub fn read<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let file = File::open(path)
            .with_context(|| format!("Failed to open recovery file: {:?}", path))?;

        // Use buffered reader for efficient small reads
        let mut file = BufReader::new(file);

        // Read and verify header
        let magic = file
            .read_u64::<LittleEndian>()
            .context("Failed to read magic number")?;
        if magic != RECOVERY_MAGIC {
            return Err(anyhow::anyhow!(
                "Invalid recovery file magic: expected 0x{:016x}, got 0x{:016x}",
                RECOVERY_MAGIC,
                magic
            ));
        }

        let version = file
            .read_u32::<LittleEndian>()
            .context("Failed to read version")?;
        if version != RECOVERY_VERSION {
            return Err(anyhow::anyhow!(
                "Unsupported recovery file version: expected {}, got {}",
                RECOVERY_VERSION,
                version
            ));
        }

        // Read checksum
        let mut stored_checksum = [0u8; 8];
        file.read_exact(&mut stored_checksum)
            .context("Failed to read checksum")?;

        // Read checkpoint data
        let mut data_buf = Vec::new();
        file.read_to_end(&mut data_buf)
            .context("Failed to read checkpoint data")?;

        // Verify checksum
        let computed_checksum = crate::hash::hash_64(&data_buf);
        if stored_checksum != computed_checksum.as_slice() {
            return Err(anyhow::anyhow!(
                "Checkpoint checksum mismatch - file may be corrupted or suffered from bit rot"
            ));
        }

        // Parse the data
        let mut cursor = std::io::Cursor::new(&data_buf);
        let hashes_file_size = cursor
            .read_u64::<LittleEndian>()
            .context("Failed to read hashes_file_size")?;
        let data_slab_file_id = cursor
            .read_u32::<LittleEndian>()
            .context("Failed to read data_slab_file_id")?;
        let data_slab_file_size = cursor
            .read_u64::<LittleEndian>()
            .context("Failed to read data_slab_file_size")?;

        let (stream_metadata_size, stream_mappings_size) = if version >= 2 {
            let metadata_size = cursor
                .read_u64::<LittleEndian>()
                .context("Failed to read stream_metadata_size")?;
            let mappings_size = cursor
                .read_u64::<LittleEndian>()
                .context("Failed to read stream_mappings_size")?;
            (metadata_size, mappings_size)
        } else {
            // Version 1: no stream files, start from empty
            (0, 0)
        };

        Ok(Self {
            hashes_file_size,
            data_slab_file_id,
            data_slab_file_size,
            stream_metadata_size,
            stream_mappings_size,
        })
    }

    /// Check if a recovery checkpoint exists
    pub fn exists<P: AsRef<Path>>(path: P) -> bool {
        path.as_ref().exists()
    }

    /// Apply this checkpoint by truncating all relevant files to checkpoint sizes
    ///
    /// This should be called on startup before opening the archive for writing.
    /// If the last operation completed successfully, the files will already be at
    /// these sizes, making this a no-op. If the last operation was interrupted,
    /// this truncates files back to the last known-good state.
    pub fn apply<P: AsRef<Path>>(&self, archive_dir: P) -> Result<()> {
        let archive_dir_ref = archive_dir.as_ref();

        // Truncate hashes file (will fail if missing)
        let hashes_path = paths::hashes_path(archive_dir_ref);
        let hashes_truncated = Self::truncate_file(&hashes_path, self.hashes_file_size)?;

        // If hashes file was truncated, regenerate its index to reflect correct slab count
        if hashes_truncated {
            let mut hashes_index = crate::slab::regenerate_index(&hashes_path, false)
                .with_context(|| {
                    format!("Failed to regenerate hashes index for {:?}", hashes_path)
                })?;
            hashes_index.write_offset_file(true).with_context(|| {
                format!("Failed to write hashes offset file for {:?}", hashes_path)
            })?;
            drop(hashes_index);
        }

        // Truncate the current write file (will fail if missing)
        let current_file_path =
            crate::slab::multi_file::file_id_to_path(archive_dir_ref, self.data_slab_file_id);
        let data_truncated = Self::truncate_file(&current_file_path, self.data_slab_file_size)?;

        // If data file was truncated, regenerate its index to reflect correct slab count
        if data_truncated {
            let mut data_index = crate::slab::regenerate_index(&current_file_path, false)
                .with_context(|| {
                    format!(
                        "Failed to regenerate data index for {:?}",
                        current_file_path
                    )
                })?;
            data_index.write_offset_file(true).with_context(|| {
                format!(
                    "Failed to write data offset file for {:?}",
                    current_file_path
                )
            })?;
            drop(data_index);
        }

        // Note: Older files (file_id < data_slab_file_id) are fully written and don't
        // need truncation (well, that is our expectation :-)
        // Remove any files with ID > data_slab_file_id (created after checkpoint)
        let mut file_id = self.data_slab_file_id + 1;
        loop {
            let file_path = crate::slab::multi_file::file_id_to_path(archive_dir_ref, file_id);
            if file_path.exists() {
                std::fs::remove_file(&file_path)
                    .with_context(|| format!("Failed to remove extra file: {:?}", file_path))?;

                // Also remove its offsets file if it exists
                let offsets_path = file_path.with_extension("offsets");
                if offsets_path.exists() {
                    std::fs::remove_file(&offsets_path)?;
                }

                // Sync the parent directory to ensure file removals are visible
                file_path.sync_parent()?;
                file_id += 1;
            } else {
                break;
            }
        }

        // Truncate stream metadata file
        let metadata_path = paths::streams_metadata_path(archive_dir_ref);
        if metadata_path.exists() {
            let metadata_truncated =
                Self::truncate_file(&metadata_path, self.stream_metadata_size)?;

            if metadata_truncated
                && self.stream_metadata_size >= crate::slab::file::SLAB_FILE_HDR_LEN
            {
                let mut metadata_index = crate::slab::regenerate_index(&metadata_path, false)
                    .with_context(|| {
                        format!(
                            "Failed to regenerate stream metadata index for {:?}",
                            metadata_path
                        )
                    })?;
                metadata_index.write_offset_file(true).with_context(|| {
                    format!(
                        "Failed to write stream metadata offset file for {:?}",
                        metadata_path
                    )
                })?;
                drop(metadata_index);
            }
        }

        // Truncate stream mappings file
        let mappings_path = paths::stream_mappings_path(archive_dir_ref);
        if mappings_path.exists() {
            let mappings_truncated =
                Self::truncate_file(&mappings_path, self.stream_mappings_size)?;

            if mappings_truncated
                && self.stream_mappings_size >= crate::slab::file::SLAB_FILE_HDR_LEN
            {
                let mut mappings_index = crate::slab::regenerate_index(&mappings_path, false)
                    .with_context(|| {
                        format!(
                            "Failed to regenerate stream mappings index for {:?}",
                            mappings_path
                        )
                    })?;
                mappings_index.write_offset_file(true).with_context(|| {
                    format!(
                        "Failed to write stream mappings offset file for {:?}",
                        mappings_path
                    )
                })?;
                drop(mappings_index);
            }
        }

        Ok(())
    }

    /// Truncate a file to the specified size
    ///
    /// Fails if the file is smaller than the target size, as this indicates corruption.
    /// Returns true if the file was actually truncated (size was reduced), false otherwise.
    pub fn truncate_file<P: AsRef<Path>>(path: P, size: u64) -> Result<bool> {
        let path = path.as_ref();
        let file = OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("Failed to open file for truncation: {:?}", path))?;

        let current_size = file
            .metadata()
            .with_context(|| format!("Failed to get metadata for file: {:?}", path))?
            .len();

        if current_size < size {
            return Err(anyhow::anyhow!(
                "File {:?} is smaller ({} bytes) than checkpoint size ({} bytes) - possible corruption",
                path, current_size, size
            ));
        }

        let was_truncated = current_size > size;

        if was_truncated {
            file.set_len(size)
                .with_context(|| format!("Failed to truncate file {:?} to size {}", path, size))?;

            file.sync_all()?;
        }

        Ok(was_truncated)
    }

    /// Delete a recovery checkpoint file (optional utility)
    ///
    /// Note: Under normal operation, checkpoints are never deleted - they're simply
    /// overwritten on each sync. This method is provided for cleanup or testing purposes.
    pub fn delete<P: AsRef<Path>>(path: P) -> Result<()> {
        let path = path.as_ref();
        if path.exists() {
            std::fs::remove_file(path)
                .with_context(|| format!("Failed to delete recovery file: {:?}", path))?;
        }
        Ok(())
    }
}

impl Default for RecoveryCheckpoint {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the default recovery checkpoint file name
pub fn check_point_file() -> PathBuf {
    PathBuf::from("recovery.checkpoint")
}

pub fn confirm_data_loss_warning() -> bool {
    // Write to stderr and stdout explicitly
    println!("WARNING: DATA LOSS WILL OCCUR IF YOU CONTINUE");
    println!("Press Y to continue, any other key to exit.");

    // Flush to make sure messages appear before waiting for input
    let _ = io::stdout().flush();

    // Read a single line from stdin
    let mut input = String::new();
    matches!(
        io::stdin().read_line(&mut input).ok().map(|_| input.trim()),
        Some("y" | "Y")
    )
}

/// Helper to create checkpoint from current archive state
///
/// This collects metadata from all files involved in the pack operation:
pub fn create_checkpoint_from_files<P: AsRef<Path>>(
    archive_dir: P,
    data_slab_file_id: u32,
) -> Result<RecoveryCheckpoint> {
    let base_path = archive_dir.as_ref();

    // Get hashes file size
    let hashes_path = paths::hashes_path(base_path);
    let hashes_file_size = std::fs::metadata(&hashes_path)
        .with_context(|| format!("Failed to get metadata for hashes file: {:?}", hashes_path))?
        .len();

    // Get data slab file size (MultiFile mode only)
    let file_path =
        crate::slab::multi_file::file_id_to_path(archive_dir.as_ref(), data_slab_file_id);
    let data_slab_file_size = std::fs::metadata(&file_path)
        .with_context(|| format!("Failed to get metadata for data file: {:?}", file_path))?
        .len();

    // Get stream metadata file size
    let metadata_path = paths::streams_metadata_path(base_path);
    let stream_metadata_size = if metadata_path.exists() {
        std::fs::metadata(&metadata_path)
            .with_context(|| {
                format!(
                    "Failed to get metadata for stream metadata file: {:?}",
                    metadata_path
                )
            })?
            .len()
    } else {
        0
    };

    // Get stream mappings file size
    let mappings_path = paths::stream_mappings_path(base_path);
    let stream_mappings_size = if mappings_path.exists() {
        std::fs::metadata(&mappings_path)
            .with_context(|| {
                format!(
                    "Failed to get metadata for stream mappings file: {:?}",
                    mappings_path
                )
            })?
            .len()
    } else {
        0
    };

    Ok(RecoveryCheckpoint {
        hashes_file_size,
        data_slab_file_id,
        data_slab_file_size,
        stream_metadata_size,
        stream_mappings_size,
    })
}

pub fn apply_check_point<P: AsRef<std::path::Path>>(archive_path: P) -> Result<()> {
    let checkpoint_path = archive_path
        .as_ref()
        .join(crate::recovery::check_point_file());
    if RecoveryCheckpoint::exists(&checkpoint_path) {
        let checkpoint = RecoveryCheckpoint::read(&checkpoint_path)
            .with_context(|| format!("Read error on checkpoint from {:?}", checkpoint_path))?;
        checkpoint.apply(archive_path.as_ref()).with_context(|| {
            format!(
                "Error applying recovery checkpoint at {:?}",
                archive_path.as_ref()
            )
        })?;
    }
    Ok(())
}

fn generate_warning<P: AsRef<std::path::Path>>(archive: P, message: &str) -> Result<()> {
    let a = archive.as_ref();
    Err(anyhow!(
        "Critical error: {message}\n\
                 To repair archive {a:?}, run: verify -a <archive> --all --repair\n\
                 CAUTION: This will result in lost data in the archive!",
    ))
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
    // Make sure the archive directory actually exists
    if !RecoveryCheckpoint::exists(&archive_path) {
        return Err(anyhow!(format!(
            "archive and/or checkpoint file for {:?} does not exist!",
            archive_path.as_ref()
        )));
    }

    // Apply the checkpoint, this is a no-op if we exited cleanly
    apply_check_point(&archive_path)?;

    // Retrieve the slab counts from data slabs and hashes slab
    let (data_slab_count, data_regen) = archive::archive_data_slab_count(&archive_path)?;
    let (hash_slab_count, hash_regen) = archive::archive_hashes_slab_count(&archive_path)?;

    // Check if counts match bettween the data and hashes slab
    if data_slab_count != hash_slab_count {
        eprintln!(
            "WARNING: missmatch between data slab counts {} and hashes slab counts {} fixing ...",
            data_slab_count, hash_slab_count,
        );

        if !data_regen {
            slab::MultiFile::fix_data_file_slab_indexes(&archive_path, false).with_context(
                || {
                    format!(
                        "flight_check: failed to fix data file slab indexes at {:?}",
                        archive_path.as_ref()
                    )
                },
            )?;
        }

        if !hash_regen {
            // hashes index file has an error, fix
            let hashes_path = paths::hashes_path(&archive_path);
            let mut hash_index =
                crate::slab::regenerate_index(&hashes_path, false).with_context(|| {
                    format!(
                        "flight_check: Failed to regenerate hashes index for {:?}",
                        hashes_path
                    )
                })?;
            hash_index.write_offset_file(true)?;
        }

        // get counts and check again
        let (data_slab_count, _data_regen) = archive::archive_data_slab_count(&archive_path)?;
        let (hash_slab_count, _hash_regen) = archive::archive_hashes_slab_count(&archive_path)?;
        if data_slab_count != hash_slab_count {
            let message = format!(
                "The number of slabs in the \
                 data file(s) {} doesn't match the number of slabs in the hash file {}.",
                data_slab_count, hash_slab_count
            );
            return generate_warning(&archive_path, &message);
        }
    }

    // Perform quick consistency checks on hashes file
    let hashes_path = paths::hashes_path(&archive_path);
    if let Err(e) = slab::quick_consistency_check(&hashes_path) {
        eprintln!(
            "WARNING: Hashes file consistency check failed: {}\nAttempting to regenerate index without data loss...",
            e
        );
        // Try to regenerate without truncation first (no data loss)
        match crate::slab::regenerate_index(&hashes_path, false) {
            Ok(mut hash_index) => {
                hash_index.write_offset_file(true)?;
                eprintln!("Successfully regenerated hashes index without data loss");
            }
            Err(regen_err) => {
                let message =
                    format!(
                    "Hashes file {:?} has corruption that cannot be repaired without data loss.\n\
                     Original error: {}\n\
                     Regeneration error: {}", hashes_path, e, regen_err);

                return generate_warning(&archive_path, &message);
            }
        }
    }

    // Perform quick consistency checks on all data slab files
    let mf = slab::MultiFile::quick_consistency_check(&archive_path, false);
    if let Err(e) = mf {
        let message = format!(
            "Data slab has corruption that cannot be repaired without data loss.\n\
             Error: {}",
            e
        );
        return generate_warning(archive_path, &message);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_checkpoint_write_read() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test.checkpoint");

        let checkpoint = RecoveryCheckpoint {
            hashes_file_size: 1024,
            data_slab_file_id: 3,
            data_slab_file_size: 4096,
            stream_metadata_size: 2048,
            stream_mappings_size: 8192,
        };

        // Write checkpoint
        checkpoint.write(&checkpoint_path).unwrap();

        // Read it back
        let loaded = RecoveryCheckpoint::read(&checkpoint_path).unwrap();

        assert_eq!(checkpoint, loaded);
    }

    #[test]
    fn test_checkpoint_new() {
        let checkpoint = RecoveryCheckpoint::new();
        assert_eq!(checkpoint.hashes_file_size, 0);
        assert_eq!(checkpoint.data_slab_file_id, 0);
        assert_eq!(checkpoint.data_slab_file_size, 0);
    }

    #[test]
    fn test_checkpoint_exists() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test.checkpoint");

        assert!(!RecoveryCheckpoint::exists(&checkpoint_path));

        let checkpoint = RecoveryCheckpoint::new();
        checkpoint.write(&checkpoint_path).unwrap();

        assert!(RecoveryCheckpoint::exists(&checkpoint_path));
    }

    #[test]
    fn test_checkpoint_delete() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test.checkpoint");

        let checkpoint = RecoveryCheckpoint::new();
        checkpoint.write(&checkpoint_path).unwrap();
        assert!(checkpoint_path.exists());

        RecoveryCheckpoint::delete(&checkpoint_path).unwrap();
        assert!(!checkpoint_path.exists());

        // Deleting non-existent file should not error
        RecoveryCheckpoint::delete(&checkpoint_path).unwrap();
    }

    #[test]
    fn test_truncate_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.dat");

        // Create a file with some data
        let mut file = File::create(&file_path).unwrap();
        file.write_all(&[0u8; 1024]).unwrap();
        drop(file);

        assert_eq!(std::fs::metadata(&file_path).unwrap().len(), 1024);

        // Truncate to smaller size
        RecoveryCheckpoint::truncate_file(&file_path, 512).unwrap();
        assert_eq!(std::fs::metadata(&file_path).unwrap().len(), 512);

        // Attempting to "truncate" to larger size should now fail (would extend with zeros)
        let result = RecoveryCheckpoint::truncate_file(&file_path, 2048);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("smaller"));
    }

    #[test]
    fn test_invalid_magic() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("bad.checkpoint");

        // Write invalid magic
        let mut file = File::create(&checkpoint_path).unwrap();
        file.write_u64::<LittleEndian>(0xBADBADBADBADBAD).unwrap();
        drop(file);

        let result = RecoveryCheckpoint::read(&checkpoint_path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid recovery file magic"));
    }

    #[test]
    fn test_invalid_version() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("bad.checkpoint");

        // Write correct magic but wrong version
        let mut file = File::create(&checkpoint_path).unwrap();
        file.write_u64::<LittleEndian>(RECOVERY_MAGIC).unwrap();
        file.write_u32::<LittleEndian>(999).unwrap();
        drop(file);

        let result = RecoveryCheckpoint::read(&checkpoint_path);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported recovery file version"));
    }

    #[test]
    fn test_atomic_checkpoint_write() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test.checkpoint");

        let checkpoint1 = RecoveryCheckpoint {
            hashes_file_size: 100,
            data_slab_file_id: 0,
            data_slab_file_size: 300,
            stream_metadata_size: 0,
            stream_mappings_size: 0,
        };

        let checkpoint2 = RecoveryCheckpoint {
            hashes_file_size: 1000,
            data_slab_file_id: 1,
            data_slab_file_size: 3000,
            stream_metadata_size: 0,
            stream_mappings_size: 0,
        };

        // Write first checkpoint
        checkpoint1.write(&checkpoint_path).unwrap();
        let loaded = RecoveryCheckpoint::read(&checkpoint_path).unwrap();
        assert_eq!(checkpoint1, loaded);

        // Overwrite with second checkpoint
        checkpoint2.write(&checkpoint_path).unwrap();
        let loaded = RecoveryCheckpoint::read(&checkpoint_path).unwrap();
        assert_eq!(checkpoint2, loaded);

        // Verify no temp file remains
        let tmp_path = checkpoint_path.with_extension("tmp");
        assert!(!tmp_path.exists());
    }

    #[test]
    fn test_checksum_validation() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test.checkpoint");

        let checkpoint = RecoveryCheckpoint {
            hashes_file_size: 1024,
            data_slab_file_id: 3,
            data_slab_file_size: 4096,
            stream_metadata_size: 0,
            stream_mappings_size: 0,
        };

        // Write valid checkpoint
        checkpoint.write(&checkpoint_path).unwrap();

        // Should read successfully with valid checksum
        let loaded = RecoveryCheckpoint::read(&checkpoint_path).unwrap();
        assert_eq!(checkpoint, loaded);

        // Corrupt the file by flipping a bit in the data section
        let mut file_data = std::fs::read(&checkpoint_path).unwrap();
        // Skip magic (8) + version (4) + checksum (8) = 20 bytes, then corrupt data
        if file_data.len() > 20 {
            file_data[20] ^= 0xFF; // Flip all bits in first data byte
            std::fs::write(&checkpoint_path, &file_data).unwrap();

            // Should fail checksum validation
            let result = RecoveryCheckpoint::read(&checkpoint_path);
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(err_msg.contains("checksum mismatch") || err_msg.contains("bit rot"));
        }
    }

    #[test]
    fn test_checksum_detects_truncation() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint_path = temp_dir.path().join("test.checkpoint");

        let checkpoint = RecoveryCheckpoint {
            hashes_file_size: 1024,
            data_slab_file_id: 3,
            data_slab_file_size: 4096,
            stream_metadata_size: 0,
            stream_mappings_size: 0,
        };

        // Write valid checkpoint
        checkpoint.write(&checkpoint_path).unwrap();

        // Truncate the file
        let mut file_data = std::fs::read(&checkpoint_path).unwrap();
        file_data.truncate(file_data.len() - 8); // Remove last 8 bytes
        std::fs::write(&checkpoint_path, &file_data).unwrap();

        // Should fail checksum validation
        let result = RecoveryCheckpoint::read(&checkpoint_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncate_file_detects_undersized_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.dat");

        // Create a small file
        std::fs::write(&file_path, vec![0u8; 500]).unwrap();

        // Try to "truncate" to larger size - should fail with corruption error
        let result = RecoveryCheckpoint::truncate_file(&file_path, 1000);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("smaller"));
        assert!(err_msg.contains("500"));
        assert!(err_msg.contains("1000"));
        assert!(err_msg.contains("corruption"));
    }

    #[test]
    fn test_truncate_file_allows_same_size() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.dat");

        // Create a file
        std::fs::write(&file_path, vec![0u8; 1000]).unwrap();

        // Truncate to same size - should succeed (no-op)
        RecoveryCheckpoint::truncate_file(&file_path, 1000).unwrap();

        // Verify size unchanged
        assert_eq!(std::fs::metadata(&file_path).unwrap().len(), 1000);
    }

    #[test]
    fn test_truncate_file_truncates_larger_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.dat");

        // Create a larger file
        std::fs::write(&file_path, vec![0u8; 2000]).unwrap();

        // Truncate to smaller size - should succeed
        RecoveryCheckpoint::truncate_file(&file_path, 1000).unwrap();

        // Verify truncation
        assert_eq!(std::fs::metadata(&file_path).unwrap().len(), 1000);
    }
}
