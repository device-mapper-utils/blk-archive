//! Binary stream archive management
//!
//! This module provides a high-level interface for managing binary stream metadata
//! and mappings. It encapsulates the slab file implementation details.

use anyhow::{anyhow, Context, Result};
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::config::StreamConfig;
use crate::output::Output;
use crate::paths::{stream_mappings_path, streams_metadata_path};
use crate::slab::builder::SlabFileBuilder;
use crate::slab::{SlabFile, StreamData};
use crate::stream_metadata::{deserialize_stream_config, serialize_stream_config};

/// Stream archive manager
///
/// Manages the binary stream metadata and mappings files, providing
/// a clean interface for reading and writing stream information.
pub struct StreamArchive<'a> {
    metadata_file: Arc<Mutex<SlabFile<'a>>>,
    mappings_file: Arc<Mutex<SlabFile<'a>>>,
}

pub struct MemorySlab {
    slab: Arc<Vec<u8>>,
}

impl MemorySlab {
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            slab: Arc::new(data),
        }
    }
}

impl StreamData for MemorySlab {
    fn read(&mut self, slab: u32) -> Result<Arc<Vec<u8>>> {
        if slab == 0 {
            Ok(self.slab.clone())
        } else {
            Err(anyhow!("invalid slab index (only 0 exists)"))
        }
    }

    fn get_nr_slabs(&self) -> usize {
        1
    }
}

/// Lazy stream slab that reads data on-demand from the slab file
///
/// This implementation reads mapping slabs from the file system as needed,
/// making it suitable for streams of any size without consuming memory proportional
/// to the stream size.
pub struct LazyStreamSlab<'a> {
    mappings_file: Arc<Mutex<SlabFile<'a>>>,
    first_mapping_slab: u32,
    num_mapping_slabs: u32,
}

impl<'a> LazyStreamSlab<'a> {
    pub fn new(
        mappings_file: Arc<Mutex<SlabFile<'a>>>,
        first_mapping_slab: u32,
        num_mapping_slabs: u32,
    ) -> Self {
        Self {
            mappings_file,
            first_mapping_slab,
            num_mapping_slabs,
        }
    }
}

impl<'a> StreamData for LazyStreamSlab<'a> {
    fn read(&mut self, slab: u32) -> Result<Arc<Vec<u8>>> {
        if slab >= self.num_mapping_slabs {
            return Err(anyhow!(
                "invalid slab index {} (max {})",
                slab,
                self.num_mapping_slabs - 1
            ));
        }

        let actual_slab_id = self.first_mapping_slab + slab;
        let mut mappings = self.mappings_file.lock().unwrap();
        mappings.read(actual_slab_id).with_context(|| {
            format!(
                "Failed to read mapping slab {} (logical slab {})",
                actual_slab_id, slab
            )
        })
    }

    fn get_nr_slabs(&self) -> usize {
        self.num_mapping_slabs as usize
    }
}

impl<'a> StreamArchive<'a> {
    /// Open stream archive for reading
    pub fn open_read(archive_dir: &Path) -> Result<StreamArchive<'static>> {
        let metadata_file = Arc::new(Mutex::new(
            SlabFileBuilder::open(streams_metadata_path(archive_dir))
                .build()
                .context("couldn't open stream metadata file")?,
        ));

        let mappings_file = Arc::new(Mutex::new(
            SlabFileBuilder::open(stream_mappings_path(archive_dir))
                .build()
                .context("couldn't open stream mappings file")?,
        ));

        Ok(StreamArchive {
            metadata_file,
            mappings_file,
        })
    }

    /// Create a new stream archive
    pub fn create(archive_dir: &Path, queue_depth: usize) -> Result<StreamArchive<'static>> {
        use std::fs;

        // Ensure the streams directory exists
        let streams_dir = archive_dir.join("streams");
        fs::create_dir_all(&streams_dir)
            .with_context(|| format!("Failed to create streams directory {:?}", streams_dir))?;

        let metadata_file = Arc::new(Mutex::new(
            SlabFileBuilder::create(streams_metadata_path(archive_dir))
                .write(true)
                .queue_depth(queue_depth)
                .build()
                .context("couldn't create stream metadata file")?,
        ));

        let mappings_file = Arc::new(Mutex::new(
            SlabFileBuilder::create(stream_mappings_path(archive_dir))
                .write(true)
                .compressed(true)
                .queue_depth(queue_depth)
                .build()
                .context("couldn't create stream mappings file")?,
        ));

        Ok(StreamArchive {
            metadata_file,
            mappings_file,
        })
    }

    /// Open stream archive for writing
    pub fn open_write(archive_dir: &Path, queue_depth: usize) -> Result<StreamArchive<'static>> {
        let metadata_file = Arc::new(Mutex::new(
            SlabFileBuilder::open(streams_metadata_path(archive_dir))
                .write(true)
                .queue_depth(queue_depth)
                .build()
                .context("couldn't open stream metadata file for writing")?,
        ));

        let mappings_file = Arc::new(Mutex::new(
            SlabFileBuilder::open(stream_mappings_path(archive_dir))
                .write(true)
                .queue_depth(queue_depth)
                .build()
                .context("couldn't open stream mappings file for writing")?,
        ));

        Ok(StreamArchive {
            metadata_file,
            mappings_file,
        })
    }

    /// Read stream configuration by stream ID
    pub fn read_config(&self, stream_id: u32) -> Result<StreamConfig> {
        let mut metadata = self.metadata_file.lock().unwrap();
        let data = metadata
            .read(stream_id)
            .with_context(|| format!("Failed to read metadata for stream {}", stream_id))?;
        deserialize_stream_config(&data)
            .with_context(|| format!("Failed to deserialize metadata for stream {}", stream_id))
    }

    /// Write stream configuration (allocates next stream ID)
    ///
    /// Returns the allocated stream ID
    pub fn write_config(&self, config: &StreamConfig) -> Result<u32> {
        let stream_id = {
            let metadata = self.metadata_file.lock().unwrap();
            metadata.get_nr_slabs() as u32
        };

        let metadata_bytes =
            serialize_stream_config(config).context("Failed to serialize stream config")?;

        let mut metadata = self.metadata_file.lock().unwrap();
        metadata
            .write_slab(&metadata_bytes)
            .context("Failed to write stream metadata slab")?;
        metadata
            .sync_all()
            .context("Failed to sync stream metadata")?;

        Ok(stream_id)
    }

    /// Get the number of streams in the archive
    pub fn stream_count(&self) -> usize {
        let metadata = self.metadata_file.lock().unwrap();
        metadata.get_nr_slabs()
    }

    /// Get a reference to the metadata file (for advanced use)
    pub fn metadata_file(&self) -> Arc<Mutex<SlabFile<'a>>> {
        self.metadata_file.clone()
    }

    /// Get a reference to the mappings file (for advanced use)
    pub fn mappings_file(&self) -> Arc<Mutex<SlabFile<'a>>> {
        self.mappings_file.clone()
    }

    /// Open stream mappings for a specific stream
    ///
    /// Returns a StreamData implementation. For streams with less than 24 MiB of mapping data,
    /// returns MemorySlab which loads all data into memory. For larger streams, returns
    /// LazyStreamSlab which reads data on-demand from the slab file.
    pub fn get_stream(&self, stream_id: u32) -> Result<Box<dyn StreamData + Send + Sync + 'a>> {
        let config = self.read_config(stream_id)?;

        // Calculate total mapping data size
        const MEMORY_THRESHOLD_SLABS: u32 = 6; // 24 MiB = 6 * 4 MiB slabs

        if config.num_mapping_slabs < MEMORY_THRESHOLD_SLABS {
            // Small stream: load all data into memory
            let mut combined_data = Vec::new();
            {
                let mut mappings = self.mappings_file.lock().unwrap();
                for slab_offset in 0..config.num_mapping_slabs {
                    let slab_id = config.first_mapping_slab + slab_offset;
                    let slab_data = mappings.read(slab_id).with_context(|| {
                        format!(
                            "Failed to read mapping slab {} for stream {}",
                            slab_id, stream_id
                        )
                    })?;
                    combined_data.extend_from_slice(&slab_data);
                }
            }
            Ok(Box::new(MemorySlab::new(combined_data)))
        } else {
            // Large stream: use lazy loading
            Ok(Box::new(LazyStreamSlab::new(
                self.mappings_file.clone(),
                config.first_mapping_slab,
                config.num_mapping_slabs,
            )))
        }
    }

    /// Close the stream archive files
    ///
    /// This ensures all offset files are written correctly
    pub fn close(&mut self) -> Result<()> {
        {
            let mut metadata = self.metadata_file.lock().unwrap();
            metadata
                .close()
                .context("Failed to close stream metadata file")?;
        }
        {
            let mut mappings = self.mappings_file.lock().unwrap();
            mappings
                .close()
                .context("Failed to close stream mappings file")?;
        }
        Ok(())
    }
}

pub fn retrieve_stream_slab(
    archive_dir: &Path,
    stream_id: u32,
) -> Result<Box<dyn StreamData + Send + Sync + 'static>> {
    let stream_archive = StreamArchive::open_read(archive_dir)?;
    stream_archive.get_stream(stream_id)
}

/// Helper function to read stream configuration by stream ID string
///
/// Supports both hex (16-char) and decimal formats
pub fn read_stream_config(archive_dir: &Path, stream: &str) -> Result<StreamConfig> {
    let stream_id = parse_stream_id(stream)?;
    let archive = StreamArchive::open_read(archive_dir)?;
    archive.read_config(stream_id)
}

/// Helper function to open a stream by stream ID string
///
/// Supports both hex (16-char) and decimal formats. Returns a StreamData implementation
/// that is either memory-based (for streams < 24 MiB) or lazy-loaded (for larger streams).
pub fn open_stream(
    archive_dir: &Path,
    stream: &str,
) -> Result<Box<dyn StreamData + Send + Sync + 'static>> {
    let stream_id = parse_stream_id(stream)?;
    let archive = StreamArchive::open_read(archive_dir)?;
    archive.get_stream(stream_id)
}

/// Parse stream ID from string (supports hex and decimal)
pub fn parse_stream_id(stream: &str) -> Result<u32> {
    if stream.len() == 16 && stream.chars().all(|c| c.is_ascii_hexdigit()) {
        u32::from_str_radix(stream, 16)
            .with_context(|| format!("Invalid hex stream ID: {}", stream))
    } else {
        stream
            .parse::<u32>()
            .with_context(|| format!("Invalid stream ID: {}", stream))
    }
}

/// Verify and rebuild stream archive
///
/// This function walks through all streams in the archive, verifies each one can be read,
/// and copies verified streams to a new archive in a temporary directory. After all streams
/// are processed, it atomically swaps the old and new archives.
pub fn verify_and_rebuild_streams(
    archive_dir: &Path,
    verbose: bool,
    report_output: Arc<Output>,
    num_cache_entries: usize,
) -> Result<usize> {
    use std::fs;

    // Open the existing stream archive for reading
    let source_archive =
        StreamArchive::open_read(archive_dir).context("Failed to open source stream archive")?;

    let stream_count = source_archive.stream_count();
    if verbose {
        eprintln!("Found {} streams to verify", stream_count);
    }

    // Set up directory paths
    // Note: StreamArchive::create() will append "streams" to the base path,
    // so we need temp_base to be archive_dir itself, not archive_dir/streams.tmp
    let streams_dir = archive_dir.join("streams");
    let temp_streams_dir = archive_dir.join("streams.tmp");
    let backup_dir = archive_dir.join("streams.backup");

    // Clean up any previous temporary directory
    if temp_streams_dir.exists() {
        fs::remove_dir_all(&temp_streams_dir).with_context(|| {
            format!(
                "Failed to remove existing temporary directory {:?}",
                temp_streams_dir
            )
        })?;
    }

    // Create temp directory and build archive there
    // We'll create the archive with a temporary base directory that will produce
    // streams.tmp/metadata and streams.tmp/mappings paths
    let temp_base = {
        // Create a temporary parent directory
        let temp_parent = archive_dir.join(".rebuild.tmp");
        if temp_parent.exists() {
            fs::remove_dir_all(&temp_parent)?;
        }
        fs::create_dir_all(&temp_parent)?;
        temp_parent
    };

    // Create new stream archive - this will create temp_base/streams/{metadata,mappings}
    let dest_archive = StreamArchive::create(&temp_base, 16)
        .context("Failed to create destination stream archive")?;

    // The actual streams directory created is at temp_base/streams
    let temp_streams_created = temp_base.join("streams");

    let mut verified_count = 0;
    let mut failed_streams = Vec::new();
    let mut next_mapping_slab: u32 = 0; // Track the next available mapping slab in destination

    // Iterate through all streams
    for stream_id in 0..stream_count as u32 {
        if verbose {
            eprint!("\rVerifying stream {}/{}", stream_id + 1, stream_count);
        }

        // Try to read the stream configuration
        let config = match source_archive.read_config(stream_id) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("\nFailed to read config for stream {}: {}", stream_id, e);
                failed_streams.push((stream_id, format!("config read failed: {}", e)));
                continue;
            }
        };

        let stream_result = crate::unpack::run_verify_stream(
            archive_dir,
            &format!("{stream_id}"),
            report_output.clone(),
            config.mapped_size,
            num_cache_entries,
        );

        match stream_result {
            Ok(checksum) => {
                if let Some(cs) = &config.source_sig {
                    if checksum != *cs {
                        eprintln!("\nChecksum failure {checksum} != {cs}");
                        failed_streams.push((stream_id, String::from("Failed checksum!")));
                        continue;
                    }
                }

                // Stream verified successfully, copy it to the new archive
                // Create updated config with new mapping slab positions
                let mut new_config = config.clone();
                new_config.first_mapping_slab = next_mapping_slab;
                // num_mapping_slabs stays the same

                // Write the metadata - this allocates a new stream ID
                // Note: The new stream ID may differ from the old one if we've skipped failed streams
                let _new_stream_id = dest_archive
                    .write_config(&new_config)
                    .with_context(|| format!("Failed to write config for stream {}", stream_id))?;

                // Copy all mapping slabs
                let nr_slabs = config.num_mapping_slabs;
                for slab_offset in 0..nr_slabs {
                    let source_slab_id = config.first_mapping_slab + slab_offset;

                    // Read from source
                    let slab_data = {
                        let mut mappings = source_archive.mappings_file.lock().unwrap();
                        mappings.read(source_slab_id).with_context(|| {
                            format!(
                                "Failed to read mapping slab {} for stream {}",
                                source_slab_id, stream_id
                            )
                        })?
                    };

                    // Write to destination
                    {
                        let mut dest_mappings = dest_archive.mappings_file.lock().unwrap();
                        dest_mappings.write_slab(&slab_data).with_context(|| {
                            format!("Failed to write mapping slab for stream {}", stream_id)
                        })?;
                    }
                }

                // Sync the mappings file after each stream
                {
                    let mut dest_mappings = dest_archive.mappings_file.lock().unwrap();
                    dest_mappings
                        .sync_all()
                        .context("Failed to sync mappings file")?;
                }

                // Update the next available mapping slab position
                next_mapping_slab += nr_slabs;

                verified_count += 1;
            }
            Err(e) => {
                eprintln!("\nFailed to verify stream {}: {}", stream_id, e);
                failed_streams.push((stream_id, format!("{}", e)));
            }
        }
    }

    if verbose {
        eprintln!();
    }

    // Close both archives to ensure all data is written
    let mut dest_archive_mut = dest_archive;
    dest_archive_mut
        .close()
        .context("Failed to close destination archive")?;

    drop(source_archive);

    if verbose {
        eprintln!("Verified {} streams successfully", verified_count);
        if !failed_streams.is_empty() {
            eprintln!(
                "Failed to verify {} streams, they have been removed (stream ids have changed):",
                failed_streams.len()
            );
            for (id, err) in &failed_streams {
                eprintln!("  Stream {}: {}", id, err);
            }
        }
    }

    // If no streams were verified, don't proceed with the swap
    if verified_count == 0 && stream_count > 0 {
        return Err(anyhow!(
            "No streams were successfully verified (out of {})",
            stream_count
        ));
    }

    // Atomic swap: move existing to backup, then move temp to streams
    // Note: This is as atomic as we can get on most filesystems
    // On the same filesystem, rename is atomic

    // Remove old backup if it exists
    if backup_dir.exists() {
        fs::remove_dir_all(&backup_dir)
            .with_context(|| format!("Failed to remove old backup directory {:?}", backup_dir))?;
    }

    // Move current streams to backup
    if streams_dir.exists() {
        fs::rename(&streams_dir, &backup_dir)
            .with_context(|| "Failed to move streams to backup")?;
    }

    // Move temp streams to final location (this is the atomic part if on same filesystem)
    fs::rename(&temp_streams_created, &streams_dir)
        .with_context(|| "Failed to move temporary directory to streams location")?;

    // Clean up the temporary parent directory
    fs::remove_dir_all(&temp_base).with_context(|| {
        format!(
            "Failed to remove temporary parent directory {:?}",
            temp_base
        )
    })?;

    if verbose {
        eprintln!("Successfully rebuilt stream archive");
        eprintln!("Original archive backed up to: {:?}", backup_dir);
    }

    Ok(verified_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_verify_and_rebuild_empty_archive() {
        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();
        let archive_dir = temp_dir.path();

        // Create the streams directory structure
        let streams_dir = archive_dir.join("streams");
        fs::create_dir_all(&streams_dir).unwrap();

        // Create empty stream files
        let metadata_path = streams_dir.join("metadata");
        let mappings_path = streams_dir.join("mappings");

        // Initialize empty slab files
        use crate::slab::builder::SlabFileBuilder;
        {
            let mut metadata = SlabFileBuilder::create(&metadata_path)
                .write(true)
                .build()
                .unwrap();
            metadata.close().unwrap();

            let mut mappings = SlabFileBuilder::create(&mappings_path)
                .write(true)
                .build()
                .unwrap();
            mappings.close().unwrap();
        }

        // Run verify and rebuild on empty archive
        let output = crate::utils::mk_output(false);

        let result = verify_and_rebuild_streams(archive_dir, false, output, 1024);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);

        // Verify the backup directory was created
        assert!(archive_dir.join("streams.backup").exists());
        // Verify the new streams directory exists
        assert!(archive_dir.join("streams").exists());

        // Verify the structure is correct (not nested)
        assert!(archive_dir.join("streams").join("metadata").exists());
        assert!(archive_dir.join("streams").join("mappings").exists());
        assert!(
            !archive_dir.join("streams").join("streams").exists(),
            "streams directory should not be nested"
        );

        // Verify temp directory was cleaned up
        assert!(!archive_dir.join(".rebuild.tmp").exists());
    }
}
