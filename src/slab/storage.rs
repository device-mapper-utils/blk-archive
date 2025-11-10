use anyhow::Result;
use std::sync::Arc;

/// Trait for slab storage abstraction
///
/// This trait provides a common interface for different slab storage implementations,
/// allowing code to work with both single-file (`SlabFile`) and multi-file (`MultiFile`)
/// storage backends interchangeably.
pub trait SlabStorage {
    /// Write a slab of data to storage
    /// Returns an error if the write fails
    fn write_slab(&mut self, data: &[u8]) -> Result<()>;

    /// Read a slab by its index
    /// Returns the slab data wrapped in an Arc for efficient sharing
    fn read(&mut self, slab: u32) -> Result<Arc<Vec<u8>>>;

    /// Sync all pending writes to disk without closing
    /// Returns an error if the sync fails
    fn sync_all(&mut self) -> Result<()>;

    /// Close the storage, flushing any pending writes
    fn close(&mut self) -> Result<()>;

    /// Get the total number of slabs currently stored
    fn get_nr_slabs(&self) -> u32;

    /// Get the next slab index that will be assigned
    fn index(&self) -> u32;

    /// Get the total file size in bytes
    fn get_file_size(&self) -> u64;

    /// Check if the next write_slab() call will cross a file boundary
    ///
    /// For single-file storage (SlabFile), this always returns false.
    /// For multi-file storage (MultiFile), this returns true when the next
    /// write would create a new file.
    fn will_cross_boundary_on_next_write(&self) -> bool {
        false
    }

    /// Handle file boundary crossing with proper synchronization
    ///
    /// For single-file storage (SlabFile), this is a no-op.
    /// For multi-file storage (MultiFile), this closes the current file
    /// and creates a new one.
    ///
    /// IMPORTANT: The caller must sync all related state and create checkpoints
    /// BEFORE calling this method to ensure crash consistency.
    fn cross_file_boundary(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
#[cfg(not(debug_assertions))]
mod tests {
    use super::*;
    use crate::archive::SLAB_SIZE_TARGET;
    use crate::slab::file::SlabFile;
    use crate::slab::multi_file::MultiFile;
    use std::time::Instant;
    use tempfile::TempDir;

    /// Performance test parameters
    const PERF_NUM_SLABS: u32 = 100;
    const PERF_QUEUE_DEPTH: usize = 4;
    const PERF_CACHE_ENTRIES: usize = 10;

    /// Number of slabs for file boundary crossing test
    /// SLABS_PER_FILE = 1023, so 1025 will cross into second file
    const PERF_NUM_SLABS_BOUNDARY: u32 = 1025;

    /// Maximum allowed performance difference between implementations (as a ratio)
    /// A value of 1.08 means one implementation can be up to 8% slower than the other
    /// This allows for natural performance variation while catching major regressions
    const MAX_PERF_RATIO: f64 = 1.08;

    /// Helper function to measure write performance
    fn measure_write_performance<F, S>(name: &str, create_storage: F, num_slabs: u32) -> f64
    where
        F: FnOnce() -> S,
        S: SlabStorage,
    {
        let mut storage = create_storage();
        let data = vec![42u8; SLAB_SIZE_TARGET];
        let start = Instant::now();

        for _ in 0..num_slabs {
            storage.write_slab(&data).unwrap();
        }

        storage.close().unwrap();
        let duration = start.elapsed();
        let throughput = (num_slabs as f64 * SLAB_SIZE_TARGET as f64)
            / (1024.0 * 1024.0)
            / duration.as_secs_f64();

        println!("{} write performance:", name);
        println!("  Slabs: {}", num_slabs);
        println!("  Duration: {:?}", duration);
        println!("  Throughput: {:.2} MB/s", throughput);

        assert_eq!(storage.get_nr_slabs() as u32, num_slabs);
        throughput
    }

    /// Helper function to measure MultiFile write performance with boundary handling
    fn measure_multifile_write_performance(
        name: &str,
        base_path: &std::path::Path,
        num_slabs: u32,
    ) -> f64 {
        use crate::slab::multi_file::SLABS_PER_FILE;

        let mut storage =
            MultiFile::create(base_path, PERF_QUEUE_DEPTH, false, PERF_CACHE_ENTRIES).unwrap();
        let data = vec![42u8; SLAB_SIZE_TARGET];
        let start = Instant::now();

        for _ in 0..num_slabs {
            // Check if we're at a boundary and need to cross
            if storage.will_cross_boundary_on_next_write() {
                // For testing, we just cross the boundary without checkpointing
                // In production, handle_file_boundary_crossing() would sync and checkpoint
                storage.cross_file_boundary().unwrap();
            }
            storage.write_slab(&data).unwrap();
        }

        storage.close().unwrap();
        let duration = start.elapsed();
        let throughput = (num_slabs as f64 * SLAB_SIZE_TARGET as f64)
            / (1024.0 * 1024.0)
            / duration.as_secs_f64();

        println!("{} write performance:", name);
        println!("  Slabs: {}", num_slabs);
        println!("  Duration: {:?}", duration);
        println!("  Throughput: {:.2} MB/s", throughput);
        println!(
            "  Files created: {}",
            (num_slabs + SLABS_PER_FILE - 1) / SLABS_PER_FILE
        );

        assert_eq!(storage.get_nr_slabs() as u32, num_slabs);
        throughput
    }

    /// Helper function to measure read performance
    fn measure_read_performance<F, S>(name: &str, create_storage: F, num_slabs: u32) -> f64
    where
        F: FnOnce() -> S,
        S: SlabStorage,
    {
        let mut storage = create_storage();
        let start = Instant::now();

        for i in 0..num_slabs {
            let data = storage.read(i).unwrap();
            assert_eq!(data.len(), SLAB_SIZE_TARGET);
        }

        let duration = start.elapsed();
        let throughput = (num_slabs as f64 * SLAB_SIZE_TARGET as f64)
            / (1024.0 * 1024.0)
            / duration.as_secs_f64();

        println!("{} read performance:", name);
        println!("  Slabs: {}", num_slabs);
        println!("  Duration: {:?}", duration);
        println!("  Throughput: {:.2} MB/s", throughput);

        throughput
    }

    /// Compare write performance between SlabFile and MultiFile
    #[test]
    fn test_compare_write_performance() {
        let temp_dir = TempDir::new().unwrap();

        // Test SlabFile
        let slabfile_path = temp_dir.path().join("slabfile.slab");
        let slabfile_path_clone = slabfile_path.clone();
        let slabfile_throughput = measure_write_performance(
            "SlabFile",
            move || {
                SlabFile::create(
                    &slabfile_path_clone,
                    PERF_QUEUE_DEPTH,
                    false,
                    PERF_CACHE_ENTRIES,
                )
                .unwrap()
            },
            PERF_NUM_SLABS,
        );

        // Test MultiFile
        let multifile_path = temp_dir.path().join("multifile");
        let multifile_throughput =
            measure_multifile_write_performance("MultiFile", &multifile_path, PERF_NUM_SLABS);

        // Compare performance
        println!("\nWrite Performance Comparison:");
        println!("  SlabFile:  {:.2} MB/s", slabfile_throughput);
        println!("  MultiFile: {:.2} MB/s", multifile_throughput);

        // Only assert if MultiFile is slower than SlabFile
        if multifile_throughput < slabfile_throughput {
            let ratio = slabfile_throughput / multifile_throughput;
            println!("  MultiFile slower by: {:.2}x", ratio);
            assert!(
                ratio <= MAX_PERF_RATIO,
                "MultiFile write performance too slow: {:.2}x slower than SlabFile (max allowed: {:.2}x)",
                ratio,
                MAX_PERF_RATIO
            );
        } else {
            let ratio = multifile_throughput / slabfile_throughput;
            println!("  MultiFile faster by: {:.2}x", ratio);
        }
    }

    /// Compare read performance between SlabFile and MultiFile
    #[test]
    fn test_compare_read_performance() {
        let temp_dir = TempDir::new().unwrap();

        // Prepare SlabFile
        let slabfile_path = temp_dir.path().join("slabfile.slab");
        {
            let mut storage =
                SlabFile::create(&slabfile_path, PERF_QUEUE_DEPTH, false, PERF_CACHE_ENTRIES)
                    .unwrap();
            let data = vec![42u8; SLAB_SIZE_TARGET];
            for _ in 0..PERF_NUM_SLABS {
                storage.write_slab(&data).unwrap();
            }
            storage.close().unwrap();
        }

        // Prepare MultiFile
        let multifile_path = temp_dir.path().join("multifile");
        {
            let mut storage =
                MultiFile::create(&multifile_path, PERF_QUEUE_DEPTH, false, PERF_CACHE_ENTRIES)
                    .unwrap();
            let data = vec![42u8; SLAB_SIZE_TARGET];
            for _ in 0..PERF_NUM_SLABS {
                storage.write_slab(&data).unwrap();
            }
            storage.close().unwrap();
        }

        // Test SlabFile read
        let slabfile_path_clone = slabfile_path.clone();
        let slabfile_throughput = measure_read_performance(
            "SlabFile",
            move || SlabFile::open_for_read(&slabfile_path_clone, PERF_CACHE_ENTRIES).unwrap(),
            PERF_NUM_SLABS,
        );

        // Test MultiFile read
        let multifile_path_clone = multifile_path.clone();
        let multifile_throughput = measure_read_performance(
            "MultiFile",
            move || MultiFile::open_for_read(&multifile_path_clone, PERF_CACHE_ENTRIES).unwrap(),
            PERF_NUM_SLABS,
        );

        // Compare performance
        println!("\nRead Performance Comparison:");
        println!("  SlabFile:  {:.2} MB/s", slabfile_throughput);
        println!("  MultiFile: {:.2} MB/s", multifile_throughput);

        // Only assert if MultiFile is slower than SlabFile
        if multifile_throughput < slabfile_throughput {
            let ratio = slabfile_throughput / multifile_throughput;
            println!("  MultiFile slower by: {:.2}x", ratio);
            assert!(
                ratio <= MAX_PERF_RATIO,
                "MultiFile read performance too slow: {:.2}x slower than SlabFile (max allowed: {:.2}x)",
                ratio,
                MAX_PERF_RATIO
            );
        } else {
            let ratio = multifile_throughput / slabfile_throughput;
            println!("  MultiFile faster by: {:.2}x", ratio);
        }
    }

    /// Test compressed write performance
    #[test]
    fn test_compressed_write_performance() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("perf_test_compressed.slab");

        let mut storage =
            SlabFile::create(&file_path, PERF_QUEUE_DEPTH, true, PERF_CACHE_ENTRIES).unwrap();

        // Use highly compressible data (zeros)
        let data = vec![0u8; SLAB_SIZE_TARGET];
        let start = Instant::now();

        for _ in 0..PERF_NUM_SLABS {
            storage.write_slab(&data).unwrap();
        }

        storage.close().unwrap();
        let duration = start.elapsed();

        let throughput_mb_s = (PERF_NUM_SLABS as f64 * SLAB_SIZE_TARGET as f64)
            / (1024.0 * 1024.0)
            / duration.as_secs_f64();
        let file_size = storage.get_file_size();
        let compression_ratio =
            (PERF_NUM_SLABS as f64 * SLAB_SIZE_TARGET as f64) / file_size as f64;

        println!("Compressed write performance:");
        println!("  Slabs: {}", PERF_NUM_SLABS);
        println!("  Duration: {:?}", duration);
        println!("  Throughput: {:.2} MB/s", throughput_mb_s);
        println!("  File size: {} bytes", file_size);
        println!("  Compression ratio: {:.2}x", compression_ratio);
    }

    /// Test random access read performance
    #[test]
    fn test_random_access_performance() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("perf_test_random.slab");

        // Write data first
        {
            let mut storage =
                SlabFile::create(&file_path, PERF_QUEUE_DEPTH, false, PERF_CACHE_ENTRIES).unwrap();
            let data = vec![42u8; SLAB_SIZE_TARGET];
            for _ in 0..PERF_NUM_SLABS {
                storage.write_slab(&data).unwrap();
            }
            storage.close().unwrap();
        }

        // Random access test
        let mut storage = SlabFile::open_for_read(&file_path, PERF_CACHE_ENTRIES).unwrap();
        let start = Instant::now();

        // Read slabs in reverse order (worst case for sequential access)
        for i in (0..PERF_NUM_SLABS).rev() {
            let data = storage.read(i).unwrap();
            assert_eq!(data.len(), SLAB_SIZE_TARGET);
        }

        let duration = start.elapsed();
        let throughput_mb_s = (PERF_NUM_SLABS as f64 * SLAB_SIZE_TARGET as f64)
            / (1024.0 * 1024.0)
            / duration.as_secs_f64();

        println!("Random access performance (reverse order):");
        println!("  Slabs: {}", PERF_NUM_SLABS);
        println!("  Duration: {:?}", duration);
        println!("  Throughput: {:.2} MB/s", throughput_mb_s);
        println!("  Cache hits: {}", storage.hits());
        println!("  Cache misses: {}", storage.misses());
    }

    /// Generic performance test using trait object
    fn test_storage_performance<F>(name: &str, create_storage: F) -> (f64, f64)
    where
        F: FnOnce() -> Box<dyn SlabStorage>,
    {
        let mut storage = create_storage();
        let data = vec![42u8; SLAB_SIZE_TARGET];

        // Write test
        let write_start = Instant::now();
        for _ in 0..PERF_NUM_SLABS {
            storage.write_slab(&data).unwrap();
        }
        let write_duration = write_start.elapsed();

        // Read test
        let read_start = Instant::now();
        for i in 0..PERF_NUM_SLABS {
            let read_data = storage.read(i).unwrap();
            assert_eq!(read_data.len(), SLAB_SIZE_TARGET);
        }
        let read_duration = read_start.elapsed();

        storage.close().unwrap();

        let write_throughput = (PERF_NUM_SLABS as f64 * SLAB_SIZE_TARGET as f64)
            / (1024.0 * 1024.0)
            / write_duration.as_secs_f64();
        let read_throughput = (PERF_NUM_SLABS as f64 * SLAB_SIZE_TARGET as f64)
            / (1024.0 * 1024.0)
            / read_duration.as_secs_f64();

        println!("{} performance:", name);
        println!(
            "  Write: {:.2} MB/s ({:?})",
            write_throughput, write_duration
        );
        println!("  Read:  {:.2} MB/s ({:?})", read_throughput, read_duration);

        (write_throughput, read_throughput)
    }

    /// Compare performance when using trait objects (dynamic dispatch)
    #[test]
    fn test_trait_object_performance() {
        let temp_dir = TempDir::new().unwrap();

        // Test SlabFile via trait object
        let file_path = temp_dir.path().join("trait_slabfile.slab");
        let file_path_clone = file_path.clone();
        let (slabfile_write, slabfile_read) =
            test_storage_performance("SlabFile (trait object)", move || {
                Box::new(
                    SlabFile::create(
                        &file_path_clone,
                        PERF_QUEUE_DEPTH,
                        false,
                        PERF_CACHE_ENTRIES,
                    )
                    .unwrap(),
                )
            });

        // Test MultiFile via trait object
        let multi_path = temp_dir.path().join("trait_multifile");
        let multi_path_clone = multi_path.clone();
        let (multifile_write, multifile_read) =
            test_storage_performance("MultiFile (trait object)", move || {
                Box::new(
                    MultiFile::create(
                        &multi_path_clone,
                        PERF_QUEUE_DEPTH,
                        false,
                        PERF_CACHE_ENTRIES,
                    )
                    .unwrap(),
                )
            });

        // Compare write performance
        println!("\nTrait Object Write Performance Comparison:");
        println!("  SlabFile:  {:.2} MB/s", slabfile_write);
        println!("  MultiFile: {:.2} MB/s", multifile_write);

        // Only assert if MultiFile is slower than SlabFile
        if multifile_write < slabfile_write {
            let write_ratio = slabfile_write / multifile_write;
            println!("  MultiFile slower by: {:.2}x", write_ratio);
            assert!(
                write_ratio <= MAX_PERF_RATIO,
                "MultiFile write performance too slow: {:.2}x slower than SlabFile (max allowed: {:.2}x)",
                write_ratio,
                MAX_PERF_RATIO
            );
        } else {
            let write_ratio = multifile_write / slabfile_write;
            println!("  MultiFile faster by: {:.2}x", write_ratio);
        }

        // Compare read performance
        println!("\nTrait Object Read Performance Comparison:");
        println!("  SlabFile:  {:.2} MB/s", slabfile_read);
        println!("  MultiFile: {:.2} MB/s", multifile_read);

        // Only assert if MultiFile is slower than SlabFile
        if multifile_read < slabfile_read {
            let read_ratio = slabfile_read / multifile_read;
            println!("  MultiFile slower by: {:.2}x", read_ratio);
            assert!(
                read_ratio <= MAX_PERF_RATIO,
                "MultiFile read performance too slow: {:.2}x slower than SlabFile (max allowed: {:.2}x)",
                read_ratio,
                MAX_PERF_RATIO
            );
        } else {
            let read_ratio = multifile_read / slabfile_read;
            println!("  MultiFile faster by: {:.2}x", read_ratio);
        }
    }

    /// Test MultiFile performance when crossing file boundaries and compare to SlabFile
    #[test]
    fn test_multifile_boundary_crossing_performance() {
        use crate::slab::multi_file::SLABS_PER_FILE;

        let temp_dir = TempDir::new().unwrap();

        println!("\nTesting boundary crossing performance...");
        println!(
            "SLABS_PER_FILE = {}, writing {} slabs (~{:.2} GB)",
            SLABS_PER_FILE,
            PERF_NUM_SLABS_BOUNDARY,
            (PERF_NUM_SLABS_BOUNDARY as f64 * SLAB_SIZE_TARGET as f64) / (1024.0 * 1024.0 * 1024.0)
        );

        // Test SlabFile (single large file)
        let slabfile_path = temp_dir.path().join("slabfile_large.slab");
        let slabfile_path_clone = slabfile_path.clone();
        let slabfile_write_throughput = measure_write_performance(
            "SlabFile (large)",
            move || {
                SlabFile::create(
                    &slabfile_path_clone,
                    PERF_QUEUE_DEPTH,
                    false,
                    PERF_CACHE_ENTRIES,
                )
                .unwrap()
            },
            PERF_NUM_SLABS_BOUNDARY,
        );

        // Test MultiFile (crosses boundary)
        let multifile_path = temp_dir.path().join("multifile_boundary");
        let multifile_write_throughput = measure_multifile_write_performance(
            "MultiFile (boundary crossing)",
            &multifile_path,
            PERF_NUM_SLABS_BOUNDARY,
        );

        // Compare write performance
        println!("\nBoundary Crossing Write Performance Comparison:");
        println!("  SlabFile:  {:.2} MB/s", slabfile_write_throughput);
        println!("  MultiFile: {:.2} MB/s", multifile_write_throughput);

        // Only assert if MultiFile is slower than SlabFile
        if multifile_write_throughput < slabfile_write_throughput {
            let ratio = slabfile_write_throughput / multifile_write_throughput;
            println!("  MultiFile slower by: {:.2}x", ratio);
            assert!(
                ratio <= MAX_PERF_RATIO,
                "MultiFile write performance too slow: {:.2}x slower than SlabFile (max allowed: {:.2}x)",
                ratio,
                MAX_PERF_RATIO
            );
        } else {
            let ratio = multifile_write_throughput / slabfile_write_throughput;
            println!("  MultiFile faster by: {:.2}x", ratio);
        }

        // Test SlabFile read
        let slabfile_path_clone = slabfile_path.clone();
        let slabfile_read_throughput = measure_read_performance(
            "SlabFile (large)",
            move || SlabFile::open_for_read(&slabfile_path_clone, PERF_CACHE_ENTRIES).unwrap(),
            PERF_NUM_SLABS_BOUNDARY,
        );

        // Test MultiFile read
        let multifile_path_clone = multifile_path.clone();
        let multifile_read_throughput = measure_read_performance(
            "MultiFile (boundary crossing)",
            move || MultiFile::open_for_read(&multifile_path_clone, PERF_CACHE_ENTRIES).unwrap(),
            PERF_NUM_SLABS_BOUNDARY,
        );

        // Compare read performance
        println!("\nBoundary Crossing Read Performance Comparison:");
        println!("  SlabFile:  {:.2} MB/s", slabfile_read_throughput);
        println!("  MultiFile: {:.2} MB/s", multifile_read_throughput);

        // Only assert if MultiFile is slower than SlabFile
        if multifile_read_throughput < slabfile_read_throughput {
            let ratio = slabfile_read_throughput / multifile_read_throughput;
            println!("  MultiFile slower by: {:.2}x", ratio);
            assert!(
                ratio <= MAX_PERF_RATIO,
                "MultiFile read performance too slow: {:.2}x slower than SlabFile (max allowed: {:.2}x)",
                ratio,
                MAX_PERF_RATIO
            );
        } else {
            let ratio = multifile_read_throughput / slabfile_read_throughput;
            println!("  MultiFile faster by: {:.2}x", ratio);
        }

        // Verify MultiFile created two files
        use crate::slab::multi_file::file_id_to_path;
        let file0_path = file_id_to_path(&multifile_path, 0);
        let file1_path = file_id_to_path(&multifile_path, 1);
        assert!(file0_path.exists(), "First file should exist");
        assert!(
            file1_path.exists(),
            "Second file should exist after crossing boundary"
        );
    }
}
