use std::collections::BTreeMap;

/// Statistics for Content-Defined Chunking performance analysis
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct CdcStats {
    /// Total number of chunks processed
    pub total_chunks: u64,

    /// Number of chunks that were duplicates (already in archive)
    pub duplicate_chunks: u64,

    /// Number of unique chunks (newly added to archive)
    pub unique_chunks: u64,

    /// Total bytes in all chunks before deduplication
    pub total_bytes: u64,

    /// Bytes actually written to archive (after deduplication)
    pub bytes_written: u64,

    /// Histogram of chunk sizes: size -> count
    /// Using BTreeMap to keep sizes sorted
    pub size_histogram: BTreeMap<u64, u64>,

    /// Histogram of chunk sizes in power-of-2 buckets for easier visualization
    /// bucket_index -> count, where bucket size = 2^bucket_index
    pub size_histogram_pow2: BTreeMap<u32, u64>,
}

impl CdcStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a chunk being processed
    ///
    /// # Arguments
    /// * `chunk_size` - Size of the chunk in bytes
    /// * `was_duplicate` - Whether this chunk was a duplicate (already in archive)
    pub fn record_chunk(&mut self, chunk_size: u64, was_duplicate: bool) {
        self.total_chunks += 1;
        self.total_bytes += chunk_size;

        if was_duplicate {
            self.duplicate_chunks += 1;
        } else {
            self.unique_chunks += 1;
            self.bytes_written += chunk_size;
        }

        // Update exact size histogram
        *self.size_histogram.entry(chunk_size).or_insert(0) += 1;

        // Update power-of-2 bucket histogram
        let bucket = if chunk_size == 0 {
            0
        } else {
            // Find the highest bit set (log2)
            63 - chunk_size.leading_zeros()
        };
        *self.size_histogram_pow2.entry(bucket).or_insert(0) += 1;
    }

    /// Get the deduplication ratio (0.0 = no dedup, 1.0 = perfect dedup)
    pub fn dedup_ratio(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            1.0 - (self.bytes_written as f64 / self.total_bytes as f64)
        }
    }

    /// Get the percentage of chunks that were duplicates
    pub fn duplicate_percentage(&self) -> f64 {
        if self.total_chunks == 0 {
            0.0
        } else {
            (self.duplicate_chunks as f64 / self.total_chunks as f64) * 100.0
        }
    }

    /// Get the average chunk size
    pub fn average_chunk_size(&self) -> f64 {
        if self.total_chunks == 0 {
            0.0
        } else {
            self.total_bytes as f64 / self.total_chunks as f64
        }
    }

    /// Get the median chunk size (approximate using histogram)
    pub fn median_chunk_size(&self) -> u64 {
        if self.total_chunks == 0 {
            return 0;
        }

        let target = self.total_chunks / 2;
        let mut count = 0u64;

        for (size, freq) in &self.size_histogram {
            count += freq;
            if count >= target {
                return *size;
            }
        }

        0
    }

    /// Get min and max chunk sizes
    pub fn min_max_chunk_size(&self) -> (u64, u64) {
        let min = self.size_histogram.keys().next().copied().unwrap_or(0);
        let max = self.size_histogram.keys().next_back().copied().unwrap_or(0);
        (min, max)
    }

    /// Format statistics as a human-readable string
    pub fn format_summary(&self) -> String {
        let (min, max) = self.min_max_chunk_size();

        format!(
            "CDC Statistics:\n\
             Total Chunks:       {}\n\
             Unique Chunks:      {} ({:.2}%)\n\
             Duplicate Chunks:   {} ({:.2}%)\n\
             Total Bytes:        {} ({:.2} MB)\n\
             Bytes Written:      {} ({:.2} MB)\n\
             Dedup Ratio:        {:.2}%\n\
             Avg Chunk Size:     {:.2} KB\n\
             Median Chunk Size:  {:.2} KB\n\
             Min Chunk Size:     {} bytes\n\
             Max Chunk Size:     {} bytes",
            self.total_chunks,
            self.unique_chunks,
            if self.total_chunks > 0 {
                (self.unique_chunks as f64 / self.total_chunks as f64) * 100.0
            } else {
                0.0
            },
            self.duplicate_chunks,
            self.duplicate_percentage(),
            self.total_bytes,
            self.total_bytes as f64 / 1_048_576.0,
            self.bytes_written,
            self.bytes_written as f64 / 1_048_576.0,
            self.dedup_ratio() * 100.0,
            self.average_chunk_size() / 1024.0,
            self.median_chunk_size() as f64 / 1024.0,
            min,
            max,
        )
    }

    /// Format the power-of-2 histogram as a string
    pub fn format_histogram_pow2(&self) -> String {
        let mut output = String::from("Chunk Size Distribution (power-of-2 buckets):\n");
        output.push_str(&format!(
            "{:<15} {:<10} {:<10}\n",
            "Size Range", "Count", "Percentage"
        ));
        output.push_str(&"-".repeat(40));
        output.push('\n');

        for (bucket, count) in &self.size_histogram_pow2 {
            let lower = 1u64 << bucket;
            let upper = (1u64 << (bucket + 1)) - 1;
            let percentage = if self.total_chunks > 0 {
                (*count as f64 / self.total_chunks as f64) * 100.0
            } else {
                0.0
            };

            output.push_str(&format!(
                "{:<15} {:<10} {:.2}%\n",
                format!("{}-{}", format_size(lower), format_size(upper)),
                count,
                percentage
            ));
        }

        output
    }

    /// Write exact chunk size histogram to a CSV file
    pub fn write_histogram_csv(&self, path: &std::path::Path) -> std::io::Result<()> {
        use std::io::Write;

        let mut file = std::fs::File::create(path)?;
        writeln!(file, "chunk_size_bytes,count")?;

        for (size, count) in &self.size_histogram {
            writeln!(file, "{},{}", size, count)?;
        }

        Ok(())
    }
}

/// Format byte size in human-readable form
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{}KB", bytes / 1024)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{}MB", bytes / (1024 * 1024))
    } else {
        format!("{}GB", bytes / (1024 * 1024 * 1024))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_stats() {
        let mut stats = CdcStats::new();

        // Record some chunks
        stats.record_chunk(4096, false); // unique
        stats.record_chunk(8192, false); // unique
        stats.record_chunk(4096, true); // duplicate

        assert_eq!(stats.total_chunks, 3);
        assert_eq!(stats.unique_chunks, 2);
        assert_eq!(stats.duplicate_chunks, 1);
        assert_eq!(stats.total_bytes, 4096 + 8192 + 4096);
        assert_eq!(stats.bytes_written, 4096 + 8192);
    }

    #[test]
    fn test_dedup_ratio() {
        let mut stats = CdcStats::new();

        stats.record_chunk(1000, false);
        stats.record_chunk(1000, true);
        stats.record_chunk(1000, true);
        stats.record_chunk(1000, true);

        // 4000 bytes total, 1000 written = 75% dedup
        assert!((stats.dedup_ratio() - 0.75).abs() < 0.01);
    }

    #[test]
    fn test_histogram() {
        let mut stats = CdcStats::new();

        stats.record_chunk(4096, false);
        stats.record_chunk(4096, false);
        stats.record_chunk(8192, false);

        assert_eq!(stats.size_histogram.get(&4096), Some(&2));
        assert_eq!(stats.size_histogram.get(&8192), Some(&1));
    }

    #[test]
    fn test_pow2_histogram() {
        let mut stats = CdcStats::new();

        stats.record_chunk(4096, false); // 2^12
        stats.record_chunk(8192, false); // 2^13

        // 4096 = 2^12, so bucket 12
        assert_eq!(stats.size_histogram_pow2.get(&12), Some(&1));
        // 8192 = 2^13, so bucket 13
        assert_eq!(stats.size_histogram_pow2.get(&13), Some(&1));
    }

    #[test]
    fn test_average() {
        let mut stats = CdcStats::new();

        stats.record_chunk(1000, false);
        stats.record_chunk(2000, false);
        stats.record_chunk(3000, false);

        assert!((stats.average_chunk_size() - 2000.0).abs() < 0.1);
    }
}
