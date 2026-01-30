use anyhow::{anyhow, Result};
use std::collections::VecDeque;

use crate::vecdeque_reader::VecDequeReader;

/// Chunking strategy enum to distinguish between incremental and buffer-based approaches
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkingStrategy {
    /// Incremental: processes new data slices with awareness of unconsumed bytes
    /// Used by GearHash and similar rolling hash algorithms
    Incremental,

    /// BufferBased: needs to see all accumulated data via a Read trait
    /// Used by FastCDC StreamCDC and similar stream-based algorithms
    BufferBased,
}

/// Content-Defined Chunking trait
///
/// This trait abstracts the algorithm used for content-defined chunking,
/// allowing different implementations (GearHashCDC, Rabin fingerprinting, etc.)
/// to be used interchangeably.
///
/// # Example
///
/// ```
/// use blk_stash::cdc::{ContentDefinedChunker, GearHashCDC, FastCDC, MinCDC};
/// use blk_stash::content_sensitive_splitter::ContentSensitiveSplitter;
///
/// // Use GearHashCDC implementation (gear-based rolling hash)
/// let splitter1 = ContentSensitiveSplitter::new(8192, GearHashCDC::new());
///
/// // Use FastCDC implementation (FastCDC algorithm)
/// let splitter2 = ContentSensitiveSplitter::new(8192, FastCDC::new(8192));
///
/// // Use MinCDC implementation (high-performance, uniform distribution)
/// let splitter3 = ContentSensitiveSplitter::new(8192, MinCDC::new(8192));
///
/// // Or implement your own CDC algorithm:
/// struct MyCDC;
/// impl ContentDefinedChunker for MyCDC {
///     fn strategy(&self) -> blk_stash::cdc::ChunkingStrategy {
///         blk_stash::cdc::ChunkingStrategy::Incremental
///     }
///
///     fn next_match(&mut self, data: &[u8], mask: u64) -> Option<usize> {
///         // Your CDC logic here
///         None
///     }
/// }
///
/// let custom_splitter = ContentSensitiveSplitter::new(8192, MyCDC);
/// ```
pub trait ContentDefinedChunker {
    /// Get the chunking strategy used by this implementation
    fn strategy(&self) -> ChunkingStrategy;

    /// Find the next chunk boundary in the data (for incremental chunking).
    ///
    /// # Arguments
    /// * `data` - The data slice to scan for chunk boundaries
    /// * `mask` - The mask used to determine chunk boundaries (implementation-specific)
    ///
    /// # Returns
    /// * `Some(offset)` - The offset of the next chunk boundary within `data`
    /// * `None` - No chunk boundary found in the provided data
    ///
    /// Note: Only used when strategy() returns ChunkingStrategy::Incremental
    fn next_match(&mut self, data: &[u8], mask: u64) -> Option<usize>;

    /// Process all buffered data and return chunk lengths (for buffer-based chunking).
    ///
    /// # Arguments
    /// * `buffers` - All accumulated buffers
    /// * `start_buffer` - Index of first unconsumed buffer
    /// * `start_offset` - Offset within the first unconsumed buffer
    /// * `min_size` - Minimum chunk size
    /// * `max_size` - Maximum chunk size
    ///
    /// # Returns
    /// * `Ok(Vec<usize>)` - Vector of chunk lengths
    /// * `Err` - If buffer-based chunking is not supported or an error occurred
    ///
    /// Note: Only used when strategy() returns ChunkingStrategy::BufferBased
    fn chunk_from_buffers(
        &mut self,
        buffers: &VecDeque<Vec<u8>>,
        start_buffer: usize,
        start_offset: usize,
        min_size: usize,
        max_size: usize,
    ) -> Result<Vec<usize>> {
        let _ = (buffers, start_buffer, start_offset, min_size, max_size);
        Err(anyhow!(
            "Buffer-based chunking not supported for this implementation"
        ))
    }

    /// Reset the hasher state. Some implementations may need to reset internal state.
    fn reset(&mut self) {
        // Default implementation does nothing
    }
}

/// GearHashCDC implementation using gearhash
pub struct GearHashCDC {
    hasher: gearhash::Hasher<'static>,
}

impl GearHashCDC {
    pub fn new() -> Self {
        Self {
            hasher: gearhash::Hasher::default(),
        }
    }
}

impl Default for GearHashCDC {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentDefinedChunker for GearHashCDC {
    fn strategy(&self) -> ChunkingStrategy {
        ChunkingStrategy::Incremental
    }

    fn next_match(&mut self, data: &[u8], mask: u64) -> Option<usize> {
        self.hasher.next_match(data, mask)
    }
}

/// FastCDC implementation using the fastcdc crate with StreamCDC.
///
/// This implementation uses the FastCDC algorithm with StreamCDC, which provides
/// better deduplication characteristics than simple gear-based rolling hash.
/// It uses a buffer-based approach, reading from accumulated buffers via the Read trait.
///
/// To minimize StreamCDC instance creation, this only processes data when there's
/// a substantial amount accumulated (at least avg_size bytes), avoiding creating
/// instances for tiny buffers.
pub struct FastCDC {
    min_size: usize,
    max_size: usize,
}

impl FastCDC {
    /// Create a new FastCDC chunker with specified size parameters.
    ///
    /// # Arguments
    /// * `avg_size` - The average chunk size (will be used to derive min/max)
    pub fn new(avg_size: usize) -> Self {
        // Derive min/max from avg_size similar to FastCDC defaults
        let min_size = avg_size / 4;
        let max_size = avg_size * 4;
        Self::with_sizes(min_size, max_size)
    }

    /// Create a new FastCDC chunker with explicit min and max sizes.
    pub fn with_sizes(min_size: usize, max_size: usize) -> Self {
        Self {
            min_size,
            max_size,
        }
    }
}

impl Default for FastCDC {
    fn default() -> Self {
        Self::new(8192) // Default to 8KB average chunk size
    }
}

impl ContentDefinedChunker for FastCDC {
    fn strategy(&self) -> ChunkingStrategy {
        ChunkingStrategy::BufferBased
    }

    fn next_match(&mut self, _data: &[u8], _mask: u64) -> Option<usize> {
        // Not used for buffer-based chunking
        // This method exists for trait compatibility but should not be called
        None
    }

    fn chunk_from_buffers(
        &mut self,
        buffers: &VecDeque<Vec<u8>>,
        start_buffer: usize,
        start_offset: usize,
        min_size: usize,
        max_size: usize,
    ) -> Result<Vec<usize>> {
        // Create a reader over the unconsumed buffers
        let reader = VecDequeReader::new_from_position(buffers, start_buffer, start_offset);

        // Use the provided min/max sizes, or fall back to instance defaults
        // The avg_size is computed as the geometric mean of min and max
        let min = if min_size > 0 { min_size } else { self.min_size };
        let max = if max_size > 0 { max_size } else { self.max_size };
        let avg = ((min as f64 * max as f64).sqrt() as usize).clamp(min, max);

        // Use StreamCDC to chunk the data
        let chunker = fastcdc::v2020::StreamCDC::new(
            reader,
            min as u32,
            avg as u32,
            max as u32,
        );

        // Collect all chunk lengths
        let mut lengths = Vec::new();
        for chunk_result in chunker {
            let chunk = chunk_result.map_err(|e| anyhow!("FastCDC error: {:?}", e))?;
            lengths.push(chunk.length);
        }

        Ok(lengths)
    }
}

/// MinCDC implementation using the mincdc crate.
///
/// MinCDC chooses chunk boundaries based on the minimum value of a sliding window
/// over the input data. This approach provides:
/// - Nearly uniform chunk size distribution between min and max sizes
/// - Extremely high performance (40+ GB/s on modern hardware)
/// - Comparable deduplication to other CDC algorithms
///
/// This implementation uses MinCdcHash4, which hashes window values for improved
/// robustness compared to the raw MinCdc4 variant.
pub struct MinCDC {
    min_size: usize,
    max_size: usize,
}

impl MinCDC {
    /// Create a new MinCDC chunker with specified size parameters.
    ///
    /// # Arguments
    /// * `avg_size` - The average chunk size (will be used to derive min/max)
    pub fn new(avg_size: usize) -> Self {
        // Use similar size ranges as FastCDC for consistency
        Self::with_sizes(avg_size / 4, avg_size * 4)
    }

    /// Create a new MinCDC chunker with explicit min and max sizes.
    pub fn with_sizes(min_size: usize, max_size: usize) -> Self {
        Self { min_size, max_size }
    }
}

impl Default for MinCDC {
    fn default() -> Self {
        Self::new(8192) // Default to 8KB average chunk size
    }
}

impl ContentDefinedChunker for MinCDC {
    fn strategy(&self) -> ChunkingStrategy {
        ChunkingStrategy::BufferBased
    }

    fn next_match(&mut self, _data: &[u8], _mask: u64) -> Option<usize> {
        // Not used for buffer-based chunking
        // This method exists for trait compatibility but should not be called
        None
    }

    fn chunk_from_buffers(
        &mut self,
        buffers: &VecDeque<Vec<u8>>,
        start_buffer: usize,
        start_offset: usize,
        min_size: usize,
        max_size: usize,
    ) -> Result<Vec<usize>> {
        // Create a reader over the unconsumed buffers
        let reader = VecDequeReader::new_from_position(buffers, start_buffer, start_offset);

        // Use the provided min/max sizes, or fall back to instance defaults
        let min = if min_size > 0 { min_size } else { self.min_size };
        let max = if max_size > 0 { max_size } else { self.max_size };

        // Use MinCDC ReadChunker to chunk the data
        // MinCdcHash4 is recommended for robustness
        let mut chunker = mincdc::ReadChunker::new(
            reader,
            min,
            max,
            mincdc::MinCdcHash4::new(),
        );

        // Collect all chunk lengths
        let mut lengths = Vec::new();
        loop {
            match chunker.next() {
                Ok(Some(chunk)) => lengths.push(chunk.len()),
                Ok(None) => break,
                Err(e) => return Err(anyhow!("MinCDC error: {}", e)),
            }
        }

        Ok(lengths)
    }
}

/// Simple fixed-size chunker for testing or as an alternative to CDC.
///
/// This implementation always chunks at fixed boundaries, ignoring content.
/// It can be useful for testing or scenarios where content-defined chunking
/// is not desired.
pub struct FixedSizeChunker {
    offset: usize,
}

impl FixedSizeChunker {
    pub fn new() -> Self {
        Self { offset: 0 }
    }
}

impl Default for FixedSizeChunker {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentDefinedChunker for FixedSizeChunker {
    fn strategy(&self) -> ChunkingStrategy {
        ChunkingStrategy::Incremental
    }

    fn next_match(&mut self, data: &[u8], _mask: u64) -> Option<usize> {
        // Always return the end of the data, effectively disabling CDC
        if data.is_empty() {
            None
        } else {
            Some(data.len())
        }
    }

    fn reset(&mut self) {
        self.offset = 0;
    }
}

/// Type-erased CDC for runtime selection of chunking algorithm.
///
/// This allows you to choose the CDC algorithm at runtime based on
/// configuration or other dynamic factors.
///
/// # Example
///
/// ```
/// use blk_stash::cdc::{ContentDefinedChunker, GearHashCDC, FastCDC, MinCDC, FixedSizeChunker};
///
/// fn create_chunker(algorithm: &str) -> Box<dyn ContentDefinedChunker> {
///     match algorithm {
///         "gearhash" => Box::new(GearHashCDC::new()),
///         "fastcdc" => Box::new(FastCDC::new(8192)),
///         "mincdc" => Box::new(MinCDC::new(8192)),
///         "fixed" => Box::new(FixedSizeChunker::new()),
///         _ => Box::new(GearHashCDC::new()),
///     }
/// }
/// ```
impl ContentDefinedChunker for Box<dyn ContentDefinedChunker> {
    fn strategy(&self) -> ChunkingStrategy {
        (**self).strategy()
    }

    fn next_match(&mut self, data: &[u8], mask: u64) -> Option<usize> {
        (**self).next_match(data, mask)
    }

    fn chunk_from_buffers(
        &mut self,
        buffers: &VecDeque<Vec<u8>>,
        start_buffer: usize,
        start_offset: usize,
        min_size: usize,
        max_size: usize,
    ) -> Result<Vec<usize>> {
        (**self).chunk_from_buffers(buffers, start_buffer, start_offset, min_size, max_size)
    }

    fn reset(&mut self) {
        (**self).reset()
    }
}

/// Create a CDC instance from an algorithm name and average chunk size.
///
/// # Arguments
/// * `algorithm` - The CDC algorithm name ("gearhash", "fastcdc", "mincdc", or "fixed")
/// * `avg_size` - Average chunk size in bytes
///
/// # Returns
/// * `Ok(Box<dyn ContentDefinedChunker>)` - A boxed CDC implementation
/// * `Err` - If the algorithm name is not recognized
///
/// # Example
/// ```
/// use blk_stash::cdc::create_cdc;
///
/// let gearhash = create_cdc("gearhash", 8192).unwrap();
/// let fastcdc = create_cdc("fastcdc", 8192).unwrap();
/// let mincdc = create_cdc("mincdc", 8192).unwrap();
/// ```
pub fn create_cdc(algorithm: &str, avg_size: usize) -> Result<Box<dyn ContentDefinedChunker>> {
    match algorithm {
        "gearhash" => Ok(Box::new(GearHashCDC::new())),
        "fastcdc" => Ok(Box::new(FastCDC::new(avg_size))),
        "mincdc" => Ok(Box::new(MinCDC::new(avg_size))),
        "fixed" => Ok(Box::new(FixedSizeChunker::new())),
        _ => Err(anyhow!("Unknown CDC algorithm: {}", algorithm)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gearhash_implements_trait() {
        let mut cdc = GearHashCDC::new();
        // Just ensure it compiles and can be called
        let data = vec![0u8; 1024];
        let _ = cdc.next_match(&data, 0xFFFF);
    }

    #[test]
    fn test_fixed_size_chunker() {
        let mut chunker = FixedSizeChunker::new();
        let data = vec![0u8; 1024];

        // Fixed chunker should return the full data length
        assert_eq!(chunker.next_match(&data, 0), Some(1024));

        // Empty data should return None
        assert_eq!(chunker.next_match(&[], 0), None);
    }

    #[test]
    fn test_fastcdc_implements_trait() {
        use std::collections::VecDeque;

        let mut cdc = FastCDC::new(8192);
        let data = vec![0u8; 16384];

        // FastCDC uses buffer-based chunking
        assert_eq!(cdc.strategy(), ChunkingStrategy::BufferBased);

        // Create a VecDeque with the data
        let mut buffers = VecDeque::new();
        buffers.push_back(data);

        // FastCDC should find chunk boundaries
        let chunks = cdc.chunk_from_buffers(&buffers, 0, 0, 2048, 32768).unwrap();
        assert!(!chunks.is_empty());

        // Total of chunks should equal input size
        let total: usize = chunks.iter().sum();
        assert_eq!(total, 16384);
    }

    #[test]
    fn test_fastcdc_with_sizes() {
        use std::collections::VecDeque;

        let mut cdc = FastCDC::with_sizes(2048, 32768);
        let data = vec![0u8; 16384];

        let mut buffers = VecDeque::new();
        buffers.push_back(data);

        let chunks = cdc.chunk_from_buffers(&buffers, 0, 0, 2048, 32768).unwrap();
        assert!(!chunks.is_empty());
    }

    #[test]
    fn test_fastcdc_empty_data() {
        use std::collections::VecDeque;

        let mut cdc = FastCDC::new(8192);
        let buffers = VecDeque::new();

        let chunks = cdc.chunk_from_buffers(&buffers, 0, 0, 2048, 32768).unwrap();
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_mincdc_implements_trait() {
        use std::collections::VecDeque;

        let mut cdc = MinCDC::new(8192);
        let data = vec![0u8; 16384];

        // MinCDC uses buffer-based chunking
        assert_eq!(cdc.strategy(), ChunkingStrategy::BufferBased);

        // Create a VecDeque with the data
        let mut buffers = VecDeque::new();
        buffers.push_back(data);

        // MinCDC should find chunk boundaries
        let chunks = cdc.chunk_from_buffers(&buffers, 0, 0, 2048, 32768).unwrap();
        assert!(!chunks.is_empty());

        // Total of chunks should equal input size
        let total: usize = chunks.iter().sum();
        assert_eq!(total, 16384);
    }

    #[test]
    fn test_mincdc_with_sizes() {
        use std::collections::VecDeque;

        let mut cdc = MinCDC::with_sizes(2048, 32768);
        let data = vec![0u8; 65536];

        let mut buffers = VecDeque::new();
        buffers.push_back(data);

        let chunks = cdc.chunk_from_buffers(&buffers, 0, 0, 2048, 32768).unwrap();
        assert!(!chunks.is_empty());

        // Verify all chunks are within bounds
        for chunk_size in &chunks {
            assert!(
                *chunk_size >= 2048 || chunks.len() == 1,
                "Chunk too small: {}",
                chunk_size
            );
            assert!(*chunk_size <= 32768, "Chunk too large: {}", chunk_size);
        }

        // Total should match input
        let total: usize = chunks.iter().sum();
        assert_eq!(total, 65536);
    }

    #[test]
    fn test_mincdc_empty_data() {
        use std::collections::VecDeque;

        let mut cdc = MinCDC::new(8192);
        let buffers = VecDeque::new();

        let chunks = cdc.chunk_from_buffers(&buffers, 0, 0, 2048, 32768).unwrap();
        assert!(chunks.is_empty());
    }

    #[test]
    fn test_boxed_chunker() {
        use std::collections::VecDeque;

        let mut cdc: Box<dyn ContentDefinedChunker> = Box::new(GearHashCDC::new());
        let data = vec![0u8; 1024];
        let _ = cdc.next_match(&data, 0xFFFF);

        // Can also box the fixed size chunker
        let mut fixed: Box<dyn ContentDefinedChunker> = Box::new(FixedSizeChunker::new());
        assert_eq!(fixed.next_match(&data, 0), Some(1024));

        // Can also box the FastCDC chunker and use buffer-based chunking
        // Use a smaller avg_size (512) so min_size (128) is less than our data size (1024)
        let mut fastcdc: Box<dyn ContentDefinedChunker> = Box::new(FastCDC::new(512));
        let mut buffers = VecDeque::new();
        buffers.push_back(data.clone());
        let chunks = fastcdc
            .chunk_from_buffers(&buffers, 0, 0, 128, 2048)
            .unwrap();
        assert!(!chunks.is_empty());
    }

    #[test]
    fn test_runtime_selection() {
        use std::collections::VecDeque;

        fn create_chunker(algorithm: &str) -> Box<dyn ContentDefinedChunker> {
            match algorithm {
                "gearhash" => Box::new(GearHashCDC::new()),
                "fastcdc" => Box::new(FastCDC::new(8192)),
                "mincdc" => Box::new(MinCDC::new(8192)),
                "fixed" => Box::new(FixedSizeChunker::new()),
                _ => Box::new(GearHashCDC::new()),
            }
        }

        let data = vec![1u8; 16384];

        // GearHash uses incremental strategy
        let mut gearhash = create_chunker("gearhash");
        assert_eq!(gearhash.strategy(), ChunkingStrategy::Incremental);
        let _ = gearhash.next_match(&data, 0xFFFF);

        // FastCDC uses buffer-based strategy
        let mut fastcdc = create_chunker("fastcdc");
        assert_eq!(fastcdc.strategy(), ChunkingStrategy::BufferBased);
        let mut buffers = VecDeque::new();
        buffers.push_back(data.clone());
        let chunks = fastcdc
            .chunk_from_buffers(&buffers, 0, 0, 2048, 32768)
            .unwrap();
        assert!(!chunks.is_empty());

        // MinCDC uses buffer-based strategy
        let mut mincdc = create_chunker("mincdc");
        assert_eq!(mincdc.strategy(), ChunkingStrategy::BufferBased);
        let mut buffers = VecDeque::new();
        buffers.push_back(data.clone());
        let chunks = mincdc
            .chunk_from_buffers(&buffers, 0, 0, 2048, 32768)
            .unwrap();
        assert!(!chunks.is_empty());

        // Fixed uses incremental strategy
        let mut fixed = create_chunker("fixed");
        assert_eq!(fixed.strategy(), ChunkingStrategy::Incremental);
        assert_eq!(fixed.next_match(&data, 0), Some(16384));
    }

    #[test]
    fn test_create_cdc_factory() {
        use std::collections::VecDeque;

        // Test that create_cdc works for all supported algorithms
        let algorithms = vec!["gearhash", "fastcdc", "mincdc", "fixed"];

        for algorithm in algorithms {
            let cdc = create_cdc(algorithm, 8192);
            assert!(
                cdc.is_ok(),
                "Failed to create CDC for algorithm: {}",
                algorithm
            );
        }

        // Test that mincdc specifically works via factory
        let mut mincdc = create_cdc("mincdc", 8192).unwrap();
        assert_eq!(mincdc.strategy(), ChunkingStrategy::BufferBased);

        let data = vec![1u8; 16384];
        let mut buffers = VecDeque::new();
        buffers.push_back(data);

        let chunks = mincdc
            .chunk_from_buffers(&buffers, 0, 0, 2048, 32768)
            .unwrap();
        assert!(!chunks.is_empty());

        // Verify total matches input
        let total: usize = chunks.iter().sum();
        assert_eq!(total, 16384);

        // Test unknown algorithm returns error
        let result = create_cdc("unknown", 8192);
        assert!(result.is_err());
    }
}
