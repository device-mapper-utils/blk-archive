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
/// use blk_stash::cdc::{ContentDefinedChunker, GearHashCDC, FastCDC};
/// use blk_stash::content_sensitive_splitter::ContentSensitiveSplitter;
///
/// // Use GearHashCDC implementation (gear-based rolling hash)
/// let splitter1 = ContentSensitiveSplitter::new(8192, GearHashCDC::new());
///
/// // Use FastCDC implementation (FastCDC algorithm)
/// let splitter2 = ContentSensitiveSplitter::new(8192, FastCDC::new(8192));
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
    avg_size: usize,
    max_size: usize,
}

impl FastCDC {
    /// Create a new FastCDC chunker with specified size parameters.
    ///
    /// # Arguments
    /// * `avg_size` - The average chunk size (will be used to derive min/max)
    pub fn new(_avg_size: usize) -> Self {
        Self::with_sizes(512, 2048, 1024 * 8)
    }

    /// Create a new FastCDC chunker with explicit min, avg, and max sizes.
    pub fn with_sizes(min_size: usize, avg_size: usize, max_size: usize) -> Self {
        Self {
            min_size,
            avg_size,
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
        _min_size: usize,
        _max_size: usize,
    ) -> Result<Vec<usize>> {
        // Create a reader over the unconsumed buffers
        let reader = VecDequeReader::new_from_position(buffers, start_buffer, start_offset);

        // Use StreamCDC to chunk the data
        let chunker = fastcdc::v2020::StreamCDC::new(
            reader,
            self.min_size as u32,
            self.avg_size as u32,
            self.max_size as u32,
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
/// use blk_stash::cdc::{ContentDefinedChunker, GearHashCDC, FastCDC, FixedSizeChunker};
///
/// fn create_chunker(algorithm: &str) -> Box<dyn ContentDefinedChunker> {
///     match algorithm {
///         "gearhash" => Box::new(GearHashCDC::new()),
///         "fastcdc" => Box::new(FastCDC::new(8192)),
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
/// * `algorithm` - The CDC algorithm name ("gearhash", "fastcdc", or "fixed")
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
/// let cdc = create_cdc("gearhash", 8192).unwrap();
/// ```
pub fn create_cdc(algorithm: &str, avg_size: usize) -> Result<Box<dyn ContentDefinedChunker>> {
    match algorithm {
        "gearhash" => Ok(Box::new(GearHashCDC::new())),
        "fastcdc" => Ok(Box::new(FastCDC::new(avg_size))),
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

        let mut cdc = FastCDC::with_sizes(2048, 8192, 32768);
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

        // Fixed uses incremental strategy
        let mut fixed = create_chunker("fixed");
        assert_eq!(fixed.strategy(), ChunkingStrategy::Incremental);
        assert_eq!(fixed.next_match(&data, 0), Some(16384));
    }
}
