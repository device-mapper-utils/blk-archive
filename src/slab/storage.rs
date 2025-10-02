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

    /// Close the storage, flushing any pending writes
    fn close(&mut self) -> Result<()>;

    /// Get the total number of slabs currently stored
    fn get_nr_slabs(&self) -> u32;

    /// Get the next slab index that will be assigned
    fn index(&self) -> u32;

    /// Get the total file size in bytes
    fn get_file_size(&self) -> u64;
}
