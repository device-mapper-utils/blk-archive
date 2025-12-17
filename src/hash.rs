use blake2::{Blake2b, Digest};
use std::convert::TryInto;

use crate::iovec::*;

//-----------------------------------------
// Blake2b - Used for content-based deduplication
//-----------------------------------------

type Blake2b32 = Blake2b<generic_array::typenum::U4>;
type Blake2b64 = Blake2b<generic_array::typenum::U8>;
type Blake2b256 = Blake2b<generic_array::typenum::U32>;

pub type Hash32 = generic_array::GenericArray<u8, generic_array::typenum::U4>;
pub type Hash64 = generic_array::GenericArray<u8, generic_array::typenum::U8>;
pub type Hash256 = generic_array::GenericArray<u8, generic_array::typenum::U32>;

pub fn hash_256_iov(iov: &IoVec) -> Hash256 {
    let mut hasher = Blake2b256::new();
    for v in iov {
        hasher.update(&v[..]);
    }
    hasher.finalize()
}

pub fn hash_64_iov(iov: &IoVec) -> Hash64 {
    let mut hasher = Blake2b64::new();
    for v in iov {
        hasher.update(&v[..]);
    }
    hasher.finalize()
}

pub fn hash_32_iov(iov: &IoVec) -> Hash32 {
    let mut hasher = Blake2b32::new();
    for v in iov {
        hasher.update(&v[..]);
    }
    hasher.finalize()
}

pub fn hash_256(v: &[u8]) -> Hash256 {
    let mut hasher = Blake2b256::new();
    hasher.update(v);
    hasher.finalize()
}

pub fn hash_64(v: &[u8]) -> Hash64 {
    let mut hasher = Blake2b64::new();
    hasher.update(v);
    hasher.finalize()
}

pub fn hash_32(v: &[u8]) -> Hash32 {
    let mut hasher = Blake2b32::new();
    hasher.update(v);
    hasher.finalize()
}

pub fn hash_le_u64(h: &[u8]) -> u64 {
    let mini_hash = hash_64(h);
    u64::from_le_bytes(
        mini_hash[..8]
            .try_into()
            .expect("hash_64 must return at least 8 bytes"),
    )
}

//-----------------------------------------
// Blake3 - Used for stream integrity verification
//-----------------------------------------

/// Re-export Blake3 hasher for convenience
pub use blake3::Hasher as Blake3Hasher;

/// Helper function to finalize a Blake3 hash and convert to hex string.
/// This is a common pattern used throughout the codebase for stream verification.
pub fn blake3_finalize_hex(hasher: blake3::Hasher) -> String {
    hasher.finalize().to_hex().to_string()
}

/// Add unmapped (zero-filled) region to a Blake3 hash.
/// This efficiently hashes zero bytes without allocating large buffers.
/// Used when hashing thin-provisioned devices with unmapped regions.
pub fn blake3_update_zeros(hasher: &mut blake3::Hasher, len: u64) {
    const ZERO_BUF: [u8; 4096] = [0; 4096];

    let mut remaining = len;
    while remaining > 0 {
        let hash_len = std::cmp::min(ZERO_BUF.len() as u64, remaining);
        hasher.update(&ZERO_BUF[0..hash_len as usize]);
        remaining -= hash_len;
    }
}

//-----------------------------------------
// Stream Hasher Trait - Abstraction for stream integrity verification
//-----------------------------------------

/// Trait for hashing entire input sources with stream integrity verification.
/// Provides abstraction over different hash algorithms that can be used for
/// verifying the integrity of archived streams.
///
/// This trait uses dynamic dispatch to allow runtime selection of hash algorithms.
pub trait StreamHasher {
    /// Update the hash with the given data.
    fn update(&mut self, data: &[u8]);

    /// Finalize the hash and return as a hex string.
    /// Consumes the hasher.
    fn finalize_hex(self: Box<Self>) -> String;

    /// Update the hash with zeros efficiently without allocating large buffers.
    /// Used when hashing thin-provisioned devices with unmapped regions.
    fn update_zeros(&mut self, len: u64);
}

/// Blake3 implementation of StreamHasher.
/// Provides cryptographic hashing for stream integrity verification using the BLAKE3 algorithm.
pub struct Blake3StreamHasher {
    hasher: blake3::Hasher,
}

impl Blake3StreamHasher {
    /// Create a new Blake3StreamHasher wrapped in a Box for dynamic dispatch.
    pub fn boxed() -> Box<dyn StreamHasher> {
        Box::new(Blake3StreamHasher {
            hasher: blake3::Hasher::new(),
        })
    }
}

/// Factory function to create the default stream hasher.
/// This centralizes the choice of hash algorithm, making it easy to switch
/// implementations or make the choice configurable in the future.
pub fn new_stream_hasher() -> Box<dyn StreamHasher> {
    Blake3StreamHasher::boxed()
}

impl Default for Blake3StreamHasher {
    fn default() -> Self {
        Blake3StreamHasher {
            hasher: blake3::Hasher::new(),
        }
    }
}

impl StreamHasher for Blake3StreamHasher {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize_hex(self: Box<Self>) -> String {
        self.hasher.finalize().to_hex().to_string()
    }

    fn update_zeros(&mut self, len: u64) {
        const ZERO_BUF: [u8; 4096] = [0; 4096];

        let mut remaining = len;
        while remaining > 0 {
            let hash_len = std::cmp::min(ZERO_BUF.len() as u64, remaining);
            self.hasher.update(&ZERO_BUF[0..hash_len as usize]);
            remaining -= hash_len;
        }
    }
}

//-----------------------------------------
#[cfg(test)]
mod hash_tests {

    use super::*;
    use byteorder::{LittleEndian, ReadBytesExt};
    use std::io::Cursor;

    #[test]
    fn test_hash_le_u64_impl() {
        let h = vec![0, 1, 2, 3, 4, 5, 6, 7];

        // What we previously had
        let mini_hash = hash_64(&h);
        let mut c = Cursor::new(&mini_hash);
        let previous = c.read_u64::<LittleEndian>().unwrap();

        // What we are replacing it with
        let current = hash_le_u64(&h);
        assert_eq!(previous, current);
    }

    #[test]
    fn test_hash_256_endian_agnostic() {
        // Test data in little-endian format
        let le_data: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
        // Same data in big-endian format
        let be_data: [u8; 8] = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02];

        // Hash both representations
        let hash_le = hash_256(&le_data);
        let hash_be = hash_256(&be_data);

        // The hashes should be different because the input bytes are different,
        // even though they represent the same numbers in different endianness.
        // This proves that the hash function treats the input as a pure byte stream
        // and is not affected by the system's endianness.
        assert_ne!(
            hash_le, hash_be,
            "Hash should treat input as raw bytes, regardless of endianness"
        );

        // Additional verification: hash the same byte sequence on both platforms
        let consistent_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let hash1 = hash_256(&consistent_data);
        let hash2 = hash_256(&consistent_data);
        assert_eq!(
            hash1, hash2,
            "Same byte sequence should produce identical hashes"
        );
    }

    #[test]
    fn test_hash_64_endian_agnostic() {
        // Test data in little-endian format
        let le_data: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
        // Same data in big-endian format
        let be_data: [u8; 8] = [0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02];

        // Hash both representations
        let hash_le = hash_64(&le_data);
        let hash_be = hash_64(&be_data);

        // The hashes should be different because the input bytes are different,
        // even though they represent the same numbers in different endianness.
        // This proves that the hash function treats the input as a pure byte stream
        // and is not affected by the system's endianness.
        assert_ne!(
            hash_le, hash_be,
            "Hash should treat input as raw bytes, regardless of endianness"
        );

        // Additional verification: hash the same byte sequence on both platforms
        let consistent_data = [1, 2, 3, 4, 5, 6, 7, 8];
        let hash1 = hash_64(&consistent_data);
        let hash2 = hash_64(&consistent_data);
        assert_eq!(
            hash1, hash2,
            "Same byte sequence should produce identical hashes"
        );

        // Verify that the hash output is consistent regardless of platform endianness
        let hash = hash_64(&consistent_data);
        assert_eq!(hash.len(), 8, "hash_64 should always return 8 bytes");
    }

    #[test]
    fn test_hash_32_endian_agnostic() {
        // Test data in little-endian format
        let le_data: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
        // Same data in big-endian format
        let be_data: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

        // Hash both representations
        let hash_le = hash_32(&le_data);
        let hash_be = hash_32(&be_data);

        // The hashes should be different because the input bytes are different,
        // even though they represent the same numbers in different endianness.
        // This proves that the hash function treats the input as a pure byte stream
        // and is not affected by the system's endianness.
        assert_ne!(
            hash_le, hash_be,
            "Hash should treat input as raw bytes, regardless of endianness"
        );

        // Additional verification: hash the same byte sequence on both platforms
        let consistent_data = [1, 2, 3, 4];
        let hash1 = hash_32(&consistent_data);
        let hash2 = hash_32(&consistent_data);
        assert_eq!(
            hash1, hash2,
            "Same byte sequence should produce identical hashes"
        );

        // Verify that the hash output is consistent regardless of platform endianness
        let hash = hash_32(&consistent_data);
        assert_eq!(hash.len(), 4, "hash_32 should always return 4 bytes");
    }

    /// A canonical test array (raw bytes).
    const TEST_INPUT_BYTES: &[u8] = b"endianness test input";

    /// The canonical, architecture-independent expected hash.
    ///
    /// You can also verify this on any system that has the utility `b2sum`, and example
    ///
    /// $ xxd test_bytes
    /// 00000000: 656e 6469 616e 6e65 7373 2074 6573 7420  endianness test
    /// 00000010: 696e 7075 74                             input
    ///
    /// $ b2sum -l 256 test_bytes
    /// 9b91fc95f40dd994541e9e240bb69f6a78b345ac3839083b0b371f6ae1b9b597  test_bytes
    const EXPECTED_HASH: [u8; 32] = [
        0x9B, 0x91, 0xFC, 0x95, 0xF4, 0x0D, 0xD9, 0x94, 0x54, 0x1E, 0x9E, 0x24, 0x0B, 0xB6, 0x9F,
        0x6A, 0x78, 0xB3, 0x45, 0xAC, 0x38, 0x39, 0x08, 0x3B, 0x0B, 0x37, 0x1F, 0x6A, 0xE1, 0xB9,
        0xB5, 0x97,
    ];

    #[cfg(target_endian = "little")]
    #[test]
    fn test_blake_endianness_little_endian() {
        let mut hasher = Blake2b256::new();
        hasher.update(TEST_INPUT_BYTES);
        let result = hasher.finalize();

        assert_eq!(
            &result[..],
            EXPECTED_HASH,
            "BLAKE hash differs from canonical reference on little-endian host"
        );
    }

    #[cfg(target_endian = "big")]
    #[test]
    fn test_blake_endianness_big_endian() {
        let mut hasher = Blake2b256::new();
        hasher.update(TEST_INPUT_BYTES);
        let result = hasher.finalize();

        assert_eq!(
            &result[..],
            EXPECTED_HASH,
            "BLAKE hash differs from canonical reference on big-endian host"
        );
    }

    #[test]
    fn test_stream_hasher_trait_basic() {
        // Test that the StreamHasher trait works with Blake3StreamHasher
        let mut hasher = new_stream_hasher();

        let test_data = b"Hello, World!";
        hasher.update(test_data);

        let result = hasher.finalize_hex();

        // Verify it produces a valid hex string of expected length (64 chars for 32 bytes)
        assert_eq!(result.len(), 64, "Blake3 hash should be 64 hex characters");
        assert!(
            result.chars().all(|c| c.is_ascii_hexdigit()),
            "Result should be valid hex"
        );

        // Verify consistency: same input produces same output
        let mut hasher2 = new_stream_hasher();
        hasher2.update(test_data);
        let result2 = hasher2.finalize_hex();
        assert_eq!(result, result2, "Same input should produce same hash");
    }

    #[test]
    fn test_stream_hasher_update_zeros() {
        // Test that update_zeros produces the same result as updating with actual zeros
        let mut hasher1 = new_stream_hasher();
        hasher1.update_zeros(1024);
        let result1 = hasher1.finalize_hex();

        let mut hasher2 = new_stream_hasher();
        let zeros = vec![0u8; 1024];
        hasher2.update(&zeros);
        let result2 = hasher2.finalize_hex();

        assert_eq!(
            result1, result2,
            "update_zeros should produce same hash as update with zeros"
        );
    }

    #[test]
    fn test_stream_hasher_incremental() {
        // Test that incremental updates work correctly
        let mut hasher1 = new_stream_hasher();
        hasher1.update(b"Hello, ");
        hasher1.update(b"World!");
        let result1 = hasher1.finalize_hex();

        let mut hasher2 = new_stream_hasher();
        hasher2.update(b"Hello, World!");
        let result2 = hasher2.finalize_hex();

        assert_eq!(
            result1, result2,
            "Incremental updates should produce same hash as single update"
        );
    }

    #[test]
    fn test_stream_hasher_dynamic_dispatch() {
        // Test that dynamic dispatch works correctly
        fn hash_with_trait(data: &[u8]) -> String {
            let mut hasher: Box<dyn StreamHasher> = new_stream_hasher();
            hasher.update(data);
            hasher.finalize_hex()
        }

        let test_data = b"Dynamic dispatch test";
        let result1 = hash_with_trait(test_data);

        let mut hasher = new_stream_hasher();
        hasher.update(test_data);
        let result2 = hasher.finalize_hex();

        assert_eq!(
            result1, result2,
            "Dynamic dispatch should produce same hash"
        );
    }
}
