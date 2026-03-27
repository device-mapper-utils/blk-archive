use blake2::{Blake2b, Digest};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::str::FromStr;
use std::sync::OnceLock;

use crate::iovec::*;

//-----------------------------------------
// Hash Type Enumerations
//-----------------------------------------

/// Block-level hash algorithms for content-based deduplication.
/// These are used to identify duplicate blocks of data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum BlockHash {
    #[default]
    #[serde(rename = "blake2b-256")]
    Blake2b256,
    #[serde(rename = "blake3-256")]
    Blake3256,
    #[serde(rename = "xxhash3-128")]
    XxHash3128,
    #[serde(rename = "murmur3-128")]
    Murmur3128,
}

impl BlockHash {
    pub fn as_str(&self) -> &'static str {
        match self {
            BlockHash::Blake2b256 => "blake2b-256",
            BlockHash::Blake3256 => "blake3-256",
            BlockHash::XxHash3128 => "xxhash3-128",
            BlockHash::Murmur3128 => "murmur3-128",
        }
    }
}

impl FromStr for BlockHash {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blake2b-256" => Ok(BlockHash::Blake2b256),
            "blake3-256" => Ok(BlockHash::Blake3256),
            "xxhash3-128" => Ok(BlockHash::XxHash3128),
            "murmur3-128" => Ok(BlockHash::Murmur3128),
            _ => Err(format!("Unknown block hash: {}", s)),
        }
    }
}

/// Stream-level hash algorithms for stream integrity verification.
/// These are used to verify the integrity of entire archived streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum StreamHash {
    #[default]
    #[serde(rename = "blake3-256")]
    Blake3256,
    #[serde(rename = "xxhash3-128")]
    XxHash3128,
    #[serde(rename = "murmur3-128")]
    Murmur3128,
}

impl StreamHash {
    pub fn as_str(&self) -> &'static str {
        match self {
            StreamHash::Blake3256 => "blake3-256",
            StreamHash::XxHash3128 => "xxhash3-128",
            StreamHash::Murmur3128 => "murmur3-128",
        }
    }
}

impl FromStr for StreamHash {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blake3-256" => Ok(StreamHash::Blake3256),
            "xxhash3-128" => Ok(StreamHash::XxHash3128),
            "murmur3-128" => Ok(StreamHash::Murmur3128),
            _ => Err(format!("Unknown stream hash: {}", s)),
        }
    }
}

//-----------------------------------------
// Blake2b - Used for content-based deduplication
//-----------------------------------------

type Blake2b64 = Blake2b<generic_array::typenum::U8>;
type Blake2b256 = Blake2b<generic_array::typenum::U32>;

pub type Hash64 = generic_array::GenericArray<u8, generic_array::typenum::U8>;
pub type Hash256 = generic_array::GenericArray<u8, generic_array::typenum::U32>;

//-----------------------------------------
// OnceLock-based Block Hash Function Pointers
//-----------------------------------------

/// Function pointer types for block hashing
type Hash256Fn = fn(&[u8]) -> Hash256;
type Hash64Fn = fn(&[u8]) -> Hash64;
type Hash256IovFn = fn(&IoVec) -> Hash256;
type Hash64IovFn = fn(&IoVec) -> Hash64;

/// Global function pointers for block hashing, initialized at runtime
static HASH_256_FN: OnceLock<Hash256Fn> = OnceLock::new();
static HASH_64_FN: OnceLock<Hash64Fn> = OnceLock::new();
static HASH_256_IOV_FN: OnceLock<Hash256IovFn> = OnceLock::new();
static HASH_64_IOV_FN: OnceLock<Hash64IovFn> = OnceLock::new();

/// Initialize the block hash functions based on the selected algorithm.
/// This must be called once at startup before any hashing operations.
pub fn init_block_hashes(hash_type: BlockHash) {
    match hash_type {
        BlockHash::Blake2b256 => {
            HASH_256_FN.set(hash_256_blake2b).ok();
            HASH_64_FN.set(hash_64_blake2b).ok();
            HASH_256_IOV_FN.set(hash_256_iov_blake2b).ok();
            HASH_64_IOV_FN.set(hash_64_iov_blake2b).ok();
        }
        BlockHash::Blake3256 => {
            HASH_256_FN.set(hash_256_blake3).ok();
            HASH_64_FN.set(hash_64_blake3).ok();
            HASH_256_IOV_FN.set(hash_256_iov_blake3).ok();
            HASH_64_IOV_FN.set(hash_64_iov_blake3).ok();
        }
        BlockHash::XxHash3128 => {
            HASH_256_FN.set(hash_256_xxhash3).ok();
            HASH_64_FN.set(hash_64_xxhash3).ok();
            HASH_256_IOV_FN.set(hash_256_iov_xxhash3).ok();
            HASH_64_IOV_FN.set(hash_64_iov_xxhash3).ok();
        }
        BlockHash::Murmur3128 => {
            HASH_256_FN.set(hash_256_murmur3).ok();
            HASH_64_FN.set(hash_64_murmur3).ok();
            HASH_256_IOV_FN.set(hash_256_iov_murmur3).ok();
            HASH_64_IOV_FN.set(hash_64_iov_murmur3).ok();
        }
    }
}

//-----------------------------------------
// Blake2b implementations
//-----------------------------------------

fn hash_256_iov_blake2b(iov: &IoVec) -> Hash256 {
    let mut hasher = Blake2b256::new();
    for v in iov {
        hasher.update(&v[..]);
    }
    hasher.finalize()
}

fn hash_64_iov_blake2b(iov: &IoVec) -> Hash64 {
    let mut hasher = Blake2b64::new();
    for v in iov {
        hasher.update(&v[..]);
    }
    hasher.finalize()
}

fn hash_256_blake2b(v: &[u8]) -> Hash256 {
    let mut hasher = Blake2b256::new();
    hasher.update(v);
    hasher.finalize()
}

fn hash_64_blake2b(v: &[u8]) -> Hash64 {
    let mut hasher = Blake2b64::new();
    hasher.update(v);
    hasher.finalize()
}

//-----------------------------------------
// Blake3 implementations
//-----------------------------------------

fn hash_256_iov_blake3(iov: &IoVec) -> Hash256 {
    let mut hasher = blake3::Hasher::new();
    for v in iov {
        hasher.update(&v[..]);
    }
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    Hash256::clone_from_slice(bytes)
}

fn hash_64_iov_blake3(iov: &IoVec) -> Hash64 {
    let mut hasher = blake3::Hasher::new();
    for v in iov {
        hasher.update(&v[..]);
    }
    let hash = hasher.finalize();
    let bytes = hash.as_bytes();
    Hash64::clone_from_slice(&bytes[..8])
}

fn hash_256_blake3(v: &[u8]) -> Hash256 {
    let hash = blake3::hash(v);
    let bytes = hash.as_bytes();
    Hash256::clone_from_slice(bytes)
}

fn hash_64_blake3(v: &[u8]) -> Hash64 {
    let hash = blake3::hash(v);
    let bytes = hash.as_bytes();
    Hash64::clone_from_slice(&bytes[..8])
}

//-----------------------------------------
// XXHash3 implementations (128-bit hash, truncated to 256/64/32 bits)
//-----------------------------------------

fn hash_256_iov_xxhash3(iov: &IoVec) -> Hash256 {
    use xxhash_rust::xxh3::Xxh3;

    let mut hasher = Xxh3::new();
    for v in iov {
        hasher.update(&v[..]);
    }
    let hash_128 = hasher.digest128();
    let bytes = hash_128.to_le_bytes();
    // Use first 16 bytes as hash, pad remaining with zeros
    let mut result = [0u8; 32];
    result[..16].copy_from_slice(&bytes);
    Hash256::clone_from_slice(&result)
}

fn hash_64_iov_xxhash3(iov: &IoVec) -> Hash64 {
    use xxhash_rust::xxh3::Xxh3;

    let mut hasher = Xxh3::new();
    for v in iov {
        hasher.update(&v[..]);
    }
    let hash_128 = hasher.digest128();
    let bytes = hash_128.to_le_bytes();
    Hash64::clone_from_slice(&bytes[..8])
}

fn hash_256_xxhash3(v: &[u8]) -> Hash256 {
    // Use XXHash-128 but pad to 256 bits to keep ondisk format unchanged
    let h1 = xxhash_rust::xxh3::xxh3_128(v).to_le_bytes();
    let mut out = Hash256::default();
    out[..16].copy_from_slice(&h1);
    // out[16..] remain zeroed
    out
}

fn hash_64_xxhash3(v: &[u8]) -> Hash64 {
    use xxhash_rust::xxh3::Xxh3;

    let mut hasher = Xxh3::new();
    hasher.update(v);
    let hash_128 = hasher.digest128();
    let bytes = hash_128.to_le_bytes();
    Hash64::clone_from_slice(&bytes[..8])
}

//-----------------------------------------
// Murmur3 implementations (128-bit hash, truncated to 256/64/32 bits)
//-----------------------------------------

fn hash_256_iov_murmur3(iov: &IoVec) -> Hash256 {
    use fasthash::murmur3::Hasher128_x64;
    use fasthash::{FastHasher, HasherExt};
    use std::hash::Hasher;

    let mut hasher = Hasher128_x64::new();
    for v in iov {
        hasher.write(&v[..]);
    }
    let hash_128 = hasher.finish_ext();
    let bytes = hash_128.to_le_bytes();
    // Use first 16 bytes as hash, pad remaining with zeros
    let mut result = [0u8; 32];
    result[..16].copy_from_slice(&bytes);
    Hash256::clone_from_slice(&result)
}

fn hash_64_iov_murmur3(iov: &IoVec) -> Hash64 {
    use fasthash::murmur3::Hasher128_x64;
    use fasthash::{FastHasher, HasherExt};
    use std::hash::Hasher;

    let mut hasher = Hasher128_x64::new();
    for v in iov {
        hasher.write(&v[..]);
    }
    let hash_128 = hasher.finish_ext();
    let bytes = hash_128.to_le_bytes();
    Hash64::clone_from_slice(&bytes[..8])
}

fn hash_256_murmur3(v: &[u8]) -> Hash256 {
    use fasthash::murmur3::Hasher128_x64;
    use fasthash::{FastHasher, HasherExt};
    use std::hash::Hasher;

    let mut hasher = Hasher128_x64::new();
    hasher.write(v);
    let hash_128 = hasher.finish_ext();
    let bytes = hash_128.to_le_bytes();
    // Use first 16 bytes as hash, pad remaining with zeros
    let mut result = [0u8; 32];
    result[..16].copy_from_slice(&bytes);
    Hash256::clone_from_slice(&result)
}

fn hash_64_murmur3(v: &[u8]) -> Hash64 {
    use fasthash::murmur3::Hasher128_x64;
    use fasthash::{FastHasher, HasherExt};
    use std::hash::Hasher;

    let mut hasher = Hasher128_x64::new();
    hasher.write(v);
    let hash_128 = hasher.finish_ext();
    let bytes = hash_128.to_le_bytes();
    Hash64::clone_from_slice(&bytes[..8])
}

//-----------------------------------------
// Public API - uses function pointers initialized by init_block_hashes
//-----------------------------------------

pub fn hash_256_iov(iov: &IoVec) -> Hash256 {
    let f = HASH_256_IOV_FN
        .get()
        .expect("hash functions must be initialized with init_block_hashes");
    f(iov)
}

pub fn hash_64_iov(iov: &IoVec) -> Hash64 {
    let f = HASH_64_IOV_FN
        .get()
        .expect("hash functions must be initialized with init_block_hashes");
    f(iov)
}

pub fn hash_256(v: &[u8]) -> Hash256 {
    let f = HASH_256_FN
        .get()
        .expect("hash functions must be initialized with init_block_hashes");
    f(v)
}

pub fn hash_64(v: &[u8]) -> Hash64 {
    let f = HASH_64_FN
        .get()
        .expect("hash functions must be initialized with init_block_hashes");
    f(v)
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

/// Factory function to create a stream hasher based on the selected algorithm.
pub fn new_stream_hasher(hash_type: StreamHash) -> Box<dyn StreamHasher> {
    match hash_type {
        StreamHash::Blake3256 => Blake3StreamHasher::boxed(),
        StreamHash::XxHash3128 => XxHash3StreamHasher::boxed(),
        StreamHash::Murmur3128 => Murmur3StreamHasher::boxed(),
    }
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

/// XXHash3 implementation of StreamHasher.
/// Provides fast non-cryptographic hashing for stream integrity verification.
pub struct XxHash3StreamHasher {
    hasher: xxhash_rust::xxh3::Xxh3,
}

impl Default for XxHash3StreamHasher {
    fn default() -> Self {
        XxHash3StreamHasher {
            hasher: xxhash_rust::xxh3::Xxh3::new(),
        }
    }
}

impl XxHash3StreamHasher {
    /// Create a new XxHash3StreamHasher wrapped in a Box for dynamic dispatch.
    pub fn boxed() -> Box<dyn StreamHasher> {
        Box::new(XxHash3StreamHasher::default())
    }
}

impl StreamHasher for XxHash3StreamHasher {
    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize_hex(self: Box<Self>) -> String {
        let hash_128 = self.hasher.digest128();
        format!("{:032x}", hash_128)
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

/// Murmur3 implementation of StreamHasher.
/// Provides fast non-cryptographic hashing for stream integrity verification.
pub struct Murmur3StreamHasher {
    hasher: fasthash::murmur3::Hasher128_x64,
}

impl Murmur3StreamHasher {
    /// Create a new Murmur3StreamHasher wrapped in a Box for dynamic dispatch.
    pub fn boxed() -> Box<dyn StreamHasher> {
        use fasthash::FastHasher;
        Box::new(Murmur3StreamHasher {
            hasher: fasthash::murmur3::Hasher128_x64::new(),
        })
    }
}

impl Default for Murmur3StreamHasher {
    fn default() -> Self {
        use fasthash::FastHasher;
        Murmur3StreamHasher {
            hasher: fasthash::murmur3::Hasher128_x64::new(),
        }
    }
}

impl StreamHasher for Murmur3StreamHasher {
    fn update(&mut self, data: &[u8]) {
        use std::hash::Hasher;
        self.hasher.write(data);
    }

    fn finalize_hex(self: Box<Self>) -> String {
        use fasthash::HasherExt;
        let hash_128 = self.hasher.finish_ext();
        format!("{:032x}", hash_128)
    }

    fn update_zeros(&mut self, len: u64) {
        use std::hash::Hasher;
        const ZERO_BUF: [u8; 4096] = [0; 4096];

        let mut remaining = len;
        while remaining > 0 {
            let hash_len = std::cmp::min(ZERO_BUF.len() as u64, remaining);
            self.hasher.write(&ZERO_BUF[0..hash_len as usize]);
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
        init_block_hashes(BlockHash::default());
        let h = vec![0, 1, 2, 3, 4, 5, 6, 7];

        // What we previously had
        let mini_hash = hash_64(&h);
        let mut c = Cursor::new(&mini_hash);
        let previous = c.read_u64::<LittleEndian>().unwrap();

        // What we are replacing it with
        let current = hash_le_u64(&h);
        assert_eq!(previous, current);
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
    const ENDIAN_ERROR_STRING: &str = "little-endian host";

    #[cfg(target_endian = "big")]
    const ENDIAN_ERROR_STRING: &str = "big-endian host";

    #[test]
    fn test_blake_endianness_little_endian() {
        let mut hasher = Blake2b256::new();
        hasher.update(TEST_INPUT_BYTES);
        let result = hasher.finalize();

        assert_eq!(
            &result[..],
            EXPECTED_HASH,
            "blake2b hash differs from canonical reference on {}",
            ENDIAN_ERROR_STRING
        );
    }

    #[test]
    fn test_block_hash_serialization() {
        // Test that serialized format matches CLI options
        let test_cases = vec![
            (BlockHash::Blake2b256, "blake2b-256"),
            (BlockHash::Blake3256, "blake3-256"),
            (BlockHash::XxHash3128, "xxhash3-128"),
            (BlockHash::Murmur3128, "murmur3-128"),
        ];

        for (hash, expected) in test_cases {
            // Test serialization
            let yaml = serde_yaml_ng::to_string(&hash).unwrap();
            assert_eq!(yaml.trim(), expected);
            assert_eq!(hash.as_str(), expected);

            // Test deserialization
            let deserialized: BlockHash = serde_yaml_ng::from_str(expected).unwrap();
            assert_eq!(deserialized, hash);
        }
    }

    #[test]
    fn test_stream_hash_serialization() {
        // Test that serialized format matches CLI options
        let test_cases = vec![
            (StreamHash::Blake3256, "blake3-256"),
            (StreamHash::XxHash3128, "xxhash3-128"),
            (StreamHash::Murmur3128, "murmur3-128"),
        ];

        for (hash, expected) in test_cases {
            // Test serialization
            let yaml = serde_yaml_ng::to_string(&hash).unwrap();
            assert_eq!(yaml.trim(), expected);
            assert_eq!(hash.as_str(), expected);

            // Test deserialization
            let deserialized: StreamHash = serde_yaml_ng::from_str(expected).unwrap();
            assert_eq!(deserialized, hash);
        }
    }
}
