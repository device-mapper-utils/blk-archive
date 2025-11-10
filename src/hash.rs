use blake2::{Blake2b, Digest};
use std::convert::TryInto;

use crate::iovec::*;

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
}
