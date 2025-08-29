use crate::iovec::IoVec;

//-----------------------------------------

use blake3;

pub type Hash256 = [u8; 32];
pub type Hash64 = [u8; 8];
pub type Hash32 = [u8; 4];

#[inline]
pub fn hash_256(v: &[u8]) -> Hash256 {
    *blake3::hash(v).as_bytes()
}

#[inline]
pub fn hash_256_iov(iov: &IoVec) -> Hash256 {
    let mut h = blake3::Hasher::new();
    for seg in iov.iter() {
        h.update(seg);
    }
    *h.finalize().as_bytes()
}

#[inline]
pub fn hash_64(v: &[u8]) -> Hash64 {
    let mut h = blake3::Hasher::new();
    h.update(v);
    let mut out = [0u8; 8];
    h.finalize_xof().fill(&mut out);
    out
}

#[inline]
pub fn hash_32(v: &[u8]) -> Hash32 {
    let mut h = blake3::Hasher::new();
    h.update(v);
    let mut out = [0u8; 4];
    h.finalize_xof().fill(&mut out);
    out
}

#[inline]
pub fn hash_le_u64(data: &[u8]) -> u64 {
    u64::from_le_bytes(hash_64(data))
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
}
