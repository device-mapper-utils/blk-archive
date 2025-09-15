use anyhow::Result;

//-----------------------------------------

pub struct IoVec<'a>(pub Vec<&'a [u8]>);

pub trait IoVecHandler {
    fn handle_data(&mut self, iov: &IoVec) -> Result<()>;
    fn complete(&mut self) -> Result<()>;
}

/// Allow `IoVec::from(slice)`
impl<'a> From<&'a [u8]> for IoVec<'a> {
    fn from(s: &'a [u8]) -> Self {
        IoVec(vec![s])
    }
}

impl<'a> Default for IoVec<'a> {
    fn default() -> Self {
        Self::new()
    }
}

pub fn to_iovec(buf: &[u8]) -> IoVec<'_> {
    IoVec::from(buf)
}

impl<'a> IoVec<'a> {
    pub fn new() -> Self {
        IoVec(Vec::new())
    }

    pub fn len(&self) -> usize {
        self.0.iter().map(|s| s.len()).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> std::slice::Iter<'_, &'a [u8]> {
        self.0.iter()
    }

    pub fn push(&mut self, slice: &'a [u8]) {
        self.0.push(slice);
    }
}

impl<'a, 'b> IntoIterator for &'b IoVec<'a> {
    type Item = &'b &'a [u8];
    type IntoIter = std::slice::Iter<'b, &'a [u8]>;
    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}
