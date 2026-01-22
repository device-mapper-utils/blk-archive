use std::collections::VecDeque;
use std::io::{Read, Result as IoResult};

/// A Read adapter that provides a Read interface over a VecDeque of buffers.
/// This allows StreamCDC to read from accumulated buffers without copying all data.
pub struct VecDequeReader<'a> {
    buffers: &'a VecDeque<Vec<u8>>,
    current_buffer_idx: usize,
    current_offset: usize,
}

impl<'a> VecDequeReader<'a> {
    /// Create a new reader that reads from all buffers in the VecDeque
    pub fn new(buffers: &'a VecDeque<Vec<u8>>) -> Self {
        Self {
            buffers,
            current_buffer_idx: 0,
            current_offset: 0,
        }
    }

    /// Create a new reader starting from a specific position
    /// This allows reading only unconsumed data
    pub fn new_from_position(
        buffers: &'a VecDeque<Vec<u8>>,
        start_buffer: usize,
        start_offset: usize,
    ) -> Self {
        Self {
            buffers,
            current_buffer_idx: start_buffer,
            current_offset: start_offset,
        }
    }

    /// Get the total bytes available to read
    pub fn available(&self) -> usize {
        if self.current_buffer_idx >= self.buffers.len() {
            return 0;
        }

        let mut total = 0;

        // First buffer (partial read)
        if let Some(buf) = self.buffers.get(self.current_buffer_idx) {
            total += buf.len().saturating_sub(self.current_offset);
        }

        // Remaining buffers (full read)
        for i in (self.current_buffer_idx + 1)..self.buffers.len() {
            total += self.buffers[i].len();
        }

        total
    }
}

impl<'a> Read for VecDequeReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let mut total_read = 0;

        while total_read < buf.len() && self.current_buffer_idx < self.buffers.len() {
            let current_buf = &self.buffers[self.current_buffer_idx];

            // Calculate how much we can read from current buffer
            let available_in_buffer = current_buf.len() - self.current_offset;

            if available_in_buffer == 0 {
                // Move to next buffer
                self.current_buffer_idx += 1;
                self.current_offset = 0;
                continue;
            }

            // Read as much as we can
            let to_read = std::cmp::min(available_in_buffer, buf.len() - total_read);
            let src = &current_buf[self.current_offset..self.current_offset + to_read];
            buf[total_read..total_read + to_read].copy_from_slice(src);

            self.current_offset += to_read;
            total_read += to_read;

            // If we've exhausted this buffer, move to next
            if self.current_offset >= current_buf.len() {
                self.current_buffer_idx += 1;
                self.current_offset = 0;
            }
        }

        Ok(total_read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_reader() {
        let buffers = VecDeque::new();
        let mut reader = VecDequeReader::new(&buffers);

        let mut buf = [0u8; 10];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 0);
        assert_eq!(reader.available(), 0);
    }

    #[test]
    fn test_single_buffer() {
        let mut buffers = VecDeque::new();
        buffers.push_back(vec![1, 2, 3, 4, 5]);

        let mut reader = VecDequeReader::new(&buffers);
        assert_eq!(reader.available(), 5);

        let mut buf = [0u8; 10];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], &[1, 2, 3, 4, 5]);
        assert_eq!(reader.available(), 0);
    }

    #[test]
    fn test_multiple_buffers() {
        let mut buffers = VecDeque::new();
        buffers.push_back(vec![1, 2, 3]);
        buffers.push_back(vec![4, 5, 6]);
        buffers.push_back(vec![7, 8, 9]);

        let mut reader = VecDequeReader::new(&buffers);
        assert_eq!(reader.available(), 9);

        let mut buf = [0u8; 9];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 9);
        assert_eq!(&buf[..], &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_small_reads() {
        let mut buffers = VecDeque::new();
        buffers.push_back(vec![1, 2, 3]);
        buffers.push_back(vec![4, 5, 6]);

        let mut reader = VecDequeReader::new(&buffers);

        // Read 2 bytes at a time
        let mut buf = [0u8; 2];

        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..], &[1, 2]);

        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..], &[3, 4]);

        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..], &[5, 6]);

        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 0); // EOF
    }

    #[test]
    fn test_from_position() {
        let mut buffers = VecDeque::new();
        buffers.push_back(vec![1, 2, 3, 4, 5]);
        buffers.push_back(vec![6, 7, 8, 9, 10]);

        // Start from buffer 0, offset 2
        let mut reader = VecDequeReader::new_from_position(&buffers, 0, 2);
        assert_eq!(reader.available(), 8); // 3 + 5

        let mut buf = [0u8; 8];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 8);
        assert_eq!(&buf[..], &[3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_from_position_second_buffer() {
        let mut buffers = VecDeque::new();
        buffers.push_back(vec![1, 2, 3]);
        buffers.push_back(vec![4, 5, 6]);
        buffers.push_back(vec![7, 8, 9]);

        // Start from buffer 1, offset 1
        let mut reader = VecDequeReader::new_from_position(&buffers, 1, 1);
        assert_eq!(reader.available(), 5); // 2 from buffer 1, 3 from buffer 2

        let mut buf = [0u8; 10];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], &[5, 6, 7, 8, 9]);
    }
}
