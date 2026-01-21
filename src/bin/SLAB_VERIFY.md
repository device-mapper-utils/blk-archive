# slab-verify - Slab File Verification Utility

A standalone debug utility for verifying the integrity of SlabFile and SlabOffsets files used by blk-stash.

## Building

```bash
cargo build --bin slab-verify --release
```

The binary will be created at `./target/release/slab-verify`.

## Usage

```bash
slab-verify [OPTIONS] <SLAB_FILE>
```

### Basic Usage

```bash
# Verify a slab file and its offsets
./target/release/slab-verify /path/to/archive.slab

# Show verbose output with per-slab details
./target/release/slab-verify -v /path/to/archive.slab

# Dump all slab offsets to stdout
./target/release/slab-verify -d /path/to/archive.slab

# Regenerate the offsets file from the slab data
./target/release/slab-verify --regenerate /path/to/archive.slab
```

### Options

- `-s, --slab-file <SLAB_FILE>` - Path to the slab data file (can also be a positional argument)
- `-o, --offsets-file <OFFSETS_FILE>` - Path to the slab offsets file (defaults to `<slab_file>.offsets`)
- `--verify-crc <true|false>` - Verify CRC64 checksums on offsets file (default: true)
- `--regenerate` - Regenerate the offsets file from the slab data
- `-v, --verbose` - Show detailed information about each slab
- `-d, --dump-offsets` - Dump all slab offsets to stdout (skips verification steps)
- `--max-slabs <N>` - Verify only the first N slabs (0 = all, useful for large files)
- `-h, --help` - Print help information

## What It Verifies

The utility performs four main verification steps:

### 1. Slab File Header Verification
- Checks the file magic number (0xb927f96a6b611180)
- Verifies the format version (0)
- Validates the compression flag (0 = uncompressed, 1 = compressed)
- Reports file size

### 2. Slab Data Verification
- Reads each slab from the data file
- Verifies slab magic numbers (0x20565137a3100a7c)
- Validates slab length fields
- Computes and verifies Blake2 checksums for each slab
- Reports total number of slabs and data size

### 3. Offsets File Verification
- Checks the offsets file footer structure
- Verifies the magic number (0x7C0A10A33751562)
- Validates the entry count
- Optionally verifies CRC64 checksums over the entire data region

### 4. Cross-Validation
- Compares computed slab offsets from the data file with stored offsets
- Ensures the offset index is consistent with the actual slab locations

## File Formats

### Slab File Format
```
<header> <slab>*

header := <magic:u64> <version:u32> <flags:u32>
slab   := <magic:u64> <len:u64> <checksum:8bytes> <data:len bytes>
```

### Offsets File Format
```
<offset:u64>* <footer>

footer := <magic:u64> <count:u64> <crc64:u64>
```

## Examples

### Verify integrity
```bash
$ ./target/release/slab-verify archive.slab
Slab File Verification Utility
==============================
Slab file:    "archive.slab"
Offsets file: "archive.offsets"

[1/4] Verifying slab file header...
✓ Slab file header valid
  Magic:      0xb927f96a6b611180
  Version:    0
  Compressed: true
  File size:  328103 bytes

[2/4] Verifying slabs...
✓ Verified 1 slabs
  Total data: 328063 bytes
  Average slab size: 328063 bytes

[3/4] Verifying offsets file...
✓ Offsets file valid
  Entry count: 1
  File size:   32 bytes
  CRC64:       verified

[4/4] Comparing computed vs stored offsets...
✓ All 1 offsets match

========================================
✓ All verification checks passed!
========================================
```

### Dump slab offsets
```bash
$ ./target/release/slab-verify -d archive.slab
Slab Offsets Dump
=================
Total entries: 3

Index      Offset (bytes)       Offset (hex)
--------------------------------------------------
0          16                   0x0000000000000010
1          328103               0x0000000000050197
2          656190               0x00000000000a031e
```

This feature is useful for:
- Debugging offset-related issues
- Understanding slab layout in the file
- Quick inspection without full verification

### Regenerate corrupted offsets file
```bash
$ ./target/release/slab-verify --regenerate archive.slab
[1/4] Verifying slab file header...
✓ Slab file header valid
...
[4/4] Comparing computed vs stored offsets...
Regenerating offsets file...
✓ Offsets file regenerated successfully
```

### Quick check on large files
```bash
# Only verify first 100 slabs
$ ./target/release/slab-verify --max-slabs 100 large_archive.slab
```

## Exit Codes

- `0` - All verification checks passed
- `1` - Verification failed or error occurred

## Implementation

The utility uses the existing blk-stash library functions:
- `blk_stash::slab::file::regenerate_index()` - Rebuilds the offset index
- `blk_stash::slab::offsets::validate_slab_offsets_file()` - Validates offset file structure and CRC
- `blk_stash::slab::offsets::SlabOffsets` - Reads offset entries from the file
- `blk_stash::hash::hash_64()` - Computes Blake2 checksums

This ensures the verification logic matches the actual production code.
