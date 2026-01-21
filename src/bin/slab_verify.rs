use anyhow::{anyhow, Context, Result};
use blk_stash::slab::file::regenerate_index;
use blk_stash::slab::offsets::validate_slab_offsets_file;
use byteorder::{LittleEndian, ReadBytesExt};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const FILE_MAGIC: u64 = 0xb927f96a6b611180;
const SLAB_MAGIC: u64 = 0x20565137a3100a7c;
const FORMAT_VERSION: u32 = 0;
const SLAB_FILE_HDR_LEN: u64 = 16;
const SLAB_META_SIZE: u64 = 24;

struct Args {
    /// Path to the slab data file (e.g., archive.slab)
    slab_file: PathBuf,

    /// Path to the slab offsets file (defaults to <slab_file>.offsets)
    offsets_file: Option<PathBuf>,

    /// Verify CRC checksums on offsets file
    verify_crc: bool,

    /// Regenerate the offsets file from the slab file
    regenerate: bool,

    /// Show detailed information about each slab
    verbose: bool,

    /// Maximum number of slabs to verify (0 = all)
    max_slabs: usize,

    /// Dump all slab offsets to stdout
    dump_offsets: bool,
}

fn parse_args() -> Result<Args> {
    let mut args = std::env::args().skip(1);
    let mut slab_file = None;
    let mut offsets_file = None;
    let mut verify_crc = true;
    let mut regenerate = false;
    let mut verbose = false;
    let mut max_slabs = 0;
    let mut dump_offsets = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-s" | "--slab-file" => {
                slab_file = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow!("Missing value for --slab-file"))?,
                ));
            }
            "-o" | "--offsets-file" => {
                offsets_file =
                    Some(PathBuf::from(args.next().ok_or_else(|| {
                        anyhow!("Missing value for --offsets-file")
                    })?));
            }
            "--verify-crc" => {
                let val = args
                    .next()
                    .ok_or_else(|| anyhow!("Missing value for --verify-crc"))?;
                verify_crc = val == "true";
            }
            "--regenerate" => {
                regenerate = true;
            }
            "-v" | "--verbose" => {
                verbose = true;
            }
            "--max-slabs" => {
                max_slabs = args
                    .next()
                    .ok_or_else(|| anyhow!("Missing value for --max-slabs"))?
                    .parse()?;
            }
            "-d" | "--dump-offsets" => {
                dump_offsets = true;
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            _ => {
                // Treat as positional slab file if not set yet
                if slab_file.is_none() {
                    slab_file = Some(PathBuf::from(arg));
                } else {
                    return Err(anyhow!("Unknown argument: {}", arg));
                }
            }
        }
    }

    Ok(Args {
        slab_file: slab_file.ok_or_else(|| anyhow!("Missing required argument: --slab-file"))?,
        offsets_file,
        verify_crc,
        regenerate,
        verbose,
        max_slabs,
        dump_offsets,
    })
}

fn print_help() {
    println!("Slab File Verification Utility");
    println!();
    println!("USAGE:");
    println!("    slab-verify [OPTIONS] --slab-file <SLAB_FILE>");
    println!("    slab-verify [OPTIONS] <SLAB_FILE>");
    println!();
    println!("OPTIONS:");
    println!("    -s, --slab-file <SLAB_FILE>       Path to the slab data file");
    println!("    -o, --offsets-file <OFFSETS_FILE> Path to the slab offsets file");
    println!("    --verify-crc <true|false>         Verify CRC checksums (default: true)");
    println!("    --regenerate                      Regenerate the offsets file");
    println!("    -v, --verbose                     Show detailed information");
    println!("    -d, --dump-offsets                Dump all slab offsets to stdout");
    println!("    --max-slabs <N>                   Maximum slabs to verify (0 = all)");
    println!("    -h, --help                        Print help information");
}

fn offsets_path(slab_path: PathBuf) -> PathBuf {
    let mut offsets_path = slab_path.clone();
    offsets_path.set_extension("offsets");
    offsets_path
}

fn verify_slab_file_header(slab_path: &Path) -> Result<(bool, u64)> {
    let mut data = OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .open(slab_path)
        .with_context(|| format!("Failed to open slab file: {:?}", slab_path))?;

    let file_size = data.metadata()?.len();

    if file_size < SLAB_FILE_HDR_LEN {
        return Err(anyhow!(
            "Slab file is too small ({} bytes) to contain a valid header (needs {} bytes)",
            file_size,
            SLAB_FILE_HDR_LEN
        ));
    }

    let magic = data
        .read_u64::<LittleEndian>()
        .context("Failed to read magic number")?;
    let version = data
        .read_u32::<LittleEndian>()
        .context("Failed to read version")?;
    let flags = data
        .read_u32::<LittleEndian>()
        .context("Failed to read flags")?;

    if magic != FILE_MAGIC {
        return Err(anyhow!(
            "Invalid file magic: expected 0x{:016x}, got 0x{:016x}",
            FILE_MAGIC,
            magic
        ));
    }

    if version != FORMAT_VERSION {
        return Err(anyhow!(
            "Unsupported format version: expected {}, got {}",
            FORMAT_VERSION,
            version
        ));
    }

    let compressed = match flags {
        0 => false,
        1 => true,
        _ => {
            return Err(anyhow!(
                "Invalid flags value: expected 0 or 1, got {}",
                flags
            ))
        }
    };

    println!("✓ Slab file header valid");
    println!("  Magic:      0x{:016x}", magic);
    println!("  Version:    {}", version);
    println!("  Compressed: {}", compressed);
    println!("  File size:  {} bytes", file_size);

    Ok((compressed, file_size))
}

fn verify_slabs(slab_path: &Path, verbose: bool, max_slabs: usize) -> Result<Vec<u64>> {
    let mut data = OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .open(slab_path)?;

    let file_size = data.metadata()?.len();

    // Skip header
    data.seek(SeekFrom::Start(SLAB_FILE_HDR_LEN))?;

    let mut offsets = Vec::new();
    let mut slab_index = 0;
    let mut total_data_bytes = 0u64;
    let mut total_slabs = 0;

    // Check if file is empty (header only)
    if data.stream_position()? >= file_size {
        println!("✓ Verified {} slabs", total_slabs);
        println!("  Total data: {} bytes", total_data_bytes);
        println!("  Average slab size: {} bytes", 0);
        return Ok(offsets); // Empty file, return empty offsets
    }

    offsets.push(SLAB_FILE_HDR_LEN); // First slab starts after header

    loop {
        let curr_offset = data.stream_position()?;
        if curr_offset >= file_size {
            break;
        }

        let remaining = file_size - curr_offset;
        if remaining < SLAB_META_SIZE {
            return Err(anyhow!(
                "Slab {} is incomplete: only {} bytes remaining (need {})",
                slab_index,
                remaining,
                SLAB_META_SIZE
            ));
        }

        let magic = data.read_u64::<LittleEndian>()?;
        let len = data.read_u64::<LittleEndian>()?;

        if magic != SLAB_MAGIC {
            return Err(anyhow!(
                "Invalid slab magic at slab {}: expected 0x{:016x}, got 0x{:016x}",
                slab_index,
                SLAB_MAGIC,
                magic
            ));
        }

        let mut expected_csum = [0u8; 8];
        data.read_exact(&mut expected_csum)?;

        if remaining < SLAB_META_SIZE + len {
            return Err(anyhow!(
                "Slab {} payload is truncated: need {} bytes, have {} remaining",
                slab_index,
                SLAB_META_SIZE + len,
                remaining
            ));
        }

        // Read and verify checksum
        let mut buf = vec![0; len as usize];
        data.read_exact(&mut buf)?;

        let actual_csum = blk_stash::hash::hash_64(&buf);
        if actual_csum[..] != expected_csum[..] {
            return Err(anyhow!(
                "Checksum mismatch at slab {}: expected {:02x?}, got {:02x?}",
                slab_index,
                expected_csum,
                actual_csum
            ));
        }

        if verbose {
            println!(
                "  Slab {}: offset={}, size={} bytes, checksum=ok",
                slab_index, curr_offset, len
            );
        }

        total_data_bytes += len;
        total_slabs += 1;

        let next_offset = data.stream_position()?;
        if next_offset < file_size {
            offsets.push(next_offset);
        }

        slab_index += 1;

        if max_slabs > 0 && slab_index >= max_slabs {
            println!("  (Stopped at {} slabs as requested)", max_slabs);
            break;
        }
    }

    println!("✓ Verified {} slabs", total_slabs);
    println!("  Total data: {} bytes", total_data_bytes);
    println!(
        "  Average slab size: {} bytes",
        if total_slabs > 0 {
            total_data_bytes / total_slabs
        } else {
            0
        }
    );

    Ok(offsets)
}

fn verify_offsets_file(offsets_path: &Path, verify_crc: bool) -> Result<usize> {
    let is_valid = validate_slab_offsets_file(offsets_path, verify_crc)?;

    if !is_valid {
        return Err(anyhow!("Offsets file validation failed"));
    }

    // Get count from file
    let mut f = OpenOptions::new()
        .read(true)
        .write(false)
        .open(offsets_path)?;

    let len = f.metadata()?.len();

    if len == 0 {
        println!("✓ Offsets file valid (empty)");
        return Ok(0);
    }

    // Read footer to get count
    f.seek(SeekFrom::End(-24))?;
    let mut footer = [0u8; 24];
    f.read_exact(&mut footer)?;

    let count = u64::from_le_bytes(footer[8..16].try_into().unwrap());

    println!("✓ Offsets file valid");
    println!("  Entry count: {}", count);
    println!("  File size:   {} bytes", len);
    if verify_crc {
        println!("  CRC64:       verified");
    } else {
        println!("  CRC64:       not verified");
    }

    Ok(count as usize)
}

fn compare_offsets(computed: &[u64], offsets_path: &PathBuf) -> Result<()> {
    use blk_stash::slab::offsets::SlabOffsets;

    let offsets = SlabOffsets::open(offsets_path, false)?;

    if computed.len() != offsets.len() {
        return Err(anyhow!(
            "Offset count mismatch: slab file has {} entries, offsets file has {}",
            computed.len(),
            offsets.len()
        ));
    }

    for (i, &computed_offset) in computed.iter().enumerate() {
        let stored_offset = offsets
            .get_slab_offset(i)
            .ok_or_else(|| anyhow!("Failed to get offset at index {}", i))?;

        if computed_offset != stored_offset {
            return Err(anyhow!(
                "Offset mismatch at index {}: computed={}, stored={}",
                i,
                computed_offset,
                stored_offset
            ));
        }
    }

    println!("✓ All {} offsets match", computed.len());
    Ok(())
}

fn dump_offsets(offsets_path: &PathBuf) -> Result<()> {
    use blk_stash::slab::offsets::SlabOffsets;

    let offsets = SlabOffsets::open(offsets_path, false)?;
    let count = offsets.len();

    println!("Slab Offsets Dump");
    println!("=================");
    println!("Total entries: {}\n", count);
    println!(
        "{:<10} {:<20} {:<20}",
        "Index", "Offset (bytes)", "Offset (hex)"
    );
    println!("{}", "-".repeat(50));

    for i in 0..count {
        if let Some(offset) = offsets.get_slab_offset(i) {
            println!("{:<10} {:<20} 0x{:016x}", i, offset, offset);
        } else {
            return Err(anyhow!("Failed to get offset at index {}", i));
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = parse_args()?;

    let offsets_path = args
        .offsets_file
        .clone()
        .unwrap_or_else(|| offsets_path(args.slab_file.clone()));

    // If dump_offsets is specified, just dump and exit
    if args.dump_offsets {
        if !offsets_path.exists() {
            return Err(anyhow!("Offsets file does not exist: {:?}", offsets_path));
        }
        return dump_offsets(&offsets_path);
    }

    println!("Slab File Verification Utility");
    println!("==============================");
    println!("Slab file:    {:?}", args.slab_file);
    println!("Offsets file: {:?}", offsets_path);
    println!();

    // Step 1: Verify slab file header
    println!("[1/4] Verifying slab file header...");
    let (_compressed, _file_size) = verify_slab_file_header(&args.slab_file)?;
    println!();

    // Step 2: Verify all slabs
    println!("[2/4] Verifying slabs...");
    let computed_offsets = verify_slabs(&args.slab_file, args.verbose, args.max_slabs)?;
    println!();

    // Step 3: Verify offsets file if it exists
    println!("[3/4] Verifying offsets file...");
    if offsets_path.exists() {
        verify_offsets_file(&offsets_path, args.verify_crc)?;
    } else {
        println!("⚠ Offsets file does not exist");
    }
    println!();

    // Step 4: Compare computed offsets with stored offsets
    println!("[4/4] Comparing computed vs stored offsets...");
    if offsets_path.exists() && !args.regenerate {
        compare_offsets(&computed_offsets, &offsets_path)?;
    } else if args.regenerate {
        println!("Regenerating offsets file...");
        let mut so = regenerate_index(&args.slab_file, None)?;
        so.write_offset_file(true)?;
        println!("✓ Offsets file regenerated successfully");
    } else {
        println!("⚠ Skipping comparison (offsets file doesn't exist)");
    }
    println!();

    println!("========================================");
    println!("✓ All verification checks passed!");
    println!("========================================");

    Ok(())
}
