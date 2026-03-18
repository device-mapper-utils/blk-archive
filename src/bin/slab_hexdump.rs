use anyhow::{anyhow, Context, Result};
use blk_stash::config::StreamConfig;
use blk_stash::stream_metadata::deserialize_stream_config;
use byteorder::{LittleEndian, ReadBytesExt};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

const SLAB_MAGIC: u64 = 0x20565137a3100a7c;
const FILE_MAGIC: u64 = 0xb927f96a6b611180;
const SLAB_FILE_HDR_LEN: u64 = 16;

struct Args {
    /// Path to the slab file
    slab_file: PathBuf,

    /// Maximum number of slabs to dump (0 = all)
    max_slabs: Option<usize>,

    /// Bytes per line in hex dump
    bytes_per_line: usize,

    /// Show file header
    show_header: bool,

    /// Specific slab to dump (if None, dump all)
    slab_id: Option<u32>,

    /// Slab type (auto, metadata, mappings)
    slab_type: SlabType,
}

#[derive(Clone, Copy, PartialEq)]
enum SlabType {
    Auto,
    Metadata,
    Mappings,
}

fn parse_args() -> Result<Args> {
    let mut args = std::env::args().skip(1);
    let mut slab_file = None;
    let mut max_slabs = None;
    let mut bytes_per_line = 16;
    let mut show_header = false;
    let mut slab_id = None;
    let mut slab_type = SlabType::Auto;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-f" | "--file" => {
                slab_file = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow!("Missing value for --file"))?,
                ));
            }
            "-n" | "--max-slabs" => {
                let val = args
                    .next()
                    .ok_or_else(|| anyhow!("Missing value for --max-slabs"))?;
                max_slabs = Some(val.parse()?);
            }
            "-w" | "--width" => {
                let val = args
                    .next()
                    .ok_or_else(|| anyhow!("Missing value for --width"))?;
                bytes_per_line = val.parse()?;
            }
            "-H" | "--show-header" => {
                show_header = true;
            }
            "-s" | "--slab" => {
                let val = args
                    .next()
                    .ok_or_else(|| anyhow!("Missing value for --slab"))?;
                slab_id = Some(val.parse()?);
            }
            "-t" | "--type" => {
                let val = args
                    .next()
                    .ok_or_else(|| anyhow!("Missing value for --type"))?;
                slab_type = match val.as_str() {
                    "auto" => SlabType::Auto,
                    "metadata" => SlabType::Metadata,
                    "mappings" => SlabType::Mappings,
                    _ => {
                        return Err(anyhow!(
                            "Invalid slab type: {} (must be auto, metadata, or mappings)",
                            val
                        ))
                    }
                };
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
        slab_file: slab_file.ok_or_else(|| anyhow!("Missing required argument: slab file"))?,
        max_slabs,
        bytes_per_line,
        show_header,
        slab_id,
        slab_type,
    })
}

fn print_help() {
    println!("Slab File Hex Dump Utility");
    println!();
    println!("A content-aware hex dump tool for blk-stash slab files.");
    println!();
    println!("USAGE:");
    println!("    slab-hexdump [OPTIONS] <SLAB_FILE>");
    println!();
    println!("OPTIONS:");
    println!("    -f, --file <FILE>      Path to the slab file");
    println!("    -s, --slab <ID>        Dump only this slab ID");
    println!("    -n, --max-slabs <N>    Maximum number of slabs to dump");
    println!("    -w, --width <N>        Bytes per line (default: 16)");
    println!("    -t, --type <TYPE>      Slab type: auto (default), metadata, or mappings");
    println!("    -H, --show-header      Show file header");
    println!("    -h, --help             Print help information");
    println!();
    println!("EXAMPLES:");
    println!("    # Dump all slabs from a mapping file");
    println!("    slab-hexdump archive/streams/mappings");
    println!();
    println!("    # Dump only slab 0 with 32 bytes per line");
    println!("    slab-hexdump -s 0 -w 32 archive/streams/mappings");
    println!();
    println!("    # Show file header and first 3 slabs");
    println!("    slab-hexdump -H -n 3 archive/streams/metadata");
    println!();
    println!("    # Force interpretation as metadata");
    println!("    slab-hexdump -t metadata archive/streams/metadata");
}

fn dump_hex_line(offset: u64, data: &[u8], bytes_per_line: usize, interpretation: Option<&str>) {
    // Print offset
    print!("{:08x}  ", offset);

    // Print hex bytes
    for i in 0..bytes_per_line {
        if i < data.len() {
            print!("{:02x} ", data[i]);
        } else {
            print!("   ");
        }

        // Add extra space in the middle for readability
        if bytes_per_line == 16 && i == 7 {
            print!(" ");
        }
    }

    // Print interpretation or ASCII
    print!(" |");
    if let Some(interp) = interpretation {
        print!("{}", interp);
    } else {
        for &byte in data {
            if byte.is_ascii_graphic() || byte == b' ' {
                print!("{}", byte as char);
            } else {
                print!(".");
            }
        }
    }
    println!("|");
}

fn interpret_stream_instruction_byte(tag_byte: u8) -> String {
    let tag = tag_byte >> 4;
    let nibble = tag_byte & 0xf;

    match tag {
        0 => format!("Rot({})", nibble),
        1 => format!("Dup({})", nibble),
        2 => match nibble {
            1 => "Fill8".to_string(),
            2 => "Fill16".to_string(),
            3 => "Fill32".to_string(),
            4 => "Fill64".to_string(),
            5 => "SetFill".to_string(),
            _ => format!("Fill?({:x})", nibble),
        },
        3 => match nibble {
            1 => "Unmapped8".to_string(),
            2 => "Unmapped16".to_string(),
            3 => "Unmapped32".to_string(),
            4 => "Unmapped64".to_string(),
            5 => "Pos32".to_string(),
            6 => "Pos64".to_string(),
            7 => "Partial".to_string(),
            8 => "NextSlab".to_string(),
            _ => format!("Unmap?({:x})", nibble),
        },
        4 => "Slab16".to_string(),
        5 => "Slab32".to_string(),
        6 => format!("SlabΔ4({:+})", (nibble as i8) << 4 >> 4),
        7 => "SlabΔ12".to_string(),
        8 => format!("Offset4({})", nibble),
        9 => "Offset12".to_string(),
        10 => "Offset20".to_string(),
        11 => format!("OffsetΔ4({:+})", (nibble as i8) << 4 >> 4),
        12 => "OffsetΔ12".to_string(),
        13 => format!("Emit4({})", nibble),
        14 => "Emit12".to_string(),
        15 => "Emit20".to_string(),
        _ => format!("?{:x}", tag),
    }
}

struct InstructionParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> InstructionParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn peek_byte(&self) -> Option<u8> {
        if self.pos < self.data.len() {
            Some(self.data[self.pos])
        } else {
            None
        }
    }

    fn read_byte(&mut self) -> Option<u8> {
        let byte = self.peek_byte()?;
        self.pos += 1;
        Some(byte)
    }

    fn instruction_length(&mut self) -> usize {
        let start_pos = self.pos;
        let tag_byte = match self.read_byte() {
            Some(b) => b,
            None => return 0,
        };

        let tag = tag_byte >> 4;
        let nibble = tag_byte & 0xf;

        // Calculate additional bytes needed based on instruction type
        let extra_bytes = match tag {
            0 | 1 => 0, // Rot, Dup - no extra bytes
            2 => match nibble {
                1 => 1, // Fill8 - 1 byte
                2 => 2, // Fill16 - 2 bytes
                3 => 4, // Fill32 - 4 bytes
                4 => 8, // Fill64 - 8 bytes
                5 => 1, // SetFill - 1 byte
                _ => 0,
            },
            3 => match nibble {
                1 => 1, // Unmapped8 - 1 byte
                2 => 2, // Unmapped16 - 2 bytes
                3 => 4, // Unmapped32 - 4 bytes
                4 => 8, // Unmapped64 - 8 bytes
                5 => 4, // Pos32 - 4 bytes
                6 => 8, // Pos64 - 8 bytes
                7 => 8, // Partial - 4 + 4 bytes
                8 => 0, // NextSlab - no extra bytes
                _ => 0,
            },
            4 => 2,  // Slab16 - 2 bytes
            5 => 4,  // Slab32 - 4 bytes
            6 => 0,  // SlabDelta4 - nibble only
            7 => 1,  // SlabDelta12 - 1 byte
            8 => 0,  // Offset4 - nibble only
            9 => 1,  // Offset12 - 1 byte
            10 => 2, // Offset20 - 2 bytes
            11 => 0, // OffsetDelta4 - nibble only
            12 => 1, // OffsetDelta12 - 1 byte
            13 => 0, // Emit4 - nibble only
            14 => 1, // Emit12 - 1 byte
            15 => 2, // Emit20 - 2 bytes
            _ => 0,
        };

        self.pos += extra_bytes;
        self.pos - start_pos
    }
}

fn format_metadata(config: &StreamConfig) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push(format!(
        "name: {}",
        config.name.as_deref().unwrap_or("<none>")
    ));
    lines.push(format!("source_path: {}", config.source_path));
    lines.push(format!("pack_time: {}", config.pack_time));
    lines.push(format!("size: {} bytes", config.size));
    lines.push(format!("mapped_size: {} bytes", config.mapped_size));
    lines.push(format!("packed_size: {} bytes", config.packed_size));
    lines.push(format!(
        "thin_id: {}",
        config
            .thin_id
            .map_or("<none>".to_string(), |id| id.to_string())
    ));
    lines.push(format!(
        "source_sig: {}",
        config.source_sig.as_deref().unwrap_or("<none>")
    ));
    lines.push(format!("first_mapping_slab: {}", config.first_mapping_slab));
    lines.push(format!("num_mapping_slabs: {}", config.num_mapping_slabs));
    lines
}

fn dump_slab_content(
    slab_id: u32,
    offset: u64,
    data: &[u8],
    bytes_per_line: usize,
    slab_type: SlabType,
) {
    println!("──────────────────────────────────────────────────────────────");
    println!(
        "Slab {} @ offset 0x{:x} ({} bytes)",
        slab_id,
        offset,
        data.len()
    );
    println!("──────────────────────────────────────────────────────────────");

    // Try to interpret as metadata if type is Auto or Metadata
    if slab_type == SlabType::Auto || slab_type == SlabType::Metadata {
        if let Ok(config) = deserialize_stream_config(data) {
            if slab_type == SlabType::Auto {
                println!("Detected type: METADATA");
                println!();
            }

            let metadata_lines = format_metadata(&config);
            println!("Stream Metadata:");
            for line in &metadata_lines {
                println!("  {}", line);
            }
            println!();
            println!("Raw hex dump:");
        } else if slab_type == SlabType::Metadata {
            eprintln!("Warning: Failed to deserialize as metadata, showing raw hex");
        }
    }

    if slab_type == SlabType::Auto || slab_type == SlabType::Mappings {
        println!("Detected type: MAPPINGS");
        println!();
    }

    let mut parser = InstructionParser::new(data);
    let mut line_offset = 0u64;

    while line_offset < data.len() as u64 {
        let remaining = &data[line_offset as usize..];
        let line_len = bytes_per_line.min(remaining.len());
        let line_data = &remaining[..line_len];

        // Get interpretation based on slab type
        let interpretation = match slab_type {
            SlabType::Metadata => {
                // For metadata, just show ASCII-safe printable or hex
                None
            }
            SlabType::Mappings | SlabType::Auto => {
                // For mappings, interpret as stream instructions
                parser.pos = line_offset as usize;
                if let Some(tag_byte) = parser.peek_byte() {
                    let inst_str = interpret_stream_instruction_byte(tag_byte);
                    let inst_len = parser.instruction_length();
                    if inst_len > 0 {
                        Some(format!("{} [{} bytes]", inst_str, inst_len))
                    } else {
                        Some(inst_str)
                    }
                } else {
                    None
                }
            }
        };

        dump_hex_line(
            offset + line_offset,
            line_data,
            bytes_per_line,
            interpretation.as_deref(),
        );

        line_offset += line_len as u64;
    }
    println!();
}

fn dump_file_header(file: &mut BufReader<File>) -> Result<()> {
    file.seek(SeekFrom::Start(0))?;

    let magic = file.read_u64::<LittleEndian>()?;
    let version = file.read_u32::<LittleEndian>()?;
    let flags = file.read_u32::<LittleEndian>()?;

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                        FILE HEADER                           ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!(
        "║  Magic:      0x{:016x} {}",
        magic,
        if magic == FILE_MAGIC {
            "✓"
        } else {
            "✗ INVALID"
        }
    );
    println!(
        "║  Version:    {} {}",
        version,
        if version == 0 { "✓" } else { "? Unknown" }
    );
    println!(
        "║  Flags:      {} ({})",
        flags,
        if flags == 0 {
            "uncompressed"
        } else if flags == 1 {
            "compressed"
        } else {
            "unknown"
        }
    );
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    if magic != FILE_MAGIC {
        return Err(anyhow!("Invalid file magic"));
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = parse_args()?;

    // Auto-detect slab type from filename if type is Auto
    let slab_type = if args.slab_type == SlabType::Auto {
        if args.slab_file.file_name().and_then(|n| n.to_str()) == Some("metadata") {
            SlabType::Metadata
        } else if args.slab_file.file_name().and_then(|n| n.to_str()) == Some("mappings") {
            SlabType::Mappings
        } else {
            SlabType::Auto
        }
    } else {
        args.slab_type
    };

    // We need to read up the archive config to figure out what hash algr. we are using
    blk_stash::config::find_and_load_config(&args.slab_file)?;

    let file = File::open(&args.slab_file)
        .with_context(|| format!("Failed to open file: {:?}", args.slab_file))?;
    let mut reader = BufReader::new(file);

    if args.show_header {
        dump_file_header(&mut reader)?;
    }

    // Seek past header
    reader.seek(SeekFrom::Start(SLAB_FILE_HDR_LEN))?;

    let file_size = reader.get_ref().metadata()?.len();
    let mut current_offset = SLAB_FILE_HDR_LEN;
    let mut slab_index = 0u32;

    while current_offset < file_size {
        // Check if we should skip this slab
        if let Some(target_id) = args.slab_id {
            if slab_index != target_id {
                // Skip to next slab
                let slab_magic = reader.read_u64::<LittleEndian>()?;
                if slab_magic != SLAB_MAGIC {
                    return Err(anyhow!(
                        "Invalid slab magic at offset 0x{:x}",
                        current_offset
                    ));
                }
                let slab_len = reader.read_u64::<LittleEndian>()?;
                reader.seek(SeekFrom::Current(8 + slab_len as i64))?; // Skip checksum + data
                current_offset = reader.stream_position()?;
                slab_index += 1;
                continue;
            }
        }

        // Check if we've hit max slabs
        if let Some(max) = args.max_slabs {
            if slab_index >= max as u32 {
                break;
            }
        }

        // Read slab header
        let slab_magic = reader.read_u64::<LittleEndian>()?;
        if slab_magic != SLAB_MAGIC {
            return Err(anyhow!(
                "Invalid slab magic at offset 0x{:x}",
                current_offset
            ));
        }

        let slab_len = reader.read_u64::<LittleEndian>()?;
        let mut checksum = [0u8; 8];
        reader.read_exact(&mut checksum)?;

        // Read slab data
        let mut slab_data = vec![0u8; slab_len as usize];
        reader.read_exact(&mut slab_data)?;

        // Verify checksum
        let actual_checksum = blk_stash::hash::hash_64(&slab_data);
        let checksum_ok = actual_checksum[..] == checksum[..];

        println!("╔══════════════════════════════════════════════════════════════╗");
        println!(
            "║  Slab ID:    {}                                     ",
            slab_index
        );
        println!(
            "║  Offset:     0x{:08x}                              ",
            current_offset
        );
        println!(
            "║  Length:     {} bytes                              ",
            slab_len
        );
        println!(
            "║  Checksum:   {} {}",
            hex::encode(checksum),
            if checksum_ok { "✓" } else { "✗ MISMATCH" }
        );
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();

        dump_slab_content(
            slab_index,
            current_offset + 24,
            &slab_data,
            args.bytes_per_line,
            slab_type,
        );

        current_offset = reader.stream_position()?;
        slab_index += 1;

        // If we were looking for a specific slab, we're done
        if args.slab_id.is_some() {
            break;
        }
    }

    println!("Total slabs processed: {}", slab_index);

    Ok(())
}
