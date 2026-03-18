use anyhow::{anyhow, Context, Result};
use blk_stash::config::StreamConfig;
use blk_stash::slab::builder::SlabFileBuilder;
use blk_stash::slab::SlabFile;
use blk_stash::stream::{self, MapEntry};
use blk_stash::stream_metadata::deserialize_stream_config;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

struct Args {
    /// Path to the streams directory
    streams_dir: PathBuf,

    /// Stream ID to dump (optional - if not specified, dumps all streams)
    stream_id: Option<u32>,

    /// Show mapping entries in detail
    verbose: bool,

    /// Only show metadata, skip mappings
    metadata_only: bool,

    /// Output format (text, json)
    format: OutputFormat,
}

#[derive(Clone, Copy)]
enum OutputFormat {
    Text,
    Json,
}

fn parse_args() -> Result<Args> {
    let mut args = std::env::args().skip(1);
    let mut streams_dir = None;
    let mut stream_id = None;
    let mut verbose = false;
    let mut metadata_only = false;
    let mut format = OutputFormat::Text;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-d" | "--streams-dir" => {
                streams_dir = Some(PathBuf::from(
                    args.next()
                        .ok_or_else(|| anyhow!("Missing value for --streams-dir"))?,
                ));
            }
            "-s" | "--stream-id" => {
                let val = args
                    .next()
                    .ok_or_else(|| anyhow!("Missing value for --stream-id"))?;
                stream_id = Some(val.parse()?);
            }
            "-v" | "--verbose" => {
                verbose = true;
            }
            "-m" | "--metadata-only" => {
                metadata_only = true;
            }
            "-f" | "--format" => {
                let val = args
                    .next()
                    .ok_or_else(|| anyhow!("Missing value for --format"))?;
                format = match val.as_str() {
                    "text" => OutputFormat::Text,
                    "json" => OutputFormat::Json,
                    _ => {
                        return Err(anyhow!(
                            "Invalid format: {} (must be 'text' or 'json')",
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
                // Treat as positional streams directory if not set yet
                if streams_dir.is_none() {
                    streams_dir = Some(PathBuf::from(arg));
                } else {
                    return Err(anyhow!("Unknown argument: {}", arg));
                }
            }
        }
    }

    Ok(Args {
        streams_dir: streams_dir
            .ok_or_else(|| anyhow!("Missing required argument: --streams-dir"))?,
        stream_id,
        verbose,
        metadata_only,
        format,
    })
}

fn print_help() {
    println!("Stream Data Dump Utility");
    println!();
    println!("Dumps stream metadata and mapping instructions from blk-stash stream files.");
    println!();
    println!("USAGE:");
    println!("    stream-dump [OPTIONS] --streams-dir <STREAMS_DIR>");
    println!("    stream-dump [OPTIONS] <STREAMS_DIR>");
    println!();
    println!("OPTIONS:");
    println!("    -d, --streams-dir <DIR>    Path to the streams directory");
    println!("    -s, --stream-id <ID>       Dump only this stream ID (decimal)");
    println!("    -v, --verbose              Show detailed mapping entries");
    println!("    -m, --metadata-only        Only show metadata, skip mappings");
    println!("    -f, --format <FORMAT>      Output format: text (default) or json");
    println!("    -h, --help                 Print help information");
    println!();
    println!("EXAMPLES:");
    println!("    # Dump all streams");
    println!("    stream-dump /path/to/archive/streams");
    println!();
    println!("    # Dump a specific stream with detailed mappings");
    println!("    stream-dump -d /path/to/archive/streams -s 0 -v");
    println!();
    println!("    # Export metadata to JSON");
    println!("    stream-dump /path/to/archive/streams -m -f json > streams.json");
}

fn streams_metadata_path(streams_dir: &Path) -> PathBuf {
    let mut path = streams_dir.to_path_buf();
    path.push("metadata");
    path
}

fn stream_mappings_path(streams_dir: &Path) -> PathBuf {
    let mut path = streams_dir.to_path_buf();
    path.push("mappings");
    path
}

fn open_stream_files(streams_dir: &Path) -> Result<SlabHandles> {
    let metadata_file = Arc::new(Mutex::new(
        SlabFileBuilder::open(streams_metadata_path(streams_dir))
            .build()
            .context("couldn't open stream metadata file")?,
    ));

    let mappings_file = Arc::new(Mutex::new(
        SlabFileBuilder::open(stream_mappings_path(streams_dir))
            .build()
            .context("couldn't open stream mappings file")?,
    ));

    Ok(SlabHandles {
        metadata: metadata_file,
        mappings: mappings_file,
    })
}

fn read_stream_metadata(
    metadata_file: &Arc<Mutex<SlabFile>>,
    stream_id: u32,
) -> Result<StreamConfig> {
    let mut metadata = metadata_file.lock().unwrap();
    let data = metadata
        .read(stream_id)
        .with_context(|| format!("Failed to read metadata for stream {}", stream_id))?;
    deserialize_stream_config(&data)
        .with_context(|| format!("Failed to deserialize metadata for stream {}", stream_id))
}

fn read_stream_mappings(
    mappings_file: &Arc<Mutex<SlabFile>>,
    config: &StreamConfig,
) -> Result<Vec<MapEntry>> {
    let mut all_entries = Vec::new();

    let mut mappings = mappings_file.lock().unwrap();
    for slab_offset in 0..config.num_mapping_slabs {
        let slab_id = config.first_mapping_slab + slab_offset;
        let slab_data = mappings
            .read(slab_id)
            .with_context(|| format!("Failed to read mapping slab {}", slab_id))?;

        let (entries, _positions) = stream::unpack(&slab_data)
            .with_context(|| format!("Failed to parse mapping data from slab {}", slab_id))?;
        all_entries.extend(entries);
    }

    Ok(all_entries)
}

fn format_map_entry(entry: &MapEntry) -> String {
    use MapEntry::*;
    match entry {
        Fill { byte, len } => format!("Fill(byte=0x{:02x}, len={})", byte, len),
        Unmapped { len } => format!("Unmapped(len={})", len),
        Data {
            slab,
            offset,
            nr_entries,
        } => format!(
            "Data(slab={}, offset={}, entries={})",
            slab, offset, nr_entries
        ),
        Partial {
            begin,
            end,
            slab,
            offset,
            nr_entries,
        } => format!(
            "Partial(begin={}, end={}, slab={}, offset={}, entries={})",
            begin, end, slab, offset, nr_entries
        ),
        Ref { len } => format!("Ref(len={})", len),
    }
}

fn dump_stream_text(
    stream_id: u32,
    config: &StreamConfig,
    entries: Option<&[MapEntry]>,
    verbose: bool,
) {
    println!("========================================");
    println!("Stream ID: {}", stream_id);
    println!("========================================");
    println!();

    // Metadata
    println!("Metadata:");
    println!(
        "  Name:              {}",
        config.name.as_deref().unwrap_or("<none>")
    );
    println!("  Source Path:       {}", config.source_path);
    println!("  Pack Time:         {}", config.pack_time);
    println!("  Size:              {} bytes", config.size);
    println!("  Mapped Size:       {} bytes", config.mapped_size);
    println!("  Packed Size:       {} bytes", config.packed_size);
    println!(
        "  Thin ID:           {}",
        config
            .thin_id
            .map_or("<none>".to_string(), |id| id.to_string())
    );
    println!(
        "  Source Signature:  {}",
        config.source_sig.as_deref().unwrap_or("<none>")
    );
    println!("  First Mapping Slab: {}", config.first_mapping_slab);
    println!("  Num Mapping Slabs:  {}", config.num_mapping_slabs);

    // Calculate compression ratio
    if config.packed_size > 0 {
        let ratio = config.mapped_size as f64 / config.packed_size as f64;
        println!("  Dedup Ratio:       {:.2}x", ratio);
    }

    println!();

    // Mappings
    if let Some(entries) = entries {
        println!("Mapping Entries: {} total", entries.len());

        if verbose {
            println!();
            for (idx, entry) in entries.iter().enumerate() {
                println!("  [{:6}] {}", idx, format_map_entry(entry));
            }
        } else {
            // Summary statistics
            let mut counts: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::new();
            let mut total_fill = 0u64;
            let mut total_unmapped = 0u64;
            let mut total_data = 0u64;

            for entry in entries {
                let name = match entry {
                    MapEntry::Fill { len, .. } => {
                        total_fill += len;
                        "Fill"
                    }
                    MapEntry::Unmapped { len } => {
                        total_unmapped += len;
                        "Unmapped"
                    }
                    MapEntry::Data { .. } => {
                        // Data entries reference chunks in the archive
                        total_data += 1;
                        "Data"
                    }
                    MapEntry::Partial { begin, end, .. } => {
                        total_data += (end - begin) as u64;
                        "Partial"
                    }
                    MapEntry::Ref { len } => {
                        total_data += len;
                        "Ref"
                    }
                };
                *counts.entry(name).or_insert(0) += 1;
            }

            println!();
            println!("  Entry Summary:");
            let mut sorted: Vec<_> = counts.iter().collect();
            sorted.sort_by_key(|(name, _)| *name);
            for (name, count) in sorted {
                println!("    {:15} {:8}", name, count);
            }

            println!();
            println!("  Data Summary:");
            println!("    Fill bytes:     {}", total_fill);
            println!("    Unmapped bytes: {}", total_unmapped);
            println!("    Data refs:      {}", total_data);
        }
        println!();
    }
}

fn dump_stream_json(
    stream_id: u32,
    config: &StreamConfig,
    entries: Option<&[MapEntry]>,
) -> Result<()> {
    use serde_json::json;

    let mut obj = json!({
        "stream_id": stream_id,
        "metadata": {
            "name": config.name,
            "source_path": config.source_path,
            "pack_time": config.pack_time,
            "size": config.size,
            "mapped_size": config.mapped_size,
            "packed_size": config.packed_size,
            "thin_id": config.thin_id,
            "source_sig": config.source_sig,
            "first_mapping_slab": config.first_mapping_slab,
            "num_mapping_slabs": config.num_mapping_slabs,
        }
    });

    if let Some(entries) = entries {
        let entry_array: Vec<String> = entries.iter().map(format_map_entry).collect();
        obj["mappings"] = json!({
            "count": entries.len(),
            "entries": entry_array,
        });
    }

    println!("{}", serde_json::to_string_pretty(&obj)?);
    Ok(())
}

type Shared<T> = Arc<Mutex<T>>;
type Slab = SlabFile<'static>;

pub struct SlabHandles {
    pub metadata: Shared<Slab>,
    pub mappings: Shared<Slab>,
}

fn main() -> Result<()> {
    let args = parse_args()?;

    // Open stream files
    let files = open_stream_files(&args.streams_dir)?;

    // Determine which streams to dump
    let stream_count = {
        let metadata = files.metadata.lock().unwrap();
        metadata.get_nr_slabs()
    };

    let stream_ids: Vec<u32> = if let Some(id) = args.stream_id {
        if id as usize >= stream_count {
            return Err(anyhow!(
                "Stream ID {} out of bounds (archive has {} streams)",
                id,
                stream_count
            ));
        }
        vec![id]
    } else {
        (0..stream_count as u32).collect()
    };

    // Dump streams
    match args.format {
        OutputFormat::Json => {
            println!("[");
            for (idx, &stream_id) in stream_ids.iter().enumerate() {
                let config = read_stream_metadata(&files.metadata, stream_id)?;
                let entries = if args.metadata_only {
                    None
                } else {
                    Some(read_stream_mappings(&files.mappings, &config)?)
                };

                dump_stream_json(stream_id, &config, entries.as_deref())?;

                if idx < stream_ids.len() - 1 {
                    println!(",");
                }
            }
            println!("]");
        }
        OutputFormat::Text => {
            for &stream_id in &stream_ids {
                let config = read_stream_metadata(&files.metadata, stream_id)?;
                let entries = if args.metadata_only {
                    None
                } else {
                    Some(read_stream_mappings(&files.mappings, &config)?)
                };

                dump_stream_text(stream_id, &config, entries.as_deref(), args.verbose);
            }

            if stream_ids.len() > 1 {
                println!("========================================");
                println!("Total streams: {}", stream_ids.len());
                println!("========================================");
            }
        }
    }

    Ok(())
}
