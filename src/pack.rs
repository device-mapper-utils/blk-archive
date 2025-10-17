use anyhow::{anyhow, Context, Result};
use chrono::prelude::*;
use clap::ArgMatches;
use rand::prelude::*;
use rand_chacha::ChaCha20Rng;
use serde_json::json;
use serde_json::to_string_pretty;
use size_display::Size;
use std::boxed::Box;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, FileTypeExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::archive::*;
use crate::chunkers::*;
use crate::config;
use crate::content_sensitive_splitter::*;
use crate::hash::*;
use crate::iovec::*;
use crate::output::Output;
use crate::paths::*;
use crate::run_iter::*;
use crate::slab::builder::*;
use crate::slab::*;
use crate::splitter::*;
use crate::stream::*;
use crate::stream_builders::*;
use crate::thin_metadata::*;
use crate::utils::unmapped_digest_add;

//-----------------------------------------

fn iov_len_(iov: &IoVec) -> u64 {
    let mut len = 0;
    for v in iov {
        len += v.len() as u64;
    }

    len
}

fn first_b_(iov: &IoVec) -> Option<u8> {
    if let Some(v) = iov.iter().find(|v| !v.is_empty()) {
        return Some(v[0]);
    }

    None
}

fn all_same(iov: &IoVec) -> Option<u8> {
    if let Some(first_b) = first_b_(iov) {
        for v in iov.iter() {
            for b in *v {
                if *b != first_b {
                    return None;
                }
            }
        }
        Some(first_b)
    } else {
        None
    }
}

//-----------------------------------------
#[derive(serde::Serialize, Default)]
struct DedupStats {
    data_written: u64,
    mapped_size: u64,
    fill_size: u64,
}

struct DedupHandler<'a> {
    nr_chunks: usize,

    stream_file: SlabFile<'a>,
    stream_buf: Vec<u8>,

    mapping_builder: Arc<Mutex<dyn Builder>>,

    stats: DedupStats,
    archive: Data<'a, MultiFile>,
}

impl<'a> DedupHandler<'a> {
    fn new(
        stream_file: SlabFile<'a>,
        mapping_builder: Arc<Mutex<dyn Builder>>,
        archive: Data<'a, MultiFile>,
    ) -> Result<Self> {
        let stats = DedupStats::default();

        Ok(Self {
            nr_chunks: 0,
            stream_file,
            stream_buf: Vec::new(),
            mapping_builder,
            stats,
            archive,
        })
    }

    fn maybe_complete_stream(&mut self) -> Result<()> {
        complete_slab(
            &mut self.stream_file,
            &mut self.stream_buf,
            SLAB_SIZE_TARGET,
            false,
        )?;
        Ok(())
    }

    fn add_stream_entry(&mut self, e: &MapEntry, len: u64) -> Result<()> {
        let mut builder = self.mapping_builder.lock().unwrap();
        builder.next(e, len, &mut self.stream_buf)
    }

    fn handle_gap(&mut self, len: u64) -> Result<()> {
        self.add_stream_entry(&MapEntry::Unmapped { len }, len)?;
        self.maybe_complete_stream()?;

        Ok(())
    }

    fn handle_ref(&mut self, len: u64) -> Result<()> {
        self.add_stream_entry(&MapEntry::Ref { len }, len)?;
        self.maybe_complete_stream()?;

        Ok(())
    }

    // TODO: Is there a better way to handle this and what are the ramifications with
    // client server with multiple clients and one server?
    fn ensure_extra_capacity(&mut self, blocks: usize) -> Result<()> {
        self.archive.ensure_extra_capacity(blocks)
    }

    /// Extract the archive, taking ownership and preventing Drop
    fn take_archive(self) -> Data<'a> {
        self.archive
    }
}

impl<'a> IoVecHandler for DedupHandler<'a> {
    fn handle_data(&mut self, iov: &IoVec) -> Result<()> {
        self.nr_chunks += 1;
        let len = iov_len_(iov);
        self.stats.mapped_size += len;
        assert!(len != 0);

        if let Some(first_byte) = all_same(iov) {
            self.stats.fill_size += len;
            self.add_stream_entry(
                &MapEntry::Fill {
                    byte: first_byte,
                    len,
                },
                len,
            )?;
            self.maybe_complete_stream()?;
        } else {
            let h = hash_256_iov(iov);
            // Note: add_data_entry returns existing entry if present, else returns newly inserted
            // entry.
            let (entry_location, data_written) =
                self.archive.data_add_with_boundary_check(h, iov, len)?;
            let me = MapEntry::Data {
                slab: entry_location.0,
                offset: entry_location.1,
                nr_entries: 1,
            };
            self.stats.data_written += data_written;
            self.add_stream_entry(&me, len)?;
            self.maybe_complete_stream()?;
        }

        Ok(())
    }

    fn complete(&mut self) -> Result<()> {
        let mut builder = self.mapping_builder.lock().unwrap();
        builder.complete(&mut self.stream_buf)?;
        drop(builder);

        complete_slab(&mut self.stream_file, &mut self.stream_buf, 0, false)?;
        self.stream_file.close()?;

        Ok(())
    }
}

//-----------------------------------------

// Returns (stream_id, temp_path, final_path)
fn new_stream_path_(
    archive_dir: &Path,
    rng: &mut ChaCha20Rng,
) -> Result<Option<(String, PathBuf, PathBuf)>> {
    // choose a random number
    let n: u64 = rng.gen();

    // turn this into a path
    let name = format!("{:>016x}", n);
    let temp_name = format!(".tmp_{}", name);
    let temp_path: PathBuf = ["streams", &temp_name].iter().collect();
    let final_path: PathBuf = ["streams", &name].iter().collect();
    let final_path = archive_dir.join(final_path);
    let temp_path = archive_dir.join(&temp_path);

    // Check both temp and final paths don't exist
    if temp_path.exists() || final_path.exists() {
        Ok(None)
    } else {
        Ok(Some((name, temp_path, final_path)))
    }
}

fn new_stream_path(archive_dir: &Path) -> Result<(String, PathBuf, PathBuf)> {
    let mut rng = ChaCha20Rng::from_entropy();
    loop {
        if let Some(r) = new_stream_path_(archive_dir, &mut rng)? {
            return Ok(r);
        }
    }

    // Can't get here
}

#[inline]
fn read_positional(file: &File, buf: &mut [u8], pos: u64) -> io::Result<usize> {
    file.read_at(buf, pos)
}

/// Hash `len` bytes from `file` starting at `offset` into `hasher`.
/// Returns the number of bytes actually hashed (could be < len if EOF reached).
pub fn hash_region(
    file: &mut File,
    hasher: &mut blake3::Hasher,
    offset: u64,
    len: u64,
) -> Result<u64> {
    const BUF_SIZE: usize = 1 << 20; // 1 MiB
    let mut buf = vec![0u8; BUF_SIZE];

    let mut pos = offset;
    let mut remaining = len;
    let mut total = 0u64;

    while remaining > 0 {
        let want = std::cmp::min(remaining, buf.len() as u64) as usize;

        let n = read_positional(file, &mut buf[..want], pos)?;
        if n == 0 {
            break; // EOF
        }

        hasher.update(&buf[..n]);
        pos += n as u64;
        remaining -= n as u64;
        total += n as u64;
    }

    Ok(total)
}

struct Packer {
    output: Arc<Output>,
    input_path: PathBuf,
    stream_name: String,
    it: Box<dyn Iterator<Item = Result<Chunk>>>,
    input_size: u64,
    mapping_builder: Arc<Mutex<dyn Builder>>,
    mapped_size: u64,
    block_size: usize,
    thin_id: Option<u32>,
    hash_cache_size_meg: usize,
    sync_point_secs: u64,
}

impl Packer {
    #[allow(clippy::too_many_arguments)]
    fn new(
        output: Arc<Output>,
        input_path: PathBuf,
        stream_name: String,
        it: Box<dyn Iterator<Item = Result<Chunk>>>,
        input_size: u64,
        mapping_builder: Arc<Mutex<dyn Builder>>,
        mapped_size: u64,
        block_size: usize,
        thin_id: Option<u32>,
        hash_cache_size_meg: usize,
        sync_point_secs: u64,
    ) -> Self {
        Self {
            output,
            input_path,
            stream_name,
            it,
            input_size,
            mapping_builder,
            mapped_size,
            block_size,
            thin_id,
            hash_cache_size_meg,
            sync_point_secs,
        }
    }

    fn pack(
        mut self,
        archive_dir: &Path,
        hashes_file: Arc<Mutex<SlabFile<'static>>>,
        data_archive_opt: Option<Data<'static, MultiFile>>,
        splitter: &mut ContentSensitiveSplitter,
        is_last_file: bool,
    ) -> Result<(u32, Data<'static, MultiFile>)> {
        // Reuse existing Data archive or create a new one
        let ad = if let Some(archive) = data_archive_opt {
            archive
        } else {
            let hashes_per_slab = std::cmp::max(SLAB_SIZE_TARGET / self.block_size, 1);
            let slab_capacity = ((self.hash_cache_size_meg * 1024 * 1024)
                / std::mem::size_of::<Hash256>())
                / hashes_per_slab;

            let data_file = MultiFile::open_for_write(archive_dir, 128, slab_capacity)
                .with_context(|| {
                    format!(
                        "Failed to open data slab file for writing (path: {:?}, capacity: {})",
                        data_path(archive_dir),
                        slab_capacity
                    )
                })?;
            Data::new(archive_dir, data_file, hashes_file.clone(), slab_capacity).with_context(
                || {
                    format!(
                        "Failed to create Data archive (block_size: {}, slab_capacity: {})",
                        self.block_size, slab_capacity
                    )
                },
            )?
        };

        let (stream_id, temp_stream_dir, final_stream_dir) = new_stream_path(archive_dir)?;

        // Create temporary stream directory
        std::fs::create_dir(&temp_stream_dir)
            .with_context(|| format!("error creating directory = {:?}", temp_stream_dir))?;
        let mut stream_path = temp_stream_dir.clone();
        stream_path.push("stream");

        let stream_file = SlabFileBuilder::create(&stream_path)
            .queue_depth(16)
            .compressed(true)
            .build()
            .context("couldn't open stream slab file")?;

        let mut handler = DedupHandler::new(stream_file, self.mapping_builder.clone(), ad)?;

        handler.ensure_extra_capacity(self.mapped_size as usize / self.block_size)?;

        self.output.report.progress(0);
        let start_time: DateTime<Utc> = Utc::now();

        let mut input_digest = blake3::Hasher::new();

        let mut offset = 0u64;
        let mut total_read = 0u64;
        let mut input_source = File::open(self.input_path.clone())?;
        let mut last_checkpoint_time = Instant::now();
        let checkpoint_interval = Duration::from_secs(self.sync_point_secs);

        for chunk in &mut self.it {
            match chunk? {
                Chunk::Mapped(buffer) => {
                    let len = buffer.len();
                    offset += len as u64;
                    input_digest.update(&buffer[..len]);
                    splitter.next_data(buffer, &mut handler)?;
                    total_read += len as u64;
                    self.output
                        .report
                        .progress(((100 * total_read) / self.mapped_size) as u8);
                }
                Chunk::Unmapped(len) => {
                    assert!(len > 0);
                    unmapped_digest_add(&mut input_digest, len);
                    offset += len;
                    splitter.next_break(&mut handler)?;
                    handler.handle_gap(len)?;
                }
                Chunk::Ref(len) => {
                    // We need to retrieve the data from the source device or file starting at
                    // offset with the supplied length to update the input hash
                    // Note: How much of a preformance hit does this cause?
                    let processed_len =
                        hash_region(&mut input_source, &mut input_digest, offset, len)?;
                    assert_eq!(len, processed_len);

                    splitter.next_break(&mut handler)?;
                    handler.handle_ref(len)?;
                    offset += len;
                }
            }

            // Check if it's time to create a checkpoint (at slab boundaries)
            if handler.archive.slab_just_completed()
                && last_checkpoint_time.elapsed() >= checkpoint_interval
            {
                handler.archive.sync_checkpoint()?;
                last_checkpoint_time = Instant::now();
            }
        }

        // Only complete the splitter if this is the last file
        // Otherwise just break to indicate non-contiguous data
        if is_last_file {
            // We need to consume the splitter, so create a temporary one to swap
            let temp_splitter = ContentSensitiveSplitter::new(self.block_size as u32);
            let final_splitter = std::mem::replace(splitter, temp_splitter);
            final_splitter.complete(&mut handler)?;
        } else {
            // Just break between files, don't complete the splitter
            splitter.next_break(&mut handler)?;
        }
        self.output.report.progress(100);

        // Complete the handler to flush and close the stream file for each file
        handler
            .complete()
            .with_context(|| format!("error while completing the stream {:?}", stream_path))?;

        let input_hex_digest = input_digest.finalize().to_hex().to_string();

        let end_time: DateTime<Utc> = Utc::now();
        let elapsed = end_time - start_time;
        let elapsed = elapsed.num_milliseconds() as f64 / 1000.0;
        let stream_written = handler.stream_file.get_file_size();
        let ratio =
            (self.mapped_size as f64) / ((handler.stats.data_written + stream_written) as f64);

        if self.output.json {
            // Should all the values simply be added to the json too?  We can always add entries, but
            // we can never take any away to maintains backwards compatibility with JSON consumers.
            let result = json!({ "input_file": self.input_path, "stream_id": stream_id, "stats": handler.stats, "hash": input_hex_digest});
            println!("{}", to_string_pretty(&result).unwrap());
        } else {
            self.output
                .report
                .info(&format!("elapsed          : {elapsed}"));
            self.output
                .report
                .info(&format!("stream id        : {stream_id}"));
            self.output
                .report
                .info(&format!("file size        : {:.2}", Size(self.input_size)));
            self.output
                .report
                .info(&format!("mapped size      : {:.2}", Size(self.mapped_size)));
            self.output
                .report
                .info(&format!("total read       : {:.2}", Size(total_read)));
            self.output.report.info(&format!(
                "fills size       : {:.2}",
                Size(handler.stats.fill_size)
            ));
            self.output.report.info(&format!(
                "duplicate data   : {:.2}",
                Size(total_read - handler.stats.data_written - handler.stats.fill_size)
            ));

            self.output.report.info(&format!(
                "data written     : {:.2}",
                Size(handler.stats.data_written)
            ));
            self.output
                .report
                .info(&format!("stream written   : {:.2}", Size(stream_written)));
            self.output
                .report
                .info(&format!("ratio            : {ratio:.2}"));
            self.output.report.info(&format!(
                "speed            : {:.2}/s",
                Size((total_read as f64 / elapsed) as u64)
            ));
        }

        // Write stream config to temp directory
        let temp_stream_id = temp_stream_dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid temp stream directory"))?;

        let cfg = config::StreamConfig {
            name: Some(self.stream_name.to_string()),
            source_path: self.input_path.display().to_string(),
            pack_time: config::now(),
            size: self.input_size,
            mapped_size: self.mapped_size,
            packed_size: handler.stats.data_written + stream_written,
            thin_id: self.thin_id,
            source_sig: Some(input_hex_digest),
        };
        config::write_stream_config(archive_dir, temp_stream_id, &cfg)?;

        // Atomically move temp stream directory to final location
        // This is the commit point - either the stream exists completely or not at all
        std::fs::rename(&temp_stream_dir, &final_stream_dir).with_context(|| {
            format!(
                "Failed to atomically commit stream directory: {:?} -> {:?}",
                temp_stream_dir, final_stream_dir
            )
        })?;

        //TODO: Sync stream directory?

        // Extract the Data archive from the handler to return it for reuse
        let archive = handler.take_archive();
        let data_slab_file_id = archive.get_current_write_file_id();

        Ok((data_slab_file_id, archive))
    }
}

//-----------------------------------------

fn thick_packer(
    output: Arc<Output>,
    input_file: &Path,
    input_name: String,
    config: &config::Config,
    sync_point_secs: u64,
) -> Result<Packer> {
    let input_size = thinp::file_utils::file_size(input_file)?;

    let mapped_size = input_size;
    let input_iter = Box::new(ThickChunker::new(input_file, 16 * 1024 * 1024)?);
    let thin_id = None;
    let builder = Arc::new(Mutex::new(MappingBuilder::default()));

    Ok(Packer::new(
        output,
        input_file.to_path_buf(),
        input_name,
        input_iter,
        input_size,
        builder,
        mapped_size,
        config.block_size,
        thin_id,
        config.hash_cache_size_meg,
        sync_point_secs,
    ))
}

fn thin_packer(
    output: Arc<Output>,
    input_file: &Path,
    input_name: String,
    config: &config::Config,
    sync_point_secs: u64,
) -> Result<Packer> {
    let input = OpenOptions::new()
        .read(true)
        .write(false)
        .open(input_file)
        .context("couldn't open input file/dev")?;
    let input_size = thinp::file_utils::file_size(input_file)?;

    let mappings = read_thin_mappings(input_file)?;
    let mapped_size = mappings.provisioned_blocks.len() * mappings.data_block_size as u64 * 512;
    let run_iter = RunIter::new(
        mappings.provisioned_blocks,
        (input_size / (mappings.data_block_size as u64 * 512)) as u32,
    );
    let input_iter = Box::new(ThinChunker::new(
        input,
        run_iter,
        mappings.data_block_size as u64 * 512,
    ));
    let thin_id = Some(mappings.thin_id);
    let builder = Arc::new(Mutex::new(MappingBuilder::default()));

    output
        .report
        .set_title(&format!("Packing {} ...", input_file.display()));
    Ok(Packer::new(
        output,
        input_file.to_path_buf(),
        input_name,
        input_iter,
        input_size,
        builder,
        mapped_size,
        config.block_size,
        thin_id,
        config.hash_cache_size_meg,
        sync_point_secs,
    ))
}

// FIXME: slow
fn open_thin_stream(base: &Path, stream_id: &str) -> Result<SlabFile<'static>> {
    SlabFileBuilder::open(stream_path(base, stream_id))
        .build()
        .context("couldn't open old stream file")
}

#[allow(clippy::too_many_arguments)]
fn thin_delta_packer(
    archive_dir: &Path,
    output: Arc<Output>,
    input_file: &Path,
    input_name: String,
    config: &config::Config,
    delta_device: &Path,
    delta_id: &str,
    hashes_file: Arc<Mutex<SlabFile<'static>>>,
    sync_point_secs: u64,
) -> Result<Packer> {
    let input = OpenOptions::new()
        .read(true)
        .write(false)
        .open(input_file)
        .context("couldn't open input file/dev")?;
    let input_size = thinp::file_utils::file_size(input_file)?;

    let mappings = read_thin_delta(delta_device, input_file)?;
    let old_config = config::read_stream_config(archive_dir, delta_id)?;
    let mapped_size = old_config.mapped_size;

    let run_iter = DualIter::new(
        mappings.additions,
        mappings.removals,
        (input_size / (mappings.data_block_size as u64 * 512)) as u32,
    );

    let input_iter = Box::new(DeltaChunker::new(
        input,
        run_iter,
        mappings.data_block_size as u64 * 512,
    ));
    let thin_id = Some(mappings.thin_id);

    let old_stream = open_thin_stream(archive_dir, delta_id)?;
    let old_entries = StreamIter::new(old_stream)?;
    let builder = Arc::new(Mutex::new(DeltaBuilder::new(old_entries, hashes_file)));

    output
        .report
        .set_title(&format!("Packing {} ...", input_file.display()));
    Ok(Packer::new(
        output,
        input_file.to_path_buf(),
        input_name,
        input_iter,
        input_size,
        builder,
        mapped_size,
        config.block_size,
        thin_id,
        config.hash_cache_size_meg,
        sync_point_secs,
    ))
}

// Looks up both --delta-stream and --delta-device
fn get_delta_args(matches: &ArgMatches) -> Result<Option<(String, PathBuf)>> {
    match (
        matches.get_one::<String>("DELTA_STREAM"),
        matches.get_one::<String>("DELTA_DEVICE"),
    ) {
        (None, None) => Ok(None),
        (Some(stream), Some(device)) => {
            let mut buf = PathBuf::new();
            buf.push(device);
            Ok(Some((stream.to_string(), buf)))
        }
        _ => Err(anyhow!(
            "--delta-stream and --delta-device must both be given"
        )),
    }
}

/// Resolve `path_str`, ensure it refers to a readable regular file or block device,
/// and return the canonical absolute path (symlinks resolved).
/// Linux-only (uses `FileTypeExt::is_block_device`).
pub fn canonicalize_readable_regular_or_block(path_str: String) -> Result<PathBuf> {
    let input = Path::new(&path_str);

    // 1) Canonicalize (resolves symlinks, returns absolute path)
    let canon = fs::canonicalize(input).with_context(|| format!("canonicalizing {:?}", input))?;

    // 2) Stat the resolved target
    let meta = fs::metadata(&canon).with_context(|| format!("metadata for {:?}", canon))?;
    let ft = meta.file_type();

    // 3) Must be a regular file OR a block device
    if !ft.is_file() && !ft.is_block_device() {
        return Err(anyhow!("not a regular file or block device: {:?}", canon));
    }

    // 4) Verify we can actually read it (covers permissions, RO mounts, etc.)
    let _fh = OpenOptions::new()
        .read(true)
        .open(&canon)
        .with_context(|| format!("opening for read {:?}", canon))?;
    // (File handle drops here; open succeeded = readable)

    Ok(canon)
}

pub fn run(matches: &ArgMatches, output: Arc<Output>) -> Result<()> {
    let archive_dir = Path::new(matches.get_one::<String>("ARCHIVE").unwrap()).canonicalize()?;
    let input_files: Vec<&String> = matches.get_many::<String>("INPUT").unwrap().collect();

    let sync_point_secs = *matches.get_one::<u64>("SYNC_POINT_SECS").unwrap_or(&15u64);
    let config = config::read_config(&archive_dir, matches)?;

    // Check that multiple inputs are not allowed with delta mode
    let delta_args = get_delta_args(matches)?;
    if delta_args.is_some() && input_files.len() > 1 {
        return Err(anyhow!(
            "Multiple INPUTs are not allowed when using --delta-stream and --delta-device"
        ));
    }

    let hashes_file = Arc::new(Mutex::new(
        SlabFileBuilder::open(hashes_path(&archive_dir))
            .write(true)
            .queue_depth(16)
            .build()
            .context("couldn't open hashes slab file")?,
    ));

    // Categorize input files into delta, thin, and thick lists
    let mut delta_block_devs = Vec::new();
    let mut thin_block_devs = Vec::new();
    let mut thick_input = Vec::new();

    for input_file_str in input_files {
        let result = canonicalize_readable_regular_or_block(input_file_str.to_string());

        if let Err(e) = result {
            eprintln!(
                "error processing {} for reason {}, skipping!",
                input_file_str, e
            );
            continue;
        }

        let input_file = result.unwrap();

        if delta_args.is_some() {
            delta_block_devs.push(input_file);
        } else if is_thin_device(&input_file).with_context(|| {
            format!(
                "Failed to check if {} is a thin device",
                input_file.display()
            )
        })? {
            thin_block_devs.push(input_file);
        } else {
            // As we know it was either a file or a block device, and it isn't a delta or thin
            // simply add.
            thick_input.push(input_file);
        }
    }

    let mut final_archive: Option<Data<MultiFile>> = None;

    // Process delta devices with one packer
    if !delta_block_devs.is_empty() {
        if let Some((delta_stream, delta_device)) = &delta_args {
            final_archive = process_file_list(
                &archive_dir,
                &delta_block_devs,
                output.clone(),
                &config,
                hashes_file.clone(),
                sync_point_secs,
                |output, input_file, input_name, config, hashes_file, sync_point_secs| {
                    thin_delta_packer(
                        &archive_dir,
                        output,
                        input_file,
                        input_name,
                        config,
                        delta_device,
                        delta_stream,
                        hashes_file,
                        sync_point_secs,
                    )
                },
            )
            .with_context(|| {
                format!(
                    "Failed to process delta device list ({} files)",
                    delta_block_devs.len()
                )
            })?;
        }
    }

    // Process thin devices with one packer
    if !thin_block_devs.is_empty() {
        final_archive = process_file_list(
            &archive_dir,
            &thin_block_devs,
            output.clone(),
            &config,
            hashes_file.clone(),
            sync_point_secs,
            |output, input_file, input_name, config, _hashes_file, sync_point_secs| {
                thin_packer(output, input_file, input_name, config, sync_point_secs)
            },
        )
        .with_context(|| {
            format!(
                "Failed to process thin device list ({} files)",
                thin_block_devs.len()
            )
        })?;
    }

    // Process thick devices/files with one packer
    if !thick_input.is_empty() {
        final_archive = process_file_list(
            &archive_dir,
            &thick_input,
            output.clone(),
            &config,
            hashes_file.clone(),
            sync_point_secs,
            |output, input_file, input_name, config, _hashes_file, sync_point_secs| {
                thick_packer(output, input_file, input_name, config, sync_point_secs)
            },
        )
        .with_context(|| {
            format!(
                "Failed to process thick device/file list ({} files)",
                thick_input.len()
            )
        })?;
    }

    // Write final checkpoint after all files are processed
    if let Some(mut archive) = final_archive {
        archive.sync_checkpoint()?;
    }

    Ok(())
}

fn process_file_list<F>(
    archive_dir: &Path,
    files: &[PathBuf],
    output: Arc<Output>,
    config: &config::Config,
    hashes_file: Arc<Mutex<SlabFile<'static>>>,
    sync_point_secs: u64,
    packer_factory: F,
) -> Result<Option<Data<'static, MultiFile>>>
where
    F: Fn(
        Arc<Output>,
        &Path,
        String,
        &config::Config,
        Arc<Mutex<SlabFile<'static>>>,
        u64,
    ) -> Result<Packer>,
{
    let mut data_archive_opt: Option<Data<'static, MultiFile>> = None;

    // Create a single splitter to be reused across all files
    let mut splitter = ContentSensitiveSplitter::new(config.block_size as u32);

    for (idx, input_file) in files.iter().enumerate() {
        let is_last_file = idx == files.len() - 1;
        let input_name = input_file
            .file_name()
            .ok_or_else(|| anyhow!("Input file has no filename: {:?}", input_file))
            .with_context(|| format!("Failed to extract filename from path: {:?}", input_file))?
            .to_str()
            .ok_or_else(|| anyhow!("Input filename is not valid UTF-8: {:?}", input_file))
            .with_context(|| format!("Failed to convert filename to string: {:?}", input_file))?
            .to_string();

        output
            .report
            .set_title(&format!("Building packer {} ...", input_file.display()));

        let packer = packer_factory(
            output.clone(),
            input_file,
            input_name.clone(),
            config,
            hashes_file.clone(),
            sync_point_secs,
        )
        .with_context(|| format!("Failed to create packer for file: {}", input_file.display()))?;

        output
            .report
            .set_title(&format!("Packing {} ...", input_file.display()));
        let (_slab_id, archive) = packer
            .pack(
                archive_dir,
                hashes_file.clone(),
                data_archive_opt,
                &mut splitter,
                is_last_file,
            )
            .with_context(|| {
                format!(
                    "Failed to pack file: {} (name: {})",
                    input_file.display(),
                    input_name
                )
            })?;
        data_archive_opt = Some(archive);
    }

    Ok(data_archive_opt)
}

//-----------------------------------------
