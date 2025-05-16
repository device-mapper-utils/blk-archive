use anyhow::{anyhow, Context, Result};
use chrono::prelude::*;
use clap::ArgMatches;
use parking_lot::Mutex;
use serde_json::json;
use serde_json::to_string_pretty;
use size_display::Size;
use std::boxed::Box;
use std::env;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::archive;
use crate::archive_transport;
use crate::chunkers::*;
use crate::client;
use crate::content_sensitive_splitter::*;
use crate::iovec::*;
use crate::output::Output;
use crate::paths::*;
use crate::run_iter::*;
use crate::slab::builder::*;
use crate::slab::*;
use crate::splitter::*;
use crate::stream::*;
use crate::stream_builders::*;
use crate::stream_meta;
use crate::stream_orderer::*;
use crate::thin_metadata::*;
use crate::threaded_hasher::HashedData;
use crate::wire;

//-----------------------------------------
struct DedupHandler {
    nr_chunks: usize,
    stream_buf: Vec<u8>,
    pub stream_meta: stream_meta::StreamMeta,
    mapping_builder: Arc<Mutex<dyn Builder>>,
    pub stats: stream_meta::StreamStats,
    so: StreamOrder<Sentry>,
    archive: Box<dyn archive_transport::Transport>,
}

impl DedupHandler {
    fn new(
        names: stream_meta::StreamNames,
        stats: stream_meta::StreamStats,
        thin_id: Option<u32>,
        mapping_builder: Arc<Mutex<dyn Builder>>,
        server_addr: Option<String>,
        matches: &ArgMatches,
    ) -> Result<Self> {
        let so = StreamOrder::new();
        let tp = archive_transport::create_archive_transport(server_addr, so.clone(), matches)?;

        // Create the stream meta and store
        let stream_meta = stream_meta::StreamMeta::new(names, thin_id, tp.remote())?;

        Ok(Self {
            nr_chunks: 0,
            stream_meta,
            stream_buf: Vec::new(),
            mapping_builder,
            stats,
            so,
            archive: tp,
        })
    }

    fn process_stream_entry(&mut self, e: &MapEntry, len: u64) -> Result<()> {
        let mut builder = self.mapping_builder.lock();
        builder.next(e, len, &mut self.stream_buf)
    }

    fn process_stream(&mut self, wait: bool) -> Result<bool> {
        let mut me: MapEntry;
        let mut len: u64;

        let (entries, complete) = self.so.drain(wait);

        for e in entries {
            me = e.e;
            len = e.len.unwrap();
            self.process_stream_entry(&me, len)?;
            self.maybe_complete_stream()?
        }
        Ok(complete)
    }

    fn maybe_complete_stream(&mut self) -> Result<()> {
        archive::complete_slab(
            &mut self.stream_meta.stream_file,
            &mut self.stream_buf,
            archive::SLAB_SIZE_TARGET,
        )?;
        Ok(())
    }

    fn enqueue_entry(&mut self, e: MapEntry, len: u64) -> Result<()> {
        let se = Sentry {
            e,
            len: Some(len),
            data: None,
        };
        self.so.entry_add(se);
        Ok(())
    }

    fn handle_gap(&mut self, len: u64) -> Result<()> {
        self.enqueue_entry(MapEntry::Unmapped { len }, len)
    }

    fn handle_ref(&mut self, len: u64) -> Result<()> {
        self.enqueue_entry(MapEntry::Ref { len }, len)
    }

    // TODO: Is there a better way to handle this and what are the ramifications with
    // client server with multiple clients and one server?
    //fn ensure_extra_capacity(&mut self, blocks: usize) -> Result<()> {
    //    self.c.ensure_extra_capacity(blocks)
    //}
}

impl IoVecHandler for DedupHandler {
    fn handle_data(&mut self, hash_data: HashedData) -> Result<()> {
        self.nr_chunks += 1;
        let len = hash_data.data.len() as u64;
        self.stats.mapped_size += len;
        assert!(len != 0);

        if let Some(first_byte) = all_same_vec(&hash_data.data) {
            self.stats.fill_size += len;
            self.enqueue_entry(
                MapEntry::Fill {
                    byte: first_byte,
                    len,
                },
                len,
            )?;
        } else {
            self.stats.written += self.archive.pack(&mut self.so, hash_data, len)?;
        }

        self.process_stream(false)?;

        Ok(())
    }

    fn complete(&mut self) -> Result<()> {
        // We need to process everything that is outstanding which could be
        // quite a bit
        // TODO: Make this handle errors, like if we end up hanging forever
        loop {
            if self.process_stream(true)? {
                break;
            }
        }

        let mut builder = self.mapping_builder.lock();
        builder.complete(&mut self.stream_buf)?;
        drop(builder);

        archive::complete_slab(&mut self.stream_meta.stream_file, &mut self.stream_buf, 0)?;
        self.stream_meta.stream_file.close()?;

        // The stream file is done, lets put the create_archive_transportfile in the correct place which could be the
        // correct local archive directory or remote archive directory.
        self.archive
            .complete(&mut self.stream_meta, &mut self.stats)?;
        Ok(())
    }
}

//-----------------------------------------

struct Packer {
    output: Arc<Output>,
    names: stream_meta::StreamNames,
    it: Box<dyn Iterator<Item = Result<Chunk>>>,
    mapping_builder: Arc<Mutex<dyn Builder>>,
    block_size: usize,
    thin_id: Option<u32>,
    stats: stream_meta::StreamStats,
}

impl Packer {
    #[allow(clippy::too_many_arguments)]
    fn new(
        output: Arc<Output>,
        names: stream_meta::StreamNames,
        it: Box<dyn Iterator<Item = Result<Chunk>>>,
        stats: stream_meta::StreamStats,
        mapping_builder: Arc<Mutex<dyn Builder>>,
        block_size: usize,
        thin_id: Option<u32>,
    ) -> Self {
        Self {
            output,
            names,
            it,
            mapping_builder,
            block_size,
            thin_id,
            stats,
        }
    }

    fn pack(mut self, server_addr: Option<String>, matches: &ArgMatches) -> Result<()> {
        let mut splitter = ContentSensitiveSplitter::new(self.block_size as u32);

        let mut handler = DedupHandler::new(
            self.names,
            self.stats,
            self.thin_id,
            self.mapping_builder.clone(),
            server_addr,
            matches,
        )?;

        self.output.report.progress(0);

        let mut total_read = 0u64;
        for chunk in &mut self.it {
            match chunk? {
                Chunk::Mapped(buffer) => {
                    let len = buffer.len();
                    splitter.next_data(buffer, &mut handler)?;
                    total_read += len as u64;
                    self.output
                        .report
                        .progress(((100 * total_read) / handler.stats.mapped_size) as u8);
                }
                Chunk::Unmapped(len) => {
                    assert!(len > 0);
                    splitter.next_break(&mut handler)?;
                    handler.handle_gap(len)?;
                }
                Chunk::Ref(len) => {
                    splitter.next_break(&mut handler)?;
                    handler.handle_ref(len)?;
                }
            }
        }

        splitter.complete(&mut handler)?;
        self.output.report.progress(100);

        handler.archive.flush()?;

        let end_time: DateTime<Utc> = Utc::now();
        let elapsed = end_time - self.output.start_time;
        let elapsed = elapsed.num_milliseconds() as f64 / 1000.0;

        let stream_id = handler.stream_meta.stream_id;

        let ratio = (handler.stats.mapped_size as f64)
            / ((handler.stats.written + handler.stats.stream_written) as f64);

        if self.output.json {
            // Should all the values simply be added to the json too?  We can always add entries, but
            // we can never take any away to maintains backwards compatibility with JSON consumers.
            let result = json!({ "stream_id": stream_id, "stats": handler.stats, });
            println!("{}", to_string_pretty(&result).unwrap());
        } else {
            self.output
                .report
                .info(&format!("elapsed          : {}", elapsed));
            self.output
                .report
                .info(&format!("stream id        : {}", stream_id));
            self.output.report.info(&format!(
                "file size        : {:.2}",
                Size(handler.stats.size)
            ));
            self.output.report.info(&format!(
                "mapped size      : {:.2}",
                Size(handler.stats.mapped_size)
            ));
            self.output
                .report
                .info(&format!("total read       : {:.2}", Size(total_read)));
            self.output.report.info(&format!(
                "fills size       : {:.2}",
                Size(handler.stats.fill_size)
            ));
            self.output.report.info(&format!(
                "duplicate data   : {:.2}",
                Size(total_read - handler.stats.written - handler.stats.fill_size)
            ));

            self.output.report.info(&format!(
                "data written     : {:.2}",
                Size(handler.stats.written)
            ));
            self.output.report.info(&format!(
                "stream written   : {:.2}",
                Size(handler.stats.stream_written)
            ));
            self.output
                .report
                .info(&format!("ratio            : {:.2}", ratio));
            self.output.report.info(&format!(
                "speed            : {:.2}/s",
                Size((total_read as f64 / elapsed) as u64)
            ));
        }
        Ok(())
    }
}

//-----------------------------------------

fn thick_packer(output: Arc<Output>, names: stream_meta::StreamNames) -> Result<Packer> {
    let mut stats = stream_meta::StreamStats::zero();

    stats.size = thinp::file_utils::file_size(names.input_file.clone())?;

    let input_iter = Box::new(ThickChunker::new(
        &names.input_file.clone(),
        16 * 1024 * 1024,
    )?);
    let thin_id = None;
    let builder = Arc::new(Mutex::new(MappingBuilder::default()));

    Ok(Packer::new(
        output, names, input_iter, stats, builder, 4096, thin_id,
    ))
}

fn thin_packer(output: Arc<Output>, names: stream_meta::StreamNames) -> Result<Packer> {
    let input = OpenOptions::new()
        .read(true)
        .write(false)
        .open(names.input_file.clone())
        .context("couldn't open input file/dev")?;
    let mut stats = stream_meta::StreamStats::zero();
    stats.size = thinp::file_utils::file_size(names.input_file.clone())?;

    let mappings = read_thin_mappings(names.input_file.clone())?;
    stats.mapped_size = mappings.provisioned_blocks.len() * mappings.data_block_size as u64 * 512;
    let run_iter = RunIter::new(
        mappings.provisioned_blocks,
        (stats.size / (mappings.data_block_size as u64 * 512)) as u32,
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
        .set_title(&format!("Packing {} ...", names.input_file.display()));
    Ok(Packer::new(
        output, names, input_iter, stats, builder, 4096, thin_id,
    ))
}

// FIXME: slow
fn open_thin_stream(stream_id: &str) -> Result<SlabFile> {
    SlabFileBuilder::open(stream_path(stream_id))
        .build()
        .context("couldn't open old stream file")
}

fn thin_delta_packer(
    matches: &ArgMatches,
    output: Arc<Output>,
    names: stream_meta::StreamNames,
    delta_device: &Path,
    delta_id: &str,
    server: &Option<String>,
) -> Result<Packer> {
    let input = OpenOptions::new()
        .read(true)
        .write(false)
        .open(names.input_file.clone())
        .context("couldn't open input file/dev")?;

    let mut stats = stream_meta::StreamStats::zero();
    stats.size = thinp::file_utils::file_size(names.input_file.clone())?;

    let mappings = read_thin_delta(delta_device, &names.input_file.clone())?;

    let run_iter = DualIter::new(
        mappings.additions,
        mappings.removals,
        (stats.size / (mappings.data_block_size as u64 * 512)) as u32,
    );

    let mut old_entries: Vec<MapEntry>;

    if server.is_none() {
        let old_config = stream_meta::read_stream_config(delta_id)?;
        stats.mapped_size = old_config.mapped_size;

        let old_stream = open_thin_stream(delta_id)?;
        let stream_iter = StreamIter::new(old_stream)?;

        // TODO: How much memory are we using here for large block devices?  Do we need to change
        // this back to reading off of disk as we are processing the block device/file?
        old_entries = stream_iter.collect::<Result<_, _>>()?;

        archive::Data::calculate_stream_map_entry_lengths(matches, &mut old_entries)?;
    } else {
        // For client/server we need to fetch this from server
        let server = server.clone().unwrap();
        let response = client::one_rpc(
            &server,
            wire::Rpc::StreamRetrieveDelta(0, delta_id.to_string()),
        );
        match response {
            Ok(v) => {
                let v = v.unwrap();
                if let wire::Rpc::StreamRetrieveDeltaResp(_id, meta, map_entries) = v {
                    stats.mapped_size = meta.mapped_size;
                    old_entries = map_entries;
                } else {
                    panic!("We are expecting a result from wire::Rpc::StreamRetrieveDeltaResp");
                }
            }
            Err(e) => {
                let msg = format!("error while retrieving delta stream meta data & stream map entries, server {} error {}", server, e);
                return Err(anyhow!(msg));
            }
        }
    }

    let input_iter = Box::new(DeltaChunker::new(
        input,
        run_iter,
        mappings.data_block_size as u64 * 512,
    ));
    let thin_id = Some(mappings.thin_id);

    let builder = Arc::new(Mutex::new(DeltaBuilder::new(old_entries.into_iter())));

    output
        .report
        .set_title(&format!("Packing {} ...", names.input_file.display()));
    Ok(Packer::new(
        output, names, input_iter, stats, builder, 4096, thin_id,
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

pub fn run(matches: &ArgMatches, output: Arc<Output>, server: Option<String>) -> Result<()> {
    let input_file = Path::new(matches.get_one::<String>("INPUT").unwrap());
    let input_name = input_file
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let input_file = Path::new(matches.get_one::<String>("INPUT").unwrap()).canonicalize()?;

    let names = stream_meta::StreamNames {
        name: input_name,
        input_file: input_file.clone(),
    };

    if server.is_none() {
        let archive_dir =
            Path::new(matches.get_one::<String>("ARCHIVE").unwrap()).canonicalize()?;
        env::set_current_dir(archive_dir)?;
    }

    output
        .report
        .set_title(&format!("Building packer {} ...", input_file.display()));

    let packer = if let Some((delta_stream, delta_device)) = get_delta_args(matches)? {
        thin_delta_packer(
            matches,
            output.clone(),
            names,
            &delta_device,
            &delta_stream,
            &server,
        )?
    } else if is_thin_device(&input_file)? {
        thin_packer(output.clone(), names)?
    } else {
        thick_packer(output.clone(), names)?
    };

    output
        .report
        .set_title(&format!("Packing {} ...", input_file.display()));
    packer.pack(server, matches)
}

//-----------------------------------------
