use anyhow::{anyhow, Result};

use crate::hash::bytes_to_hash256;
use crate::wire::{self, IOResult, WriteChunk};
use crate::{archive::*, config};

use clap::ArgMatches;
use nix::sys::signal;
use nix::sys::signal::SigSet;
use nix::sys::signalfd::{SfdFlags, SignalFd};
use rkyv::rancor::Error;
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tempfile::TempDir;

use crate::client;
use crate::iovec::*;
use crate::ipc;
use crate::ipc::*;
use crate::list::streams_get;
use crate::stream_meta;

#[derive(Debug, Default)]
struct ServerStats {
    have_data_req: u64,
    have_data_req_found: u64,
    have_data_req_missing: u64,
    pack_req: u64,
    stream_send: u64,
    archive_list_req: u64,
    archive_config: u64,
    stream_config: u64,
    stream_retrieve: u64,
    stream_retrieve_delta: u64,
    retrieve_chunk_req: u64,
    cuckoo_filter_req: u64,
}

impl ServerStats {
    pub fn new() -> Self {
        Self::default()
    }
}

impl fmt::Display for ServerStats {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "ServerStats:\n\
            have_data_req: {}\n\
            have_data_req_found: {}\n\
            have_data_req_missing: {}\n\
            pack_req: {}\n\
            stream_send: {}\n\
            archive_list_req: {}\n\
            archive_config: {}\n\
            stream_config: {}\n\
            stream_retrieve: {}\n\
            retrieve_chunk_req: {}\n\
            cuckoo_filter_req: {}",
            self.have_data_req,
            self.have_data_req_found,
            self.have_data_req_missing,
            self.pack_req,
            self.stream_send,
            self.archive_list_req,
            self.archive_config,
            self.stream_config,
            self.stream_retrieve,
            self.retrieve_chunk_req,
            self.cuckoo_filter_req
        )
    }
}

pub struct Server {
    da: Data,
    listener: Box<dyn ipc::Listening>,
    signalfd: SignalFd,
    pub exit: Arc<AtomicBool>,
    _ipc_dir: Option<TempDir>,
    matches: ArgMatches,
    stats: ServerStats,
}

struct Client<'a> {
    c: Box<dyn ReadAndWrite>,
    bm: wire::BufferMeta,
    w: wire::OutstandingWrites<'a>,
}

impl Client<'_> {
    fn new(c: Box<dyn ReadAndWrite>) -> Self {
        Self {
            c,
            bm: wire::BufferMeta::new(),
            w: wire::OutstandingWrites::new(),
        }
    }
}

impl Server {
    pub fn new(
        matches: ArgMatches,
        archive_path: Option<&Path>,
        one_system: bool,
    ) -> Result<(Self, Option<String>)> {
        // If we don't have an archive_dir, we'll assume caller already set the current working
        // directory
        if let Some(archive_dir) = archive_path {
            let archive_dir = archive_dir.canonicalize()?;
            env::set_current_dir(&archive_dir)?;
        }

        let sfd = {
            let mut mask = SigSet::empty();
            mask.add(signal::SIGINT);
            mask.thread_block()?;
            SignalFd::with_flags(&mask, SfdFlags::SFD_NONBLOCK)?
        };

        let da = Data::new(None, None, None, &matches)?;

        let ipc_dir = if one_system {
            Some(ipc::create_unix_ipc_dir()?)
        } else {
            None
        };

        let server_addr = if let Some(d) = &ipc_dir {
            let f = d.path().join("ipc_socket");
            f.into_os_string().into_string().unwrap()
        } else {
            "0.0.0.0:9876".to_string()
        };

        let listener = create_listening_socket(&server_addr)?;

        let c_path = if one_system { Some(server_addr) } else { None };

        Ok((
            Self {
                da,
                listener,
                signalfd: sfd,
                exit: Arc::new(AtomicBool::new(false)),
                _ipc_dir: ipc_dir,
                matches,
                stats: ServerStats::new(),
            },
            c_path,
        ))
    }

    fn send_error(
        id: u64,
        c: &mut Client,
        error: impl std::fmt::Display,
        message_prefix: &str,
        rc: &mut wire::IOResult,
    ) -> Result<wire::IOResult> {
        let message = format!("{}{}", message_prefix, error);

        if wire::write_request(
            &mut c.c,
            &wire::Rpc::Error(id, message),
            wire::WriteChunk::None,
            &mut c.w,
        )? {
            *rc = wire::IOResult::WriteWouldBlock;
        }

        Ok(wire::IOResult::Ok)
    }

    fn send_rpc(
        c: &mut Client,
        m: &wire::Rpc,
        d: wire::WriteChunk,
        rc: &mut wire::IOResult,
    ) -> Result<wire::IOResult> {
        if wire::write_request(&mut c.c, m, d, &mut c.w)? {
            *rc = wire::IOResult::WriteWouldBlock;
        }

        Ok(wire::IOResult::Ok)
    }

    fn send_rpc_no_data(
        c: &mut Client,
        m: &wire::Rpc,
        rc: &mut wire::IOResult,
    ) -> Result<wire::IOResult> {
        Self::send_rpc(c, m, wire::WriteChunk::None, rc)
    }

    fn process_read(&mut self, c: &mut Client) -> Result<wire::IOResult> {
        let mut found_it = Vec::new();
        let mut data_needed: Vec<u64> = Vec::new();

        // This reads a single request from the wire, we may need to change it to handle
        // all the requests to keep the incoming data as empty as possible.
        let mut rc = wire::read_request(&mut c.c, &mut c.bm)?;

        if rc == wire::IOResult::Ok {
            // We have a complete RPC request

            let r = rkyv::access::<wire::ArchivedRpc, Error>(
                &c.bm.buff[c.bm.meta_start..c.bm.meta_end],
            )
            .unwrap();
            let d = rkyv::deserialize::<wire::Rpc, Error>(r).unwrap();
            match d {
                wire::Rpc::HaveDataReq(data_req) => {
                    self.stats.have_data_req += 1;
                    for i in data_req {
                        let hash256 = bytes_to_hash256(&i.hash);
                        if let Some(location) = self.da.is_known(hash256)? {
                            self.stats.have_data_req_found += 1;
                            // We know about this one
                            let l = wire::DataRespYes {
                                id: i.id,
                                slab: location.0,
                                offset: location.1,
                            };
                            found_it.push(l);
                        } else {
                            // We need to add the data
                            self.stats.have_data_req_missing += 1;
                            data_needed.push(i.id);
                        }
                    }
                }
                wire::Rpc::PackReq(id, hash) => {
                    self.stats.pack_req += 1;
                    let mut iov = IoVec::new();
                    let hash256 = bytes_to_hash256(&hash);
                    iov.push(&c.bm.buff[c.bm.data_start..c.bm.data_end]);
                    let (entry, data_written) =
                        self.da.data_add_iov(*hash256, &iov, c.bm.data_len())?;
                    let new_entry = wire::PackResp {
                        slab: entry.0,
                        offset: entry.1,
                        data_written,
                    };

                    let r = wire::Rpc::PackResp(id, Box::new(new_entry));
                    Self::send_rpc_no_data(c, &r, &mut rc)?;
                }
                wire::Rpc::StreamSend(id, sm, stream_files_bytes) => {
                    self.stats.stream_send += 1;
                    let packed_path = sm.source_path.clone();
                    let sf = wire::bytes_to_stream_files(&stream_files_bytes);
                    let write_rc =
                        stream_meta::package_unwrap(&sm, sf.stream.to_vec(), sf.offsets.to_vec());
                    // We have been sent a stream file, lets sync the data slab
                    self.da.flush().unwrap();
                    match write_rc {
                        Ok(_) => {
                            Self::send_rpc_no_data(c, &wire::Rpc::StreamSendComplete(id), &mut rc)?;
                        }
                        Err(e) => {
                            let message = format!(
                                "During stream write id={} for stream = {} we encountered {}",
                                id, packed_path, e
                            );
                            Self::send_error(id, c, e, &message, &mut rc)?;
                        }
                    }
                }
                wire::Rpc::ArchiveListReq(id) => {
                    self.stats.archive_list_req += 1;
                    let streams = streams_get(&PathBuf::from("./streams"));
                    match streams {
                        Ok(streams) => {
                            Self::send_rpc_no_data(
                                c,
                                &wire::Rpc::ArchiveListResp(id, streams),
                                &mut rc,
                            )?;
                        }
                        Err(e) => {
                            let message = format!("During list::streams_get we encountered {}", e);
                            Self::send_error(id, c, e, &message, &mut rc)?;
                        }
                    }
                }
                wire::Rpc::ArchiveConfig(id) => {
                    self.stats.archive_config += 1;
                    let config = config::read_config(".", &self.matches);
                    match config {
                        Ok(config) => {
                            Self::send_rpc_no_data(
                                c,
                                &wire::Rpc::ArchiveConfigResp(id, config),
                                &mut rc,
                            )?;
                        }
                        Err(e) => {
                            let message =
                                format!("During wire::Rpc::ArchiveConfig we encountered {}", e);
                            Self::send_error(id, c, e, &message, &mut rc)?;
                        }
                    }
                }
                wire::Rpc::StreamConfig(id, stream_id) => {
                    self.stats.stream_config += 1;
                    // Read up the stream config
                    let stream_config = stream_meta::read_stream_config(&stream_id);

                    match stream_config {
                        Ok(stream_config) => {
                            Self::send_rpc_no_data(
                                c,
                                &wire::Rpc::StreamConfigResp(id, Box::new(stream_config)),
                                &mut rc,
                            )?;
                        }
                        Err(e) => {
                            let message =   //println!("process_read entry!");
                                format!("During wire::Rpc::StreamConfig we encountered {}", e);
                            Self::send_error(id, c, e, &message, &mut rc)?;
                        }
                    }
                }
                wire::Rpc::StreamRetrieve(id, stream_id) => {
                    self.stats.stream_retrieve += 1;
                    let stream_files = stream_meta::stream_id_to_stream_files(&stream_id);

                    if let Err(e) = stream_files {
                        let message =
                            format!("During wire::Rpc::StreamRetrieve we encountered {}", e);
                        Self::send_error(id, c, e, &message, &mut rc)?;
                    } else {
                        let stream_files = stream_files.unwrap();
                        Self::send_rpc_no_data(
                            c,
                            &wire::Rpc::StreamRetrieveResp(id, stream_files),
                            &mut rc,
                        )?;
                    }
                }
                wire::Rpc::StreamRetrieveDelta(id, stream_id) => {
                    self.stats.stream_retrieve_delta += 1;

                    match stream_meta::read_stream_config(&stream_id) {
                        Ok(config) => {
                            let stream_entries = stream_meta::stream_map_entries_with_data_lengths(
                                &mut self.da,
                                &stream_id,
                            );
                            match stream_entries {
                                Ok(se) => {
                                    Self::send_rpc_no_data(
                                        c,
                                        &wire::Rpc::StreamRetrieveDeltaResp(id, config, se),
                                        &mut rc,
                                    )?;
                                }
                                Err(e) => {
                                    let message = format!(
                                        "wire::Rpc::StreamRetrieveDelta failure for stream {:?}: {}",
                                        stream_id, e
                                    );
                                    Self::send_error(id, c, e, &message, &mut rc)?;
                                }
                            }
                        }
                        Err(e) => {
                            let message = format!(
                                "wire::Rpc::StreamRetrieveDelta failed to load stream config: {}",
                                e
                            );
                            Self::send_error(id, c, e, &message, &mut rc)?;
                        }
                    }
                }
                wire::Rpc::RetrieveChunkReq(id, op_type) => {
                    self.stats.retrieve_chunk_req += 1;
                    if let client::IdType::Unpack(s) = op_type {
                        let p = s.partial.map(|partial| (partial.begin, partial.end));

                        // How could this fail in normal operation?
                        let (data, start, end) =
                            self.da.data_get(s.slab, s.offset, s.nr_entries, p).unwrap();

                        Self::send_rpc(
                            c,
                            &wire::Rpc::RetrieveChunkResp(id),
                            WriteChunk::ArcData(data, start, end),
                            &mut rc,
                        )?;
                    } else {
                        panic!(
                            "expecting RetrieveChunkReq client::IdType::Unpack, got {:?}",
                            op_type
                        );
                    }
                }
                wire::Rpc::CuckooFilterReq => {
                    self.stats.cuckoo_filter_req += 1;
                    let filter = self.da.get_seen();

                    Self::send_rpc_no_data(
                        c,
                        &wire::Rpc::CuckooFilterResp(Box::new(filter)),
                        &mut rc,
                    )?;
                }
                _ => {
                    eprint!("What are we not handling! {:?}", d);
                }
            }
            c.bm.rezero();
        } else if rc == IOResult::PeerGone {
            return Err(anyhow!("Client closed connection"));
        }

        if !found_it.is_empty() {
            Self::send_rpc_no_data(c, &wire::Rpc::HaveDataRespYes(found_it), &mut rc)?;
        }

        if !data_needed.is_empty() {
            Self::send_rpc_no_data(c, &wire::Rpc::HaveDataRespNo(data_needed), &mut rc)?;
        }

        Ok(rc)
    }

    pub fn run(&mut self) -> Result<()> {
        println!("running as a service!");
        let event_fd = epoll::create(true)?;
        let mut clients = HashMap::<i32, Client>::new();

        let listen_fd = self.listener.as_raw_fd();

        let mut event: epoll::Event = epoll::Event {
            events: epoll::Events::EPOLLIN.bits(),
            data: listen_fd as u64,
        };

        epoll::ctl(
            event_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            listen_fd,
            event,
        )?;

        let sfd_fd = self.signalfd.as_raw_fd();
        event = ipc::read_event(sfd_fd);
        event.data = sfd_fd as u64;

        epoll::ctl(
            event_fd,
            epoll::ControlOptions::EPOLL_CTL_ADD,
            sfd_fd,
            event,
        )?;

        loop {
            let mut events = [epoll::Event::new(epoll::Events::empty(), 0); 10];
            let rdy = epoll::wait(event_fd, 100, &mut events)?;
            let mut end = false;

            for item_rdy in events.iter().take(rdy) {
                if item_rdy.events == epoll::Events::EPOLLIN.bits()
                    && item_rdy.data == listen_fd as u64
                {
                    let (new_client, addr) = self.listener.accept()?;
                    println!("We accepted a connection from {}", addr);
                    let fd = new_client.as_raw_fd();

                    event = ipc::read_event(fd);
                    epoll::ctl(event_fd, epoll::ControlOptions::EPOLL_CTL_ADD, fd, event)?;
                    clients.insert(fd, Client::new(new_client));
                }

                //if events[i].events == epoll::Events::EPOLLIN.bits() && events[i].data == sfd_fd as u64
                if item_rdy.data == sfd_fd as u64 {
                    eprintln!("SIGINT, exiting!");
                    end = true;
                    break;
                }

                if item_rdy.events & epoll::Events::EPOLLERR.bits()
                    == epoll::Events::EPOLLERR.bits()
                    || item_rdy.events & epoll::Events::EPOLLHUP.bits()
                        == epoll::Events::EPOLLHUP.bits()
                {
                    eprintln!("POLLERR");

                    let fd_to_remove = item_rdy.data as i32;
                    event.data = fd_to_remove as u64;
                    epoll::ctl(
                        event_fd,
                        epoll::ControlOptions::EPOLL_CTL_DEL,
                        fd_to_remove,
                        event,
                    )?;

                    clients.remove(&fd_to_remove.clone());
                    eprintln!("Removed client due to error!");
                } else if item_rdy.events & epoll::Events::EPOLLIN.bits()
                    == epoll::Events::EPOLLIN.bits()
                    && item_rdy.data != listen_fd as u64
                {
                    let fd: i32 = item_rdy.data as i32;
                    let s = clients.get_mut(&fd).unwrap();

                    let result = self.process_read(s);
                    match result {
                        Err(e) => {
                            println!("Client removed: {}", e);
                            clients.remove(&fd);
                        }
                        Ok(r) => {
                            if r == wire::IOResult::WriteWouldBlock {
                                event.events |= epoll::Events::EPOLLOUT.bits();
                                event.data = fd as u64;
                                epoll::ctl(
                                    event_fd,
                                    epoll::ControlOptions::EPOLL_CTL_MOD,
                                    fd,
                                    event,
                                )?;
                            }
                        }
                    }
                }

                if item_rdy.events & epoll::Events::EPOLLOUT.bits()
                    == epoll::Events::EPOLLOUT.bits()
                {
                    eprintln!("POLLOUT!");

                    // We only get here if we got an would block on a write before
                    let fd: i32 = item_rdy.data as i32;
                    let c = clients.get_mut(&fd).unwrap();

                    if c.w.write(&mut c.c)? == IOResult::Ok {
                        // We have no more pending data to write.
                        event = ipc::read_event(fd);
                        epoll::ctl(event_fd, epoll::ControlOptions::EPOLL_CTL_MOD, fd, event)?;
                    }
                }
            }

            if end {
                println!("{}", self.stats);
                break;
            }

            if self.exit.load(Ordering::Relaxed) {
                eprintln!("Server asked to exit!");
                break;
            }
        }
        Ok(())
    }
}
