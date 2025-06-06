use anyhow::Result;
use parking_lot::{Condvar, Mutex};
use rkyv::{rancor::Error, Archive, Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::process;
use std::sync::Arc;
use std::thread;

use crate::cuckoo_filter;
use crate::handshake;
use crate::handshake::HandShake;
use crate::hash;
use crate::ipc;
use crate::ipc::*;
use crate::stream::*;
use crate::stream_orderer::*;
use crate::wire::{self, IOResult};

pub struct Client {
    s: Box<dyn ReadAndWrite>,
    data_inflight: HashMap<u64, Data>, // Data items waiting to complete
    cmds_inflight: HashMap<u64, HandShake>,
    so: StreamOrder<Sentry>,
    req_q: Arc<ClientRequests>,
    cuckoo: Option<cuckoo_filter::CuckooFilter>,
    cuckoo_req_outstanding: bool,
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Clone)]
#[rkyv(
    // This will generate a PartialEq impl between our unarchived
    // and archived types
    compare(PartialEq),
    // Derives can be passed through to the generated type:
    derive(Debug),
)]
pub struct Partial {
    pub begin: u32,
    pub end: u32,
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Clone)]
#[rkyv(
    // This will generate a PartialEq impl between our unarchived
    // and archived types
    compare(PartialEq),
    // Derives can be passed through to the generated type:
    derive(Debug),
)]
pub struct SlabInfo {
    pub slab: u32,
    pub offset: u32,
    pub nr_entries: u32,
    pub partial: Option<Partial>,
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Clone)]
#[rkyv(
    // This will generate a PartialEq impl between our unarchived
    // and archived types
    compare(PartialEq),
    // Derives can be passed through to the generated type:
    derive(Debug),
)]
pub enum IdType {
    Pack([u8; 32], u64),
    Unpack(SlabInfo), // Slab, offset, number entries, (partial_begin, partial_end)
}

#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Clone)]
#[rkyv(
    // This will generate a PartialEq impl between our unarchived
    // and archived types
    compare(PartialEq),
    // Derives can be passed through to the generated type:
    derive(Debug),
)]
pub struct Data {
    pub id: u64,
    pub t: IdType,
    pub data: Option<Vec<u8>>,
    pub entry: Option<MapEntry>,
}

#[derive(Debug)]
pub enum Command {
    Cmd(Box<wire::Rpc>),
    Exit,
}

pub struct SyncCommand {
    pub c: Command,
    pub h: HandShake,
}

impl SyncCommand {
    pub fn new(c: Command) -> Self {
        SyncCommand {
            c,
            h: HandShake::new(),
        }
    }
}

const HIGH_WATER_START: u64 = 1024 * 1024 * 5;

pub struct ClientRequests {
    inner: Mutex<Inner>,
    condvar: Condvar,
}

struct Inner {
    data: VecDeque<Data>,
    control: VecDeque<SyncCommand>,
    data_queued: u64,
    dead_thread: bool,
    data_written: u64,
    high_water_mark: u64,
    data_add_wait_count: u64,
    data_remove_empty_count: u64,
}

impl ClientRequests {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                data: VecDeque::new(),
                control: VecDeque::new(),
                data_queued: 0,
                dead_thread: false,
                data_written: 0,
                high_water_mark: HIGH_WATER_START,
                data_add_wait_count: 0,
                data_remove_empty_count: 0,
            }),
            condvar: Condvar::new(),
        })
    }

    pub fn increment_counts(&self, data_written: u64) {
        let mut inner = self.inner.lock();
        inner.data_written += data_written;
    }

    pub fn current_counts(&self) -> u64 {
        let inner = self.inner.lock();
        inner.data_written
    }

    pub fn thread_exited(&self) {
        let mut inner = self.inner.lock();
        inner.dead_thread = true;
    }

    pub fn no_longer_serviced(&self) -> bool {
        let inner = self.inner.lock();
        inner.dead_thread
    }

    pub fn handle_data(&self, d: Data) {
        let mut inner = self.inner.lock();
        if let Some(ref d) = d.data {
            inner.data_queued += d.len() as u64;
        }
        inner.data.push_back(d);

        if inner.data_queued >= inner.high_water_mark {
            inner.data_add_wait_count += 1;

            if inner.data_add_wait_count > 3 && inner.data_remove_empty_count > 0 {
                inner.high_water_mark += (1024 * 1024) as u64;
                inner.data_add_wait_count = 0;
                inner.data_remove_empty_count = 0;
            }

            while inner.data_queued > inner.high_water_mark - (1024 * 1024) {
                self.condvar.wait(&mut inner);
            }
        }
    }

    pub fn remove(&self) -> Option<Data> {
        let mut inner = self.inner.lock();
        let r = inner.data.pop_front();
        if let Some(ref tmp) = r {
            if let Some(ref d) = tmp.data {
                inner.data_queued = inner.data_queued.saturating_sub(d.len() as u64);
                self.condvar.notify_one();
            }
        } else {
            inner.data_remove_empty_count += 1;
        }

        r
    }

    pub fn handle_control(&self, c: SyncCommand) {
        let mut inner = self.inner.lock();
        inner.control.push_back(c);
    }

    pub fn remove_control(&self) -> Option<SyncCommand> {
        let mut inner = self.inner.lock();
        inner.control.pop_front()
    }
}

pub const END: Data = Data {
    id: u64::MAX,
    t: IdType::Pack([0; 32], 0),
    data: None,
    entry: None,
};

pub fn client_thread_end(client_req: &Arc<ClientRequests>) {
    client_req.handle_data(END);
}

impl Client {
    pub fn new(server: String, so: StreamOrder<Sentry>) -> Result<Self> {
        let s = create_connected_socket(server)?;

        Ok(Self {
            s,
            data_inflight: HashMap::new(),
            cmds_inflight: HashMap::new(),
            so,
            req_q: ClientRequests::new(),
            cuckoo: None,
            cuckoo_req_outstanding: false,
        })
    }

    fn remove_data_req(&mut self) -> Option<Data> {
        self.req_q.remove()
    }

    fn remove_control_req(&mut self) -> Option<SyncCommand> {
        self.req_q.remove_control()
    }

    fn request_cuckoo(&mut self, w_b: &mut wire::OutstandingWrites) -> Result<wire::IOResult> {
        self.cuckoo_req_outstanding = true;
        let mut rc = wire::IOResult::Ok;
        let rpc = wire::Rpc::CuckooFilterReq;
        if wire::write_request(&mut self.s, &rpc, wire::WriteChunk::None, w_b)? {
            rc = wire::IOResult::WriteWouldBlock;
        }
        Ok(rc)
    }

    fn process_request_queue(
        &mut self,
        w_b: &mut wire::OutstandingWrites,
    ) -> Result<wire::IOResult> {
        // Empty the request queue and send as one packet!
        let mut rc = wire::IOResult::Ok;
        let mut pack_entries = Vec::new();
        let mut should_exit = false;

        while let Some(mut e) = self.remove_data_req() {
            if e.id == u64::MAX {
                should_exit = true;
                rc = wire::IOResult::Exit;
            } else {
                // We need to
                let t = &e.t;
                let id = e.id;
                match t {
                    IdType::Pack(hash, _len) => {
                        // check to see if we have a local replicated cuckoo filter, so that we
                        // can tell without making a round trip that we need to send the data.
                        if let Some(cf) = &mut self.cuckoo {
                            let mh = hash::hash_le_u64(hash);
                            if let Ok(test_result) = cf.test(mh) {
                                if test_result == cuckoo_filter::InsertResult::Inserted {
                                    // Definitely not present, so lets simply send the data
                                    let d = e.data.take().expect("no data on a pack!");
                                    let pack_req = wire::Rpc::PackReq(id, *hash);
                                    if wire::write_request(
                                        &mut self.s,
                                        &pack_req,
                                        wire::WriteChunk::Data(d),
                                        w_b,
                                    )? {
                                        rc = wire::IOResult::WriteWouldBlock;
                                    }
                                } else {
                                    // May already be present, lets check
                                    pack_entries.push(wire::DataReq { id, hash: *hash });
                                }
                            }
                        } else {
                            if !self.cuckoo_req_outstanding {
                                let request_result = self.request_cuckoo(w_b)?;
                                if request_result != wire::IOResult::Ok {
                                    rc = request_result;
                                }
                            }

                            pack_entries.push(wire::DataReq { id, hash: *hash });
                        }
                        self.data_inflight.insert(id, e);
                        if rc == wire::IOResult::WriteWouldBlock {
                            break;
                        }
                    }
                    IdType::Unpack(_s) => {
                        let t = e.t.clone();
                        self.data_inflight.insert(e.id, e);
                        let rpc_request = wire::Rpc::RetrieveChunkReq(id, t);
                        if wire::write_request(
                            &mut self.s,
                            &rpc_request,
                            wire::WriteChunk::None,
                            w_b,
                        )? {
                            return Ok(wire::IOResult::WriteWouldBlock);
                        }
                    }
                }
            }
        }
        if !pack_entries.is_empty() {
            let rpc_request = wire::Rpc::HaveDataReq(pack_entries);
            if wire::write_request(&mut self.s, &rpc_request, wire::WriteChunk::None, w_b)? {
                rc = wire::IOResult::WriteWouldBlock;
            }

            if should_exit {
                self.s.flush()?;
            }
        }

        if let Some(e) = self.remove_control_req() {
            match e.c {
                Command::Cmd(rpc) => {
                    self.cmds_inflight.insert(wire::id_get(&rpc), e.h.clone());
                    if wire::write_request(&mut self.s, &rpc, wire::WriteChunk::None, w_b)? {
                        rc = wire::IOResult::WriteWouldBlock;
                    }
                }
                Command::Exit => {
                    rc = wire::IOResult::Exit;
                    e.h.done(None);
                }
            }
        }

        if should_exit {
            // Are we OK if rc == WriteWouldBlock???
            rc = wire::IOResult::Exit;
        }

        Ok(rc)
    }

    fn process_read(
        &mut self,
        r: &mut wire::BufferMeta,
        w: &mut wire::OutstandingWrites,
    ) -> Result<wire::IOResult> {
        let mut rc = wire::read_request(&mut self.s, r)?;

        if rc == wire::IOResult::Ok {
            let arpc = rkyv::access::<wire::ArchivedRpc, Error>(&r.buff[r.meta_start..r.meta_end])
                .unwrap();
            let d = rkyv::deserialize::<wire::Rpc, Error>(arpc).unwrap();

            match d {
                wire::Rpc::RetrieveChunkResp(id) => {
                    let removed = self.data_inflight.remove(&id).unwrap();
                    if let IdType::Unpack(_s) = removed.t {
                        // The code can handle responses out of order, but the current implementation
                        // handles things in order.  Thus, when we receive this chunk of data for
                        // the unpack operation if we are caught up with processing the entries in
                        // the stream order, we could simply write this data to the output file/
                        // device which would prevent us from having to allocate memory here.
                        let mut data = Vec::with_capacity(r.data_len() as usize);
                        data.extend_from_slice(&r.buff[r.data_start..r.data_end]);

                        self.so.entry_complete(
                            id,
                            Sentry {
                                e: removed.entry.unwrap(),
                                len: None,
                                data: Some(data),
                            },
                        );
                    }
                }
                wire::Rpc::HaveDataRespYes(y) => {
                    // Server already had data, build the stream
                    for s in y {
                        let e = MapEntry::Data(DataFields {
                            slab: s.slab,
                            offset: s.offset,
                            nr_entries: 1,
                        });
                        let removed = self.data_inflight.remove(&s.id).unwrap();

                        match removed.t {
                            IdType::Pack(_hash, len) => {
                                self.so.entry_complete(
                                    s.id,
                                    Sentry {
                                        e,
                                        len: Some(len),
                                        data: None,
                                    },
                                );
                            }
                            _ => {
                                panic!("We are expecting only Pack type!");
                            }
                        }
                    }
                }
                wire::Rpc::HaveDataRespNo(to_send) => {
                    // Server does not have data, lets send it
                    for id in to_send {
                        if let Some(data) = self.data_inflight.get_mut(&id) {
                            if let IdType::Pack(hash, _len) = data.t {
                                let d = data.data.take().unwrap();
                                let pack_req = wire::Rpc::PackReq(data.id, hash);
                                if wire::write_request(
                                    &mut self.s,
                                    &pack_req,
                                    wire::WriteChunk::Data(d),
                                    w,
                                )? {
                                    rc = wire::IOResult::WriteWouldBlock;
                                }
                            }
                        } else {
                            panic!("How does this happen? {}", id);
                        }
                    }
                }
                wire::Rpc::PackResp(id, p) => {
                    self.req_q.increment_counts(p.data_written);
                    let e = MapEntry::Data(DataFields {
                        slab: p.slab,
                        offset: p.offset,
                        nr_entries: 1,
                    });
                    let removed = self.data_inflight.remove(&id).unwrap();

                    if let IdType::Pack(hash, len) = removed.t {
                        // If we have a local cuckoo filter, update it
                        if let Some(cf) = &mut self.cuckoo {
                            if p.data_written > 0 {
                                let ts_result = cf.test_and_set(hash::hash_le_u64(&hash), p.slab);
                                if ts_result.is_err() {
                                    self.cuckoo.take();
                                    let request_result = self.request_cuckoo(w)?;
                                    if request_result != wire::IOResult::Ok {
                                        rc = request_result;
                                    }
                                }
                            }
                        }

                        let se = Sentry {
                            e,
                            len: Some(len),
                            data: None,
                        };
                        self.so.entry_complete(id, se);
                    } else {
                        panic!("we're expecting IdType::Pack, got {:?}", removed.t);
                    }
                }
                wire::Rpc::StreamSendComplete(id) => {
                    self.cmds_inflight.remove(&id).unwrap().done(None);
                }
                wire::Rpc::ArchiveListResp(id, archive_list) => {
                    // This seems wrong, to have a Archive Resp and craft another to return?
                    self.cmds_inflight
                        .remove(&id)
                        .unwrap()
                        .done(Some(wire::Rpc::ArchiveListResp(id, archive_list)));
                }
                wire::Rpc::ArchiveConfigResp(id, config) => {
                    self.cmds_inflight
                        .remove(&id)
                        .unwrap()
                        .done(Some(wire::Rpc::ArchiveConfigResp(id, config)));
                }
                wire::Rpc::StreamRetrieveResp(id, data) => {
                    self.cmds_inflight
                        .remove(&id)
                        .unwrap()
                        .done(Some(wire::Rpc::StreamRetrieveResp(id, data)));
                }
                wire::Rpc::StreamRetrieveDeltaResp(id, stream_config, map_entries) => {
                    self.cmds_inflight.remove(&id).unwrap().done(Some(
                        wire::Rpc::StreamRetrieveDeltaResp(id, stream_config, map_entries),
                    ));
                }
                wire::Rpc::StreamConfigResp(id, config) => {
                    self.cmds_inflight
                        .remove(&id)
                        .unwrap()
                        .done(Some(wire::Rpc::StreamConfigResp(id, config)));
                }
                wire::Rpc::CuckooFilterResp(filter) => {
                    self.cuckoo = Some(cuckoo_filter::CuckooFilter::from_rpc(*filter));
                    self.cuckoo_req_outstanding = false;
                }
                wire::Rpc::Error(_id, msg) => {
                    eprintln!("Unexpected error, server reported: {}", msg);
                    process::exit(2);
                }
                _ => {
                    panic!("What are we not handling! {:?}", d);
                }
            }
            r.rezero();
        }

        Ok(rc)
    }

    fn _enable_poll_out(event_fd: i32, fd: i32, current_setting: &mut bool) -> Result<()> {
        if *current_setting {
            return Ok(());
        }

        *current_setting = true;
        let mut event = ipc::read_event(fd);
        event.events |= epoll::Events::EPOLLOUT.bits();
        event.data = fd as u64;

        Ok(epoll::ctl(
            event_fd,
            epoll::ControlOptions::EPOLL_CTL_MOD,
            fd,
            event,
        )?)
    }

    fn _run(&mut self) -> Result<()> {
        let event_fd = epoll::create(true)?;
        let fd = self.s.as_raw_fd();
        let mut event = ipc::read_event(fd);
        let mut poll_out = false;

        epoll::ctl(event_fd, epoll::ControlOptions::EPOLL_CTL_ADD, fd, event)?;

        let mut r = wire::BufferMeta::new();
        let mut w = wire::OutstandingWrites::new();

        loop {
            let mut events = [epoll::Event::new(epoll::Events::empty(), 0); 10];
            let rdy = epoll::wait(event_fd, 2, &mut events)?;
            let mut end = false;

            for item_rdy in events.iter().take(rdy) {
                if item_rdy.events & epoll::Events::EPOLLERR.bits()
                    == epoll::Events::EPOLLERR.bits()
                    || item_rdy.events & epoll::Events::EPOLLHUP.bits()
                        == epoll::Events::EPOLLHUP.bits()
                {
                    epoll::ctl(
                        event_fd,
                        epoll::ControlOptions::EPOLL_CTL_DEL,
                        event.data as i32,
                        event,
                    )?;
                    eprintln!("Socket errors, exiting!");
                    end = true;
                    break;
                }

                if item_rdy.events & epoll::Events::EPOLLIN.bits() == epoll::Events::EPOLLIN.bits()
                {
                    let read_result = self.process_read(&mut r, &mut w);
                    match read_result {
                        Err(e) => {
                            eprintln!("Error on read, exiting! {:?}", e);
                            return Err(e);
                        }
                        Ok(r) => {
                            if r == wire::IOResult::WriteWouldBlock {
                                Client::_enable_poll_out(event_fd, fd, &mut poll_out)?;
                            }
                        }
                    }
                }

                if item_rdy.events & epoll::Events::EPOLLOUT.bits()
                    == epoll::Events::EPOLLOUT.bits()
                    && w.write(&mut self.s)? == IOResult::Ok
                {
                    poll_out = false;
                    event = ipc::read_event(event.data as i32);
                    event.data = fd as u64;
                    epoll::ctl(
                        event_fd,
                        epoll::ControlOptions::EPOLL_CTL_MOD,
                        event.data as i32,
                        event,
                    )?;
                }
            }

            if end {
                break;
            }

            let rc = self.process_request_queue(&mut w)?;
            if rc == wire::IOResult::Exit {
                break;
            } else if rc == wire::IOResult::WriteWouldBlock {
                Client::_enable_poll_out(event_fd, fd, &mut poll_out)?;
            }
        }
        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        let result = self._run();

        self.req_q.thread_exited();

        if let Err(e) = result {
            eprintln!("Client runner errored: {}", e);
            return Err(e);
        }

        Ok(())
    }

    pub fn get_request_queue(&self) -> Arc<ClientRequests> {
        self.req_q.clone()
    }
}

pub fn rpc_invoke(rq: &Arc<ClientRequests>, rpc: wire::Rpc) -> Result<Option<wire::Rpc>> {
    let h: handshake::HandShake;
    {
        let cmd = SyncCommand::new(Command::Cmd(Box::new(rpc)));
        h = cmd.h.clone();
        rq.handle_control(cmd);
    }

    // Wait for this to be done
    Ok(h.wait())
}

pub fn one_rpc(server: &str, rpc: wire::Rpc) -> Result<Option<wire::Rpc>> {
    let so = StreamOrder::new();

    let mut client = Client::new(server.to_string(), so)?;
    let rq = client.get_request_queue();
    // Start a thread to handle client communication
    let thread_handle = thread::Builder::new()
        .name("one_rpc".to_string())
        .spawn(move || client.run())?;

    let response = rpc_invoke(&rq, rpc)?;
    client_thread_end(&rq);

    let rc = thread_handle.join();
    if rc.is_err() {
        eprintln!("client worker thread ended with {:?}", rc);
    }

    Ok(response)
}
