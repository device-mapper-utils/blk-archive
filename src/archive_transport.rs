use anyhow::{Context, Result};
use clap::ArgMatches;
use parking_lot::Mutex;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;

use crate::archive;
use crate::client;
use crate::handshake::HandShake;
use crate::hash::*;
use crate::paths::*;
use crate::slab::*;
use crate::stream::*;
use crate::stream_meta;
use crate::stream_orderer::*;
use crate::threaded_hasher::*;

pub trait Transport {
    fn pack(
        &mut self,
        so: &mut StreamOrder<Sentry>,
        hashed_data: HashedData,
        len: u64,
    ) -> Result<u64>;
    fn complete(
        &mut self,
        sm: &mut stream_meta::StreamMeta,
        stats: &mut stream_meta::StreamStats,
    ) -> Result<()>;
    fn remote(&self) -> bool {
        false
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

struct LocalArchive {
    ad: archive::Data,
}

struct RemoteArchive {
    client: Arc<client::ClientRequests>,
    join_handle: Option<JoinHandle<std::result::Result<(), anyhow::Error>>>,
}

impl LocalArchive {
    fn new(matches: &ArgMatches) -> Result<Self> {
        let data_file = SlabFileBuilder::open(data_path())
            .write(true)
            .queue_depth(128)
            .build()
            .context("couldn't open data slab file")?;

        let hashes_file = Arc::new(Mutex::new(
            SlabFileBuilder::open(hashes_path())
                .write(true)
                .queue_depth(16)
                .build()
                .context("couldn't open hashes slab file")?,
        ));
        Ok(Self {
            ad: archive::Data::new(None, Some(data_file), Some(hashes_file), matches)?,
        })
    }
}

impl Transport for LocalArchive {
    fn pack(
        &mut self,
        so: &mut StreamOrder<Sentry>,
        hashed_data: HashedData,
        len: u64,
    ) -> Result<u64> {
        let ((slab, offset), len_written) = self.ad.data_add(hashed_data, len)?;
        let me = MapEntry::Data(DataFields {
            slab,
            offset,
            nr_entries: 1,
        });
        so.entry_add(Sentry {
            e: me,
            len: Some(len),
            data: None,
        });
        Ok(len_written)
    }

    fn complete(
        &mut self,
        sm: &mut stream_meta::StreamMeta,
        stats: &mut stream_meta::StreamStats,
    ) -> Result<()> {
        sm.complete(stats)?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        self.ad.flush()
    }
}

impl RemoteArchive {
    fn new(s_conn: String, so: StreamOrder<Sentry>) -> Result<Self> {
        println!("Client is connecting to server using {}", s_conn);
        let mut client = client::Client::new(s_conn, so)?;
        let rq = client.get_request_queue();
        // Start a thread to handle client communication
        let h = thread::Builder::new()
            .name("client socket handler".to_string())
            .spawn(move || client.run())?;

        Ok(Self {
            client: rq,
            join_handle: Some(h),
        })
    }
}

impl Transport for RemoteArchive {
    fn pack(&mut self, so: &mut StreamOrder<Sentry>, hd: HashedData, len: u64) -> Result<u64> {
        let data = client::Data {
            id: so.entry_start(),
            t: client::IdType::Pack(hash256_to_bytes(&hd.h256), len),
            data: Some(hd.data),
            entry: None,
        };
        self.client.handle_data(data);
        Ok(0)
    }

    fn complete(
        &mut self,
        sm: &mut stream_meta::StreamMeta,
        stats: &mut stream_meta::StreamStats,
    ) -> Result<()> {
        let h: HandShake;
        // Send the stream file to the server and wait for it to complete
        {
            stats.written = self.client.current_counts();
            // Send the stream metadata & stream itself to the server side
            let to_send = sm.package(stats)?;
            let cmd = client::SyncCommand::new(client::Command::Cmd(Box::new(to_send)));
            h = cmd.h.clone();
            self.client.handle_control(cmd);
        }

        // You need to make sure we are not holding a lock when we call wait,
        // this is achieved by using different scopes.
        h.wait();

        client::client_thread_end(&self.client);

        if let Some(worker) = self.join_handle.take() {
            let rc = worker.join();
            if rc.is_err() {
                println!("client worker thread ended with {:?}", rc);
            }
        }
        Ok(())
    }

    fn remote(&self) -> bool {
        true
    }
}

pub fn create_archive_transport(
    server_addr: Option<String>,
    so: StreamOrder<Sentry>,
    matches: &ArgMatches,
) -> Result<Box<dyn Transport>> {
    if let Some(s_conn) = server_addr {
        Ok(Box::new(RemoteArchive::new(s_conn, so)?))
    } else {
        Ok(Box::new(LocalArchive::new(matches)?))
    }
}
