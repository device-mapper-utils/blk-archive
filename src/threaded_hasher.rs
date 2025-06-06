use anyhow::Result;
use crossbeam::channel::{unbounded, Receiver, Sender};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;

use crate::hash::*;
use crate::iovec::IoVecHandler;
use crate::stream_orderer::StreamOrder;

#[derive(Debug, Default, Clone)]
pub struct HashedData {
    pub h64: Hash64,
    pub h256: Hash256,
    pub data: Vec<u8>,
}

pub struct ThreadedHasher {
    queue: StreamOrder<HashedData>,
    sender: Sender<Option<(u64, Vec<u8>)>>,
    done: Arc<AtomicBool>,
    count: usize,
}

type WorkItem = Option<(u64, Vec<u8>)>;
type WorkChannel = (Sender<WorkItem>, Receiver<WorkItem>);

impl ThreadedHasher {
    pub fn new(worker_count: usize) -> Self {
        let queue = StreamOrder::new();
        let (tx, rx): WorkChannel = unbounded();
        let done = Arc::new(AtomicBool::new(false));

        let queue_clone = queue.clone();
        let done_clone = Arc::clone(&done);

        for _ in 0..worker_count {
            let queue_worker = queue_clone.clone();
            let rx_worker = rx.clone();
            let done_worker = Arc::clone(&done_clone);

            thread::spawn(move || {
                while let Some((id, data)) = rx_worker.recv().unwrap() {
                    let h256 = hash_256(&data);
                    let h64 = hash_64(&h256);
                    let hashed = HashedData { h64, h256, data };
                    queue_worker.entry_complete(id, hashed);

                    if done_worker.load(Ordering::SeqCst) {
                        break;
                    }
                }
            });
        }

        Self {
            queue,
            sender: tx,
            done,
            count: worker_count,
        }
    }

    pub fn enqueue_data(&self, data: Vec<u8>) {
        let id = self.queue.entry_start();
        self.sender.send(Some((id, data))).unwrap();
    }

    pub fn shut_down(&self) {
        self.done.store(true, Ordering::SeqCst);
        for _ in 0..self.count {
            self.sender.send(None).unwrap();
        }
    }

    pub fn drain(&self, wait: bool) -> (Vec<HashedData>, bool) {
        self.queue.drain(wait)
    }

    pub fn input_complete(&mut self) -> Result<()> {
        self.queue.input_complete();
        Ok(())
    }

    pub fn handle_all_outstanding(&self, handler: &mut impl IoVecHandler) -> Result<()> {
        loop {
            let (process, done) = self.drain(true);
            for t in process {
                handler.handle_data(t)?;
            }
            if done {
                break;
            }
        }
        Ok(())
    }
}
