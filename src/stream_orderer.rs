use parking_lot::{Condvar, Mutex};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::Arc;

use crate::stream::MapEntry;

// Creates order out of the unordered stream of map entries

#[derive(Debug)]
pub struct Sentry {
    pub e: MapEntry,
    pub len: Option<u64>,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug)]
struct Protected<T> {
    input_done: bool,
    seq_id: u64,
    next: u64,
    ready: BTreeMap<u64, T>,
}

#[derive(Debug)]
pub struct StreamOrder<T> {
    pair: Arc<(Mutex<Protected<T>>, Condvar)>,
}

impl<T> Clone for StreamOrder<T> {
    fn clone(&self) -> Self {
        Self {
            pair: Arc::clone(&self.pair),
        }
    }
}

impl<T> Default for StreamOrder<T>
where
    T: Debug,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> StreamOrder<T>
where
    T: Debug,
{
    pub fn new() -> Self {
        let p = Mutex::new(Protected {
            input_done: false,
            seq_id: 0,
            next: 0,
            ready: BTreeMap::new(),
        });

        Self {
            pair: Arc::new((p, Condvar::new())),
        }
    }

    fn _next(p: &mut Protected<T>) -> u64 {
        let v = p.seq_id;
        p.seq_id += 1;
        v
    }

    pub fn input_complete(&mut self) {
        let (protected, cvar) = &*self.pair;
        let mut p = protected.lock();
        p.input_done = true;
        cvar.notify_all();
    }

    pub fn entry_add(&self, item: T) {
        let (protected, cvar) = &*self.pair;
        let mut p = protected.lock();
        let next = Self::_next(&mut p);
        p.ready.insert(next, item);
        cvar.notify_all();
    }

    pub fn entry_start(&self) -> u64 {
        let (protected, _) = &*self.pair;
        let mut p = protected.lock();
        Self::_next(&mut p)
    }

    pub fn entry_complete(&self, id: u64, item: T) {
        let (protected, cvar) = &*self.pair;
        let mut p = protected.lock();
        p.ready.insert(id, item);
        cvar.notify_all();
    }

    fn remove(p: &mut Protected<T>) -> Option<T> {
        p.ready.remove(&p.next).inspect(|_| {
            p.next += 1;
        })
    }

    fn _complete(p: &Protected<T>) -> bool {
        p.input_done && p.ready.is_empty() && (p.seq_id == p.next)
            || (p.ready.is_empty() && (p.seq_id == p.next) && p.seq_id > 0)
    }

    pub fn drain(&self, wait: bool) -> (Vec<T>, bool) {
        let (protected, cvar) = &*self.pair;
        let mut p = protected.lock();

        if wait {
            while p.ready.is_empty() {
                // Before we place ourselves to sleep, make sure we aren't done!
                if !Self::_complete(&p) {
                    cvar.wait(&mut p);
                } else {
                    break;
                }
            }
        }

        let mut rc = Vec::new();
        while let Some(e) = Self::remove(&mut p) {
            rc.push(e);
        }
        (rc, Self::_complete(&p))
    }

    pub fn is_complete(&self) -> bool {
        let (protected, _) = &*self.pair;
        let p = protected.lock();
        Self::_complete(&p)
    }
}
