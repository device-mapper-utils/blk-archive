use crate::stream::*;
use anyhow::{anyhow, Result};
use std::io::Write;

//------------------------------

pub trait Builder {
    fn next(&mut self, e: &MapEntry, len: u64, w: &mut Vec<u8>) -> Result<()>;

    // I'd rather pass plain 'self' here, but that won't work with runtime
    // polymorphism.
    fn complete(&mut self, w: &mut Vec<u8>) -> Result<()>;
}

pub struct MappingBuilder {
    // We insert a Pos instruction for every 'index_period' entries.
    index_period: u64,
    entries_emitted: u64,
    position: u64, // byte len of stream so far
    entry: Option<MapEntry>,
    vm_state: VMState,
}

fn pack_instrs<W: Write>(w: &mut W, instrs: &IVec) -> Result<()> {
    for i in instrs {
        i.pack(w)?;
    }
    Ok(())
}

// FIXME: bump up to 128
const INDEX_PERIOD: u64 = 128;

impl Default for MappingBuilder {
    fn default() -> Self {
        Self {
            index_period: INDEX_PERIOD,
            entries_emitted: 0,
            position: 0,
            entry: None,
            vm_state: VMState::default(),
        }
    }
}

impl MappingBuilder {
    fn encode_entry(&mut self, e: &MapEntry, instrs: &mut IVec) -> Result<()> {
        use MapEntry::*;

        match e {
            Fill { byte, len } => {
                self.vm_state.encode_fill(*byte, *len, instrs)?;
            }
            Unmapped { len } => {
                self.vm_state.encode_unmapped(*len, instrs)?;
            }
            MapEntry::Data(d) | MapEntry::DataWithLen { d, .. } => {
                self.vm_state
                    .encode_data(d.slab, d.offset, d.nr_entries, instrs)?;
            }
            Partial {
                begin,
                end,
                slab,
                offset,
                nr_entries,
            } => {
                self.vm_state.encode_partial(*begin, *end, instrs)?;
                self.vm_state
                    .encode_data(*slab, *offset, *nr_entries, instrs)?;
            }
            Ref { .. } => return Err(anyhow!("MappingBuilder does not support Ref")),
        }

        self.entries_emitted += 1;
        if self.entries_emitted % self.index_period == 0 {
            self.vm_state.encode_pos(self.position, instrs)?;
        }

        Ok(())
    }
}

impl Builder for MappingBuilder {
    fn next(&mut self, e: &MapEntry, len: u64, w: &mut Vec<u8>) -> Result<()> {
        use MapEntry::*;

        if self.entry.is_none() {
            self.entry = Some(*e);
            self.position += len;
            return Ok(());
        }

        let mut instrs = Vec::with_capacity(4);
        match (self.entry.take().unwrap(), e) {
            (Fill { byte: b1, len: l1 }, Fill { byte: b2, len: l2 }) if b1 == *b2 => {
                self.entry = Some(Fill {
                    byte: b1,
                    len: l1 + l2,
                });
            }
            (Unmapped { len: l1 }, Unmapped { len: l2 }) => {
                self.entry = Some(Unmapped { len: l1 + l2 });
            }
            (Data(d1), Data(d2)) => {
                if d1.slab == d2.slab && d1.offset + d1.nr_entries == d2.offset {
                    self.entry = Some(Data(DataFields {
                        slab: d1.slab,
                        offset: d1.offset,
                        nr_entries: d1.nr_entries + d2.nr_entries,
                    }));
                } else {
                    self.vm_state
                        .encode_data(d1.slab, d1.offset, d1.nr_entries, &mut instrs)?;
                    self.entry = Some(Data(DataFields {
                        slab: d2.slab,
                        offset: d2.offset,
                        nr_entries: d2.nr_entries,
                    }));
                }
            }
            (old_e, new_e) => {
                self.encode_entry(&old_e, &mut instrs)?;
                self.entry = Some(*new_e);
            }
        }

        self.position += len;
        pack_instrs(w, &instrs)
    }

    fn complete(&mut self, w: &mut Vec<u8>) -> Result<()> {
        if let Some(e) = self.entry.take() {
            let mut instrs = Vec::with_capacity(4);
            self.encode_entry(&e, &mut instrs)?;
            pack_instrs(w, &instrs)?;
        }

        Ok(())
    }
}

//------------------------------

pub struct DeltaBuilder<I>
where
    I: Iterator<Item = MapEntry>,
{
    old_entries: I,
    old_entry: Option<MapEntry>, // unconsumed remnant from the old_entries
    builder: MappingBuilder,
}

impl<I> DeltaBuilder<I>
where
    I: Iterator<Item = MapEntry>,
{
    pub fn new(old_entries: I) -> Self {
        Self {
            old_entries,
            old_entry: None,
            builder: MappingBuilder::default(),
        }
    }

    fn entry_len(&mut self, e: &MapEntry) -> Result<u64> {
        use MapEntry::*;

        match e {
            Fill { len, .. } => Ok(*len),
            Data(_d) => {
                panic!("The delta build path is expected to only use 'DataWithLen entries!");
            }
            DataWithLen { d: _, len } => Ok(*len),
            Unmapped { len } => Ok(*len),
            Partial { begin, end, .. } => Ok((end - begin) as u64),
            Ref { len } => Ok(*len),
        }
    }

    fn split_entry(
        &mut self,
        e: &MapEntry,
        entry_len: u64,
        split_point: u64,
    ) -> (MapEntry, MapEntry) {
        use MapEntry::*;
        assert!(split_point < entry_len);

        match e {
            Fill { byte, .. } => (
                Fill {
                    byte: *byte,
                    len: split_point,
                },
                Fill {
                    byte: *byte,
                    len: entry_len - split_point,
                },
            ),
            Unmapped { .. } => (
                Unmapped { len: split_point },
                Unmapped {
                    len: entry_len - split_point,
                },
            ),
            MapEntry::Data(d) | MapEntry::DataWithLen { d, .. } => (
                Partial {
                    begin: 0,
                    end: split_point as u32,
                    slab: d.slab,
                    offset: d.offset,
                    nr_entries: d.nr_entries,
                },
                Partial {
                    begin: split_point as u32,
                    end: entry_len as u32,
                    slab: d.slab,
                    offset: d.offset,
                    nr_entries: d.nr_entries,
                },
            ),
            Partial {
                begin,
                end,
                slab,
                offset,
                nr_entries,
            } => (
                Partial {
                    begin: *begin,
                    end: *begin + split_point as u32,
                    slab: *slab,
                    offset: *offset,
                    nr_entries: *nr_entries,
                },
                Partial {
                    begin: *begin + split_point as u32,
                    end: *end,
                    slab: *slab,
                    offset: *offset,
                    nr_entries: *nr_entries,
                },
            ),
            Ref { .. } => (
                Ref { len: split_point },
                Ref {
                    len: entry_len - split_point,
                },
            ),
        }
    }

    fn next_old(&mut self) -> Result<Option<MapEntry>> {
        let mut maybe_entry = self.old_entry.take();

        if maybe_entry.is_none() {
            maybe_entry = self.old_entries.next();
        }

        Ok(maybe_entry)
    }

    fn emit_old(&mut self, len: u64, w: &mut Vec<u8>) -> Result<()> {
        let mut remaining = len;

        while remaining > 0 {
            let maybe_entry = self.next_old()?;

            match maybe_entry {
                Some(e) => {
                    let e_len = self.entry_len(&e)?;

                    if remaining < e_len {
                        let (e1, e2) = self.split_entry(&e, e_len, remaining);
                        self.builder.next(&e1, remaining, w)?;
                        self.old_entry = Some(e2);
                        remaining = 0;
                    } else {
                        self.builder.next(&e, e_len, w)?;
                        remaining -= e_len;
                    }
                }
                None => return Err(anyhow!("expected short stream")),
            }
        }
        Ok(())
    }

    fn skip_old(&mut self, len: u64) -> Result<()> {
        let mut remaining = len;

        while remaining > 0 {
            let maybe_entry = self.next_old()?;

            match maybe_entry {
                Some(e) => {
                    let e_len = self.entry_len(&e)?;

                    if remaining < e_len {
                        let (_, e2) = self.split_entry(&e, e_len, remaining);
                        self.old_entry = Some(e2);
                        remaining = 0;
                    } else {
                        remaining -= e_len;
                    }
                }
                None => return Err(anyhow!("expected short stream")),
            }
        }
        Ok(())
    }
}

impl<I> Builder for DeltaBuilder<I>
where
    I: Iterator<Item = MapEntry>,
{
    fn next(&mut self, e: &MapEntry, len: u64, w: &mut Vec<u8>) -> Result<()> {
        use MapEntry::*;

        match e {
            Ref { len } => self.emit_old(*len, w),
            _ => {
                self.skip_old(len)?;
                self.builder.next(e, len, w)
            }
        }
    }

    fn complete(&mut self, w: &mut Vec<u8>) -> Result<()> {
        self.builder.complete(w)
    }
}

//------------------------------

#[cfg(test)]
mod stream_tests {
    use super::*;

    fn mk_run(slab: u32, b: u32, e: u32) -> MapEntry {
        assert!((e - b) < u16::MAX as u32);
        MapEntry::Data(DataFields {
            slab,
            offset: b,
            nr_entries: e - b,
        })
    }

    #[test]
    fn pack_unpack_cycle() {
        use MapEntry::*;

        let tests: Vec<Vec<MapEntry>> = vec![
            vec![],
            vec![Fill { byte: 0, len: 1 }],
            /*
             * Test doesn't work now we aggregate zeroes
            vec![
                Zero { len: 15 },
                Zero { len: 16 },
                Zero { len: 4095 },
                Zero { len: 4096 },
                Zero {
                    len: (4 * 1024 * 1024) - 1,
                },
                Zero {
                    len: 4 * 1024 * 1024,
                },
                Zero {
                    len: 16 * 1024 * 1024,
                },
            ],
            */
            vec![mk_run(0, 0, 4)],
            vec![mk_run(1, 1, 4)],
            vec![mk_run(1, 1, 1024)],
            vec![mk_run(1, 1, 16000)],
        ];

        for t in tests {
            // pack
            let mut buf: Vec<u8> = Vec::new();

            let mut builder = MappingBuilder::default();
            for e in &t {
                let len = 16; // FIXME: assume all entries are 16 bytes in length
                builder
                    .next(e, len, &mut buf)
                    .expect("builder.next() failed");
            }
            builder
                .complete(&mut buf)
                .expect("builder.complete() failed");

            // unpack
            let (actual, _) = unpack(&buf[..]).expect("unpack failed");

            assert_eq!(*t, actual);
        }
    }
}

//-----------------------------------------
