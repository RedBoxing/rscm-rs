use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use super::{Buffer, Debugger, PacketHandler};
use crate::debugger::MemoryInfo;

use super::utils::{get_result, AnySizedNumber, DataType};
use predicates::function::FnPredicate;
use predicates::Predicate;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct DumpIndex {
    pub addr: u64,
    pub size: u64,
    pub file_pos: u64,
}

#[derive(Clone)]
pub struct MemoryDump {
    pub infos: Vec<MemoryInfo>,
    pub indices: Vec<DumpIndex>,
    pub cache: HashMap<DumpIndex, Buffer>,
    pub tid: u64,
    pub buffer: Buffer,
    //prev: Option<DumpIndex>,
}

impl MemoryDump {
    pub fn new() -> MemoryDump {
        let dump = MemoryDump {
            infos: Vec::new(),
            indices: Vec::new(),
            cache: HashMap::new(),
            tid: 0,
            buffer: Buffer::new(),
            //  prev: None,
        };

        dump
    }

    pub fn size(&self) -> usize {
        self.buffer.len()
    }

    pub fn start(&self) -> u64 {
        let mut min: u64 = u64::MAX;
        for idx in self.indices.iter() {
            if idx.addr < min {
                min = idx.addr;
            }
        }

        min
    }

    pub fn end(&self) -> u64 {
        let mut max: u64 = 0;
        for idx in self.indices.iter() {
            if idx.addr + idx.size >= max {
                max = idx.addr + idx.size;
            }
        }

        max
    }

    pub fn index(&self, addr: u64) -> Option<DumpIndex> {
        /*if let Some(idx) = self.prev {
            if addr >= idx.addr && addr < idx.addr + idx.size {
                return Some(idx);
            }
        }*/

        for idx in self.indices.iter() {
            if addr >= idx.addr && addr < idx.addr + idx.size {
                //    self.prev = Some(idx.clone());
                return Some(idx.clone());
            }
        }

        None
    }

    pub fn buffer_idx(&self, idx: DumpIndex) -> Buffer {
        /*     if let Some(buffer) = self.cache.get(&idx) {
            return buffer.clone();
        }*/

        let buffer = Buffer::from(
            self.buffer
                .read_slice(idx.file_pos as usize, idx.size as usize)
                .to_vec(),
        );
        // self.cache.insert(idx, buffer.clone());
        buffer
    }

    pub fn buffer_addr(&self, addr: u64) -> Buffer {
        let idx = self.index(addr);
        if idx.is_none() {
            return Buffer::new();
        }

        self.buffer_idx(idx.unwrap())
    }

    pub fn value(&self, addr: u64, data_type: DataType) -> AnySizedNumber {
        let mut buffer = self.buffer_addr(addr);
        AnySizedNumber::from_buffer(&mut buffer, data_type)
    }
}

pub struct DumpRegionSupplier {
    start: u64,
    end: u64,
    size: usize,
    index: usize,

    regions: Vec<MemoryInfo>,
    filter: Rc<FnPredicate<Box<dyn Fn(&MemoryInfo) -> bool>, MemoryInfo>>,
}

impl DumpRegionSupplier {
    pub fn new(
        filter: Rc<FnPredicate<Box<dyn Fn(&MemoryInfo) -> bool>, MemoryInfo>>,
    ) -> Option<DumpRegionSupplier> {
        Some(DumpRegionSupplier {
            start: 0,
            end: 0,
            size: 0,
            index: 0,

            regions: Vec::new(),
            filter,
        })
    }

    pub async fn reload<T: PacketHandler + Send + 'static>(&mut self, debugger: &mut Debugger<T>) {
        self.regions = get_result!(debugger.query_multi(0, 10000).await);

        for info in self.regions.clone() {
            if !self.filter.eval(&info) {
                continue;
            }

            let addr = info.addr;
            let next = addr + info.size;

            if self.start == 0 {
                self.start = addr;
            }

            if next > self.end {
                self.end = next;
            }

            self.size += info.size as usize;
        }
    }

    pub async fn start(&mut self) -> u64 {
        self.start
    }

    pub async fn end(&mut self) -> u64 {
        self.end
    }

    pub async fn size(&mut self) -> usize {
        self.size
    }

    pub async fn get(&mut self) -> Option<MemoryInfo> {
        let mut current: MemoryInfo;

        loop {
            if self.index >= self.regions.len() {
                return None;
            }

            self.index += 1;
            current = self.regions[self.index].clone();

            if self.filter.eval(&current) {
                break;
            }
        }

        Some(current)
    }
}
