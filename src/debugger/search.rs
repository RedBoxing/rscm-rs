use std::{
    rc::Rc,
    sync::{Arc, Mutex},
};

use predicates::function::FnPredicate;
use predicates::prelude::*;

use crate::debugger::dump::DumpIndex;

use super::{
    dump::{DumpRegionSupplier, MemoryDump},
    utils::{get_result, AnySizedNumber, DataType},
    Debugger, MemoryInfo, PacketHandler, Status,
};

const PAGE_SIZE: usize = 1024;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum SearchType {
    Unknown,
    Previous,
    Known,
    Different,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum ConditionType {
    Equals,
    NotEquals,
    LessThan,
    LessThanOrEquals,
    GreaterThan,
    GreaterThanOrEquals,
}

#[derive(Clone)]
pub struct SearchResult {
    pub addresses: Vec<(u64, AnySizedNumber)>,
    pub regions: Vec<MemoryInfo>,
    pub data_type: DataType,
    pub search_type: SearchType,
    pub start: u64,
    pub end: u64,
    pub curr: Option<Box<MemoryDump>>,
    pub prev: Option<Rc<SearchResult>>,
    pub filter: Option<Rc<FnPredicate<Box<dyn Fn(&MemoryInfo) -> bool>, MemoryInfo>>>,
}
impl SearchResult {
    pub fn new() -> SearchResult {
        SearchResult {
            addresses: Vec::new(),
            regions: Vec::new(),
            data_type: DataType::Byte,
            search_type: SearchType::Unknown,
            start: 0,
            end: 0,
            curr: None,
            prev: None,
            filter: None,
        }
    }

    pub fn current(&self, addr: u64) -> AnySizedNumber {
        if let Some(dump) = &self.curr {
            return dump.value(addr, self.data_type);
        }

        AnySizedNumber::from_u8(0)
    }

    pub fn previous(&self, addr: u64) -> AnySizedNumber {
        if let Some(prev) = &self.prev {
            return prev.current(addr);
        }

        self.current(addr)
    }

    pub fn page(&self, idx: usize) -> Vec<(u64, AnySizedNumber)> {
        self.addresses
            [idx * PAGE_SIZE as usize..std::cmp::min(self.addresses.len(), PAGE_SIZE * (idx + 1))]
            .to_vec()
    }

    pub fn page_count(&self) -> usize {
        let mut size = self.addresses.len();
        if size == 0 {
            return 0;
        }

        if size % PAGE_SIZE != 0 {
            size += PAGE_SIZE
        }

        size / PAGE_SIZE
    }
}

pub struct MemorySearcher<T: PacketHandler + Send + 'static> {
    regions: Vec<MemoryInfo>,
    debugger: Arc<Mutex<Debugger<T>>>,
    pub data_type: DataType,
    pub search_type: SearchType,
    pub condition_type: ConditionType,
    pub know_value: AnySizedNumber,
    pub prev_result: Option<Rc<SearchResult>>,
}

impl<T: PacketHandler + Send> MemorySearcher<T> {
    pub fn new(debugger: Arc<Mutex<Debugger<T>>>) -> MemorySearcher<T> {
        MemorySearcher {
            regions: Vec::new(),
            debugger: debugger,
            data_type: DataType::Byte,
            search_type: SearchType::Unknown,
            condition_type: ConditionType::Equals,
            know_value: AnySizedNumber::from_u8(0),
            prev_result: None,
        }
    }

    pub fn compare(&self, value: AnySizedNumber, other: AnySizedNumber) -> bool {
        match self.condition_type {
            ConditionType::Equals => value == other,
            ConditionType::NotEquals => value != other,
            ConditionType::LessThan => value < other,
            ConditionType::LessThanOrEquals => value <= other,
            ConditionType::GreaterThan => value > other,
            ConditionType::GreaterThanOrEquals => value >= other,
        }
    }

    pub fn condition(&self, value: AnySizedNumber, prev: AnySizedNumber) -> bool {
        match self.search_type {
            SearchType::Previous => self.compare(value, prev),
            SearchType::Known => self.compare(value, self.know_value.clone()),
            SearchType::Different => self.compare((value - prev).abs(), self.know_value.clone()),
            _ => true,
        }
    }

    pub fn search(&self, result: &mut SearchResult) {
        if let Some(dump) = &result.curr {
            for idx in dump.indices.iter() {
                let mut offset = 0 as usize;

                while offset + (result.data_type.size() as usize) <= idx.size as usize {
                    let addr = idx.addr as u64 + offset as u64;
                    let value = AnySizedNumber::from_slice(
                        dump.buffer
                            .read_slice(idx.file_pos as usize + offset, self.data_type.size()),
                        self.data_type,
                    );
                    let prev = result.previous(idx.file_pos).clone();

                    if self.condition(value.clone(), prev) {
                        result.addresses.push((addr, value));

                        if addr < result.start {
                            result.start = addr;
                        }

                        if addr > result.end {
                            result.end = addr;
                        }
                    }

                    offset += result.data_type.size() as usize;
                }
            }

            result.curr = None;
        }
    }

    async fn create_dump(
        &mut self,
        supplier: &mut DumpRegionSupplier<T>,
    ) -> Option<Box<MemoryDump>> {
        let mut debugger = self.debugger.lock().expect("Failed to lock debugger");

        if get_result!(debugger.get_status().await) != Status::Paused {
            get_result!(debugger.pause().await);
        }

        let total_size = supplier.size().await;
        let last_update = 0;
        let mut prev_read: u64 = 0;
        let mut avg = Rolling::new(10);
        let mut read: u64 = 0;

        let mut dump = MemoryDump::new();

        let title_id = get_result!(debugger.get_current_title_id().await);
        dump.tid = title_id;
        dump.infos = get_result!(debugger.query_multi(0, 10000).await);

        loop {
            let r = supplier.get().await;
            if r.is_none() {
                break;
            }

            let r = r.unwrap();

            let size = r.size;
            let addr = r.addr;
            let start = std::time::Instant::now();

            while size > 0 {
                if start.elapsed() > std::time::Duration::from_millis(500) {
                    avg.add((read - prev_read) as f64);
                    prev_read = read;

                    println!(
                        "Dumping memory: {}% ({}/{}), {} KB/s",
                        (read as f64 / total_size as f64) * 100.0,
                        read,
                        total_size,
                        avg.get_average() / 1024.0
                    );
                }

                let remaining_size = size;
                while size > 0 {
                    let len = remaining_size.min(2000000);
                    let buf = get_result!(debugger.read_memory(addr, len as u32).await);

                    dump.buffer.write(dump.buffer.pos(), &buf);
                }
            }

            dump.indices.push(DumpIndex {
                addr: addr,
                file_pos: dump.buffer.pos() as u64,
                size: size,
            });

            read += size;
        }

        if get_result!(debugger.get_status().await) == Status::Paused {
            get_result!(debugger.resume().await);
        }

        Some(Box::new(dump))
    }

    pub async fn start_search(
        &mut self,
        filter: FnPredicate<Box<dyn Fn(&MemoryInfo) -> bool>, MemoryInfo>,
    ) -> &Option<Rc<SearchResult>> {
        self.prev_result = None;

        let filter = Rc::new(filter);

        let mut result = SearchResult::new();
        result.data_type = self.data_type;
        result.search_type = self.search_type;
        result.filter = Some(filter.clone());

        let supplier = DumpRegionSupplier::new(self.debugger.clone(), filter);
        if supplier.is_none() {
            return &None;
        }

        result.curr = self.create_dump(&mut supplier.unwrap()).await;

        self.search(&mut result);
        self.prev_result = Some(Rc::new(result));

        &self.prev_result
    }

    pub async fn continue_search(&mut self) -> &Option<Rc<SearchResult>> {
        if self.prev_result.is_none() {
            return &None;
        }

        let filter = self
            .prev_result
            .clone()
            .unwrap()
            .filter
            .clone()
            .expect("There is no previous filter");

        let mut result = SearchResult::new();
        result.data_type = self.data_type;
        result.search_type = self.search_type;
        result.prev = self.prev_result.clone();
        result.filter = Some(filter.clone());

        let supplier = DumpRegionSupplier::new(self.debugger.clone(), filter);
        if supplier.is_none() {
            return &None;
        }

        result.curr = self.create_dump(&mut supplier.unwrap()).await;
        // let res = Rc::new(result);

        self.search(&mut result);
        self.prev_result = Some(Rc::new(result));

        &self.prev_result
    }
}

struct Rolling {
    size: usize,
    total: f64,
    index: usize,
    samples: Vec<f64>,
}

impl Rolling {
    pub fn new(size: usize) -> Rolling {
        Rolling {
            size: size,
            total: 0.0,
            index: 0,
            samples: Vec::new(),
        }
    }

    pub fn add(&mut self, x: f64) {
        self.total -= self.samples[self.index];
        self.samples[self.index] = x;
        self.total += x;
        self.index += 1;

        if self.index == self.size {
            self.index = 0;
        }
    }

    pub fn get_average(&self) -> f64 {
        self.total / self.size as f64
    }
}
