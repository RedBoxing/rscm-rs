use std::{borrow::BorrowMut, fs::File};

use crate::{
    buffer::Buffer,
    debugger::{Debugger, MemoryInfo, Status},
    dump::MemoryDump,
};
use tempfile::tempfile_in;

const PAGE_SIZE: usize = 1024;

pub enum SearchType {
    Unknown,
    Previous,
    Known,
    Different,
}

pub struct DataType(u32);

impl DataType {
    pub const Byte: DataType = DataType(1);
    pub const Short: DataType = DataType(2);
    pub const Int: DataType = DataType(4);
    pub const Long: DataType = DataType(8);
    pub const Float: DataType = DataType(4);
    pub const Double: DataType = DataType(8);
}

pub enum ConditionType {
    Equals,
    NotEquals,
    LessThan,
    LessThanOrEquals,
    GreaterThan,
    GreaterThanOrEquals,
}

pub struct SearchResult {
    file: File,
    pub addresses: Vec<u64>,
    pub regions: Vec<MemoryInfo>,
    pub dataType: DataType,
    pub searchType: SearchType,
    pub start: u64,
    pub end: u64,
    pub curr: Option<MemoryDump>,
    prev: Option<Box<SearchResult>>,
}

impl SearchResult {
    pub fn new() -> SearchResult {
        let file = tempfile_in("./").unwrap();
        SearchResult {
            file: file,
            addresses: Vec::new(),
            regions: Vec::new(),
            dataType: DataType::Byte,
            searchType: SearchType::Unknown,
            start: 0,
            end: 0,
            curr: None,
            prev: None,
        }
    }

    pub fn current(&mut self, addr: u64) -> u64 {
        if let Some(dump) = self.curr.borrow_mut() {
            return dump.value(addr, self.dataType.0);
        }

        0
    }

    pub fn previous(&mut self, addr: u64) -> u64 {
        if let Some(prev) = self.prev.borrow_mut() {
            return prev.current(addr);
        }

        self.current(addr)
    }

    pub fn page(&self, idx: usize) -> Vec<u64> {
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

    pub fn close(&mut self) {
        if let Some(current) = self.curr.borrow_mut() {
            current.close();
        }

        if let Some(prev) = self.prev.borrow_mut() {
            prev.close();
        }
    }
}

pub struct MemorySearcher {
    regions: Vec<MemoryInfo>,
    debugger: Debugger,
    pub dataType: DataType,
    pub searchType: SearchType,
    pub conditionType: ConditionType,
    pub knowValue: i64,
    pub prevResult: Option<SearchResult>,
}

impl MemorySearcher {
    pub fn new(debugger: Debugger) -> MemorySearcher {
        MemorySearcher {
            regions: Vec::new(),
            debugger: Debugger::new(),
            dataType: DataType::Byte,
            searchType: SearchType::Unknown,
            conditionType: ConditionType::Equals,
            knowValue: 0,
            prevResult: None,
        }
    }

    pub fn compare(&self, value: i64, other: i64) -> bool {
        match self.conditionType {
            ConditionType::Equals => value == other,
            ConditionType::NotEquals => value != other,
            ConditionType::LessThan => value < other,
            ConditionType::LessThanOrEquals => value <= other,
            ConditionType::GreaterThan => value > other,
            ConditionType::GreaterThanOrEquals => value >= other,
        }
    }

    pub fn condition(&self, value: i64, prev: i64) -> bool {
        match self.searchType {
            SearchType::Previous => self.compare(value, prev),
            SearchType::Known => self.compare(value, self.knowValue),
            SearchType::Different => self.compare((value - prev).abs(), self.knowValue),
            _ => true,
        }
    }

    pub fn search(result: SearchResult, buffer: Buffer, baseAddress: u64) {}

    /*pub async fn create_dump(&self, searchResult: SearchResult) -> MemoryDump {
        let resume = self.debugger.get_status().await? == Status::Paused;
        if let Err(e) = self.debugger.pause().await? {
            panic!("Failed to pause debugger: {}", e);
        }

        let totalSize = 0;
    }*/
}
