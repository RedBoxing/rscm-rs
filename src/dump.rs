use std::borrow::BorrowMut;
use std::{collections::HashMap, path::PathBuf};

use crate::buffer::Buffer;
use crate::debugger::MemoryInfo;
use std::fs::File;
use std::io::prelude::*;

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct DumpIndex {
    addr: u64,
    size: u64,
    file_pos: u64,
}

pub struct MemoryDump {
    pub infos: Vec<MemoryInfo>,
    pub indices: Vec<DumpIndex>,
    pub cache: HashMap<DumpIndex, Buffer>,
    file: File,
    pub tid: u64,
    pub buffer: Buffer,
    prev: Option<DumpIndex>,
}

impl MemoryDump {
    pub fn new(file: File, newFile: bool) -> MemoryDump {
        let mut dump = MemoryDump {
            infos: Vec::new(),
            indices: Vec::new(),
            cache: HashMap::new(),
            file: file,
            tid: 0,
            buffer: Buffer::new(),
            prev: None,
        };

        if newFile {
            dump.write_header();
        } else {
            dump.read_header();
        }

        dump
    }

    fn write_header(&mut self) {
        let buffer = self.buffer.borrow_mut();
        let mut pos = buffer.pos();

        buffer.set_pos(0);
        buffer.write_u32(0x4E444D50); // "NDMP"
        buffer.write_u64(self.tid);
        buffer.write_u32(self.infos.len() as u32); // info count
        buffer.write_u64(0); // mem-info pointer
        buffer.write_u32(self.indices.len() as u32); // index count
        buffer.write_u64(pos as u64); // pointer to index data

        buffer.set_pos(pos);

        for i in 0..self.indices.len() {
            let index = &self.indices[i];
            buffer.write_u64(index.addr);
            buffer.write_u64(index.file_pos);
            buffer.write_u64(index.size);
        }

        pos = buffer.pos();

        for i in 0..self.infos.len() {
            let info = &self.infos[i];
            buffer.write_u64(info.addr);
            buffer.write_u64(info.size);
            buffer.write_u32(info.memory_type.clone() as u32);
            buffer.write_u32(info.perm);
        }

        buffer.set_pos(0x10); // mem-info pointer
        buffer.write_u64(pos as u64);

        buffer.set_pos(0x32);
    }

    fn read_header(&mut self) {
        let buffer = self.buffer.borrow_mut();
        let mut pos = buffer.pos();

        buffer.set_pos(0);
        let magic = buffer.read_u32();
        if magic != 0x4E444D50 {
            panic!("Invalid magic");
        }

        self.tid = buffer.read_u64();
        let info_count = buffer.read_u32();
        let info_ptr = buffer.read_u64();
        let index_count = buffer.read_u32();
        let index_ptr = buffer.read_u64();

        let data_ptr = buffer.pos();

        buffer.set_pos(index_ptr as usize);

        for _ in 0..index_count {
            let addr = buffer.read_u64();
            let file_pos = buffer.read_u64();
            let size = buffer.read_u64();

            self.indices.push(DumpIndex {
                addr,
                file_pos,
                size,
            });
        }

        buffer.set_pos(info_ptr as usize);

        for _ in 0..info_count {
            let addr = buffer.read_u64();
            let size = buffer.read_u64();
            let memory_type = buffer.read_u32();
            let perm = buffer.read_u32();

            self.infos.push(MemoryInfo {
                addr,
                size,
                memory_type: num::FromPrimitive::from_u32(memory_type).unwrap(),
                perm,
            });
        }

        buffer.set_pos(data_ptr);
    }

    pub fn close(&mut self) {
        self.write_header();
        self.file.write_all(self.buffer.buffer()).unwrap();
        self.cache.clear();
        self.indices.clear();
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

    pub fn index(&mut self, addr: u64) -> Option<DumpIndex> {
        if let Some(idx) = self.prev {
            if addr >= idx.addr && addr < idx.addr + idx.size {
                return Some(idx);
            }
        }

        for idx in self.indices.iter() {
            if addr >= idx.addr && addr < idx.addr + idx.size {
                self.prev = Some(idx.clone());
                return Some(idx.clone());
            }
        }

        None
    }

    pub fn buffer_idx(&mut self, idx: DumpIndex) -> Buffer {
        if let Some(buffer) = self.cache.get(&idx) {
            return buffer.clone();
        }

        let buffer = Buffer::from(
            self.buffer
                .read_slice(idx.file_pos as usize, idx.size as usize)
                .to_vec(),
        );
        self.cache.insert(idx, buffer.clone());
        buffer
    }

    pub fn buffer_addr(&mut self, addr: u64) -> Buffer {
        let idx = self.index(addr);
        if idx.is_none() {
            return Buffer::new();
        }

        self.buffer_idx(idx.unwrap())
    }

    pub fn value(&mut self, addr: u64, size: u32) -> u64 {
        let mut buffer = self.buffer_addr(addr);
        match size {
            1 => buffer.read_u8() as u64,
            2 => buffer.read_u16() as u64,
            4 => buffer.read_u32() as u64,
            8 => buffer.read_u64(),
            _ => panic!("Invalid size"),
        }
    }
}
