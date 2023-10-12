use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use debugger::{
    search::{ConditionType, SearchType},
    utils::{AnySizedNumber, DataType},
    Commands, Packet, PacketHandler, Status,
};
use predicates::prelude::predicate;

use crate::debugger::{MemoryInfo, MemoryType};

extern crate num;
#[macro_use]
extern crate num_derive;
#[macro_use]
pub mod debugger;

struct MyPacketHandler {}

#[async_trait]
impl PacketHandler for MyPacketHandler {
    async fn handle(s: Arc<Mutex<Self>>, packet: &mut Packet) {
        println!("Packet: {:?}", packet.header);

        match packet.header.command {
            Commands::Log => {
                let len = packet.data.read_u32() as usize;
                let s = packet.data.read_string(len);

                println!("[DEBUG] {}", s);
            }
            _ => {}
        }
    }
}

type Debugger = debugger::Debugger<MyPacketHandler>;
type MemorySearcher = debugger::search::MemorySearcher<MyPacketHandler>;

#[tokio::main]
async fn main() {
    let debugger = Arc::new(Mutex::new(Debugger::new()));

    {
        let mut debugger = debugger.lock().expect("Failed to lock debugger");
        debugger.set_packet_handler(Arc::new(Mutex::new(MyPacketHandler {})));
    }

    let mut heap_start: u64 = 0;
    let mut heap_end: u64 = 0;
    let mut main_start: u64 = 0;
    let mut main_end: u64 = 0;

    let mut searcher = MemorySearcher::new(debugger.clone());

    loop {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

        let args = input
            .split_whitespace()
            .map(String::from)
            .collect::<Vec<_>>();
        let command = args[0].clone();
        let args = args[1..].to_vec();

        match command.as_str() {
            "exit" => break,
            "connect" => {
                get_result!(
                    debugger
                        .lock()
                        .expect("Failed to lock debugger")
                        .connect(args[0].as_str())
                        .await
                );
                println!("Connected to {}", args[0]);
            }
            "status" => {
                let mut debugger = debugger.lock().expect("Failed to lock debugger");
                let status = get_result!(debugger.get_status().await);

                let attached_pid = get_result!(debugger.get_attached_pid().await);

                let attached_tid = if attached_pid != 0 {
                    get_result!(debugger.get_title_id(attached_pid).await)
                } else {
                    0
                };

                println!("---- Status ----");
                println!("Attached PID: {}", attached_pid);
                println!("Attached Title ID: {:#x}", attached_tid);
                println!("Status: {:?}", status);
                println!("Main: {:#x} - {:#x}", main_start, main_end);
                println!("Heap: {:#x} - {:#x}", heap_start, heap_end);
                println!("----------------");
            }
            "get_pids" => {
                let mut debugger = debugger.lock().expect("Failed to lock debugger");
                let pids = get_result!(debugger.get_pids().await);

                println!("PIDs:");
                for pid in pids {
                    let title_id = debugger.get_title_id(pid).await;
                    if title_id.is_err() {
                        println!("{} => Failed to get title ID", pid);
                        continue;
                    }

                    println!("{} => {:#16x}", pid, title_id.unwrap());
                }
            }
            "get_current_pid" => {
                let pid = get_result!(
                    debugger
                        .lock()
                        .expect("Failed to lock debugger")
                        .get_current_pid()
                        .await
                );
                println!("Current PID: {}", pid);
            }
            "get_current_title_id" => {
                let title_id = get_result!(
                    debugger
                        .lock()
                        .expect("Failed to lock debugger")
                        .get_current_title_id()
                        .await
                );
                println!("Current title ID: {:#16x}", title_id);
            }
            "get_attached_pid" => {
                let pid = get_result!(
                    debugger
                        .lock()
                        .expect("Failed to lock debugger")
                        .get_attached_pid()
                        .await
                );
                println!("Attached PID: {}", pid);
            }
            "attach" => {
                let mut debugger = debugger.lock().expect("Failed to lock debugger");
                let pid = args[0].parse::<u64>().unwrap();
                get_result!(debugger.attach(pid).await);

                println!("Attached to {}", pid);
                println!("Getting memory regions...");
                let meminfos = get_result!(debugger.query_multi(0, 10000).await);

                println!("Found {} memory regions", meminfos.len());

                let mut m_count = 0;
                for meminfo in meminfos.iter() {
                    if meminfo.memory_type == MemoryType::CodeStatic && meminfo.perm == 0x5 {
                        m_count += 1;
                        if m_count == 2 {
                            main_start = meminfo.addr;
                        } else if m_count == 3 {
                            main_end = meminfo.addr;
                        }
                    }
                }

                let heaps: Vec<MemoryInfo> = meminfos
                    .iter()
                    .filter(|x| x.memory_type == debugger::MemoryType::Heap)
                    .cloned()
                    .collect();

                heap_start = heaps.first().unwrap().addr;
                heap_end = heaps.last().unwrap().addr + heaps.last().unwrap().size;

                println!("Done!");
            }
            "attach_current" => {
                let mut debugger = debugger.lock().expect("Failed to lock debugger");
                let pid = get_result!(debugger.get_current_pid().await);
                if pid == 0 {
                    println!("No PID found");
                    continue;
                }

                get_result!(debugger.attach(pid).await);

                println!("Attached to {}", pid);
                println!("Getting memory regions...");
                let meminfos = get_result!(debugger.query_multi(0, 10000).await);
                println!("Found {} memory regions", meminfos.len());

                let mut m_count = 0;
                for meminfo in meminfos.iter() {
                    if meminfo.memory_type == MemoryType::CodeStatic && meminfo.perm == 0x5 {
                        m_count += 1;
                        if m_count == 2 {
                            main_start = meminfo.addr;
                        } else if m_count == 3 {
                            main_end = meminfo.addr;
                        }
                    }
                }

                let heaps: Vec<MemoryInfo> = meminfos
                    .iter()
                    .filter(|x| x.memory_type == debugger::MemoryType::Heap)
                    .cloned()
                    .collect();

                heap_start = heaps.first().unwrap().addr;
                heap_end = heaps.last().unwrap().addr + heaps.last().unwrap().size;

                println!("Done!");
            }
            "detach" => {
                get_result!(
                    debugger
                        .lock()
                        .expect("Failed to lock debugger")
                        .detach()
                        .await
                );
                println!("Detached");
            }
            "pause" => {
                get_result!(
                    debugger
                        .lock()
                        .expect("Failed to lock debugger")
                        .pause()
                        .await
                );
                println!("Paused");
            }
            "resume" => {
                get_result!(
                    debugger
                        .lock()
                        .expect("Failed to lock debugger")
                        .resume()
                        .await
                );
                println!("Resumed");
            }
            "query" => {
                let addr = u64::from_str_radix(args[0].trim_start_matches("0x"), 16);
                if addr.is_err() {
                    println!("Invalid address: {}", args[0]);
                    continue;
                }

                let res = get_result!(
                    debugger
                        .lock()
                        .expect("Failed to lock debugger")
                        .query(addr.unwrap())
                        .await
                );
                println!("{}", res);
            }
            "peek" => {
                let mut debugger = debugger.lock().expect("Failed to lock debugger");
                let addr = u64::from_str_radix(args[0].trim_start_matches("0x"), 16);
                let size = if args[1].starts_with("0x") {
                    u64::from_str_radix(args[1].trim_start_matches("0x"), 16)
                } else {
                    args[1].parse::<u64>()
                };

                if addr.is_err() {
                    println!("Invalid address: {}", args[0]);
                    continue;
                }

                if size.is_err() {
                    println!("Invalid size: {}", args[1]);
                    continue;
                }

                let address = addr.unwrap();
                let size = size.unwrap();

                let data: Vec<u8> = if size == 1 || size == 2 || size == 4 || size == 8 {
                    let res = get_result!(debugger.peek(size as u8, address).await);
                    match size {
                        1 => (res as u8).to_le_bytes().to_vec(),
                        2 => (res as u16).to_le_bytes().to_vec(),
                        4 => (res as u32).to_le_bytes().to_vec(),
                        8 => res.to_le_bytes().to_vec(),
                        _ => unreachable!(),
                    }
                } else {
                    let res = get_result!(debugger.read_memory(address, size as u32).await);
                    res
                };

                let data: &[u32] = unsafe {
                    std::slice::from_raw_parts(data.as_ptr() as *const u32, data.len() / 4)
                };

                for i in 0..data.len() {
                    let b = data[i];
                    let addr = address + (i as u64 * 4);

                    let decoded = bad64::decode(b.clone(), addr);
                    let a: [u8; 4] = bytemuck::cast(b.clone());

                    print!("{:#x} | ", addr);

                    for i in 0..4 {
                        print!("{:#04x} ", a[i]);
                    }

                    print!("| ");

                    if decoded.is_ok() {
                        print!("{}", decoded.unwrap());
                    }

                    println!();
                }
            }
            "poke" => {
                let addr = u64::from_str_radix(args[0].trim_start_matches("0x"), 16);
                let size = if args[1].starts_with("0x") {
                    u8::from_str_radix(args[1].trim_start_matches("0x"), 16)
                } else {
                    args[1].parse::<u8>()
                };
                let bytes = u64::from_str_radix(args[2].trim_start_matches("0x"), 16);

                if addr.is_err() {
                    println!("Invalid address: {}", args[0]);
                    continue;
                }

                if size.is_err() {
                    println!("Invalid bytes: {}", args[1]);
                    continue;
                }

                if bytes.is_err() {
                    println!("Invalid bytes: {}", args[2]);
                    continue;
                }

                let address = addr.unwrap();
                let size = size.unwrap();
                let bytes = bytes.unwrap();

                let res = get_result!(
                    debugger
                        .lock()
                        .expect("Failed to lock debugger")
                        .poke(size, address, bytes)
                        .await
                );
                println!("Wrote {} bytes to {:#x}", size, address);
            }
            "search" => match args[0].as_str() {
                "help" => {
                    println!("Usage: start_search <region> <type>");
                }
                "start" => {
                    let region = args[1].clone();
                    let data_type = args[2].as_str();
                    let search_type = args[3].as_str();
                    let condition = args[4].as_str();

                    match search_type {
                        "unk" => searcher.search_type = SearchType::Unknown,
                        "prev" => searcher.search_type = SearchType::Previous,
                        "know" => searcher.search_type = SearchType::Known,
                        "diff" => searcher.search_type = SearchType::Different,
                        _ => {
                            println!("Unknown search type: {}", search_type);
                            continue;
                        }
                    }

                    match data_type {
                        "u8" => {
                            searcher.data_type = DataType::UnsignedByte;
                            if searcher.search_type == SearchType::Known {
                                searcher.know_value = AnySizedNumber::from_u8(
                                    args[5].parse::<u8>().expect("Failed to parse value"),
                                );
                            }
                        }
                        "i8" => {
                            searcher.data_type = DataType::Byte;
                            if searcher.search_type == SearchType::Known {
                                searcher.know_value = AnySizedNumber::from_i8(
                                    args[5].parse::<i8>().expect("Failed to parse value"),
                                );
                            }
                        }
                        "u16" => {
                            searcher.data_type = DataType::UnsignedShort;
                            if searcher.search_type == SearchType::Known {
                                searcher.know_value = AnySizedNumber::from_u16(
                                    args[5].parse::<u16>().expect("Failed to parse value"),
                                );
                            }
                        }
                        "i16" => {
                            searcher.data_type = DataType::Short;
                            if searcher.search_type == SearchType::Known {
                                searcher.know_value = AnySizedNumber::from_i16(
                                    args[5].parse::<i16>().expect("Failed to parse value"),
                                );
                            }
                        }
                        "u32" => {
                            searcher.data_type = DataType::UnsignedInt;
                            if searcher.search_type == SearchType::Known {
                                searcher.know_value = AnySizedNumber::from_u32(
                                    args[5].parse::<u32>().expect("Failed to parse value"),
                                );
                            }
                        }
                        "i32" => {
                            searcher.data_type = DataType::Int;
                            if searcher.search_type == SearchType::Known {
                                searcher.know_value = AnySizedNumber::from_i32(
                                    args[5].parse::<i32>().expect("Failed to parse value"),
                                );
                            }
                        }
                        "u64" => {
                            searcher.data_type = DataType::UnsignedLong;
                            if searcher.search_type == SearchType::Known {
                                searcher.know_value = AnySizedNumber::from_u64(
                                    args[5].parse::<u64>().expect("Failed to parse value"),
                                );
                            }
                        }
                        "i64" => {
                            searcher.data_type = DataType::Long;
                            if searcher.search_type == SearchType::Known {
                                searcher.know_value = AnySizedNumber::from_i64(
                                    args[5].parse::<i64>().expect("Failed to parse value"),
                                );
                            }
                        }
                        "f32" => {
                            searcher.data_type = DataType::Float;
                            if searcher.search_type == SearchType::Known {
                                searcher.know_value = AnySizedNumber::from_f32(
                                    args[5].parse::<f32>().expect("Failed to parse value"),
                                );
                            }
                        }
                        "f64" => {
                            searcher.data_type = DataType::Double;
                            if searcher.search_type == SearchType::Known {
                                searcher.know_value = AnySizedNumber::from_f64(
                                    args[5].parse::<f64>().expect("Failed to parse value"),
                                );
                            }
                        }
                        _ => {
                            println!("Unknown data type: {}", data_type);
                            continue;
                        }
                    }

                    match condition {
                        "==" => searcher.condition_type = ConditionType::Equals,
                        "!=" => searcher.condition_type = ConditionType::NotEquals,
                        "<" => searcher.condition_type = ConditionType::LessThan,
                        "<=" => searcher.condition_type = ConditionType::LessThanOrEquals,
                        ">" => searcher.condition_type = ConditionType::GreaterThan,
                        ">=" => searcher.condition_type = ConditionType::GreaterThanOrEquals,
                        _ => {
                            println!("Unknown condition type: {}", condition);
                            continue;
                        }
                    }

                    let result = searcher
                        .start_search(predicate::function(Box::new(move |&info: &MemoryInfo| {
                            match region.as_str() {
                                "heap" => {
                                    (info.perm & 0x1) != 0 && info.memory_type == MemoryType::Heap
                                }
                                "main" => {
                                    (info.perm & 0x4) != 0
                                        && info.addr >= main_start
                                        && (info.addr + info.size) <= main_end
                                }
                                "heap+main" => {
                                    ((info.perm & 0x1) != 0 && info.memory_type == MemoryType::Heap)
                                        || ((info.perm & 0x4) != 0
                                            && info.addr >= main_start
                                            && (info.addr + info.size) <= main_end)
                                }
                                _ => {
                                    print!("Unknown region: {}", region);
                                    false
                                }
                            }
                        })))
                        .await;

                    if let Some(res) = result {
                        println!("Found {} results", res.addresses.len());

                        if res.addresses.len() < 20 {
                            for (addr, value) in res.addresses.iter() {
                                println!("{:#x} => {}", addr, value);
                            }
                        }
                    } else {
                        println!("Failed to start search");
                    }
                }
                "continue" => {
                    let search_type = args[1].as_str();
                    let condition = args[2].as_str();

                    match search_type {
                        "know" => searcher.search_type = SearchType::Unknown,
                        "prev" => searcher.search_type = SearchType::Previous,
                        "know" => searcher.search_type = SearchType::Known,
                        "diff" => searcher.search_type = SearchType::Different,
                        _ => {
                            println!("Unknown search type: {}", search_type);
                            continue;
                        }
                    }

                    if searcher.search_type == SearchType::Known {
                        match searcher.data_type {
                            DataType::UnsignedByte => {
                                searcher.know_value = AnySizedNumber::from_u8(
                                    args[3].parse::<u8>().expect("Failed to parse value"),
                                );
                            }
                            DataType::Byte => {
                                searcher.know_value = AnySizedNumber::from_i8(
                                    args[3].parse::<i8>().expect("Failed to parse value"),
                                );
                            }
                            DataType::UnsignedShort => {
                                searcher.know_value = AnySizedNumber::from_u16(
                                    args[3].parse::<u16>().expect("Failed to parse value"),
                                );
                            }
                            DataType::Short => {
                                searcher.know_value = AnySizedNumber::from_i16(
                                    args[3].parse::<i16>().expect("Failed to parse value"),
                                );
                            }
                            DataType::UnsignedInt => {
                                searcher.know_value = AnySizedNumber::from_u32(
                                    args[3].parse::<u32>().expect("Failed to parse value"),
                                );
                            }
                            DataType::Int => {
                                searcher.know_value = AnySizedNumber::from_i32(
                                    args[3].parse::<i32>().expect("Failed to parse value"),
                                );
                            }
                            DataType::UnsignedLong => {
                                searcher.know_value = AnySizedNumber::from_u64(
                                    args[3].parse::<u64>().expect("Failed to parse value"),
                                );
                            }
                            DataType::Long => {
                                searcher.know_value = AnySizedNumber::from_i64(
                                    args[3].parse::<i64>().expect("Failed to parse value"),
                                );
                            }
                            DataType::Float => {
                                searcher.know_value = AnySizedNumber::from_f32(
                                    args[3].parse::<f32>().expect("Failed to parse value"),
                                );
                            }
                            DataType::Double => {
                                searcher.know_value = AnySizedNumber::from_f64(
                                    args[3].parse::<f64>().expect("Failed to parse value"),
                                );
                            }
                            _ => {
                                println!("Unknown data type: {}", searcher.data_type);
                                continue;
                            }
                        }
                    }

                    match condition {
                        "==" => searcher.condition_type = ConditionType::Equals,
                        "!=" => searcher.condition_type = ConditionType::NotEquals,
                        "<" => searcher.condition_type = ConditionType::LessThan,
                        "<=" => searcher.condition_type = ConditionType::LessThanOrEquals,
                        ">" => searcher.condition_type = ConditionType::GreaterThan,
                        ">=" => searcher.condition_type = ConditionType::GreaterThanOrEquals,
                        _ => {
                            println!("Unknown condition type: {}", condition);
                            continue;
                        }
                    }

                    let result = searcher.continue_search().await;

                    if let Some(res) = result {
                        println!("Found {} results", res.addresses.len());

                        if res.addresses.len() < 20 {
                            for (addr, value) in res.addresses.iter() {
                                println!("{:#x} => {}", addr, value);
                            }
                        }
                    } else {
                        println!("Failed to start search");
                    }
                }
                _ => {
                    println!("Unknown search type: {}", args[0]);
                }
            },
            _ => println!("Unknown command: {}", command),
        }
    }

    let mut debugger = debugger.lock().expect("Failed to lock debugger");
    if debugger.connected {
        let status = get_result!(debugger.get_status().await);
        if status == Status::Paused {
            get_result!(debugger.resume().await);
        }
    }
}
