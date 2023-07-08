use debugger::{MemoryInfo, Status};

use crate::debugger::MemoryType;

extern crate num;
#[macro_use]
extern crate num_derive;

mod buffer;
mod debugger;
mod dump;
mod search;

#[tokio::main]
async fn main() {
    let mut debugger = debugger::Debugger::new();
    let mut heap_start: u64 = 0;
    let mut heap_end: u64 = 0;
    let mut main_start: u64 = 0;
    let mut main_end: u64 = 0;

    loop {
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

        let args = input.split_whitespace().collect::<Vec<_>>();
        let command = args[0];
        let args = &args[1..];

        match command {
            "exit" => break,
            "connect" => {
                if let Err(e) = debugger.connect(args[0]).await {
                    println!("Failed to connect: {}", e);
                } else {
                    println!("Connected to {}", args[0]);
                }
            }
            "status" => {
                let status = debugger.get_status().await;
                if status.is_err() {
                    println!("{}", status.err().unwrap());
                    continue;
                }
                let status = status.unwrap();

                println!("Got status");

                let attached_pid = debugger.get_attached_pid().await;
                if attached_pid.is_err() {
                    println!("{}", attached_pid.err().unwrap());
                    continue;
                }

                let attached_pid = attached_pid.unwrap();

                let attached_tid = debugger.get_title_id(attached_pid).await;
                if attached_tid.is_err() {
                    println!("{}", attached_tid.err().unwrap());
                    continue;
                }

                println!("---- Status ----");
                println!("Attached PID: {}", attached_pid);
                println!("Attached Title ID: {:#x}", attached_tid.unwrap());
                println!("Status: {:?}", status);
                println!("Main: {:#x} - {:#x}", main_start, main_end);
                println!("Heap: {:#x} - {:#x}", heap_start, heap_end);
                println!("----------------");
            }
            "get_pids" => {
                let pids = debugger.get_pids().await;
                if pids.is_err() {
                    println!("Failed to get PIDs");
                    continue;
                }
                let pids = pids.unwrap();

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
                let pid = debugger.get_current_pid().await;
                if pid.is_err() {
                    println!("Failed to get current PID");
                    continue;
                }
                let pid = pid.unwrap();

                println!("Current PID: {}", pid);
            }
            "get_current_title_id" => {
                let title_id = debugger.get_current_title_id().await;
                if title_id.is_err() {
                    println!("Failed to get current title ID");
                    continue;
                }
                let title_id = title_id.unwrap();

                println!("Current title ID: {:#16x}", title_id);
            }
            "get_attached_pid" => {
                let pid = debugger.get_attached_pid().await;
                if pid.is_err() {
                    println!("Failed to get attached PID");
                    continue;
                }
                let pid = pid.unwrap();

                println!("Attached PID: {}", pid);
            }
            "attach" => {
                let pid = args[0].parse::<u64>().unwrap();
                if let Err(e) = debugger.attach(pid).await {
                    println!("Failed to attach: {}", e);
                } else {
                    println!("Attached to {}", pid);
                    println!("Getting memory regions...");
                    let res = debugger.query_multi(0, 10000).await;
                    if res.is_err() {
                        println!("Failed to query: {}", res.err().unwrap());
                        continue;
                    }
                    let meminfos = res.unwrap();

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
            }
            "attach_current" => {
                let pid = debugger.get_current_pid().await;
                if pid.is_err() {
                    println!("Failed to get current PID");
                    continue;
                }

                let pid = pid.unwrap();
                if let Err(e) = debugger.attach(pid).await {
                    println!("Failed to attach: {}", e);
                } else {
                    println!("Attached to {}", pid);
                    println!("Getting memory regions...");
                    let res = debugger.query_multi(0, 10000).await;
                    if res.is_err() {
                        println!("Failed to query: {}", res.err().unwrap());
                        continue;
                    }
                    let meminfos = res.unwrap();

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
            }
            "pause" => {
                let res = debugger.pause().await;
                if let Err(e) = res {
                    println!("Failed to pause: {}", e);
                } else if res.unwrap().failed() {
                    println!("Failed to pause");
                } else {
                    println!("Paused");
                }
            }
            "resume" => {
                let res = debugger.resume().await;
                if let Err(e) = res {
                    println!("Failed to resume: {}", e);
                } else if res.unwrap().failed() {
                    println!("Failed to resume");
                } else {
                    println!("Resumed");
                }
            }
            "query" => {
                let addr = u64::from_str_radix(args[0].trim_start_matches("0x"), 16);
                if addr.is_err() {
                    println!("Invalid address: {}", args[0]);
                    continue;
                }
                let res = debugger.query(addr.unwrap()).await;
                if let Err(e) = res {
                    println!("Failed to query: {}", e);
                } else {
                    println!("{}", res.unwrap());
                }
            }
            "peek" => {
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
                    let res = debugger.peek(size as u8, address).await;
                    if let Err(e) = res {
                        println!("Failed to peek: {}", e);
                        continue;
                    }
                    match size {
                        1 => (res.unwrap() as u8).to_le_bytes().to_vec(),
                        2 => (res.unwrap() as u16).to_le_bytes().to_vec(),
                        4 => (res.unwrap() as u32).to_le_bytes().to_vec(),
                        8 => res.unwrap().to_le_bytes().to_vec(),
                        _ => unreachable!(),
                    }
                } else {
                    let res = debugger.read_memory(address, size as u32).await;
                    if let Err(e) = res {
                        println!("Failed to read memory: {}", e);
                        continue;
                    }
                    res.unwrap().to_vec()
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

                let res = debugger.poke(size, address, bytes).await;
                if let Err(e) = res {
                    println!("Failed to poke: {}", e);
                } else {
                    println!("Wrote {} bytes to {:#x}", size, address);
                }
            }
            "search" => match args[0] {
                "help" => {
                    println!("Usage: start_search <region> <type>");
                }
                "start" => {
                    let region = args[0].parse::<u64>().unwrap(); // 0 = heap, 1 = main, 2 = heap+main
                    let search_type = args[1].parse::<u64>().unwrap(); // 0 = u8, 1 = u16, 2 = u32, 3 = u64, 4 = f32, 5 = f64
                    let condition = args[2].parse::<u64>().unwrap(); // 0 = unknown, 1 = equal, 2 = not equal, 3 = greater than, 4 = less than, 5 = greater than or equal, 6 = less than or equal
                    let value = args[3].parse::<u64>().unwrap();

                    let mut start: u64 = 0;
                    let mut end: u64 = 0;

                    if region == 0 {
                        start = heap_start;
                        end = heap_end;
                    } else if region == 1 {
                        start = main_start;
                        end = main_end;
                    }
                }
                _ => {
                    println!("Unknown search type: {}", args[0]);
                }
            },
            _ => println!("Unknown command: {}", command),
        }
    }

    if debugger.connected {
        let status = debugger.get_status().await;
        if status.is_ok() && status.unwrap() == Status::Paused {
            let rc = debugger.resume().await;
            if let Err(e) = rc {
                println!("Failed to resume: {}", e);
            } else if rc.unwrap().failed() {
                println!("Failed to resume");
            }
        }
    }
}
