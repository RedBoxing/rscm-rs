mod buffer;
mod dump;
pub mod search;

#[macro_use]
pub mod utils;

use crate::debugger::buffer::Buffer;

use async_trait::async_trait;
use std::collections::HashMap;
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;

use uuid::Uuid;

const VERSION_MAJOR: u32 = 1;
const VERSION_MINOR: u32 = 0;
const VERSION_PATCH: u32 = 0;

#[derive(FromPrimitive, Debug, Clone)]
pub enum Commands {
    None,

    Attach,
    Detach,
    GetStatus,

    QueryMemory,
    QueryMemoryMulti,
    ReadMemory,
    WriteMemory,

    Pause,
    Resume,

    GetCurrentPID,
    GetAttachedPID,
    GetTitleID,
    GetPIDs,

    SetBreakpoint,

    Log,
}

#[derive(Debug, PartialEq)]
pub enum Status {
    Stopped = 0x0,
    Running = 0x1,
    Paused = 0x2,
}

#[derive(Debug)]
pub struct DebuggerResult {
    pub _mod: u32,
    pub desc: u32,
}

impl DebuggerResult {
    pub fn new(_mod: u32, desc: u32) -> DebuggerResult {
        DebuggerResult {
            _mod: _mod,
            desc: desc,
        }
    }

    pub fn value_of(rc: u32) -> DebuggerResult {
        DebuggerResult {
            _mod: rc & 0x1FF,
            desc: (rc >> 9) & 0x1FF,
        }
    }

    pub fn failed(&self) -> bool {
        self._mod != 0 || self.desc != 0
    }

    pub fn success(&self) -> bool {
        self._mod == 0 && self.desc == 0
    }
}

#[derive(FromPrimitive, Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum MemoryType {
    Unmapped = 0x0,
    Io = 0x01,
    Normal = 0x02,
    CodeStatic = 0x03,
    CodeMutable = 0x04,
    Heap = 0x05,
    Shared = 0x06,
    WeirdMapped = 0x07,
    ModuleCodeStatic = 0x08,
    ModuleCodeMutable = 0x09,
    IPCBuffer0 = 0x0A,
    Mapped = 0x0B,
    ThreadLocal = 0x0C,
    IsolatedTransfer = 0x0D,
    Transfer = 0x0E,
    Process = 0x0F,
    Reserved = 0x10,
    IPCBuffer1 = 0x11,
    IPCBuffer3 = 0x12,
    KernelStach = 0x13,
    CodeReadOnly = 0x14,
    CodeWritable = 0x15,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryInfo {
    pub addr: u64,
    pub size: u64,
    pub memory_type: MemoryType,
    pub perm: u32,
}

impl std::fmt::Display for MemoryInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut perm = String::new();
        if self.perm & 1 != 0 {
            perm.push('R');
        }
        if self.perm & 2 != 0 {
            perm.push('W');
        }
        if self.perm & 4 != 0 {
            perm.push('X');
        }

        if perm.len() == 0 {
            perm.push_str("None");
        }

        let mut s = String::new();

        s.push_str("--- Memory Info ---\n");
        s.push_str(format!("Address: {:#x}\n", self.addr).as_str());
        s.push_str(format!("Size: {:#x}\n", self.size).as_str());
        s.push_str(format!("Type: {:?}\n", self.memory_type).as_str());
        s.push_str(format!("Perm: {}\n", perm).as_str());
        s.push_str("-------------------");

        write!(f, "{}", s)
    }
}

#[derive(Clone, Debug)]
pub struct PacketHeader {
    pub command: Commands,
    pub uuid: Uuid,
    pub len: u32,
}

#[derive(Clone)] // Probably not the best way to do this specially if there is a lot of data
pub struct Packet {
    pub header: PacketHeader,
    pub data: Buffer,
}

#[async_trait]
pub trait PacketHandler {
    async fn handle(s: Arc<Mutex<Self>>, packet: &mut Packet);
}

pub struct Debugger<T: PacketHandler + Send + 'static> {
    pending_responses: Arc<Vec<Uuid>>,
    packet_map: Arc<Mutex<HashMap<Uuid, Packet>>>,
    queue: Arc<Mutex<Vec<Packet>>>,

    protocol_version: u32,
    last_query: Box<Option<MemoryInfo>>,

    handler: Option<Arc<Mutex<T>>>,

    pub connected: bool,
}

impl<T: PacketHandler + Send + 'static> Debugger<T> {
    pub fn new() -> Debugger<T> {
        Debugger {
            pending_responses: Arc::new(Vec::new()),
            packet_map: Arc::new(Mutex::new(HashMap::new())),
            queue: Arc::new(Mutex::new(Vec::new())),
            protocol_version: 0,
            last_query: Box::new(None),
            handler: None,
            connected: false,
        }
    }

    pub fn set_packet_handler(&mut self, handler: Arc<Mutex<T>>) {
        self.handler = Some(handler);
    }

    pub async fn connect(&mut self, address: &str) -> Result<(), Box<dyn Error>> {
        let addr = if address.contains(":") {
            address.to_string()
        } else {
            format!("{}:1337", address)
        };

        let stream = TcpStream::connect(addr);
        if let Err(e) = stream {
            return Err(format!("Failed to connect to {} : {}", address, e).into());
        }

        self.connected = true;

        let stream = stream.unwrap();
        let queue = Arc::clone(&self.queue);
        let packet_map = Arc::clone(&self.packet_map);
        let handler = self.handler.clone();

        thread::spawn(move || {
            let mut stream = stream;

            loop {
                // process outgoing packets queue
                let mut q = queue.lock().unwrap();

                if q.len() > 0 {
                    let packet = q.remove(0);

                    let mut buffer = Buffer::new();
                    buffer.write_u8(packet.header.command as u8);
                    buffer.write_u128(packet.header.uuid.as_u128());
                    buffer.write_u32(packet.data.len() as u32);
                    buffer.write_buffer(&packet.data);

                    let rc = stream.write_all(buffer.buffer());
                    if rc.is_err() {
                        println!("Failed to write to the debugger: {:?}", rc);
                        continue;
                    }
                }

                drop(q);

                let timeout = stream.read_timeout().unwrap();
                let rc = stream.set_read_timeout(Some(std::time::Duration::from_millis(1000)));
                if rc.is_err() {
                    println!("Failed to set read timeout: {:?}", rc);
                    continue;
                }

                let mut header_buffer = [0; 1 + 16 + 4];
                let is_data_available = stream.read_exact(&mut header_buffer);

                let rc = stream.set_read_timeout(timeout);
                if rc.is_err() {
                    println!("Failed to set read timeout: {:?}", rc);
                    continue;
                }

                if is_data_available.is_ok() {
                    let mut p_map = packet_map.lock().unwrap();

                    let header = PacketHeader {
                        command: num::FromPrimitive::from_u8(header_buffer[0]).unwrap(),
                        uuid: Uuid::from_u128(u128::from_le_bytes(
                            header_buffer[1..17].try_into().unwrap(),
                        )),
                        len: u32::from_le_bytes(header_buffer[17..21].try_into().unwrap()),
                    };

                    let mut data_buffer = vec![0; header.len as usize];
                    let res = stream.read_exact(&mut data_buffer);
                    if res.is_err() {
                        println!(
                            "An error occured while reading the data from the debugger: {:?}",
                            res
                        );
                        continue;
                    }

                    let packet = Packet {
                        header: header,
                        data: Buffer::from(data_buffer),
                    };

                    p_map.insert(packet.header.uuid, packet.clone());
                    drop(p_map);

                    if let Some(handler) = handler.clone() {
                        let s = Arc::clone(&handler);
                        let mut packet = packet;

                        tokio::spawn(async move {
                            T::handle(s, &mut packet).await;
                        });
                    }
                }

                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });

        Ok(())
    }

    pub async fn send_command(&mut self, packet: Packet) -> Result<Packet, Box<dyn Error>> {
        let start = std::time::Instant::now();
        let header = packet.header.clone();

        let mut queue = self.queue.lock().unwrap();
        queue.push(packet);
        drop(queue);

        loop {
            let mut packet_map = self.packet_map.lock().unwrap();

            if start.elapsed().as_secs() > 30 {
                if packet_map.contains_key(&header.uuid) {
                    packet_map.remove(&header.uuid).unwrap();
                    drop(packet_map);
                }

                return Err(format!("Command {:?} timed out!", header.command).into());
            }

            if packet_map.contains_key(&header.uuid) {
                let p = packet_map.remove(&header.uuid).unwrap();
                return Ok(p);
            }

            drop(packet_map);

            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    pub async fn get_status(&mut self) -> Result<Status, Box<dyn Error>> {
        let mut packet = self
            .send_command(Packet {
                header: PacketHeader {
                    command: Commands::GetStatus,
                    uuid: Uuid::new_v4(),
                    len: 0,
                },
                data: Buffer::new(),
            })
            .await?;

        let status = packet.data.read_u8() as u32;
        let major = packet.data.read_u8() as u32;
        let minor = packet.data.read_u8() as u32;
        let patch = packet.data.read_u8() as u32;

        self.protocol_version = (major << 16) | (minor << 8);

        if self.protocol_version > ((VERSION_MAJOR << 16) | (VERSION_MINOR << 8)) {
            return Err("Failed to get status: Unsupported protocol version".into());
        }

        self.protocol_version |= patch;

        let status: Status = match status {
            0x0 => Status::Stopped,
            0x1 => Status::Running,
            0x2 => Status::Paused,
            _ => return Err("Failed to get status: Unknown status".into()),
        };

        Ok(status)
    }

    pub async fn poke(
        &mut self,
        data_type: u8,
        addr: u64,
        value: u64,
    ) -> Result<(), Box<dyn Error>> {
        Ok(match data_type {
            1 => self.poke8(addr, value as u8).await?,
            2 => self.poke16(addr, value as u16).await?,
            4 => self.poke32(addr, value as u32).await?,
            8 => self.poke64(addr, value).await?,
            _ => return Err("Failed to poke memory: Invalid data type".into()),
        })
    }

    pub async fn peek(&mut self, data_type: u8, addr: u64) -> Result<u64, Box<dyn Error>> {
        Ok(match data_type {
            1 => self.peek8(addr).await? as u64,
            2 => self.peek16(addr).await? as u64,
            4 => self.peek32(addr).await? as u64,
            8 => self.peek64(addr).await?,
            _ => return Err("Failed to peek memory: Invalid data type".into()),
        })
    }

    pub async fn poke8(&mut self, addr: u64, value: u8) -> Result<(), Box<dyn Error>> {
        self.write_memory(addr, &[value]).await?;
        Ok(())
    }

    pub async fn peek8(&mut self, addr: u64) -> Result<u8, Box<dyn Error>> {
        let buffer = self.read_memory(addr, 1).await?;
        Ok(buffer[0])
    }

    pub async fn poke16(&mut self, addr: u64, value: u16) -> Result<(), Box<dyn Error>> {
        self.write_memory(addr, &value.to_le_bytes()).await?;
        Ok(())
    }

    pub async fn peek16(&mut self, addr: u64) -> Result<u16, Box<dyn Error>> {
        let buffer = self.read_memory(addr, 2).await?;
        Ok(u16::from_le_bytes(buffer.try_into().unwrap()))
    }

    pub async fn poke32(&mut self, addr: u64, value: u32) -> Result<(), Box<dyn Error>> {
        self.write_memory(addr, &value.to_le_bytes()).await?;
        Ok(())
    }

    pub async fn peek32(&mut self, addr: u64) -> Result<u32, Box<dyn Error>> {
        let buffer = self.read_memory(addr, 4).await?;
        Ok(u32::from_le_bytes(buffer.try_into().unwrap()))
    }

    pub async fn poke64(&mut self, addr: u64, value: u64) -> Result<(), Box<dyn Error>> {
        self.write_memory(addr, &value.to_le_bytes()).await?;
        Ok(())
    }

    pub async fn peek64(&mut self, addr: u64) -> Result<u64, Box<dyn Error>> {
        let buffer = self.read_memory(addr, 8).await?;
        Ok(u64::from_le_bytes(buffer.try_into().unwrap()))
    }

    pub async fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut packet = self
            .send_command(Packet {
                header: PacketHeader {
                    command: Commands::WriteMemory,
                    uuid: Uuid::new_v4(),
                    len: 0,
                },
                data: (&mut Buffer::new())
                    .write_u64(addr)
                    .write_compressed(data.to_vec())
                    .clone(),
            })
            .await?;

        let rc = DebuggerResult::value_of(packet.data.read_u32());
        if rc.failed() {
            return Err(format!("Failed to write memory: {:?}", rc).into());
        }

        Ok(())
    }

    pub async fn read_memory(&mut self, addr: u64, size: u32) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut packet = self
            .send_command(Packet {
                header: PacketHeader {
                    command: Commands::ReadMemory,
                    uuid: Uuid::new_v4(),
                    len: 0,
                },
                data: (&mut Buffer::new()).write_u64(addr).write_u32(size).clone(),
            })
            .await?;

        let mut size = size;
        let mut buffer = Vec::new();

        while size > 0 {
            let rc = DebuggerResult::value_of(packet.data.read_u32());
            if rc.failed() {
                return Err(format!("Failed to read memory: {:?}", rc).into());
            }

            let mut len: u32 = 0;
            let decompressed = packet.data.read_compressed(&mut len);

            buffer.extend_from_slice(decompressed.buffer());

            size -= len;
        }

        Ok(buffer)
    }

    pub async fn set_breakpoint(
        &mut self,
        id: u32,
        flags: u64,
        addr: u64,
    ) -> Result<(), Box<dyn Error>> {
        let mut packet = self
            .send_command(Packet {
                header: PacketHeader {
                    command: Commands::SetBreakpoint,
                    uuid: Uuid::new_v4(),
                    len: 0,
                },
                data: (&mut Buffer::new())
                    .write_u32(id)
                    .write_u64(flags)
                    .write_u64(addr)
                    .clone(),
            })
            .await?;

        let rc = DebuggerResult::value_of(packet.data.read_u32());
        if rc.failed() {
            return Err(format!("Failed to set breakpoint: {:?}", rc).into());
        }

        Ok(())
    }

    pub async fn set_watchpoint(
        &mut self,
        read: bool,
        write: bool,
        addr: u64,
    ) -> Result<(), Box<dyn Error>> {
        let size: u32 = 4;
        let id: u32 = 0;
        let bp_id: u32 = id + 4;
        let offset: u32 = (addr - (addr & !3)) as u32;
        let mask: u32 = ((1 << size) - 1) << offset;

        let mut bp_flags: u64 = 0;
        bp_flags |= 0x1; // enabled

        bp_flags |= 0xF << 5; // address
        bp_flags |= 0 << 16; // linked breakpoint number
        bp_flags |= 0x0011 << 20; // breakpoint type = LINKED_CONTEXT_IDR_MATCH

        let mut wp_flags: u64 = 0;

        wp_flags |= 0x1; // enabled

        // access control
        if read && write {
            wp_flags |= 0x11 << 3; // read/write
        } else if read {
            wp_flags |= 0x01 << 3; // read
        } else if write {
            wp_flags |= 0x10 << 3; // write
        }

        wp_flags |= (mask << 5) as u64; // address
        wp_flags |= (bp_id << 16) as u64; // linked breakpoint number
        wp_flags |= (0 << 24) as u64; // mask

        let rc = self.set_breakpoint(bp_id, bp_flags, 0).await;
        if rc.is_ok() {
            self.set_breakpoint(0x10 + id, wp_flags, addr).await
        } else {
            rc
        }
    }

    async fn get_result(&mut self, cmd: Commands) -> Result<(), Box<dyn Error>> {
        let mut packet = self
            .send_command(Packet {
                header: PacketHeader {
                    command: cmd.clone(),
                    uuid: Uuid::new_v4(),
                    len: 0,
                },
                data: Buffer::new(),
            })
            .await?;

        let rc = DebuggerResult::value_of(packet.data.read_u32());
        if rc.failed() {
            return Err(format!("Failed to execute {:?}: {:?}", cmd, rc).into());
        }

        Ok(())
    }

    pub async fn resume(&mut self) -> Result<(), Box<dyn Error>> {
        self.get_result(Commands::Resume).await
    }

    pub async fn pause(&mut self) -> Result<(), Box<dyn Error>> {
        self.get_result(Commands::Pause).await
    }

    pub async fn attach(&mut self, pid: u64) -> Result<(), Box<dyn Error>> {
        let mut packet = self
            .send_command(Packet {
                header: PacketHeader {
                    command: Commands::Attach,
                    uuid: Uuid::new_v4(),
                    len: 0,
                },
                data: (&mut Buffer::new()).write_u64(pid).clone(),
            })
            .await?;

        let result = DebuggerResult::value_of(packet.data.read_u32());
        if result.failed() {
            return Err(format!("Failed to attach to process {} : {:?}", pid, result).into());
        }

        Ok(())
    }

    pub async fn detach(&mut self) -> Result<(), Box<dyn Error>> {
        self.get_result(Commands::Detach).await
    }

    pub async fn query(&mut self, addr: u64) -> Result<MemoryInfo, Box<dyn Error>> {
        let last_query = self.last_query.clone();
        if last_query.is_some() {
            let last_query = last_query.unwrap();
            if last_query.addr != 0
                && addr > last_query.addr
                && addr < last_query.addr + last_query.size
            {
                return Ok(last_query);
            }
        }

        let mut packet = self
            .send_command(Packet {
                header: PacketHeader {
                    command: Commands::QueryMemory,
                    uuid: Uuid::new_v4(),
                    len: 0,
                },
                data: (&mut Buffer::new()).write_u64(addr).clone(),
            })
            .await?;

        let info = read_info(&mut packet.data).await?;
        self.last_query = Box::new(Some(info.clone()));

        Ok(info)
    }

    pub async fn query_multi(
        &mut self,
        addr: u64,
        max: u32,
    ) -> Result<Vec<MemoryInfo>, Box<dyn Error>> {
        let mut packet = self
            .send_command(Packet {
                header: PacketHeader {
                    command: Commands::QueryMemoryMulti,
                    uuid: Uuid::new_v4(),
                    len: 0,
                },
                data: (&mut Buffer::new()).write_u64(addr).write_u32(max).clone(),
            })
            .await?;

        let mut infos = Vec::new();

        for _ in 0..max {
            let info = read_info(&mut packet.data).await?;
            infos.push(info.clone());

            if info.memory_type == MemoryType::Reserved {
                break;
            }
        }
        Ok(infos)
    }

    pub async fn get_current_pid(&mut self) -> Result<u64, Box<dyn Error>> {
        let mut packet = self
            .send_command(Packet {
                header: PacketHeader {
                    command: Commands::GetCurrentPID,
                    uuid: Uuid::new_v4(),
                    len: 0,
                },
                data: Buffer::new(),
            })
            .await?;

        let result = DebuggerResult::value_of(packet.data.read_u32());
        if result.failed() {
            println!("Failed to get current pid: {:?}", result);
            return Ok(0);
        }

        let pid = packet.data.read_u64();
        Ok(pid)
    }

    pub async fn get_attached_pid(&mut self) -> Result<u64, Box<dyn Error>> {
        let mut packet = self
            .send_command(Packet {
                header: PacketHeader {
                    command: Commands::GetAttachedPID,
                    uuid: Uuid::new_v4(),
                    len: 0,
                },
                data: Buffer::new(),
            })
            .await?;

        let pid = packet.data.read_u64();
        Ok(pid)
    }

    pub async fn get_pids(&mut self) -> Result<Vec<u64>, Box<dyn Error>> {
        let mut packet = self
            .send_command(Packet {
                header: PacketHeader {
                    command: Commands::GetPIDs,
                    uuid: Uuid::new_v4(),
                    len: 0,
                },
                data: Buffer::new(),
            })
            .await?;

        let result = DebuggerResult::value_of(packet.data.read_u32());
        if result.failed() {
            return Err(format!("Failed to get pids : {:?}", result).into());
        }

        let count = packet.data.read_u32();
        let mut pids = Vec::new();

        for _ in 0..count {
            let pid = packet.data.read_u64();
            pids.push(pid);
        }

        Ok(pids)
    }

    pub async fn get_title_id(&mut self, pid: u64) -> Result<u64, Box<dyn Error>> {
        let mut packet = self
            .send_command(Packet {
                header: PacketHeader {
                    command: Commands::GetTitleID,
                    uuid: Uuid::new_v4(),
                    len: 0,
                },
                data: (&mut Buffer::new()).write_u64(pid).clone(),
            })
            .await?;

        let result = DebuggerResult::value_of(packet.data.read_u32());
        if result.failed() {
            return Err(format!("Failed to get title id : {:?}", result).into());
        }

        let title_id = packet.data.read_u64();
        Ok(title_id)
    }

    pub async fn get_current_title_id(&mut self) -> Result<u64, Box<dyn Error>> {
        let pid = self.get_current_pid().await?;
        if pid == 0 {
            return Err("Failed to get current pid".into());
        }

        self.get_title_id(pid).await
    }

    pub async fn attached(&mut self) -> Result<bool, Box<dyn Error>> {
        let pid = self.get_attached_pid().await?;
        Ok(pid != 0)
    }
}

async fn read_info(buffer: &mut Buffer) -> Result<MemoryInfo, Box<dyn Error>> {
    let addr = buffer.read_u64();
    let size = buffer.read_u64();
    let flags = buffer.read_u32();
    let perm = buffer.read_u32();

    let rc = DebuggerResult::value_of(buffer.read_u32());
    if rc.failed() {
        return Err(format!("Failed to read memory info: {:?}", rc).into());
    }

    Ok(MemoryInfo {
        addr: addr,
        size: size,
        memory_type: num::FromPrimitive::from_u32(flags).unwrap(),
        perm: perm,
    })
}
