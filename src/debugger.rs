use std::borrow::BorrowMut;
use std::error::Error;
use std::path::PathBuf;

use bytes::{buf, Buf, BufMut, BytesMut};

use std::convert::TryInto;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub enum Commands {
    Status = 0x01,

    Poke8 = 0x02,
    Poke16 = 0x03,
    Poke32 = 0x04,
    Poke64 = 0x05,

    Read = 0x06,
    Write = 0x07,
    Continue = 0x08,
    Pause = 0x09,
    Attach = 0x0A,
    Detach = 0x0B,
    QueryMemory = 0x0C,
    QueryMemoryMulti = 0x0D,
    CurrentPID = 0x0E,
    AttachedPID = 0x0F,
    GetPIDs = 0x10,
    GetTitleID = 0x11,
    Disconnect = 0x12,
    ReadMulti = 0x13,
    SetBreakpoint = 0x14,
}

#[derive(Debug)]
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

#[derive(FromPrimitive, Clone, PartialEq, Eq, Debug, Hash)]
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

#[derive(Clone, PartialEq, Eq, Hash)]
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

pub struct Debugger {
    current_dump: PathBuf,
    stream: Option<TcpStream>,
    protocol_version: u32,
    last_query: Box<Option<MemoryInfo>>,
}

impl Debugger {
    pub fn new() -> Debugger {
        Debugger {
            current_dump: PathBuf::from(""),
            stream: None,
            protocol_version: 0,
            last_query: Box::new(None),
        }
    }

    pub async fn connect(&mut self, address: &str) -> Result<(), Box<dyn Error>> {
        let stream = TcpStream::connect(address).await;
        if stream.is_err() {
            return Err(format!("Failed to connect to {}", address).into());
        }

        self.stream = Some(stream.unwrap());

        Ok(())
    }

    pub async fn get_status(&mut self) -> Result<Status, Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(1);
        buffer.put_u8(Commands::Status as u8);

        stream.write_all(&buffer).await?;

        let status = stream.read_u8().await? as u32;
        let major = stream.read_u8().await? as u32;
        let minor = stream.read_u8().await? as u32;
        let patch = stream.read_u8().await? as u32;

        self.protocol_version = (major << 16) | (minor << 8);

        let result = DebuggerResult::value_of(stream.read_u32_le().await?);
        if result.failed() {
            return Err(format!("Failed to get status: {:?}", result).into());
        }

        if self.protocol_version > ((1 << 16) | (1 << 8)) {
            return Err("Unsupported protocol version".into());
        }

        self.protocol_version |= patch;

        let status: Status = match status {
            0x0 => Status::Stopped,
            0x1 => Status::Running,
            0x2 => Status::Paused,
            _ => return Err("Unknown status".into()),
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
            _ => return Err("Invalid data type".into()),
        })
    }

    pub async fn peek(&mut self, data_type: u8, addr: u64) -> Result<u64, Box<dyn Error>> {
        Ok(match data_type {
            1 => self.peek8(addr).await? as u64,
            2 => self.peek16(addr).await? as u64,
            4 => self.peek32(addr).await? as u64,
            8 => self.peek64(addr).await?,
            _ => return Err("Invalid data type".into()),
        })
    }

    pub async fn poke8(&mut self, addr: u64, value: u8) -> Result<(), Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(10);
        buffer.put_u8(Commands::Poke8 as u8);
        buffer.put_u64_le(addr);
        buffer.put_u8(value);

        stream.write_all(&buffer).await?;

        let result = DebuggerResult::value_of(stream.read_u32_le().await?);
        if result.failed() {
            return Err(format!("Failed to poke8: {:?}", result).into());
        }

        Ok(())
    }

    pub async fn peek8(&mut self, addr: u64) -> Result<u8, Box<dyn Error>> {
        let mut buffer = self.read_memory(addr, 1).await?;
        Ok(buffer.get_u8())
    }

    pub async fn poke16(&mut self, addr: u64, value: u16) -> Result<(), Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(11);
        buffer.put_u8(Commands::Poke16 as u8);
        buffer.put_u64_le(addr);
        buffer.put_u16_le(value);

        stream.write_all(&buffer).await?;

        let result = DebuggerResult::value_of(stream.read_u32_le().await?);
        if result.failed() {
            return Err(format!("Failed to poke16: {:?}", result).into());
        }

        Ok(())
    }

    pub async fn peek16(&mut self, addr: u64) -> Result<u16, Box<dyn Error>> {
        let mut buffer = self.read_memory(addr, 2).await?;
        Ok(buffer.get_u16())
    }

    pub async fn poke32(&mut self, addr: u64, value: u32) -> Result<(), Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(13);
        buffer.put_u8(Commands::Poke32 as u8);
        buffer.put_u64_le(addr);
        buffer.put_u32_le(value);

        stream.write_all(&buffer).await?;

        let result = DebuggerResult::value_of(stream.read_u32_le().await?);
        if result.failed() {
            return Err(format!("Failed to poke32: {:?}", result).into());
        }

        Ok(())
    }

    pub async fn peek32(&mut self, addr: u64) -> Result<u32, Box<dyn Error>> {
        let mut buffer = self.read_memory(addr, 4).await?;
        Ok(buffer.get_u32_le())
    }

    pub async fn poke64(&mut self, addr: u64, value: u64) -> Result<(), Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(17);
        buffer.put_u8(Commands::Poke64 as u8);
        buffer.put_u64_le(addr);
        buffer.put_u64_le(value);

        stream.write_all(&buffer).await?;

        let result = DebuggerResult::value_of(stream.read_u32_le().await?);
        if result.failed() {
            return Err(format!("Failed to poke64: {:?}", result).into());
        }

        Ok(())
    }

    pub async fn peek64(&mut self, addr: u64) -> Result<u64, Box<dyn Error>> {
        let mut buffer = self.read_memory(addr, 8).await?;
        Ok(buffer.get_u64_le())
    }

    pub async fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(13);
        buffer.put_u8(Commands::Write as u8);
        buffer.put_u64_le(addr);
        buffer.put_u32_le(data.len() as u32);

        stream.write_all(&buffer).await?;

        let result = DebuggerResult::value_of(stream.read_u32_le().await?);
        if result.success() {
            let mut buffer = BytesMut::with_capacity(data.len());
            buffer.put_slice(data);

            stream.write_all(&buffer).await?;
        } else {
            let result = DebuggerResult::value_of(stream.read_u32_le().await?);
            return Err(format!("Failed to write memory: {:?}", result).into());
        }

        Ok(())
    }

    pub async fn read_memory(&mut self, addr: u64, size: u32) -> Result<BytesMut, Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(13);
        buffer.put_u8(Commands::Read as u8);
        buffer.put_u64_le(addr);
        buffer.put_u32_le(size);

        stream.write_all(&buffer).await?;

        let result = DebuggerResult::value_of(stream.read_u32_le().await?);
        if result.success() {
            let mut size = size;
            let mut buffer = BytesMut::with_capacity(2048 * 4);

            while size > 0 {
                let result = DebuggerResult::value_of(stream.read_u32_le().await?);
                if result.failed() {
                    stream.read_u32_le().await?;
                    return Err(format!("Failed to read memory: {:?}", result).into());
                }

                let mut buffer2 = Vec::new();
                let len = read_compressed(stream, &mut buffer2).await;

                buffer.reserve(len as usize);
                buffer.put_slice(&buffer2[0..(len as usize)]);

                size -= len;
            }

            stream.read_u32_le().await?;
            Ok(buffer)
        } else {
            let result = DebuggerResult::value_of(stream.read_u32_le().await?);
            Err(format!("Failed to read memory: {:?}", result).into())
        }
    }

    pub async fn set_breakpoint(
        &mut self,
        id: u32,
        flags: u64,
        addr: u64,
    ) -> Result<(), Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(21);
        buffer.put_u8(Commands::SetBreakpoint as u8);
        buffer.put_u32_le(id);
        buffer.put_u64_le(addr);
        buffer.put_u64_le(flags);

        stream.write_all(&buffer).await?;

        let result = DebuggerResult::value_of(stream.read_u32_le().await?);
        if result.failed() {
            return Err(format!("Failed to set breakpoint: {:?}", result).into());
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

    async fn get_result(&mut self, cmd: Commands) -> Result<DebuggerResult, Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(1);
        buffer.put_u8(cmd as u8);

        stream.write_all(&buffer).await?;

        let result = DebuggerResult::value_of(stream.read_u32_le().await?);
        Ok(result)
    }

    pub async fn resume(&mut self) -> Result<DebuggerResult, Box<dyn Error>> {
        self.get_result(Commands::Continue).await
    }

    pub async fn pause(&mut self) -> Result<DebuggerResult, Box<dyn Error>> {
        self.get_result(Commands::Pause).await
    }

    pub async fn attach(&mut self, pid: u64) -> Result<DebuggerResult, Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(9);
        buffer.put_u8(Commands::Attach as u8);
        buffer.put_u64_le(pid);

        stream.write_all(&buffer).await?;

        let result = DebuggerResult::value_of(stream.read_u32_le().await?);
        Ok(result)
    }

    pub async fn detach(&mut self) -> Result<DebuggerResult, Box<dyn Error>> {
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

        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(9);
        buffer.put_u8(Commands::QueryMemory as u8);
        buffer.put_u64_le(addr);

        stream.write_all(&buffer).await?;

        let info = read_info(stream).await?;
        self.last_query = Box::new(Some(info.clone()));

        Ok(info)
    }

    pub async fn query_multi(
        &mut self,
        addr: u64,
        max: u32,
    ) -> Result<Vec<MemoryInfo>, Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(13);
        buffer.put_u8(Commands::QueryMemoryMulti as u8);
        buffer.put_u64_le(addr);
        buffer.put_u32_le(max);

        stream.write_all(&buffer).await?;

        let mut infos = Vec::new();

        for i in 0..max {
            let info = read_info(stream).await?;
            infos.push(info.clone());

            if info.memory_type == MemoryType::Reserved {
                break;
            }
        }

        stream.read_u32_le().await?;
        Ok(infos)
    }

    pub async fn get_current_pid(&mut self) -> Result<u64, Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(1);
        buffer.put_u8(Commands::CurrentPID as u8);

        stream.write_all(&buffer).await?;

        let mut pid = stream.read_u64_le().await?;
        let result = DebuggerResult::value_of(stream.read_u32_le().await?);
        if result.failed() {
            pid = 0;
        }

        Ok(pid)
    }

    pub async fn get_attached_pid(&mut self) -> Result<u64, Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(1);
        buffer.put_u8(Commands::AttachedPID as u8);

        stream.write_all(&buffer).await?;

        let mut pid = stream.read_u64_le().await?;
        let result = DebuggerResult::value_of(stream.read_u32_le().await?);
        if result.failed() {
            pid = 0;
        }

        Ok(pid)
    }

    pub async fn get_pids(&mut self) -> Result<Vec<u64>, Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(1);
        buffer.put_u8(Commands::GetPIDs as u8);

        stream.write_all(&buffer).await?;

        let count = stream.read_u32_le().await?;
        let mut pids = Vec::new();

        for _ in 0..count {
            let pid = stream.read_u64_le().await?;
            pids.push(pid);
        }

        let result = DebuggerResult::value_of(stream.read_u32_le().await?);
        if result.failed() {
            return Err("Failed to get pids".into());
        }

        Ok(pids)
    }

    pub async fn get_title_id(&mut self, pid: u64) -> Result<u64, Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(9);
        buffer.put_u8(Commands::GetTitleID as u8);
        buffer.put_u64_le(pid);

        stream.write_all(&buffer).await?;

        let mut title_id = stream.read_u64_le().await?;
        let result = DebuggerResult::value_of(stream.read_u32_le().await?);
        if result.failed() {
            title_id = 0;
        }

        Ok(title_id)
    }

    pub async fn disconnect(&mut self) -> Result<(), Box<dyn Error>> {
        if !self.stream.is_some() {
            return Err("Not connected to debugger".into());
        }

        let stream = self.stream.as_mut().unwrap();

        let mut buffer = BytesMut::with_capacity(8);
        buffer.put_u8(Commands::Disconnect as u8);

        stream.write_all(&buffer).await?;

        let result = DebuggerResult::value_of(stream.read_u32_le().await?);
        if result.failed() {
            return Err("Failed to disconnect???".into());
        }

        self.stream.as_mut().unwrap().shutdown().await?;
        self.stream = None;

        Ok(())
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

    pub fn connected(&mut self) -> bool {
        self.stream.is_some()
    }
}

async fn read_compressed(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> u32 {
    let compressed_flag = stream.read_u8().await.unwrap();
    let decompressed_len = stream.read_u32_le().await.unwrap();

    if compressed_flag == 0 {
        let mut vec = vec![0; decompressed_len as usize];
        stream.read_exact(&mut vec).await.unwrap();

        buffer.reserve(decompressed_len as usize);
        buffer.append(&mut vec);
    } else {
        let compressed_len = stream.read_u32_le().await.unwrap();

        let mut compressed_buffer = vec![0; compressed_len as usize];
        stream.read_exact(&mut compressed_buffer).await.unwrap();

        let mut pos = 0;
        for i in (0..compressed_len).step_by(2) {
            let value = compressed_buffer[i as usize];
            let count = compressed_buffer[i as usize + 1] & 0xFF;

            for j in (pos..pos + count) {
                buffer.push(value);
            }

            pos += count;
        }
    }

    decompressed_len
}

async fn read_info(stream: &mut TcpStream) -> Result<MemoryInfo, Box<dyn Error>> {
    let addr = stream.read_u64_le().await.unwrap();
    let size = stream.read_u64_le().await.unwrap();
    let flags = stream.read_u32_le().await.unwrap();
    let perm = stream.read_u32_le().await.unwrap();

    let rc = DebuggerResult::value_of(stream.read_u32_le().await?);
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
