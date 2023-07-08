#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Buffer {
    buffer: Vec<u8>,
    pos: usize,
}

impl Buffer {
    pub fn new() -> Buffer {
        Buffer {
            buffer: Vec::new(),
            pos: 0,
        }
    }

    pub fn from(buffer: Vec<u8>) -> Buffer {
        Buffer { buffer, pos: 0 }
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    pub fn write(&mut self, index: usize, data: &[u8]) {
        if index + data.len() > self.buffer.len() {
            self.buffer.resize(data.len() + index, 0);
        }
        self.buffer[index..index + data.len()].copy_from_slice(data);
        self.pos += data.len();
    }

    pub fn read(&mut self, index: usize, size: usize) -> &[u8] {
        let buf = &self.buffer[index..index + size];
        self.pos += size;
        buf
    }

    pub fn read_u8(&mut self) -> u8 {
        let buf = self.read(self.pos, 1);
        buf[0]
    }

    pub fn read_u16(&mut self) -> u16 {
        let buf = self.read(self.pos, 2);
        u16::from_le_bytes([buf[0], buf[1]])
    }

    pub fn read_u32(&mut self) -> u32 {
        let buf = self.read(self.pos, 4);
        u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
    }

    pub fn read_u64(&mut self) -> u64 {
        let buf = self.read(self.pos, 8);
        u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ])
    }

    pub fn read_i8(&mut self) -> i8 {
        let buf = self.read(self.pos, 1);
        buf[0] as i8
    }

    pub fn read_i16(&mut self) -> i16 {
        let buf = self.read(self.pos, 2);
        i16::from_le_bytes([buf[0], buf[1]])
    }

    pub fn read_i32(&mut self) -> i32 {
        let buf = self.read(self.pos, 4);
        i32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
    }

    pub fn read_i64(&mut self) -> i64 {
        let buf = self.read(self.pos, 8);
        i64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ])
    }

    pub fn read_f32(&mut self) -> f32 {
        let buf = self.read(self.pos, 4);
        f32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
    }

    pub fn read_f64(&mut self) -> f64 {
        let buf = self.read(self.pos, 8);
        f64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ])
    }

    pub fn read_slice(&self, index: usize, size: usize) -> &[u8] {
        &self.buffer[index..index + size]
    }

    pub fn read_string(&mut self, size: usize) -> String {
        let buf = self.read(self.pos, size);
        String::from_utf8_lossy(buf).to_string()
    }

    pub fn read_compressed(&mut self, length: &mut u32) -> Buffer {
        let compressed_flag = self.read_u8();
        let decompressed_len = self.read_u32();

        *length = decompressed_len;

        if compressed_flag == 0 {
            let slice = self
                .read_slice(self.pos, decompressed_len as usize)
                .to_vec();
            self.pos += decompressed_len as usize;
            Buffer::from(slice)
        } else {
            let compressed_len = self.read_u32();

            let mut buffer = Vec::new();
            let compressed_buffer = self.read_slice(self.pos, compressed_len as usize).to_vec();
            self.pos += compressed_len as usize;

            let mut pos = 0;
            for i in (0..compressed_len).step_by(2) {
                let value = compressed_buffer[i as usize];
                let count = compressed_buffer[i as usize + 1];

                for _ in pos..pos + count {
                    buffer.push(value);
                }

                pos += count;
            }

            Buffer::from(buffer)
        }
    }

    pub fn write_u8(&mut self, data: u8) -> &mut Buffer {
        self.write(self.pos, &[data]);
        self
    }

    pub fn write_u16(&mut self, data: u16) -> &mut Buffer {
        self.write(self.pos, &data.to_be_bytes());
        self
    }

    pub fn write_u32(&mut self, data: u32) -> &mut Buffer {
        self.write(self.pos, &data.to_be_bytes());
        self
    }

    pub fn write_u64(&mut self, data: u64) -> &mut Buffer {
        self.write(self.pos, &data.to_be_bytes());
        self
    }

    pub fn write_u128(&mut self, data: u128) -> &mut Buffer {
        self.write(self.pos, &data.to_be_bytes());
        self
    }

    pub fn write_i8(&mut self, data: i8) -> &mut Buffer {
        self.write(self.pos, &[data as u8]);
        self
    }

    pub fn write_i16(&mut self, data: i16) -> &mut Buffer {
        self.write(self.pos, &data.to_be_bytes());
        self
    }

    pub fn write_i32(&mut self, data: i32) -> &mut Buffer {
        self.write(self.pos, &data.to_be_bytes());
        self
    }

    pub fn write_i64(&mut self, data: i64) -> &mut Buffer {
        self.write(self.pos, &data.to_be_bytes());
        self
    }

    pub fn write_f32(&mut self, data: f32) -> &mut Buffer {
        self.write(self.pos, &data.to_be_bytes());
        self
    }

    pub fn write_f64(&mut self, data: f64) -> &mut Buffer {
        self.write(self.pos, &data.to_be_bytes());
        self
    }

    pub fn write_string(&mut self, data: &str) -> &mut Buffer {
        self.write(self.pos, data.as_bytes());
        self
    }

    pub fn write_buffer(&mut self, data: &Buffer) -> &mut Buffer {
        self.write(self.pos, &data.buffer);
        self
    }

    pub fn write_buffer_at(&mut self, index: usize, data: &Buffer) {
        self.write(index, &data.buffer);
    }

    pub fn write_vec(&mut self, data: &Vec<u8>) -> &mut Buffer {
        self.write(self.pos, data);
        self
    }

    pub fn write_compressed(&mut self, data: Vec<u8>) -> &mut Buffer {
        let mut compressed_buffer = Vec::new();
        let mut pos: u32 = 0;

        for i in 0..data.len() {
            let value = data[i];
            let mut rle = 1;
            let mut i = i;

            while rle < 255 && i + 1 < data.len() && data[i + 1] == value {
                rle += 1;
                i += 1;
            }

            compressed_buffer.push(value);
            compressed_buffer.push(rle);

            pos += 2;
        }

        let compressed_flag: u8 = if pos > data.len() as u32 { 10 } else { 1 };
        self.write_u8(compressed_flag);
        self.write_u32(data.len() as u32);

        if compressed_flag == 1 {
            self.write_vec(&data);
        } else {
            self.write_u32(pos);
            self.write_vec(&compressed_buffer);
        }

        self
    }
}
