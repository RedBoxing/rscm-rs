use std::{cmp::Ordering, fmt::Display, ops::Add, ops::Sub};

use super::buffer::Buffer;

macro_rules! get_result {
    ($result:expr) => {
        match $result {
            Ok(value) => value,
            Err(err) => {
                panic!("{}", err);
            }
        }
    };
}

pub(crate) use get_result;

#[derive(PartialEq, Eq, Clone, Copy)]
pub struct DataType(usize, bool, bool); // size, signed, floating point

impl DataType {
    pub const UnsignedByte: DataType = DataType(1, false, false);
    pub const Byte: DataType = DataType(1, true, false);

    pub const UnsignedShort: DataType = DataType(2, false, false);
    pub const Short: DataType = DataType(2, true, false);

    pub const UnsignedInt: DataType = DataType(4, false, false);
    pub const Int: DataType = DataType(4, true, false);

    pub const UnsignedLong: DataType = DataType(8, false, false);
    pub const Long: DataType = DataType(8, true, false);

    pub const UnsignedLongLong: DataType = DataType(16, false, false);
    pub const LongLong: DataType = DataType(16, true, false);

    pub const Float: DataType = DataType(4, true, true);
    pub const Double: DataType = DataType(8, true, true);

    pub const fn size(&self) -> usize {
        self.0
    }
}

impl Display for DataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &DataType::UnsignedByte => write!(f, "u8"),
            &DataType::Byte => write!(f, "i8"),
            &DataType::UnsignedShort => write!(f, "u16"),
            &DataType::Short => write!(f, "i16"),
            &DataType::UnsignedInt => write!(f, "u32"),
            &DataType::Int => write!(f, "i32"),
            &DataType::UnsignedLong => write!(f, "u64"),
            &DataType::Long => write!(f, "i64"),
            &DataType::UnsignedLongLong => write!(f, "u128"),
            &DataType::LongLong => write!(f, "i128"),
            &DataType::Float => write!(f, "f32"),
            &DataType::Double => write!(f, "f64"),
            _ => write!(
                f,
                "unknown(size: {}, signed: {}, floating: {})",
                self.0, self.1, self.2
            ),
        }
    }
}

#[derive(Clone)]
pub struct AnySizedNumber {
    bytes: Vec<u8>,
    data_type: DataType,
}

impl AnySizedNumber {
    fn new(data: Vec<u8>, data_type: DataType) -> AnySizedNumber {
        AnySizedNumber {
            bytes: data,
            data_type: data_type,
        }
    }

    pub fn from_buffer(buffer: &mut Buffer, data_type: DataType) -> AnySizedNumber {
        let mut data = Vec::new();
        for _ in 0..data_type.size() {
            data.push(buffer.read_u8());
        }

        AnySizedNumber::new(data, data_type)
    }

    pub fn from_slice(slice: &[u8], data_type: DataType) -> AnySizedNumber {
        let mut data = Vec::new();
        for _ in 0..data_type.size() {
            data.push(slice[0]);
        }

        AnySizedNumber::new(data, data_type)
    }

    pub fn from_u8(data: u8) -> AnySizedNumber {
        AnySizedNumber::new(data.to_le_bytes().to_vec(), DataType::UnsignedByte)
    }

    pub fn from_i8(data: i8) -> AnySizedNumber {
        AnySizedNumber::new(data.to_le_bytes().to_vec(), DataType::Byte)
    }

    pub fn from_u16(data: u16) -> AnySizedNumber {
        AnySizedNumber::new(data.to_le_bytes().to_vec(), DataType::UnsignedShort)
    }

    pub fn from_i16(data: i16) -> AnySizedNumber {
        AnySizedNumber::new(data.to_le_bytes().to_vec(), DataType::Short)
    }

    pub fn from_u32(data: u32) -> AnySizedNumber {
        AnySizedNumber::new(data.to_le_bytes().to_vec(), DataType::UnsignedInt)
    }

    pub fn from_i32(data: i32) -> AnySizedNumber {
        AnySizedNumber::new(data.to_le_bytes().to_vec(), DataType::Int)
    }

    pub fn from_u64(data: u64) -> AnySizedNumber {
        AnySizedNumber::new(data.to_le_bytes().to_vec(), DataType::UnsignedLong)
    }

    pub fn from_i64(data: i64) -> AnySizedNumber {
        AnySizedNumber::new(data.to_le_bytes().to_vec(), DataType::Long)
    }

    pub fn from_u128(data: u128) -> AnySizedNumber {
        AnySizedNumber::new(data.to_le_bytes().to_vec(), DataType::UnsignedLongLong)
    }

    pub fn from_i128(data: i128) -> AnySizedNumber {
        AnySizedNumber::new(data.to_le_bytes().to_vec(), DataType::LongLong)
    }

    pub fn from_f32(data: f32) -> AnySizedNumber {
        AnySizedNumber::new(data.to_le_bytes().to_vec(), DataType::Float)
    }

    pub fn from_f64(data: f64) -> AnySizedNumber {
        AnySizedNumber::new(data.to_le_bytes().to_vec(), DataType::Double)
    }

    pub fn to_u8(&self) -> u8 {
        u8::from_le_bytes(self.bytes[0..1].try_into().unwrap())
    }

    pub fn to_i8(&self) -> i8 {
        i8::from_le_bytes(self.bytes[0..1].try_into().unwrap())
    }

    pub fn to_u16(&self) -> u16 {
        u16::from_le_bytes(self.bytes[0..2].try_into().unwrap())
    }

    pub fn to_i16(&self) -> i16 {
        i16::from_le_bytes(self.bytes[0..2].try_into().unwrap())
    }

    pub fn to_u32(&self) -> u32 {
        u32::from_le_bytes(self.bytes[0..4].try_into().unwrap())
    }

    pub fn to_i32(&self) -> i32 {
        i32::from_le_bytes(self.bytes[0..4].try_into().unwrap())
    }

    pub fn to_u64(&self) -> u64 {
        u64::from_le_bytes(self.bytes[0..8].try_into().unwrap())
    }

    pub fn to_i64(&self) -> i64 {
        i64::from_le_bytes(self.bytes[0..8].try_into().unwrap())
    }

    pub fn to_u128(&self) -> u128 {
        u128::from_le_bytes(self.bytes[0..16].try_into().unwrap())
    }

    pub fn to_i128(&self) -> i128 {
        i128::from_le_bytes(self.bytes[0..16].try_into().unwrap())
    }

    pub fn to_f32(&self) -> f32 {
        f32::from_le_bytes(self.bytes[0..4].try_into().unwrap())
    }

    pub fn to_f64(&self) -> f64 {
        f64::from_le_bytes(self.bytes[0..8].try_into().unwrap())
    }

    pub fn abs(&self) -> AnySizedNumber {
        match self.data_type {
            DataType::UnsignedByte => AnySizedNumber::from_u8(self.to_u8()),
            DataType::Byte => AnySizedNumber::from_i8(self.to_i8().abs()),
            DataType::UnsignedShort => AnySizedNumber::from_u16(self.to_u16()),
            DataType::Short => AnySizedNumber::from_i16(self.to_i16().abs()),
            DataType::UnsignedInt => AnySizedNumber::from_u32(self.to_u32()),
            DataType::Int => AnySizedNumber::from_i32(self.to_i32().abs()),
            DataType::UnsignedLong => AnySizedNumber::from_u64(self.to_u64()),
            DataType::Long => AnySizedNumber::from_i64(self.to_i64().abs()),
            DataType::UnsignedLongLong => AnySizedNumber::from_u128(self.to_u128()),
            DataType::LongLong => AnySizedNumber::from_i128(self.to_i128().abs()),
            DataType::Float => AnySizedNumber::from_f32(self.to_f32().abs()),
            DataType::Double => AnySizedNumber::from_f64(self.to_f64().abs()),
            _ => panic!("Unsupported data type"),
        }
    }
}

impl PartialEq for AnySizedNumber {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

impl Eq for AnySizedNumber {}

impl PartialOrd for AnySizedNumber {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self.data_type {
            DataType::UnsignedByte => self.to_u8().partial_cmp(&other.to_u8()),
            DataType::Byte => self.to_i8().partial_cmp(&other.to_i8()),
            DataType::UnsignedShort => self.to_u16().partial_cmp(&other.to_u16()),
            DataType::Short => self.to_i16().partial_cmp(&other.to_i16()),
            DataType::UnsignedInt => self.to_u32().partial_cmp(&other.to_u32()),
            DataType::Int => self.to_i32().partial_cmp(&other.to_i32()),
            DataType::UnsignedLong => self.to_u64().partial_cmp(&other.to_u64()),
            DataType::Long => self.to_i64().partial_cmp(&other.to_i64()),
            DataType::UnsignedLongLong => self.to_u128().partial_cmp(&other.to_u128()),
            DataType::LongLong => self.to_i128().partial_cmp(&other.to_i128()),
            DataType::Float => self.to_f32().partial_cmp(&other.to_f32()),
            DataType::Double => self.to_f64().partial_cmp(&other.to_f64()),
            _ => panic!("Unsupported data type"),
        }
    }
}

impl Ord for AnySizedNumber {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.data_type {
            DataType::UnsignedByte => self.to_u8().cmp(&other.to_u8()),
            DataType::Byte => self.to_i8().cmp(&other.to_i8()),
            DataType::UnsignedShort => self.to_u16().cmp(&other.to_u16()),
            DataType::Short => self.to_i16().cmp(&other.to_i16()),
            DataType::UnsignedInt => self.to_u32().cmp(&other.to_u32()),
            DataType::Int => self.to_i32().cmp(&other.to_i32()),
            DataType::UnsignedLong => self.to_u64().cmp(&other.to_u64()),
            DataType::Long => self.to_i64().cmp(&other.to_i64()),
            DataType::UnsignedLongLong => self.to_u128().cmp(&other.to_u128()),
            DataType::LongLong => self.to_i128().cmp(&other.to_i128()),
            DataType::Float => self.to_f32().partial_cmp(&other.to_f32()).unwrap(),
            DataType::Double => self.to_f64().partial_cmp(&other.to_f64()).unwrap(),
            _ => panic!("Unsupported data type"),
        }
    }
}

impl Sub for AnySizedNumber {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        match self.data_type {
            DataType::UnsignedByte => AnySizedNumber::from_u8(self.to_u8() - rhs.to_u8()),
            DataType::Byte => AnySizedNumber::from_i8(self.to_i8() - rhs.to_i8()),
            DataType::UnsignedShort => AnySizedNumber::from_u16(self.to_u16() - rhs.to_u16()),
            DataType::Short => AnySizedNumber::from_i16(self.to_i16() - rhs.to_i16()),
            DataType::UnsignedInt => AnySizedNumber::from_u32(self.to_u32() - rhs.to_u32()),
            DataType::Int => AnySizedNumber::from_i32(self.to_i32() - rhs.to_i32()),
            DataType::UnsignedLong => AnySizedNumber::from_u64(self.to_u64() - rhs.to_u64()),
            DataType::Long => AnySizedNumber::from_i64(self.to_i64() - rhs.to_i64()),
            DataType::UnsignedLongLong => AnySizedNumber::from_u128(self.to_u128() - rhs.to_u128()),
            DataType::LongLong => AnySizedNumber::from_i128(self.to_i128() - rhs.to_i128()),
            DataType::Float => AnySizedNumber::from_f32(self.to_f32() - rhs.to_f32()),
            DataType::Double => AnySizedNumber::from_f64(self.to_f64() - rhs.to_f64()),
            _ => panic!("Unsupported data type"),
        }
    }
}

impl Add for AnySizedNumber {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        match self.data_type {
            DataType::UnsignedByte => AnySizedNumber::from_u8(self.to_u8() + rhs.to_u8()),
            DataType::Byte => AnySizedNumber::from_i8(self.to_i8() + rhs.to_i8()),
            DataType::UnsignedShort => AnySizedNumber::from_u16(self.to_u16() + rhs.to_u16()),
            DataType::Short => AnySizedNumber::from_i16(self.to_i16() + rhs.to_i16()),
            DataType::UnsignedInt => AnySizedNumber::from_u32(self.to_u32() + rhs.to_u32()),
            DataType::Int => AnySizedNumber::from_i32(self.to_i32() + rhs.to_i32()),
            DataType::UnsignedLong => AnySizedNumber::from_u64(self.to_u64() + rhs.to_u64()),
            DataType::Long => AnySizedNumber::from_i64(self.to_i64() + rhs.to_i64()),
            DataType::UnsignedLongLong => AnySizedNumber::from_u128(self.to_u128() + rhs.to_u128()),
            DataType::LongLong => AnySizedNumber::from_i128(self.to_i128() + rhs.to_i128()),
            DataType::Float => AnySizedNumber::from_f32(self.to_f32() + rhs.to_f32()),
            DataType::Double => AnySizedNumber::from_f64(self.to_f64() + rhs.to_f64()),
            _ => panic!("Unsupported data type"),
        }
    }
}

impl Display for AnySizedNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.data_type {
            DataType::UnsignedByte => write!(f, "{}", self.to_u8()),
            DataType::Byte => write!(f, "{}", self.to_i8()),
            DataType::UnsignedShort => write!(f, "{}", self.to_u16()),
            DataType::Short => write!(f, "{}", self.to_i16()),
            DataType::UnsignedInt => write!(f, "{}", self.to_u32()),
            DataType::Int => write!(f, "{}", self.to_i32()),
            DataType::UnsignedLong => write!(f, "{}", self.to_u64()),
            DataType::Long => write!(f, "{}", self.to_i64()),
            DataType::UnsignedLongLong => write!(f, "{}", self.to_u128()),
            DataType::LongLong => write!(f, "{}", self.to_i128()),
            DataType::Float => write!(f, "{}", self.to_f32()),
            DataType::Double => write!(f, "{}", self.to_f64()),
            _ => panic!("Unsupported data type"),
        }
    }
}
