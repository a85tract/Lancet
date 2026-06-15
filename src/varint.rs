use std::io::{self, Read, Write};

pub fn write_u64(mut value: u64, out: &mut impl Write) -> io::Result<()> {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.write_all(&[byte])?;
        if value == 0 {
            return Ok(());
        }
    }
}

pub fn read_u64(input: &mut impl Read) -> io::Result<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for _ in 0..10 {
        let mut byte = [0u8; 1];
        input.read_exact(&mut byte)?;
        result |= ((byte[0] & 0x7f) as u64) << shift;
        if (byte[0] & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "varint too long",
    ))
}
