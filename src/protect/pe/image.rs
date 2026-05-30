use super::bytes::{rdU16, rdU32, rdU64, wrU16, wrU32};
use std::io;
use std::path::Path;

pub struct PeImage {
    pub data: Vec<u8>,
    pub peOff: usize,
}

impl PeImage {
    pub fn load(path: &Path) -> io::Result<Self> {
        let data = std::fs::read(path)?;
        if data.len() < 0x40 || rdU16(&data, 0) != 0x5A4D {
            return Err(invalid("not an MZ executable"));
        }
        let peOff = rdU32(&data, 0x3C) as usize;
        if peOff + 0x108 > data.len() || rdU32(&data, peOff) != 0x00004550 {
            return Err(invalid("missing PE signature"));
        }
        if rdU16(&data, peOff + 24) != 0x20B {
            return Err(invalid("only 64-bit (PE32+) images are supported"));
        }
        Ok(Self { data, peOff })
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        std::fs::write(path, &self.data)
    }

    pub fn optOff(&self) -> usize {
        self.peOff + 24
    }
    pub fn sizeOfOptionalHeader(&self) -> usize {
        rdU16(&self.data, self.peOff + 20) as usize
    }
    pub fn sectionTableOff(&self) -> usize {
        self.optOff() + self.sizeOfOptionalHeader()
    }
    pub fn numberOfSections(&self) -> u16 {
        rdU16(&self.data, self.peOff + 6)
    }
    pub fn setNumberOfSections(&mut self, n: u16) {
        wrU16(&mut self.data, self.peOff + 6, n);
    }
    pub fn entryRva(&self) -> u32 {
        rdU32(&self.data, self.optOff() + 16)
    }
    pub fn setEntryRva(&mut self, rva: u32) {
        let off = self.optOff() + 16;
        wrU32(&mut self.data, off, rva);
    }
    pub fn imageBase(&self) -> u64 {
        rdU64(&self.data, self.optOff() + 24)
    }
    pub fn sectionAlignment(&self) -> u32 {
        rdU32(&self.data, self.optOff() + 32)
    }
    pub fn fileAlignment(&self) -> u32 {
        rdU32(&self.data, self.optOff() + 36)
    }
    pub fn sizeOfImage(&self) -> u32 {
        rdU32(&self.data, self.optOff() + 56)
    }
    pub fn setSizeOfImage(&mut self, v: u32) {
        let off = self.optOff() + 56;
        wrU32(&mut self.data, off, v);
    }
    pub fn sizeOfHeaders(&self) -> u32 {
        rdU32(&self.data, self.optOff() + 60)
    }
    pub fn dataDirOff(&self) -> usize {
        self.optOff() + 112
    }
    pub fn clearSymbols(&mut self) {
        wrU32(&mut self.data, self.peOff + 12, 0);
        wrU32(&mut self.data, self.peOff + 16, 0);
    }
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}
