use super::bytes::{rdU32, wrU32};
use super::image::PeImage;

pub const MEM_WRITE: u32 = 0x8000_0000;
pub const MEM_DISCARDABLE: u32 = 0x0200_0000;

pub fn entryOff(img: &PeImage, idx: u16) -> usize {
    img.sectionTableOff() + idx as usize * 40
}

pub fn name(img: &PeImage, idx: u16) -> String {
    let off = entryOff(img, idx);
    let raw = &img.data[off..off + 8];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(8);
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

pub fn virtualSize(img: &PeImage, idx: u16) -> u32 {
    rdU32(&img.data, entryOff(img, idx) + 8)
}
pub fn virtualAddr(img: &PeImage, idx: u16) -> u32 {
    rdU32(&img.data, entryOff(img, idx) + 12)
}
pub fn rawSize(img: &PeImage, idx: u16) -> u32 {
    rdU32(&img.data, entryOff(img, idx) + 16)
}
pub fn rawPtr(img: &PeImage, idx: u16) -> u32 {
    rdU32(&img.data, entryOff(img, idx) + 20)
}
pub fn characteristics(img: &PeImage, idx: u16) -> u32 {
    rdU32(&img.data, entryOff(img, idx) + 36)
}
pub fn addCharacteristics(img: &mut PeImage, idx: u16, bits: u32) {
    let off = entryOff(img, idx) + 36;
    let cur = rdU32(&img.data, off);
    wrU32(&mut img.data, off, cur | bits);
}

pub fn setCharacteristics(img: &mut PeImage, idx: u16, value: u32) {
    let off = entryOff(img, idx) + 36;
    wrU32(&mut img.data, off, value);
}

pub fn rvaToFileOff(img: &PeImage, rva: u32) -> Option<usize> {
    for idx in 0..img.numberOfSections() {
        let va = virtualAddr(img, idx);
        let vsz = virtualSize(img, idx).max(rawSize(img, idx));
        if rva >= va && rva < va + vsz {
            return Some((rawPtr(img, idx) + (rva - va)) as usize);
        }
    }
    None
}

pub fn maxVirtualEnd(img: &PeImage) -> u32 {
    let mut end = 0u32;
    for idx in 0..img.numberOfSections() {
        let e = virtualAddr(img, idx) + virtualSize(img, idx);
        if e > end {
            end = e;
        }
    }
    end
}
