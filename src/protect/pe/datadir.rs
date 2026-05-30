use super::bytes::{rdU32, wrU32};
use super::image::PeImage;

pub const EXPORT: usize = 0;
pub const IMPORT: usize = 1;
pub const DEBUG: usize = 6;
pub const TLS: usize = 9;
pub const IAT: usize = 12;

pub fn setDir(img: &mut PeImage, index: usize, rva: u32, size: u32) {
    let off = img.dataDirOff() + index * 8;
    wrU32(&mut img.data, off, rva);
    wrU32(&mut img.data, off + 4, size);
}

pub fn dirRva(img: &PeImage, index: usize) -> u32 {
    rdU32(&img.data, img.dataDirOff() + index * 8)
}

pub fn dirSize(img: &PeImage, index: usize) -> u32 {
    rdU32(&img.data, img.dataDirOff() + index * 8 + 4)
}

pub fn clearDir(img: &mut PeImage, index: usize) {
    let off = img.dataDirOff() + index * 8;
    wrU32(&mut img.data, off, 0);
    wrU32(&mut img.data, off + 4, 0);
}

pub fn excludedRanges(img: &PeImage) -> Vec<(u32, u32)> {
    let mut ranges = Vec::new();
    let count = rdU32(&img.data, img.optOff() + 108) as usize;
    for index in 0..count.min(16) {
        let rva = dirRva(img, index);
        let size = dirSize(img, index);
        if rva != 0 && size != 0 {
            ranges.push((rva, rva + size));
        }
    }
    ranges
}

pub fn overlapsExcluded(ranges: &[(u32, u32)], start: u32, end: u32) -> bool {
    ranges.iter().any(|&(a, b)| start < b && end > a)
}
