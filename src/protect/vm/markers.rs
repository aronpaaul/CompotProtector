use crate::protect::pe::image::PeImage;
use crate::protect::pe::section;

const BEGIN: [u8; 8] = [0x56, 0x4D, 0x42, 0x47, 0x4E, 0xCA, 0xFE, 0xBA];
const END: [u8; 8] = [0x56, 0x4D, 0x45, 0x4E, 0x44, 0xDE, 0xC0, 0xDE];

pub struct Target {
    pub blockFileOff: usize,
    pub blockRva: u32,
    pub blockLen: usize,
    pub regionFileOff: usize,
    pub regionRva: u32,
    pub regionLen: usize,
}

pub fn find(img: &PeImage) -> Option<Target> {
    let idx = textIndex(img)?;
    let start = section::rawPtr(img, idx) as usize;
    let len = section::rawSize(img, idx) as usize;
    let va = section::virtualAddr(img, idx);
    let end = (start + len).min(img.data.len());
    let data = &img.data[start..end];
    let b = findSeq(data, &BEGIN)?;
    let e = findSeq(data, &END)?;
    if e < b + 8 {
        return None;
    }
    let blockStart = b - 2;
    let blockEnd = e + 8;
    let regionStart = b + 8;
    let regionEnd = e - 2;
    Some(Target {
        blockFileOff: start + blockStart,
        blockRva: va + blockStart as u32,
        blockLen: blockEnd - blockStart,
        regionFileOff: start + regionStart,
        regionRva: va + regionStart as u32,
        regionLen: regionEnd - regionStart,
    })
}

fn textIndex(img: &PeImage) -> Option<u16> {
    (0..img.numberOfSections()).find(|&i| section::name(img, i) == ".text")
}

fn findSeq(haystack: &[u8], needle: &[u8; 8]) -> Option<usize> {
    haystack.windows(8).position(|w| w == needle)
}
