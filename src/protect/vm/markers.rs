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

pub fn findAll(img: &PeImage) -> Vec<Target> {
    let idx = match textIndex(img) {
        Some(i) => i,
        None => return Vec::new(),
    };
    let start = section::rawPtr(img, idx) as usize;
    let len = section::rawSize(img, idx) as usize;
    let va = section::virtualAddr(img, idx);
    let end = (start + len).min(img.data.len());
    let data = &img.data[start..end];
    let mut targets = Vec::new();
    let mut pos = 0usize;
    while let Some(b) = findFrom(data, &BEGIN, pos) {
        let e = match findFrom(data, &END, b + 8) {
            Some(e) => e,
            None => break,
        };
        pos = e + 8;
        if b < 2 || e < b + 10 {
            continue;
        }
        targets.push(Target {
            blockFileOff: start + b - 2,
            blockRva: va + (b - 2) as u32,
            blockLen: (e + 8) - (b - 2),
            regionFileOff: start + b + 8,
            regionRva: va + (b + 8) as u32,
            regionLen: (e - 2) - (b + 8),
        });
    }
    targets
}

fn textIndex(img: &PeImage) -> Option<u16> {
    (0..img.numberOfSections()).find(|&i| section::name(img, i) == ".text")
}

fn findFrom(haystack: &[u8], needle: &[u8; 8], from: usize) -> Option<usize> {
    if from >= haystack.len() {
        return None;
    }
    haystack[from..].windows(8).position(|w| w == needle).map(|p| p + from)
}
