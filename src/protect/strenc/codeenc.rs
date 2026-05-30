use super::cipher;
use crate::protect::pe::image::PeImage;
use crate::protect::pe::section;

const DATA_RW: u32 = 0xC000_0040;

pub fn region(img: &PeImage) -> Option<(u32, usize, u32)> {
    for idx in 0..img.numberOfSections() {
        if section::name(img, idx) == ".text" {
            let rva = section::virtualAddr(img, idx);
            let raw = section::rawPtr(img, idx) as usize;
            let len = section::virtualSize(img, idx).min(section::rawSize(img, idx));
            return Some((rva, raw, len));
        }
    }
    None
}

pub fn prepare(img: &mut PeImage, encryptCode: bool, key: u32) -> (u32, u32, Vec<u8>) {
    match (encryptCode, region(img)) {
        (true, Some((rva, _, len))) => (rva, len, encrypt(img, key)),
        _ => (0, 0, Vec::new()),
    }
}

pub fn encrypt(img: &mut PeImage, key: u32) -> Vec<u8> {
    if let Some((_, raw, len)) = region(img) {
        let end = (raw + len as usize).min(img.data.len());
        cipher::stream(&mut img.data[raw..end], key, 0);
        for idx in 0..img.numberOfSections() {
            if section::name(img, idx) == ".text" {
                section::setCharacteristics(img, idx, DATA_RW);
            }
        }
        return img.data[raw..end].to_vec();
    }
    Vec::new()
}

pub fn zeroText(img: &mut PeImage) {
    if let Some((_, raw, len)) = region(img) {
        let end = (raw + len as usize).min(img.data.len());
        for b in &mut img.data[raw..end] {
            *b = 0;
        }
    }
}
