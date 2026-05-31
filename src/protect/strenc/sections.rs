use super::secname::randomSectionName;
use crate::protect::pe::image::PeImage;
use crate::protect::pe::section;

pub fn finalize(img: &mut PeImage) -> usize {
    wipePdata(img);
    let poisoned = poisonSections(img);
    randomizeNames(img);
    poisoned
}

fn poisonSections(img: &mut PeImage) -> usize {
    let base = img.sectionTableOff();
    let count = img.numberOfSections() as usize;
    let mut poisoned = 0;
    let mut salt = 0x1337_BEEFu32;
    for idx in 0..count {
        let off = base + idx * 40;
        salt = salt.wrapping_mul(2654435761).wrapping_add(0x9E37_79B9);
        img.data[off + 24..off + 28].copy_from_slice(&salt.to_le_bytes());
        img.data[off + 28..off + 32].copy_from_slice(&salt.rotate_left(13).to_le_bytes());
        img.data[off + 32..off + 34].copy_from_slice(&(salt as u16 | 0x8000).to_le_bytes());
        img.data[off + 34..off + 36].copy_from_slice(&((salt >> 11) as u16).to_le_bytes());
        poisoned += 1;
    }
    poisoned
}

fn wipePdata(img: &mut PeImage) {
    for idx in 0..img.numberOfSections() {
        if section::name(img, idx) == ".pdata" {
            let start = section::rawPtr(img, idx) as usize;
            let len = section::rawSize(img, idx) as usize;
            let end = (start + len).min(img.data.len());
            for b in &mut img.data[start..end] {
                *b = 0;
            }
        }
    }
}

fn randomizeNames(img: &mut PeImage) {
    let base = img.sectionTableOff();
    for idx in 0..img.numberOfSections() {
        let off = base + idx as usize * 40;
        let name = randomSectionName();
        img.data[off..off + 8].copy_from_slice(&name);
    }
}
