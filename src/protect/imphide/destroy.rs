use crate::protect::pe::datadir::{clearDir, IAT, IMPORT};
use crate::protect::pe::image::PeImage;
use crate::protect::pe::section::{self, MEM_WRITE};

pub fn destroy(img: &mut PeImage) {
    for idx in 0..img.numberOfSections() {
        if section::name(img, idx) == ".idata" {
            zeroRaw(img, idx);
            section::addCharacteristics(img, idx, MEM_WRITE);
        }
    }
    clearDir(img, IMPORT);
    clearDir(img, IAT);
}

fn zeroRaw(img: &mut PeImage, idx: u16) {
    let start = section::rawPtr(img, idx) as usize;
    let len = section::rawSize(img, idx) as usize;
    let end = (start + len).min(img.data.len());
    for b in &mut img.data[start..end] {
        *b = 0;
    }
}
