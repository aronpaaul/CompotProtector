use crate::protect::pe::image::PeImage;
use crate::protect::pe::section::{self, MEM_WRITE};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn generate(salt: u32) -> u32 {
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(0x00C0_FFEE);
    (clock ^ salt) | 1
}

pub fn markWritable(img: &mut PeImage) {
    for idx in 0..img.numberOfSections() {
        let name = section::name(img, idx);
        if name == ".rdata" || name == ".data" || name == ".xdata" {
            section::addCharacteristics(img, idx, MEM_WRITE);
        }
    }
}
