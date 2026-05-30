use crate::protect::pe::bytes::alignUp;
use crate::protect::pe::image::PeImage;
use crate::protect::pe::section::{self, maxVirtualEnd};

pub fn removeHeaders(img: &mut PeImage, keep: &[u16]) {
    let base = img.sectionTableOff();
    let mut buffer: Vec<u8> = Vec::with_capacity(keep.len() * 40);
    for &idx in keep {
        let off = base + idx as usize * 40;
        buffer.extend_from_slice(&img.data[off..off + 40]);
    }
    let total = img.numberOfSections() as usize * 40;
    img.data[base..base + buffer.len()].copy_from_slice(&buffer);
    for b in &mut img.data[base + buffer.len()..base + total] {
        *b = 0;
    }
}

pub fn fixSizeOfImage(img: &mut PeImage) {
    let secAlign = img.sectionAlignment();
    let end = alignUp(maxVirtualEnd(img), secAlign);
    img.setSizeOfImage(end);
}

pub fn maybeTruncate(img: &mut PeImage, minRemovedPtr: u32) {
    if minRemovedPtr == u32::MAX || minRemovedPtr as usize > img.data.len() {
        return;
    }
    for idx in 0..img.numberOfSections() {
        let end = section::rawPtr(img, idx) + section::rawSize(img, idx);
        if end > minRemovedPtr {
            return;
        }
    }
    img.data.truncate(minRemovedPtr as usize);
}
