use super::compact::{fixSizeOfImage, maybeTruncate, removeHeaders};
use crate::protect::pe::datadir;
use crate::protect::pe::image::PeImage;
use crate::protect::pe::section;

pub fn stripDebugSections(img: &mut PeImage) -> usize {
    let count = img.numberOfSections();
    let mut keep: Vec<u16> = Vec::new();
    let mut removed = 0usize;
    let mut minRemovedPtr = u32::MAX;

    for idx in 0..count {
        if isDebug(img, idx) {
            zeroRaw(img, idx);
            let ptr = section::rawPtr(img, idx);
            if ptr > 0 && ptr < minRemovedPtr {
                minRemovedPtr = ptr;
            }
            removed += 1;
        } else {
            keep.push(idx);
        }
    }

    if removed == 0 {
        return 0;
    }
    removeHeaders(img, &keep);
    img.setNumberOfSections(keep.len() as u16);
    datadir::clearDir(img, datadir::DEBUG);
    fixSizeOfImage(img);
    maybeTruncate(img, minRemovedPtr);
    removed
}

fn isDebug(img: &PeImage, idx: u16) -> bool {
    let n = section::name(img, idx);
    if n.starts_with(".debug") || n.starts_with(".stab") || n == ".gnu_debuglink" {
        return true;
    }
    let discardable = section::characteristics(img, idx) & section::MEM_DISCARDABLE != 0;
    discardable && !n.starts_with(".reloc")
}

fn zeroRaw(img: &mut PeImage, idx: u16) {
    let start = section::rawPtr(img, idx) as usize;
    let len = section::rawSize(img, idx) as usize;
    let end = (start + len).min(img.data.len());
    if start < end {
        for b in &mut img.data[start..end] {
            *b = 0;
        }
    }
}
