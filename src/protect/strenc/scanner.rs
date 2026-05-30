use crate::protect::pe::datadir::{excludedRanges, overlapsExcluded};
use crate::protect::pe::image::PeImage;
use crate::protect::pe::section;

pub struct Found {
    pub rva: u32,
    pub fileOff: usize,
    pub len: usize,
}

const MAX_STRINGS: usize = 40_000;

pub fn scan(img: &PeImage, minLength: usize) -> Vec<Found> {
    let mut excluded = excludedRanges(img);
    excluded.extend(crate::protect::imphide::nameRanges(img));
    let mut out = Vec::new();
    for idx in 0..img.numberOfSections() {
        let name = section::name(img, idx);
        if name != ".rdata" && name != ".data" && name != ".xdata" {
            continue;
        }
        scanSection(img, idx, minLength, &excluded, &mut out);
        if out.len() >= MAX_STRINGS {
            break;
        }
    }
    out
}

fn scanSection(
    img: &PeImage,
    idx: u16,
    minLength: usize,
    excluded: &[(u32, u32)],
    out: &mut Vec<Found>,
) {
    let start = section::rawPtr(img, idx) as usize;
    let len = section::rawSize(img, idx) as usize;
    let va = section::virtualAddr(img, idx);
    let end = (start + len).min(img.data.len());
    let data = &img.data;
    let mut pos = start;
    while pos < end && out.len() < MAX_STRINGS {
        if !printable(data[pos]) {
            pos += 1;
            continue;
        }
        let runStart = pos;
        while pos < end && printable(data[pos]) {
            pos += 1;
        }
        let runLen = pos - runStart;
        let terminated = pos < end && data[pos] == 0;
        if terminated && runLen >= minLength {
            let rva = va + (runStart - start) as u32;
            if !overlapsExcluded(excluded, rva, rva + runLen as u32) {
                out.push(Found { rva, fileOff: runStart, len: runLen });
            }
        }
        pos += 1;
    }
}

fn printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == 0x09 || b == 0x0A || b == 0x0D
}
