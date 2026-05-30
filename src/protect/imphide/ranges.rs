use crate::protect::pe::bytes::{rdU32, rdU64};
use crate::protect::pe::datadir::{dirRva, IMPORT};
use crate::protect::pe::image::PeImage;
use crate::protect::pe::section::rvaToFileOff;

const BY_ORDINAL: u64 = 0x8000_0000_0000_0000;

pub fn nameRanges(img: &PeImage) -> Vec<(u32, u32)> {
    let mut ranges = Vec::new();
    let mut descr = dirRva(img, IMPORT);
    if descr == 0 {
        return ranges;
    }
    while let Some(off) = rvaToFileOff(img, descr) {
        let originalFirst = rdU32(&img.data, off);
        let nameRva = rdU32(&img.data, off + 12);
        let firstThunk = rdU32(&img.data, off + 16);
        if nameRva == 0 && firstThunk == 0 {
            break;
        }
        if nameRva != 0 {
            ranges.push((nameRva, nameRva + cstrLen(img, nameRva)));
        }
        let iltRva = if originalFirst != 0 { originalFirst } else { firstThunk };
        let mut index = 0u32;
        while let Some(toff) = rvaToFileOff(img, iltRva + index * 8) {
            let value = rdU64(&img.data, toff);
            if value == 0 {
                break;
            }
            if value & BY_ORDINAL == 0 {
                let nrva = value as u32;
                ranges.push((nrva, nrva + 2 + cstrLen(img, nrva + 2)));
            }
            index += 1;
        }
        descr += 20;
    }
    ranges
}

fn cstrLen(img: &PeImage, rva: u32) -> u32 {
    match rvaToFileOff(img, rva) {
        Some(off) => {
            let mut end = off;
            while end < img.data.len() && img.data[end] != 0 {
                end += 1;
            }
            (end - off + 1) as u32
        }
        None => 1,
    }
}
