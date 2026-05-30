use super::ranges::nameRanges;
use crate::protect::pe::image::PeImage;
use crate::protect::pe::section::rvaToFileOff;
use crate::protect::strenc::cipher;

pub fn scramble(img: &mut PeImage, seed: u32) -> usize {
    let key = cipher::deriveKey(seed, cipher::TAG_NAMES);
    let ranges = nameRanges(img);
    let mut pos = 0u32;
    for (start, end) in &ranges {
        let len = (end - start) as usize;
        if let Some(off) = rvaToFileOff(img, *start) {
            let endOff = (off + len).min(img.data.len());
            cipher::fill(&mut img.data[off..endOff], key, pos);
        }
        pos = pos.wrapping_add(len as u32);
    }
    ranges.len()
}
