use super::secname::randomSectionName;
use crate::protect::pe::image::PeImage;
use crate::protect::pe::section;

pub fn finalize(img: &mut PeImage) {
    wipePdata(img);
    randomizeNames(img);
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
