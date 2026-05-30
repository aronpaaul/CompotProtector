use crate::protect::pe::image::PeImage;
use crate::protect::pe::section;

pub fn tripleCheck(img: &PeImage, minLength: usize) -> bool {
    sectionHas(img, ".rdata", minLength)
        || sectionHas(img, ".data", minLength)
        || imageHas(img, minLength)
}

fn sectionHas(img: &PeImage, name: &str, minLength: usize) -> bool {
    for idx in 0..img.numberOfSections() {
        if section::name(img, idx) == name {
            let start = section::rawPtr(img, idx) as usize;
            let len = section::rawSize(img, idx) as usize;
            let end = (start + len).min(img.data.len());
            return hasRun(&img.data[start..end], minLength);
        }
    }
    false
}

fn imageHas(img: &PeImage, minLength: usize) -> bool {
    hasRun(&img.data, minLength)
}

fn hasRun(data: &[u8], minLength: usize) -> bool {
    let mut run = 0usize;
    for &b in data {
        if (0x20..=0x7E).contains(&b) {
            run += 1;
            if run >= minLength {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}
