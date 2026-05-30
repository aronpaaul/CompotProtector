use crate::protect::pe::datadir::setDir;
use crate::protect::pe::image::PeImage;

const POISON_DIRS: [usize; 5] = [0, 3, 6, 7, 8];
const BOGUS_RVA: u32 = 0x0000_0000;
const BOGUS_SIZE: u32 = 0x0000_0000;

pub fn apply(img: &mut PeImage) -> usize {
    for &dir in &POISON_DIRS {
        setDir(img, dir, BOGUS_RVA, BOGUS_SIZE);
    }
    POISON_DIRS.len()
}
