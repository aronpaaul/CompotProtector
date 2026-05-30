use crate::protect::pe::bytes::{rdU16, rdU64, wrU16, wrU64};
use crate::protect::pe::datadir::{dirRva, setDir, TLS};
use crate::protect::pe::image::PeImage;
use crate::protect::pe::section::rvaToFileOff;

pub fn clearDynamicBase(img: &mut PeImage) {
    let off = img.optOff() + 70;
    let cur = rdU16(&img.data, off);
    wrU16(&mut img.data, off, cur & !0x0060);
}

pub fn originalCallbacks(img: &PeImage) -> Vec<u64> {
    let mut out = Vec::new();
    let tlsRva = dirRva(img, TLS);
    if tlsRva == 0 {
        return out;
    }
    let dirOff = match rvaToFileOff(img, tlsRva) {
        Some(o) => o,
        None => return out,
    };
    let cbVa = rdU64(&img.data, dirOff + 24);
    if cbVa == 0 {
        return out;
    }
    let cbRva = (cbVa - img.imageBase()) as u32;
    let mut off = match rvaToFileOff(img, cbRva) {
        Some(o) => o,
        None => return out,
    };
    loop {
        let entry = rdU64(&img.data, off);
        if entry == 0 {
            break;
        }
        out.push(entry);
        off += 8;
    }
    out
}

pub fn installCallbacks(img: &mut PeImage, arrayVa: u64, synthDirRva: u32, indexRva: u32, zeroRva: u32) {
    let tlsRva = dirRva(img, TLS);
    if tlsRva != 0 {
        let off = rvaToFileOff(img, tlsRva).unwrap();
        wrU64(&mut img.data, off + 24, arrayVa);
        return;
    }
    let base = img.imageBase();
    let off = rvaToFileOff(img, synthDirRva).unwrap();
    wrU64(&mut img.data, off, base + zeroRva as u64);
    wrU64(&mut img.data, off + 8, base + zeroRva as u64);
    wrU64(&mut img.data, off + 16, base + indexRva as u64);
    wrU64(&mut img.data, off + 24, arrayVa);
    setDir(img, TLS, synthDirRva, 40);
}
