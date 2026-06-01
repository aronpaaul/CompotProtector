use crate::protect::pe::adder::addSection;
use crate::protect::pe::image::PeImage;

const FLAGS: u32 = 0x4000_0040;
const NAME: &[u8; 8] = b".compot\0";
const STAMP: u32 = 0x5452_5043;

pub fn apply(img: &mut PeImage, id: u64) {
    let _ = addSection(img, NAME, &blob(id), FLAGS);
    stampTimestamp(img);
    img.data.extend_from_slice(&overlay(id));
}

fn blob(id: u64) -> Vec<u8> {
    let mut b = Vec::new();
    line(&mut b, b"CompotProtector");
    line(&mut b, b"== Protected by CompotProtector ==");
    line(&mut b, b"https://github.com/aronpaaul/CompotProtector");
    line(&mut b, format!("watermark-id: {id:016X}").as_bytes());
    line(&mut b, b"packed with CompotProtector, do not crack");
    b.extend_from_slice(b"CPRT\x01\x00\x00\x00");
    while b.len() % 16 != 0 {
        b.push(0);
    }
    b
}

fn overlay(id: u64) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(b"\n--- CompotProtector watermark ---\n");
    o.extend_from_slice(format!("build-id={id:016X}\n").as_bytes());
    o.extend_from_slice(b"CPRT-OVERLAY\0");
    o
}

fn stampTimestamp(img: &mut PeImage) {
    let pe = u32::from_le_bytes([img.data[0x3c], img.data[0x3d], img.data[0x3e], img.data[0x3f]]) as usize;
    if pe + 12 <= img.data.len() {
        img.data[pe + 8..pe + 12].copy_from_slice(&STAMP.to_le_bytes());
    }
}

fn line(out: &mut Vec<u8>, text: &[u8]) {
    out.extend_from_slice(text);
    out.push(0);
}
