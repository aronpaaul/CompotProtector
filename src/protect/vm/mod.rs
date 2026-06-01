mod asm;
mod bc;
mod blob;
mod cfg;
mod emit;
mod flatten;
mod lift;
mod map;
mod markers;
mod mba;
mod mem;
mod memalu;
mod movx;
mod opaque;
mod patch;
mod poly;
mod pushpop;

use crate::protect::options::ProtectionOptions;
use crate::protect::pe::image::PeImage;
use patch::Keys;
use std::io;

pub fn apply(img: &mut PeImage, opts: &ProtectionOptions) -> io::Result<usize> {
    if !opts.virtualize {
        return Ok(0);
    }
    let targets = markers::findAll(img);
    let mut seed = poly::clockSeed();
    let mut done = 0usize;
    for target in &targets {
        seed = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(0xD1B5_4A32_D192_ED03);
        let region = img.data[target.regionFileOff..target.regionFileOff + target.regionLen].to_vec();
        let poly = poly::generate(seed);
        let bytecode = match lift::lift(&region, target.regionRva as u64, &poly.regToSlot, poly.shuffleSeed, poly.bytecodeKey) {
            Some(b) => b,
            None => continue,
        };
        let keys = Keys { code: poly.codeKey, bytecode: poly.bytecodeKey };
        patch::install(img, target, &poly.blob, &bytecode, &keys)?;
        done += 1;
    }
    Ok(done)
}
