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
    let target = match markers::find(img) {
        Some(t) => t,
        None => return Ok(0),
    };
    let region = img.data[target.regionFileOff..target.regionFileOff + target.regionLen].to_vec();
    let poly = poly::generate();
    let bytecode = match lift::lift(&region, target.regionRva as u64, &poly.regToSlot) {
        Some(b) => b,
        None => return Ok(0),
    };
    let keys = Keys { code: poly.codeKey, bytecode: poly.bytecodeKey };
    patch::install(img, &target, &poly.blob, &bytecode, &keys)?;
    Ok(1)
}
