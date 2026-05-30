use super::blob::{CODE_START, LOADER_OFF};
use super::markers::Target;
use crate::protect::pe::adder::addSection;
use crate::protect::pe::bytes::alignUp;
use crate::protect::pe::image::PeImage;
use crate::protect::pe::section::maxVirtualEnd;
use crate::protect::strenc::{cipher, randomSectionName};
use crate::protect::tls;
use std::io;

const VM_SECTION_FLAGS: u32 = 0xE000_0020;
const MAX_BYTECODE: usize = 0x1000;

pub struct Keys {
    pub code: u32,
    pub bytecode: u32,
}

pub fn install(img: &mut PeImage, target: &Target, blob: &[u8], bytecode: &[u8], keys: &Keys) -> io::Result<()> {
    if bytecode.len() > MAX_BYTECODE {
        return Err(io::Error::other("virtualized bytecode too large"));
    }
    tls::clearDynamicBase(img);
    let base = img.imageBase();
    let predicted = alignUp(maxVirtualEnd(img), img.sectionAlignment());

    let mut content = blob.to_vec();
    let codeLen = (content.len() - CODE_START as usize) as u32;
    cipher::encrypt(&mut content[CODE_START as usize..], keys.code);
    while content.len() % 16 != 0 {
        content.push(0x90);
    }
    let bcOff = content.len() as u32;
    let mut bc = bytecode.to_vec();
    cipher::encrypt(&mut bc, keys.bytecode);
    content.extend_from_slice(&bc);

    let va = addSection(img, &randomSectionName(), &content, VM_SECTION_FLAGS)?;
    if va != predicted {
        return Err(io::Error::other("vm section VA mismatch"));
    }
    let loaderVa = base + va as u64 + LOADER_OFF as u64;
    let bytecodeVa = base + va as u64 + bcOff as u64;
    patchBlock(img, target, base, loaderVa, bytecodeVa, bytecode.len() as u32, codeLen, keys);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn patchBlock(img: &mut PeImage, target: &Target, base: u64, loaderVa: u64, bytecodeVa: u64, bcLen: u32, codeLen: u32, keys: &Keys) {
    let off = target.blockFileOff;
    let callSiteVa = base + target.blockRva as u64;
    let rel = (loaderVa as i64 - (callSiteVa as i64 + 5)) as i32;
    img.data[off] = 0xE8;
    img.data[off + 1..off + 5].copy_from_slice(&rel.to_le_bytes());
    img.data[off + 5..off + 13].copy_from_slice(&bytecodeVa.to_le_bytes());
    img.data[off + 13..off + 17].copy_from_slice(&bcLen.to_le_bytes());
    img.data[off + 17..off + 21].copy_from_slice(&keys.bytecode.to_le_bytes());
    img.data[off + 21..off + 25].copy_from_slice(&codeLen.to_le_bytes());
    img.data[off + 25..off + 29].copy_from_slice(&keys.code.to_le_bytes());
    for byte in img.data[off + 29..off + target.blockLen].iter_mut() {
        *byte = 0x90;
    }
}
