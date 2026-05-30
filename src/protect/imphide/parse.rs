use crate::protect::pe::bytes::{rdU32, rdU64};
use crate::protect::pe::datadir::{dirRva, IMPORT};
use crate::protect::pe::image::PeImage;
use crate::protect::pe::section::rvaToFileOff;

const BY_ORDINAL: u64 = 0x8000_0000_0000_0000;

pub enum FuncRef {
    Name(String, u32),
    Ordinal(u16, u32),
}

pub struct DllImports {
    pub name: String,
    pub funcs: Vec<FuncRef>,
}

pub fn parse(img: &PeImage) -> Vec<DllImports> {
    let mut out = Vec::new();
    let mut descr = dirRva(img, IMPORT);
    if descr == 0 {
        return out;
    }
    while let Some(off) = rvaToFileOff(img, descr) {
        let originalFirst = rdU32(&img.data, off);
        let nameRva = rdU32(&img.data, off + 12);
        let firstThunk = rdU32(&img.data, off + 16);
        if nameRva == 0 && firstThunk == 0 {
            break;
        }
        let iltRva = if originalFirst != 0 { originalFirst } else { firstThunk };
        let dllName = nameAt(img, nameRva);
        let funcs = thunks(img, iltRva, firstThunk);
        if !dllName.is_empty() {
            out.push(DllImports { name: dllName, funcs });
        }
        descr += 20;
    }
    out
}

fn thunks(img: &PeImage, iltRva: u32, firstThunk: u32) -> Vec<FuncRef> {
    let mut funcs = Vec::new();
    let mut index = 0u32;
    while let Some(off) = rvaToFileOff(img, iltRva + index * 8) {
        let value = rdU64(&img.data, off);
        if value == 0 {
            break;
        }
        let slot = firstThunk + index * 8;
        if value & BY_ORDINAL != 0 {
            funcs.push(FuncRef::Ordinal((value & 0xFFFF) as u16, slot));
        } else if let Some(nameOff) = rvaToFileOff(img, value as u32 + 2) {
            funcs.push(FuncRef::Name(nameAt2(&img.data, nameOff), slot));
        }
        index += 1;
    }
    funcs
}

fn nameAt(img: &PeImage, rva: u32) -> String {
    rvaToFileOff(img, rva).map(|o| nameAt2(&img.data, o)).unwrap_or_default()
}

fn nameAt2(data: &[u8], off: usize) -> String {
    let mut end = off;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[off..end]).into_owned()
}
