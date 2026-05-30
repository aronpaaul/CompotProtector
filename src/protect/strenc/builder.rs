use super::cipher;
use super::scanner::Found;
use crate::protect::pe::image::PeImage;

pub fn encryptAndBuildEntries(img: &mut PeImage, found: &[Found], seed: u64) -> (Vec<u8>, Vec<u8>) {
    let mut entries = Vec::with_capacity(found.len() * 8);
    let mut backup = Vec::new();
    for (i, f) in found.iter().enumerate() {
        let key = cipher::deriveKey(seed, cipher::TAG_STRING ^ i as u32);
        cipher::stream(&mut img.data[f.fileOff..f.fileOff + f.len], key, 0);
        backup.extend_from_slice(&img.data[f.fileOff..f.fileOff + f.len]);
        entries.extend_from_slice(&f.rva.to_le_bytes());
        entries.extend_from_slice(&(f.len as u32).to_le_bytes());
    }
    (entries, backup)
}
