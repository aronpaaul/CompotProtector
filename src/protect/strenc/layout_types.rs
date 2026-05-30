pub struct Inputs<'a> {
    pub stringEntries: &'a [u8],
    pub stringBackup: &'a [u8],
    pub stringCount: u32,
    pub importTable: &'a [u8],
    pub importDllCount: u32,
    pub origCallbacks: &'a [u64],
    pub hiding: bool,
    pub flags: u32,
    pub codeRva: u32,
    pub codeLen: u32,
    pub codeBlob: &'a [u8],
    pub selfKey: u32,
    pub lazyInterval: u32,
    pub masterSeed: u32,
}

pub struct Built {
    pub content: Vec<u8>,
    pub predictedVa: u32,
    pub tlsArrayVa: u64,
    pub synthDirRva: u32,
    pub synthIndexRva: u32,
    pub synthZeroRva: u32,
}

pub fn push(content: &mut Vec<u8>, items: &[u64]) {
    for v in items {
        content.extend_from_slice(&v.to_le_bytes());
    }
}

pub fn align(content: &mut Vec<u8>, n: usize) {
    while content.len() % n != 0 {
        content.push(0);
    }
}

pub fn patchJunk(content: &mut [u8], seed: u32) {
    let placeholders = [0xB16B_00B5u32, 0xCAFE_D00D, 0x5EED_1234];
    for (n, ph) in placeholders.iter().enumerate() {
        let pattern = ph.to_le_bytes();
        if let Some(pos) = content.windows(4).position(|w| w == pattern) {
            let value = super::cipher::deriveKey(seed, 0xABCD_0000 ^ n as u32);
            content[pos..pos + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
}
