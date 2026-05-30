pub const TAG_SELF: u32 = 0x5345_4C46;
pub const TAG_CODE: u32 = 0x434F_4445;
pub const TAG_IMPORT: u32 = 0x494D_5054;
pub const TAG_STRING: u32 = 0x5354_5247;
pub const TAG_NAMES: u32 = 0x4E41_4D45;

const GOLD: u64 = 0x9E37_79B9_7F4A_7C15;

fn splitmix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^= x >> 31;
    x
}

pub fn deriveKey(seed: u64, tag: u32) -> u64 {
    splitmix64((tag as u64).wrapping_mul(GOLD) ^ seed) | 1
}

fn keystreamByte(k0: u64, k1: u64, p: u64) -> u8 {
    let ks = super::siphash::block(k0, k1, p >> 3);
    (ks >> ((p & 7) * 8)) as u8
}

pub fn stream(buf: &mut [u8], key: u64, baseOffset: u32) {
    let (k0, k1) = (key, key ^ GOLD);
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= keystreamByte(k0, k1, baseOffset.wrapping_add(i as u32) as u64);
    }
}

pub fn fill(buf: &mut [u8], key: u64, baseOffset: u32) {
    let (k0, k1) = (key, key ^ GOLD);
    for (i, b) in buf.iter_mut().enumerate() {
        *b = keystreamByte(k0, k1, baseOffset.wrapping_add(i as u32) as u64);
    }
}

pub fn encrypt(buf: &mut [u8], key: u32) {
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= (key.wrapping_add(i as u32) & 0xFF) as u8;
    }
}
