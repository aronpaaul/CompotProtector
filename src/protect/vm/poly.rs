use super::blob::BLOB;
use super::pushpop::rewrite;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Poly {
    pub blob: Vec<u8>,
    pub regToSlot: [u8; 16],
    pub codeKey: u32,
    pub bytecodeKey: u32,
    pub shuffleSeed: u64,
}

pub fn generate(mut seed: u64) -> Poly {
    seed |= 1;
    let codeKey = next(&mut seed) as u32 | 1;
    let bytecodeKey = next(&mut seed) as u32 | 1;
    let shuffleSeed = next(&mut seed);
    let slotToReg = permutation(&mut seed);
    let mut regToSlot = [0u8; 16];
    for (slot, &reg) in slotToReg.iter().enumerate() {
        regToSlot[reg as usize] = slot as u8;
    }
    let mut blob = BLOB.to_vec();
    if !rewrite(&mut blob, &slotToReg) {
        blob = BLOB.to_vec();
        regToSlot = identity();
    }
    Poly { blob, regToSlot, codeKey, bytecodeKey, shuffleSeed }
}

fn permutation(seed: &mut u64) -> [u8; 16] {
    let mut p = identity();
    let mut i = 15usize;
    while i > 0 {
        let j = (next(seed) % (i as u64 + 1)) as usize;
        p.swap(i, j);
        i -= 1;
    }
    p
}

fn identity() -> [u8; 16] {
    let mut p = [0u8; 16];
    for (i, slot) in p.iter_mut().enumerate() {
        *slot = i as u8;
    }
    p
}

fn next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state >> 33
}

pub fn clockSeed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
        | 1
}
