const PUSH_ORIG: [u8; 24] = [
    0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x41, 0x53, 0x41, 0x52, 0x41, 0x51, 0x41, 0x50,
    0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50,
];
const POP_ORIG: [u8; 27] = [
    0x58, 0x59, 0x5A, 0x5B, 0x48, 0x83, 0xC4, 0x08, 0x5D, 0x5E, 0x5F, 0x41, 0x58, 0x41, 0x59, 0x41,
    0x5A, 0x41, 0x5B, 0x41, 0x5C, 0x41, 0x5D, 0x41, 0x5E, 0x41, 0x5F,
];

pub fn rewrite(blob: &mut [u8], slotToReg: &[u8; 16]) -> bool {
    let push = buildPush(slotToReg);
    let pop = buildPop(slotToReg);
    replace(blob, &PUSH_ORIG, &push) && replace(blob, &POP_ORIG, &pop)
}

fn buildPush(slotToReg: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    for slot in (0..16).rev() {
        pushReg(&mut out, slotToReg[slot]);
    }
    out
}

fn buildPop(slotToReg: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(27);
    for &reg in slotToReg.iter() {
        if reg == 4 {
            out.extend_from_slice(&[0x48, 0x83, 0xC4, 0x08]);
        } else {
            popReg(&mut out, reg);
        }
    }
    out
}

fn pushReg(out: &mut Vec<u8>, reg: u8) {
    if reg >= 8 {
        out.push(0x41);
        out.push(0x50 + (reg - 8));
    } else {
        out.push(0x50 + reg);
    }
}

fn popReg(out: &mut Vec<u8>, reg: u8) {
    if reg >= 8 {
        out.push(0x41);
        out.push(0x58 + (reg - 8));
    } else {
        out.push(0x58 + reg);
    }
}

fn replace(blob: &mut [u8], pattern: &[u8], with: &[u8]) -> bool {
    if let Some(pos) = blob.windows(pattern.len()).position(|w| w == pattern) {
        blob[pos..pos + with.len()].copy_from_slice(with);
        true
    } else {
        false
    }
}
