use std::collections::HashMap;

#[derive(Clone, Copy)]
pub enum Bc {
    Alu { op: u8, size: u8, dst: u8, kind: u8, src: u8, imm: i64 },
    Mem { mode: u8, size: u8, reg: u8, base: u8, index: u8, scale: u8, disp: i64 },
    Cmov { cond: u8, dst: u8, src: u8 },
    Jmp(u64),
    Jcc(u8, u64),
    JmpAbs(u32),
    JccAbs(u8, u32),
    Ret,
}

pub fn keyAt(base: u32, idx: u32) -> u32 {
    let mut x = base ^ idx.wrapping_mul(0x9E37_79B1);
    x ^= x >> 15;
    x = x.wrapping_mul(0x85EB_CA77);
    x ^= x >> 13;
    x = x.wrapping_mul(0xC2B2_AE3D);
    x ^= x >> 16;
    x
}

pub fn serialize(ops: &[Bc], ipToOff: &HashMap<u64, u32>, base: u32) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(ops.len() * 16);
    for (idx, op) in ops.iter().enumerate() {
        let mut w = [0u8; 16];
        match op {
            Bc::Alu { op, size, dst, kind, src, imm } => {
                w[0] = 0x10;
                w[1] = *op;
                w[2] = *size;
                w[3] = *dst;
                w[4] = *kind;
                w[5] = *src;
                w[8..].copy_from_slice(&imm.to_le_bytes());
            }
            Bc::Mem { mode, size, reg, base, index, scale, disp } => {
                w[0] = 0x40;
                w[1] = *mode;
                w[2] = *size;
                w[3] = *reg;
                w[4] = *base;
                w[5] = *index;
                w[6] = *scale;
                w[8..].copy_from_slice(&disp.to_le_bytes());
            }
            Bc::Cmov { cond, dst, src } => {
                w[0] = 0x41;
                w[1] = *cond;
                w[3] = *dst;
                w[5] = *src;
            }
            Bc::Jmp(ip) => {
                w[0] = 0x20;
                w[8..12].copy_from_slice(&ipToOff.get(ip)?.to_le_bytes());
            }
            Bc::Jcc(cond, ip) => {
                w[0] = 0x21;
                w[1] = *cond;
                w[8..12].copy_from_slice(&ipToOff.get(ip)?.to_le_bytes());
            }
            Bc::JmpAbs(off) => {
                w[0] = 0x20;
                w[8..12].copy_from_slice(&off.to_le_bytes());
            }
            Bc::JccAbs(cond, off) => {
                w[0] = 0x21;
                w[1] = *cond;
                w[8..12].copy_from_slice(&off.to_le_bytes());
            }
            Bc::Ret => w[0] = 0x30,
        }
        for q in 0..4u32 {
            let b = keyAt(base, idx as u32 * 4 + q).to_le_bytes();
            let o = (q * 4) as usize;
            w[o] ^= b[0];
            w[o + 1] ^= b[1];
            w[o + 2] ^= b[2];
            w[o + 3] ^= b[3];
        }
        out.extend_from_slice(&w);
    }
    Some(out)
}
