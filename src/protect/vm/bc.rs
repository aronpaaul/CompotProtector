use std::collections::HashMap;

pub enum Bc {
    Alu { op: u8, size: u8, dst: u8, kind: u8, src: u8, imm: i64 },
    Jmp(u64),
    Jcc(u8, u64),
    Ret,
}

pub fn serialize(ops: &[Bc], ipToOff: &HashMap<u64, u32>) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(ops.len() * 16);
    for op in ops {
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
            Bc::Jmp(ip) => {
                w[0] = 0x20;
                w[8..12].copy_from_slice(&ipToOff.get(ip)?.to_le_bytes());
            }
            Bc::Jcc(cond, ip) => {
                w[0] = 0x21;
                w[1] = *cond;
                w[8..12].copy_from_slice(&ipToOff.get(ip)?.to_le_bytes());
            }
            Bc::Ret => w[0] = 0x30,
        }
        out.extend_from_slice(&w);
    }
    Some(out)
}
