use super::asm::{alu, emitTrans, reloc, transLen, STATE};
use super::bc::{self, Bc};
use super::cfg::{self, Block};
use super::emit::liftOne;
use super::opaque;
use iced_x86::Instruction;
use std::collections::HashMap;

pub fn tryFlatten(instrs: &[Instruction], perm: &[u8; 16], seed: u64) -> Option<Vec<u8>> {
    if instrs.len() < 3 {
        return None;
    }
    let blocks = cfg::analyze(instrs)?;
    if blocks.len() < 2 {
        return None;
    }
    for b in &blocks {
        if cfg::isFlagReader(&instrs[b.start]) {
            return None;
        }
    }
    let mut bodies: Vec<Vec<Bc>> = Vec::new();
    let mut elig = 0usize;
    for b in &blocks {
        let mut ops = Vec::new();
        for ins in &instrs[b.start..b.bodyEnd] {
            if opaque::eligible(ins.mnemonic()) {
                if elig % 2 == 0 {
                    opaque::emit(&mut ops, elig);
                }
                elig += 1;
            }
            liftOne(ins, &mut ops, perm)?;
        }
        bodies.push(ops);
    }
    assemble(&blocks, &bodies, seed)
}

fn shuffle(n: usize, seed: u64) -> Vec<usize> {
    let mut order: Vec<usize> = (0..n).collect();
    let mut s = seed | 1;
    let mut i = n;
    while i > 1 {
        i -= 1;
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let j = ((s >> 33) % (i as u64 + 1)) as usize;
        order.swap(i, j);
    }
    order
}

fn assemble(blocks: &[Block], bodies: &[Vec<Bc>], seed: u64) -> Option<Vec<u8>> {
    let n = blocks.len();
    let order: Vec<usize> = shuffle(n, seed);
    let pieceLen: Vec<usize> = (0..n).map(|k| bodies[k].len() + transLen(&blocks[k].term)).collect();
    let mut baseOp = vec![0usize; n];
    let mut cursor = 2 * n + 1;
    for &k in &order {
        baseOp[k] = cursor;
        cursor += pieceLen[k];
    }
    let mut out: Vec<Bc> = Vec::with_capacity(cursor);
    for k in 0..n {
        out.push(alu(7, STATE, 1, 0, k as i64));
        out.push(Bc::JccAbs(4, (baseOp[k] * 16) as u32));
    }
    out.push(Bc::Ret);
    for &k in &order {
        let base = baseOp[k];
        for op in &bodies[k] {
            out.push(reloc(op, (base * 16) as u32));
        }
        emitTrans(&mut out, &blocks[k].term, base + bodies[k].len());
    }
    bc::serialize(&out, &HashMap::new())
}
