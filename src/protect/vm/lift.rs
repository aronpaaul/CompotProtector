use super::bc::{self, Bc};
use super::emit::liftOne;
use super::{flatten, opaque};
use iced_x86::{Decoder, DecoderOptions, Instruction};
use std::collections::HashMap;

pub fn lift(bytes: &[u8], ipBase: u64, perm: &[u8; 16], seed: u64) -> Option<Vec<u8>> {
    let instrs = decodeAll(bytes, ipBase)?;
    if let Some(flat) = flatten::tryFlatten(&instrs, perm, seed) {
        return Some(flat);
    }
    linear(&instrs, perm)
}

fn decodeAll(bytes: &[u8], ipBase: u64) -> Option<Vec<Instruction>> {
    let mut dec = Decoder::with_ip(64, bytes, ipBase, DecoderOptions::NONE);
    let mut instrs: Vec<Instruction> = Vec::new();
    let mut instr = Instruction::default();
    while dec.can_decode() {
        dec.decode_out(&mut instr);
        if instr.is_invalid() {
            return None;
        }
        instrs.push(instr);
    }
    Some(instrs)
}

fn linear(instrs: &[Instruction], perm: &[u8; 16]) -> Option<Vec<u8>> {
    let mut ops: Vec<Bc> = Vec::new();
    let mut ipToOff: HashMap<u64, u32> = HashMap::new();
    let mut elig = 0usize;
    for ins in instrs {
        if opaque::eligible(ins.mnemonic()) {
            if elig % 2 == 0 {
                opaque::emit(&mut ops, elig);
            }
            elig += 1;
        }
        ipToOff.insert(ins.ip(), (ops.len() * 16) as u32);
        liftOne(ins, &mut ops, perm)?;
    }
    ops.push(Bc::Ret);
    bc::serialize(&ops, &ipToOff)
}
