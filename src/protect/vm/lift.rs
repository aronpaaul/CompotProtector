use super::bc::{self, Bc};
use super::map::{aluCode, condCode, gpr, immValue, isUnary};
use super::{mba, opaque};
use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind};
use std::collections::HashMap;

pub fn lift(bytes: &[u8], ipBase: u64, perm: &[u8; 16]) -> Option<Vec<u8>> {
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
    let mut ops: Vec<Bc> = Vec::new();
    let mut ipToOff: HashMap<u64, u32> = HashMap::new();
    let mut elig = 0usize;
    for ins in &instrs {
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

fn reg(r: iced_x86::Register, perm: &[u8; 16]) -> Option<(u8, u8)> {
    let (idx, size) = gpr(r)?;
    Some((perm[idx as usize], size))
}

fn liftOne(instr: &Instruction, ops: &mut Vec<Bc>, perm: &[u8; 16]) -> Option<()> {
    let m = instr.mnemonic();
    if let Some(cond) = condCode(m) {
        wantBranch(instr)?;
        ops.push(Bc::Jcc(cond, instr.near_branch64()));
        return Some(());
    }
    if m == Mnemonic::Jmp {
        wantBranch(instr)?;
        ops.push(Bc::Jmp(instr.near_branch64()));
        return Some(());
    }
    let alu = aluCode(m)?;
    if instr.op0_kind() != OpKind::Register {
        return None;
    }
    let (dst, size) = reg(instr.op0_register(), perm)?;
    if isUnary(alu) {
        ops.push(Bc::Alu { op: alu, size, dst, kind: 0, src: 0, imm: 0 });
        return Some(());
    }
    if m == Mnemonic::Imul && instr.op_count() == 3 {
        let (src, _) = reg(instr.op1_register(), perm)?;
        if dst != src {
            ops.push(Bc::Alu { op: 0, size, dst, kind: 0, src, imm: 0 });
        }
        ops.push(Bc::Alu { op: 6, size, dst, kind: 1, src: 0, imm: immValue(instr, 2) });
        return Some(());
    }
    match instr.op1_kind() {
        OpKind::Register => {
            let (src, _) = reg(instr.op1_register(), perm)?;
            mba::liftAlu(alu, size, dst, 0, src, 0, ops);
        }
        OpKind::Immediate8 | OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64
        | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64 => {
            mba::liftAlu(alu, size, dst, 1, 0, immValue(instr, 1), ops);
        }
        _ => return None,
    }
    Some(())
}

fn wantBranch(instr: &Instruction) -> Option<()> {
    (instr.op0_kind() == OpKind::NearBranch64).then_some(())
}
