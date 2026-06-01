use super::bc::Bc;
use super::map::{aluCode, cmovCode, condCode, gpr, immValue, isUnary};
use super::{mba, mem, movx};
use iced_x86::{Instruction, Mnemonic, OpKind, Register};

pub fn liftOne(instr: &Instruction, ops: &mut Vec<Bc>, perm: &[u8; 16]) -> Option<()> {
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
    if m == Mnemonic::Lea {
        return mem::lea(instr, ops, perm);
    }
    if let Some(cond) = cmovCode(m) {
        let (dst, size) = reg(instr.op0_register(), perm)?;
        let (src, _) = reg(instr.op1_register(), perm)?;
        ops.push(Bc::Cmov { cond, size, dst, src });
        return Some(());
    }
    if matches!(m, Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd) {
        return movx::lift(instr, ops, perm, m);
    }
    if m == Mnemonic::Xchg {
        let (a, size) = reg(instr.op0_register(), perm)?;
        let (b, _) = reg(instr.op1_register(), perm)?;
        ops.push(Bc::Alu { op: 0, size, dst: 24, kind: 0, src: a, imm: 0 });
        ops.push(Bc::Alu { op: 0, size, dst: a, kind: 0, src: b, imm: 0 });
        ops.push(Bc::Alu { op: 0, size, dst: b, kind: 0, src: 24, imm: 0 });
        return Some(());
    }
    let alu = aluCode(m)?;
    if instr.op0_kind() == OpKind::Memory || instr.op1_kind() == OpKind::Memory {
        return mem::lift(instr, ops, perm, alu);
    }
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

pub(super) fn reg(r: Register, perm: &[u8; 16]) -> Option<(u8, u8)> {
    let (idx, size) = gpr(r)?;
    Some((perm[idx as usize], size))
}

fn wantBranch(instr: &Instruction) -> Option<()> {
    (instr.op0_kind() == OpKind::NearBranch64).then_some(())
}
