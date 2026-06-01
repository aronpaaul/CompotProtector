use super::bc::Bc;
use super::emit::reg;
use super::map::{gpr, immValue};
use super::{mba, memalu};
use iced_x86::{Instruction, Mnemonic, OpKind, Register};

pub(super) const SCRATCH: u8 = 24;

pub fn lea(instr: &Instruction, ops: &mut Vec<Bc>, perm: &[u8; 16]) -> Option<()> {
    let (dst, size) = reg(instr.op0_register(), perm)?;
    emitMem(ops, 2, size, dst, instr, perm)
}

pub fn lift(instr: &Instruction, ops: &mut Vec<Bc>, perm: &[u8; 16], alu: u8) -> Option<()> {
    let m = instr.mnemonic();
    let (o0, o1) = (instr.op0_kind(), instr.op1_kind());
    if m == Mnemonic::Mov {
        if o0 == OpKind::Register && o1 == OpKind::Memory {
            let (dst, size) = reg(instr.op0_register(), perm)?;
            return emitMem(ops, 1, size, dst, instr, perm);
        }
        if o0 == OpKind::Memory && o1 == OpKind::Register {
            let (src, size) = reg(instr.op1_register(), perm)?;
            return emitMem(ops, 0, size, src, instr, perm);
        }
        if o0 == OpKind::Memory && isImm(o1) {
            let size = memSize(instr)?;
            ops.push(Bc::Alu { op: 0, size, dst: SCRATCH, kind: 1, src: 0, imm: immValue(instr, 1) });
            return emitMem(ops, 0, size, SCRATCH, instr, perm);
        }
        return None;
    }
    if o0 == OpKind::Register && o1 == OpKind::Memory && instr.op_count() == 2 {
        let (dst, size) = reg(instr.op0_register(), perm)?;
        emitMem(ops, 1, size, SCRATCH, instr, perm)?;
        if mba::mbaable(alu) {
            mba::liftAlu(alu, size, dst, 0, SCRATCH, 0, ops);
        } else {
            ops.push(Bc::Alu { op: alu, size, dst, kind: 0, src: SCRATCH, imm: 0 });
        }
        return Some(());
    }
    memalu::lift(instr, ops, perm, alu)
}

pub(super) fn emitMem(ops: &mut Vec<Bc>, mode: u8, size: u8, dataReg: u8, instr: &Instruction, perm: &[u8; 16]) -> Option<()> {
    if instr.is_ip_rel_memory_operand() {
        return None;
    }
    let base = memReg(instr.memory_base(), perm)?;
    let index = memReg(instr.memory_index(), perm)?;
    let scale = instr.memory_index_scale() as u8;
    let disp = instr.memory_displacement64() as i64;
    ops.push(Bc::Mem { mode, size, reg: dataReg, base, index, scale, disp });
    Some(())
}

fn memReg(r: Register, perm: &[u8; 16]) -> Option<u8> {
    if r == Register::None {
        return Some(0xFF);
    }
    let (idx, _) = gpr(r)?;
    Some(perm[idx as usize])
}

fn isImm(k: OpKind) -> bool {
    matches!(
        k,
        OpKind::Immediate8
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate32to64
            | OpKind::Immediate64
    )
}

pub(super) fn memSize(instr: &Instruction) -> Option<u8> {
    let s = instr.memory_size().size();
    if s == 1 || s == 2 || s == 4 || s == 8 {
        Some(s as u8)
    } else {
        None
    }
}
