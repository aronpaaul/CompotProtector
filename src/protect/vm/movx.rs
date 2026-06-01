use super::bc::Bc;
use super::emit::reg;
use super::map::gpr;
use super::mem::emitMem;
use iced_x86::{Instruction, Mnemonic, OpKind, Register};

pub fn lift(instr: &Instruction, ops: &mut Vec<Bc>, perm: &[u8; 16], m: Mnemonic) -> Option<()> {
    let (dst, _) = reg(instr.op0_register(), perm)?;
    let signed = m != Mnemonic::Movzx;
    if instr.op1_kind() == OpKind::Memory {
        let ssize = instr.memory_size().size() as u8;
        if ssize != 1 && ssize != 2 && ssize != 4 {
            return None;
        }
        return emitMem(ops, if signed { 3 } else { 1 }, ssize, dst, instr, perm);
    }
    if instr.op1_kind() == OpKind::Register {
        let (sidx, ssize) = srcReg(instr.op1_register())?;
        let src = perm[sidx as usize];
        ops.push(Bc::Alu { op: 0, size: 8, dst, kind: 0, src, imm: 0 });
        if signed {
            let sh = 64 - ssize as i64 * 8;
            ops.push(Bc::Alu { op: 8, size: 8, dst, kind: 1, src: 0, imm: sh });
            ops.push(Bc::Alu { op: 10, size: 8, dst, kind: 1, src: 0, imm: sh });
        } else {
            let mask: i64 = if ssize == 1 { 0xff } else if ssize == 2 { 0xffff } else { 0xffff_ffff };
            ops.push(Bc::Alu { op: 4, size: 8, dst, kind: 1, src: 0, imm: mask });
        }
        return Some(());
    }
    None
}

fn srcReg(r: Register) -> Option<(u8, u8)> {
    let (idx, _) = gpr(r.full_register())?;
    Some((idx, r.size() as u8))
}
