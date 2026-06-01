use super::bc::Bc;
use super::emit::reg;
use super::map::isUnary;
use super::mba;
use super::mem::{emitMem, memSize, SCRATCH};
use iced_x86::{Instruction, OpKind};

pub fn lift(instr: &Instruction, ops: &mut Vec<Bc>, perm: &[u8; 16], alu: u8) -> Option<()> {
    let (o0, o1) = (instr.op0_kind(), instr.op1_kind());
    if o0 == OpKind::Memory && o1 == OpKind::Register && instr.op_count() == 2 {
        let (src, size) = reg(instr.op1_register(), perm)?;
        emitMem(ops, 1, size, SCRATCH, instr, perm)?;
        if mba::mbaable(alu) {
            mba::liftAlu(alu, size, SCRATCH, 0, src, 0, ops);
        } else {
            ops.push(Bc::Alu { op: alu, size, dst: SCRATCH, kind: 0, src, imm: 0 });
        }
        if alu != 7 && alu != 11 {
            emitMem(ops, 0, size, SCRATCH, instr, perm)?;
        }
        return Some(());
    }
    if o0 == OpKind::Memory && isUnary(alu) {
        let size = memSize(instr)?;
        emitMem(ops, 1, size, SCRATCH, instr, perm)?;
        ops.push(Bc::Alu { op: alu, size, dst: SCRATCH, kind: 0, src: 0, imm: 0 });
        return emitMem(ops, 0, size, SCRATCH, instr, perm);
    }
    None
}
