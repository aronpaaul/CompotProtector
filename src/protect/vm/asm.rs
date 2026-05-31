use super::bc::Bc;
use super::cfg::{Term, Tgt};

pub const STATE: u8 = 23;
pub const DISPATCH: u32 = 0;

pub fn alu(op: u8, dst: u8, kind: u8, src: u8, imm: i64) -> Bc {
    Bc::Alu { op, size: 8, dst, kind, src, imm }
}

pub fn tgtLen(t: Tgt) -> usize {
    match t {
        Tgt::Blk(_) => 2,
        Tgt::Ret => 1,
    }
}

pub fn transLen(term: &Term) -> usize {
    match term {
        Term::Goto(t) => tgtLen(*t),
        Term::Cond(_, taken, fall) => 1 + tgtLen(*fall) + tgtLen(*taken),
    }
}

fn emitTgt(out: &mut Vec<Bc>, t: Tgt) {
    match t {
        Tgt::Blk(s) => {
            out.push(alu(0, STATE, 1, 0, s as i64));
            out.push(Bc::JmpAbs(DISPATCH));
        }
        Tgt::Ret => out.push(Bc::Ret),
    }
}

pub fn emitTrans(out: &mut Vec<Bc>, term: &Term, start: usize) {
    match term {
        Term::Goto(t) => emitTgt(out, *t),
        Term::Cond(c, taken, fall) => {
            let takenOff = ((start + 1 + tgtLen(*fall)) * 16) as u32;
            out.push(Bc::JccAbs(*c, takenOff));
            emitTgt(out, *fall);
            emitTgt(out, *taken);
        }
    }
}

pub fn reloc(op: &Bc, delta: u32) -> Bc {
    match op {
        Bc::JccAbs(c, off) => Bc::JccAbs(*c, off + delta),
        other => *other,
    }
}
