use super::map::condCode;
use iced_x86::{Instruction, Mnemonic, OpKind};
use std::collections::{BTreeSet, HashMap};

#[derive(Clone, Copy)]
pub enum Tgt {
    Blk(usize),
    Ret,
}

pub enum Term {
    Goto(Tgt),
    Cond(u8, Tgt, Tgt),
}

pub struct Block {
    pub start: usize,
    pub bodyEnd: usize,
    pub term: Term,
}

fn isBranch(ins: &Instruction) -> bool {
    (ins.mnemonic() == Mnemonic::Jmp || condCode(ins.mnemonic()).is_some())
        && ins.op0_kind() == OpKind::NearBranch64
}

pub fn isFlagReader(ins: &Instruction) -> bool {
    condCode(ins.mnemonic()).is_some()
}

pub fn analyze(instrs: &[Instruction]) -> Option<Vec<Block>> {
    let ipIndex: HashMap<u64, usize> = instrs.iter().enumerate().map(|(i, x)| (x.ip(), i)).collect();
    let mut leaders: BTreeSet<usize> = BTreeSet::new();
    leaders.insert(0);
    for (i, ins) in instrs.iter().enumerate() {
        if isBranch(ins) {
            leaders.insert(*ipIndex.get(&ins.near_branch64())?);
            if i + 1 < instrs.len() {
                leaders.insert(i + 1);
            }
        }
    }
    let starts: Vec<usize> = leaders.iter().copied().collect();
    let idOf: HashMap<usize, usize> = starts.iter().enumerate().map(|(id, &s)| (s, id)).collect();
    let mut blocks = Vec::new();
    for (bi, &s) in starts.iter().enumerate() {
        let end = if bi + 1 < starts.len() { starts[bi + 1] } else { instrs.len() };
        let last = &instrs[end - 1];
        let next = if end >= instrs.len() { Tgt::Ret } else { Tgt::Blk(idOf[&end]) };
        let (bodyEnd, term) = if last.mnemonic() == Mnemonic::Jmp && isBranch(last) {
            (end - 1, Term::Goto(blkTgt(last, &ipIndex, &idOf)?))
        } else if isBranch(last) {
            let c = condCode(last.mnemonic())?;
            (end - 1, Term::Cond(c, blkTgt(last, &ipIndex, &idOf)?, next))
        } else {
            (end, Term::Goto(next))
        };
        blocks.push(Block { start: s, bodyEnd, term });
    }
    Some(blocks)
}

fn blkTgt(ins: &Instruction, ipIndex: &HashMap<u64, usize>, idOf: &HashMap<usize, usize>) -> Option<Tgt> {
    let ti = *ipIndex.get(&ins.near_branch64())?;
    Some(Tgt::Blk(*idOf.get(&ti)?))
}
