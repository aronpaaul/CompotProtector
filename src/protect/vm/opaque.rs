use super::bc::Bc;
use iced_x86::Mnemonic;

const X: u8 = 0;
const T: u8 = 16;
const U: u8 = 17;
const J: u8 = 18;

pub fn eligible(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Cmp
            | Mnemonic::Xor
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Test
            | Mnemonic::Neg
            | Mnemonic::Shl
            | Mnemonic::Shr
            | Mnemonic::Sar
    )
}

fn alu(ops: &mut Vec<Bc>, op: u8, dst: u8, kind: u8, src: u8, imm: i64) {
    ops.push(Bc::Alu { op, size: 8, dst, kind, src, imm });
}

pub fn emit(ops: &mut Vec<Bc>, salt: usize) {
    alu(ops, 0, T, 0, X, 0);
    alu(ops, 0, U, 0, X, 0);
    alu(ops, 6, U, 0, T, 0);
    alu(ops, 2, U, 0, T, 0);
    alu(ops, 4, U, 1, 0, 1);
    let jpos = ops.len();
    ops.push(Bc::JccAbs(4, 0));
    alu(ops, 0, J, 1, 0, ((salt as i64) << 8) | 0xCD);
    alu(ops, 1, J, 0, X, 0);
    alu(ops, 3, J, 0, T, 0);
    let target = (ops.len() * 16) as u32;
    ops[jpos] = Bc::JccAbs(4, target);
}
