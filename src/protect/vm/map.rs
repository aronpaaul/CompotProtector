use iced_x86::{Instruction, Mnemonic, Register};

pub fn gpr(r: Register) -> Option<(u8, u8)> {
    let (idx, size) = if r.is_gpr32() {
        ((r as u32 - Register::EAX as u32) as u8, 4)
    } else if r.is_gpr64() {
        ((r as u32 - Register::RAX as u32) as u8, 8)
    } else {
        return None;
    };
    if idx == 4 {
        return None;
    }
    Some((idx, size))
}

pub fn aluCode(m: Mnemonic) -> Option<u8> {
    Some(match m {
        Mnemonic::Mov => 0,
        Mnemonic::Add => 1,
        Mnemonic::Sub => 2,
        Mnemonic::Xor => 3,
        Mnemonic::And => 4,
        Mnemonic::Or => 5,
        Mnemonic::Imul => 6,
        Mnemonic::Cmp => 7,
        Mnemonic::Shl => 8,
        Mnemonic::Shr => 9,
        Mnemonic::Sar => 10,
        Mnemonic::Test => 11,
        Mnemonic::Neg => 12,
        Mnemonic::Not => 13,
        Mnemonic::Inc => 14,
        Mnemonic::Dec => 15,
        Mnemonic::Rol => 16,
        Mnemonic::Ror => 17,
        _ => return None,
    })
}

pub fn isUnary(alu: u8) -> bool {
    matches!(alu, 12 | 13 | 14 | 15)
}

pub fn condCode(m: Mnemonic) -> Option<u8> {
    Some(match m {
        Mnemonic::Jb => 2,
        Mnemonic::Jae => 3,
        Mnemonic::Je => 4,
        Mnemonic::Jne => 5,
        Mnemonic::Jbe => 6,
        Mnemonic::Ja => 7,
        Mnemonic::Js => 8,
        Mnemonic::Jns => 9,
        Mnemonic::Jl => 12,
        Mnemonic::Jge => 13,
        Mnemonic::Jle => 14,
        Mnemonic::Jg => 15,
        _ => return None,
    })
}

pub fn immValue(instr: &Instruction, op: u32) -> i64 {
    instr.immediate(op) as i64
}
