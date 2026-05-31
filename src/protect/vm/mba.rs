use super::bc::Bc;

const SCRATCH: u8 = 16;
const LEVEL: u32 = 3;

struct Temps {
    next: u8,
}

impl Temps {
    fn new() -> Self {
        Temps { next: SCRATCH }
    }
    fn alloc(&mut self) -> u8 {
        let r = self.next;
        self.next += 1;
        r
    }
}

fn emitOp(op: u8, size: u8, dst: u8, kind: u8, src: u8, imm: i64, ops: &mut Vec<Bc>) {
    ops.push(Bc::Alu { op, size, dst, kind, src, imm });
}

pub fn mbaable(op: u8) -> bool {
    matches!(op, 1 | 3 | 4 | 5)
}

fn expand(op: u8, a: u8, b: u8, level: u32, size: u8, t: &mut Temps, ops: &mut Vec<Bc>) -> u8 {
    if level == 0 || !mbaable(op) {
        let r = t.alloc();
        emitOp(0, size, r, 0, a, 0, ops);
        emitOp(op, size, r, 0, b, 0, ops);
        return r;
    }
    let mark = t.next;
    let res = match op {
        1 => {
            let x = expand(3, a, b, level - 1, size, t, ops);
            let y = expand(4, a, b, level - 1, size, t, ops);
            emitOp(1, size, y, 0, y, 0, ops);
            emitOp(1, size, x, 0, y, 0, ops);
            x
        }
        3 => {
            let o = expand(5, a, b, level - 1, size, t, ops);
            let n = expand(4, a, b, level - 1, size, t, ops);
            emitOp(2, size, o, 0, n, 0, ops);
            o
        }
        4 => {
            let o = expand(5, a, b, level - 1, size, t, ops);
            let x = expand(3, a, b, level - 1, size, t, ops);
            emitOp(2, size, o, 0, x, 0, ops);
            o
        }
        _ => {
            let n = expand(4, a, b, level - 1, size, t, ops);
            let x = expand(3, a, b, level - 1, size, t, ops);
            emitOp(1, size, n, 0, x, 0, ops);
            n
        }
    };
    t.next = mark + 1;
    res
}

pub fn liftAlu(op: u8, size: u8, dst: u8, kind: u8, src: u8, imm: i64, ops: &mut Vec<Bc>) {
    if !mbaable(op) {
        emitOp(op, size, dst, kind, src, imm, ops);
        return;
    }
    let mut t = Temps::new();
    let a = t.alloc();
    emitOp(0, size, a, 0, dst, 0, ops);
    let b = t.alloc();
    emitOp(0, size, b, kind, src, imm, ops);
    let res = expand(op, a, b, LEVEL, size, &mut t, ops);
    emitOp(0, size, dst, 0, res, 0, ops);
    if op == 1 {
        emitOp(0, size, SCRATCH + 2, 0, a, 0, ops);
        emitOp(1, size, SCRATCH + 2, 0, b, 0, ops);
    } else {
        emitOp(11, size, dst, 0, dst, 0, ops);
    }
}
