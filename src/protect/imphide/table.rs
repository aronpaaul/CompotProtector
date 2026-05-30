use super::parse::{DllImports, FuncRef};
use crate::protect::strenc::cipher;

pub fn build(dlls: &[DllImports], key: u32) -> Vec<u8> {
    let mut t = Vec::new();
    for dll in dlls {
        pushAsciz(&mut t, &dll.name);
        t.extend_from_slice(&(dll.funcs.len() as u32).to_le_bytes());
        for func in &dll.funcs {
            match func {
                FuncRef::Name(name, slot) => {
                    t.push(0);
                    pushAsciz(&mut t, name);
                    t.extend_from_slice(&slot.to_le_bytes());
                }
                FuncRef::Ordinal(ordinal, slot) => {
                    t.push(1);
                    t.extend_from_slice(&ordinal.to_le_bytes());
                    t.extend_from_slice(&slot.to_le_bytes());
                }
            }
        }
    }
    cipher::stream(&mut t, key, 0);
    t
}

fn pushAsciz(buffer: &mut Vec<u8>, text: &str) {
    buffer.extend_from_slice(text.as_bytes());
    buffer.push(0);
}
