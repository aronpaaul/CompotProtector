pub static BLOB: &[u8] = include_bytes!("vm_blob.bin");

pub const LOADER_OFF: u32 = 0;
pub const CODE_START: u32 = 0x60;
