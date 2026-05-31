pub static STUB: &[u8] = include_bytes!("cprot_stub.bin");

pub const PARAMS_OFF: usize = 0x10e0;
pub const PARAMS_LEN: usize = 196;
pub const TLS_CALLBACK_OFF: u32 = 0x0dd4;
pub const ENC_END: usize = 0x0dd4;

pub const FLAG_REENCRYPT_STRINGS: u32 = 1;
pub const FLAG_HIDE_IMPORTS: u32 = 2;
pub const FLAG_REENCRYPT_IMPORTS: u32 = 4;
pub const FLAG_ANTI_DEBUG: u32 = 8;
pub const FLAG_LAZY: u32 = 16;
pub const FLAG_ZERO_STRINGS: u32 = 32;
pub const FLAG_ANTI_VM: u32 = 64;
