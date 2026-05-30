use std::sync::atomic::{AtomicUsize, Ordering};

const NAMES: [&[u8]; 8] = [
    b".text", b".rdata", b".data", b".pdata", b".rsrc", b".reloc", b".tls", b".idata",
];

static COUNTER: AtomicUsize = AtomicUsize::new(0);

pub fn randomSectionName() -> [u8; 8] {
    let index = COUNTER.fetch_add(1, Ordering::Relaxed) % NAMES.len();
    let pick = NAMES[index];
    let mut name = [0u8; 8];
    name[..pick.len()].copy_from_slice(pick);
    name
}
