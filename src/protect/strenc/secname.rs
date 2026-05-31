use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static SEED: AtomicU64 = AtomicU64::new(0);

pub fn randomSectionName() -> [u8; 8] {
    let mut state = SEED.load(Ordering::Relaxed);
    if state == 0 {
        state = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            | 1;
    }
    let mut name = [0u8; 8];
    name[0] = b'.';
    let length = 3 + (next(&mut state) % 5) as usize;
    for slot in name.iter_mut().take(1 + length).skip(1) {
        *slot = b'a' + (next(&mut state) % 26) as u8;
    }
    SEED.store(state, Ordering::Relaxed);
    name
}

fn next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state >> 33
}
