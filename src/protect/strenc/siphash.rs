fn sipround(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17) ^ v[2];
    v[2] = v[2].rotate_left(32);
}

pub fn block(k0: u64, k1: u64, counter: u64) -> u64 {
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let b: u64 = 8 << 56;
    v[3] ^= counter;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= counter;
    v[3] ^= b;
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^= b;
    v[2] ^= 0xff;
    sipround(&mut v);
    sipround(&mut v);
    sipround(&mut v);
    sipround(&mut v);
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

#[test]
fn vector() {
    assert_eq!(block(0x0706050403020100, 0x0f0e0d0c0b0a0908, 0x0706050403020100), 0x93f5f5799a932462);
}
