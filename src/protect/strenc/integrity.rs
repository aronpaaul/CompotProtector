pub fn checksum(stub: &[u8], codeBlob: &[u8]) -> u32 {
    let mut h: u32 = 0x811C_9DC5;
    for &b in stub {
        h = (h ^ b as u32).wrapping_mul(0x0100_0193);
    }
    for &b in codeBlob {
        h = (h ^ b as u32).wrapping_mul(0x0100_0193);
    }
    h
}
