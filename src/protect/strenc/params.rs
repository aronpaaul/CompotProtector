use crate::protect::pe::bytes::wrU32;

#[derive(Default)]
pub struct Params {
    pub flags: u32,
    pub stringCount: u32,
    pub stringTableRva: u32,
    pub stringInterval: u32,
    pub stringWindow: u32,
    pub importDllCount: u32,
    pub importTableRva: u32,
    pub importTableLen: u32,
    pub importInterval: u32,
    pub importWindow: u32,
    pub oepRva: u32,
    pub origCbRva: u32,
    pub origCbCount: u32,
    pub codeRva: u32,
    pub codeLen: u32,
    pub codeBlobRva: u32,
    pub selfRva: u32,
    pub selfLen: u32,
    pub bitmapRva: u32,
    pub pageCount: u32,
    pub lazyInterval: u32,
    pub masterSeed: u64,
    pub stringBackupRva: u32,
    pub integrity: u32,
    pub textCheck: u32,
}

impl Params {
    pub fn toBytes(&self) -> [u8; 196] {
        let mut p = [0u8; 196];
        let fields = [
            (0, self.flags),
            (4, self.stringCount),
            (8, self.stringTableRva),
            (12, self.stringInterval),
            (16, self.stringWindow),
            (20, self.importDllCount),
            (24, self.importTableRva),
            (28, self.importTableLen),
            (36, self.importInterval),
            (40, self.importWindow),
            (44, self.oepRva),
            (48, ror13("LoadLibraryA")),
            (52, ror13("GetProcAddress")),
            (56, ror13("Sleep")),
            (60, ror13("CreateThread")),
            (104, self.origCbRva),
            (108, self.origCbCount),
            (112, ror13("CheckRemoteDebuggerPresent")),
            (116, ror13("ExitProcess")),
            (120, self.codeRva),
            (124, self.codeLen),
            (128, self.codeBlobRva),
            (140, self.integrity),
            (192, self.textCheck),
            (132, self.selfRva),
            (136, self.selfLen),
            (144, ror13("VirtualProtect")),
            (156, self.bitmapRva),
            (160, self.pageCount),
            (164, self.lazyInterval),
            (32, self.stringBackupRva),
            (176, ror13("NtQueryInformationProcess")),
            (180, ror13("NtSetInformationThread")),
            (184, ror13("NtClose")),
        ];
        for (off, value) in fields {
            wrU32(&mut p, off, value);
        }
        wrU32(&mut p, 168, self.masterSeed as u32);
        wrU32(&mut p, 172, (self.masterSeed >> 32) as u32);
        p
    }
}

pub fn ror13(name: &str) -> u32 {
    let mut hash: u32 = 0;
    for byte in name.bytes().chain(std::iter::once(0u8)) {
        hash = hash.rotate_right(13).wrapping_add(byte as u32);
    }
    hash
}
