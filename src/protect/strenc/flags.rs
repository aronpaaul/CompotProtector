use super::stub_blob::{
    FLAG_ANTI_DEBUG, FLAG_ANTI_VM, FLAG_HIDE_IMPORTS, FLAG_LAZY, FLAG_REENCRYPT_IMPORTS,
    FLAG_REENCRYPT_STRINGS, FLAG_ZERO_STRINGS,
};
use crate::protect::options::ProtectionOptions;

pub fn buildFlags(opts: &ProtectionOptions, hiding: bool) -> u32 {
    let mut flags = 0;
    if opts.lazy && opts.encryptCode {
        flags |= FLAG_LAZY;
    }
    if opts.strings.encrypt && opts.strings.zeroize {
        flags |= FLAG_ZERO_STRINGS;
    } else if opts.strings.encrypt && opts.strings.runtimeReencrypt {
        flags |= FLAG_REENCRYPT_STRINGS;
    }
    if hiding {
        flags |= FLAG_HIDE_IMPORTS;
    }
    if hiding && opts.imports.runtimeReencrypt {
        flags |= FLAG_REENCRYPT_IMPORTS;
    }
    if opts.antiDebug {
        flags |= FLAG_ANTI_DEBUG;
    }
    if opts.antiVm {
        flags |= FLAG_ANTI_VM;
    }
    flags
}
