#[derive(Default, Clone)]
pub struct ProtectReport {
    pub symbolsStripped: bool,
    pub removedDebugSections: usize,
    pub encryptedStrings: usize,
    pub reencryptStrings: bool,
    pub hiddenImportDlls: usize,
    pub hiddenImportFuncs: usize,
    pub reencryptImports: bool,
    pub antiDebug: bool,
    pub virtualizedRegions: usize,
    pub stringsDetected: bool,
    pub encryptedCode: usize,
    pub poisonedDirs: usize,
    pub outputBytes: usize,
}

impl ProtectReport {
    pub fn summary(&self) -> String {
        format!(
            "symbols stripped: {} | debug sections removed: {} | strings detected: {} encrypted: {} (re-encrypt: {}) | imports hidden: {} funcs in {} dlls (re-encrypt: {}) | anti-debug: {} | virtualized regions: {} | .text encrypted: {} bytes | poisoned dirs: {} | output: {} bytes",
            self.symbolsStripped,
            self.removedDebugSections,
            onoff(self.stringsDetected),
            self.encryptedStrings,
            onoff(self.reencryptStrings),
            self.hiddenImportFuncs,
            self.hiddenImportDlls,
            onoff(self.reencryptImports),
            onoff(self.antiDebug),
            self.virtualizedRegions,
            self.encryptedCode,
            self.poisonedDirs,
            self.outputBytes
        )
    }
}

fn onoff(value: bool) -> &'static str {
    if value {
        "on"
    } else {
        "off"
    }
}
