#[derive(Clone)]
pub struct DebugOptions {
    pub stripSymbols: bool,
    pub stripDebugSections: bool,
}

#[derive(Clone)]
pub struct StringOptions {
    pub encrypt: bool,
    pub minLength: usize,
    pub runtimeReencrypt: bool,
    pub zeroize: bool,
    pub intervalMs: u32,
    pub windowMs: u32,
}

#[derive(Clone)]
pub struct ImportOptions {
    pub hide: bool,
    pub runtimeReencrypt: bool,
    pub intervalMs: u32,
    pub windowMs: u32,
}

#[derive(Clone)]
pub struct ProtectionOptions {
    pub debug: DebugOptions,
    pub strings: StringOptions,
    pub imports: ImportOptions,
    pub antiDebug: bool,
    pub antiVm: bool,
    pub virtualize: bool,
    pub encryptCode: bool,
    pub lazy: bool,
    pub lazyIntervalMs: u32,
}

impl Default for DebugOptions {
    fn default() -> Self {
        Self { stripSymbols: true, stripDebugSections: true }
    }
}

impl Default for StringOptions {
    fn default() -> Self {
        Self {
            encrypt: true,
            minLength: 3,
            runtimeReencrypt: true,
            zeroize: false,
            intervalMs: 1500,
            windowMs: 40,
        }
    }
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self { hide: true, runtimeReencrypt: false, intervalMs: 2000, windowMs: 12 }
    }
}

impl Default for ProtectionOptions {
    fn default() -> Self {
        Self {
            debug: DebugOptions::default(),
            strings: StringOptions::default(),
            imports: ImportOptions::default(),
            antiDebug: true,
            antiVm: false,
            virtualize: true,
            encryptCode: true,
            lazy: false,
            lazyIntervalMs: 50,
        }
    }
}
