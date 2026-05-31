use crate::protect::ProtectionOptions;
use std::path::PathBuf;

pub struct Parsed {
    pub input: PathBuf,
    pub output: PathBuf,
    pub options: ProtectionOptions,
}

pub fn parse(argv: &[String]) -> Result<Parsed, String> {
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    let mut opts = ProtectionOptions::default();
    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        match arg {
            "-i" | "--input" => input = Some(value(argv, &mut i, arg)?.into()),
            "-o" | "--output" => output = Some(value(argv, &mut i, arg)?.into()),
            "--no-symbols" => opts.debug.stripSymbols = false,
            "--no-debug-sections" => opts.debug.stripDebugSections = false,
            "--no-strings" => opts.strings.encrypt = false,
            "--no-reencrypt" => opts.strings.runtimeReencrypt = false,
            "--zero-strings" => opts.strings.zeroize = true,
            "--min-len" => opts.strings.minLength = numeric(argv, &mut i, arg)? as usize,
            "--interval" => opts.strings.intervalMs = numeric(argv, &mut i, arg)?,
            "--window" => opts.strings.windowMs = numeric(argv, &mut i, arg)?,
            "--no-hide-imports" => opts.imports.hide = false,
            "--reencrypt-imports" => opts.imports.runtimeReencrypt = true,
            "--import-interval" => opts.imports.intervalMs = numeric(argv, &mut i, arg)?,
            "--import-window" => opts.imports.windowMs = numeric(argv, &mut i, arg)?,
            "--no-anti-debug" => opts.antiDebug = false,
            "--anti-vm" => opts.antiVm = true,
            "--no-virtualize" => opts.virtualize = false,
            "--no-encrypt-code" => opts.encryptCode = false,
            "--lazy" => opts.lazy = true,
            "--lazy-interval" => opts.lazyIntervalMs = numeric(argv, &mut i, arg)?,
            other => return Err(format!("unknown argument: {other}")),
        }
        i += 1;
    }
    Ok(Parsed {
        input: input.ok_or("missing --input")?,
        output: output.ok_or("missing --output")?,
        options: opts,
    })
}

fn value(argv: &[String], i: &mut usize, flag: &str) -> Result<String, String> {
    *i += 1;
    argv.get(*i).cloned().ok_or(format!("{flag} expects a value"))
}

fn numeric(argv: &[String], i: &mut usize, flag: &str) -> Result<u32, String> {
    value(argv, i, flag)?
        .parse()
        .map_err(|_| format!("{flag} expects a number"))
}
