use super::options::ProtectionOptions;
use super::pe::image::PeImage;
use super::progress::{report, ProgressFn};
use super::report::ProtectReport;
use super::{debugstrip, strenc, vm, watermark};
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn protect(
    input: &Path,
    output: &Path,
    opts: &ProtectionOptions,
    sink: &mut ProgressFn,
) -> io::Result<ProtectReport> {
    report(sink, 0.02, "Loading image");
    let mut img = PeImage::load(input)?;
    let mut rep = ProtectReport::default();

    if opts.debug.stripSymbols {
        report(sink, 0.12, "Stripping COFF symbol table");
        img.clearSymbols();
        rep.symbolsStripped = true;
    }
    if opts.debug.stripDebugSections {
        report(sink, 0.24, "Removing debug sections");
        rep.removedDebugSections = debugstrip::stripDebugSections(&mut img);
    }
    if opts.virtualize {
        report(sink, 0.40, "Virtualizing marked code regions");
        rep.virtualizedRegions = vm::apply(&mut img, opts)?;
    }

    let needStub = opts.strings.encrypt || opts.imports.hide || opts.antiDebug || opts.encryptCode;
    if needStub {
        report(sink, 0.55, "Triple-checking strings");
        rep.stringsDetected = strenc::tripleCheck(&img, opts.strings.minLength);
        let found = if opts.strings.encrypt && rep.stringsDetected {
            strenc::scan(&img, opts.strings.minLength)
        } else {
            Vec::new()
        };
        report(sink, 0.72, "Encrypting strings, code & hiding imports");
        report(sink, 0.85, "Injecting TLS decryptor & import resolver");
        strenc::apply(&mut img, &found, opts, &mut rep)?;
    }

    if opts.watermark {
        report(sink, 0.93, "Stamping watermark");
        let id = watermarkId();
        watermark::apply(&mut img, id);
        rep.watermarkId = id;
    }
    report(sink, 0.95, "Writing output");
    img.save(output)?;
    rep.outputBytes = img.data.len();
    report(sink, 1.0, "Done");
    Ok(rep)
}

fn watermarkId() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x436F_6D70_6F74_5072)
        | 1
}
