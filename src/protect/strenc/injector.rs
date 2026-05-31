use super::builder::encryptAndBuildEntries;
use super::cipher;
use super::codeenc;
use super::flags::buildFlags;
use super::layout;
use super::layout_types::Inputs;
use super::scanner::Found;
use super::secname::randomSectionName;
use super::sections;
use super::stub_blob::{FLAG_ANTI_DEBUG, FLAG_REENCRYPT_IMPORTS, FLAG_REENCRYPT_STRINGS};
use crate::protect::imphide;
use crate::protect::options::ProtectionOptions;
use crate::protect::pe::adder::addSection;
use super::util;
use crate::protect::pe::image::PeImage;
use crate::protect::report::ProtectReport;
use crate::protect::tls;
use std::io;

const SECTION_FLAGS: u32 = 0xE000_0020;

pub fn apply(
    img: &mut PeImage,
    found: &[Found],
    opts: &ProtectionOptions,
    rep: &mut ProtectReport,
) -> io::Result<()> {
    let seed = util::generate(img.data.len() as u32);
    let (stringEntries, stringBackup) = encryptAndBuildEntries(img, found, seed);
    rep.encryptedStrings = found.len();

    let dlls = if opts.imports.hide { imphide::parse(img) } else { Vec::new() };
    let hiding = opts.imports.hide && !dlls.is_empty();
    let importKey = cipher::deriveKey(seed, cipher::TAG_IMPORT);
    let importTable = imphide::build(&dlls, importKey);
    rep.hiddenImportDlls = if hiding { dlls.len() } else { 0 };
    rep.hiddenImportFuncs = if hiding { dlls.iter().map(|d| d.funcs.len()).sum() } else { 0 };

    let origCallbacks = tls::originalCallbacks(img);
    let flags = buildFlags(opts, hiding);
    let codeKey = cipher::deriveKey(seed, cipher::TAG_CODE);
    let textCheck = codeenc::textChecksum(img, opts.encryptCode);
    let (codeRva, codeLen, codeBlob) = codeenc::prepare(img, opts.encryptCode, codeKey);

    let inp = Inputs {
        stringEntries: &stringEntries,
        stringBackup: &stringBackup,
        stringCount: found.len() as u32,
        importTable: &importTable,
        importDllCount: dlls.len() as u32,
        origCallbacks: &origCallbacks,
        hiding,
        flags,
        codeRva,
        codeLen,
        codeBlob: &codeBlob,
        selfKey: cipher::deriveKey(seed, cipher::TAG_SELF),
        lazyInterval: opts.lazyIntervalMs,
        masterSeed: seed ^ super::envkey::envExpected() as u64,
        textCheck,
    };
    let built = layout::build(img, opts, &inp);

    let sectionName = randomSectionName();
    let va = addSection(img, &sectionName, &built.content, SECTION_FLAGS)?;
    if va != built.predictedVa {
        return Err(io::Error::other("section VA prediction mismatch"));
    }
    img.setEntryRva(va);
    tls::clearDynamicBase(img);
    tls::installCallbacks(img, built.tlsArrayVa, built.synthDirRva, built.synthIndexRva, built.synthZeroRva);
    if hiding {
        imphide::scramble(img, seed);
        imphide::destroy(img);
    }
    rep.poisonedDirs = imphide::poisonDirectories(img);
    util::markWritable(img);
    if codeLen > 0 {
        codeenc::zeroText(img);
        rep.encryptedCode = codeLen as usize;
    }
    rep.poisonedSections = sections::finalize(img);

    rep.reencryptStrings = flags & FLAG_REENCRYPT_STRINGS != 0;
    rep.reencryptImports = flags & FLAG_REENCRYPT_IMPORTS != 0;
    rep.antiDebug = flags & FLAG_ANTI_DEBUG != 0;
    Ok(())
}
