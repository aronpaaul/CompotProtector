use super::cipher;
use super::layout_types::{align, patchJunk, push, Built, Inputs};
use super::params::Params;
use super::stub_blob::{ENC_END, PARAMS_LEN, PARAMS_OFF, STUB, TLS_CALLBACK_OFF};
use crate::protect::options::ProtectionOptions;
use crate::protect::pe::bytes::alignUp;
use crate::protect::pe::image::PeImage;
use crate::protect::pe::section::maxVirtualEnd;

pub fn build(img: &PeImage, opts: &ProtectionOptions, inp: &Inputs) -> Built {
    let base = img.imageBase();
    let va = alignUp(maxVirtualEnd(img), img.sectionAlignment());

    let mut content = STUB.to_vec();
    let stringOff = content.len() as u32;
    content.extend_from_slice(inp.stringEntries);
    align(&mut content, 4);
    let backupOff = content.len() as u32;
    content.extend_from_slice(inp.stringBackup);
    align(&mut content, 4);
    let importOff = content.len() as u32;
    content.extend_from_slice(inp.importTable);
    align(&mut content, 8);
    let origOff = content.len() as u32;
    if inp.hiding {
        push(&mut content, inp.origCallbacks);
    }
    align(&mut content, 8);
    let tlsArrayOff = content.len() as u32;
    content.extend_from_slice(&(base + va as u64 + TLS_CALLBACK_OFF as u64).to_le_bytes());
    if !inp.hiding {
        push(&mut content, inp.origCallbacks);
    }
    content.extend_from_slice(&0u64.to_le_bytes());

    align(&mut content, 8);
    let zeroOff = content.len() as u32;
    content.extend_from_slice(&[0u8; 8]);
    let indexOff = content.len() as u32;
    content.extend_from_slice(&[0u8; 4]);
    align(&mut content, 8);
    let dirOff = content.len() as u32;
    content.extend_from_slice(&[0u8; 40]);

    align(&mut content, 8);
    let bitmapOff = content.len() as u32;
    let pageCount = inp.codeLen.div_ceil(0x1000);
    content.extend(std::iter::repeat(0xFFu8).take((pageCount as usize).div_ceil(8)));
    align(&mut content, 16);
    let codeBlobOff = content.len() as u32;
    content.extend_from_slice(inp.codeBlob);
    let params = Params {
        flags: inp.flags,
        stringCount: inp.stringCount,
        stringTableRva: va + stringOff,
        stringInterval: opts.strings.intervalMs,
        stringWindow: opts.strings.windowMs,
        importDllCount: inp.importDllCount,
        importTableRva: va + importOff,
        importTableLen: inp.importTable.len() as u32,
        importInterval: opts.imports.intervalMs,
        importWindow: opts.imports.windowMs,
        oepRva: img.entryRva(),
        origCbRva: va + origOff,
        origCbCount: if inp.hiding { inp.origCallbacks.len() as u32 } else { 0 },
        codeRva: inp.codeRva,
        codeLen: inp.codeLen,
        codeBlobRva: if inp.codeLen > 0 { va + codeBlobOff } else { 0 },
        selfRva: va,
        selfLen: ENC_END as u32,
        bitmapRva: va + bitmapOff,
        pageCount,
        lazyInterval: inp.lazyInterval,
        masterSeed: inp.masterSeed,
        stringBackupRva: va + backupOff,
        integrity: super::integrity::checksum(&STUB[0..ENC_END], inp.codeBlob),
        textCheck: inp.textCheck,
    };
    content[PARAMS_OFF..PARAMS_OFF + PARAMS_LEN].copy_from_slice(&params.toBytes());
    cipher::stream(&mut content[0..ENC_END], inp.selfKey, 0);
    patchJunk(&mut content, inp.masterSeed);
    Built {
        content,
        predictedVa: va,
        tlsArrayVa: base + va as u64 + tlsArrayOff as u64,
        synthDirRva: va + dirOff,
        synthIndexRva: va + indexOff,
        synthZeroRva: va + zeroOff,
    }
}
