use super::bytes::alignUp;
use super::image::PeImage;
use super::section::maxVirtualEnd;
use std::io;

pub fn addSection(
    img: &mut PeImage,
    tag: &[u8; 8],
    content: &[u8],
    characteristics: u32,
) -> io::Result<u32> {
    let secAlign = img.sectionAlignment();
    let fileAlign = img.fileAlignment();
    let count = img.numberOfSections();

    let tableEnd = img.sectionTableOff() + count as usize * 40;
    if tableEnd + 40 > img.sizeOfHeaders() as usize {
        return Err(io::Error::other("no room in header for a new section"));
    }

    let newVa = alignUp(maxVirtualEnd(img), secAlign);
    let newRawPtr = alignUp(img.data.len() as u32, fileAlign);
    let virtualSize = content.len() as u32;
    let rawDataSize = alignUp(virtualSize, fileAlign);

    writeHeader(img, tableEnd, tag, newVa, virtualSize, newRawPtr, rawDataSize, characteristics);

    img.setNumberOfSections(count + 1);
    img.setSizeOfImage(alignUp(newVa + virtualSize, secAlign));

    img.data.resize(newRawPtr as usize, 0);
    img.data.extend_from_slice(content);
    img.data.resize((newRawPtr + rawDataSize) as usize, 0);
    Ok(newVa)
}

#[allow(clippy::too_many_arguments)]
fn writeHeader(
    img: &mut PeImage,
    off: usize,
    tag: &[u8; 8],
    va: u32,
    vSize: u32,
    rawPtr: u32,
    rawSize: u32,
    chars: u32,
) {
    img.data[off..off + 8].copy_from_slice(tag);
    super::bytes::wrU32(&mut img.data, off + 8, vSize);
    super::bytes::wrU32(&mut img.data, off + 12, va);
    super::bytes::wrU32(&mut img.data, off + 16, rawSize);
    super::bytes::wrU32(&mut img.data, off + 20, rawPtr);
    for b in &mut img.data[off + 24..off + 36] {
        *b = 0;
    }
    super::bytes::wrU32(&mut img.data, off + 36, chars);
}
