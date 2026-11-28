use serde::{Deserialize, Serialize};

const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
const IMAGE_FILE_DLL: u16 = 0x2000;
const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const MIN_ENTROPY_SECTION_BYTES: usize = 4096;
const MAX_ENTROPY_SAMPLE_BYTES: usize = 2 * 1024 * 1024;
pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.45;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Valid,
    Unsigned,
    Untrusted,
    Invalid,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeSummary {
    pub format: String,
    pub is_dll: bool,
    pub sections: usize,
    pub has_authenticode_table: bool,
    pub max_code_entropy: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub packer_section: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureStatus>,
}

impl PeSummary {
    pub fn is_packed_or_high_entropy(&self) -> bool {
        self.packer_section.is_some() || self.max_code_entropy >= HIGH_ENTROPY_THRESHOLD
    }
}

pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let sample = &bytes[..bytes.len().min(MAX_ENTROPY_SAMPLE_BYTES)];
    let mut counts = [0u64; 256];
    for &b in sample {
        counts[b as usize] += 1;
    }
    let total = sample.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    (entropy * 100.0).round() / 100.0
}

fn is_known_packer_section(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "upx0"
            | "upx1"
            | "upx2"
            | ".aspack"
            | ".adata"
            | ".mpress1"
            | ".mpress2"
            | ".themida"
            | ".vmp0"
            | ".vmp1"
            | ".enigma1"
            | ".enigma2"
            | ".petite"
            | ".nsp0"
            | ".nsp1"
    )
}

pub fn analyze(bytes: &[u8]) -> Option<PeSummary> {
    if !bytes.starts_with(b"MZ") || bytes.len() < 64 {
        return None;
    }
    let offset = u32::from_le_bytes(bytes[60..64].try_into().ok()?) as usize;
    if offset < 4 {
        return None;
    }
    let header = bytes.get(offset..)?;
    if header.len() < 26 || !header.starts_with(b"PE\0\0") {
        return None;
    }

    let sections = u16::from_le_bytes([header[6], header[7]]) as usize;
    let optional_len = u16::from_le_bytes([header[20], header[21]]) as usize;
    let characteristics = u16::from_le_bytes([header[22], header[23]]);
    if sections == 0 || (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) == 0 || optional_len < 2 {
        return None;
    }

    let required = 24usize
        .checked_add(optional_len)?
        .checked_add(sections.checked_mul(40)?)?;
    if header.len() < required {
        return None;
    }

    let magic = u16::from_le_bytes([header[24], header[25]]);
    let (format, dir_count_off, cert_dir_off) = match magic {
        0x10b => ("PE32", 92usize, 128usize),
        0x20b => ("PE32+", 108usize, 144usize),
        _ => return None,
    };

    let opt = &header[24..24 + optional_len];
    let has_authenticode_table = if opt.len() >= cert_dir_off + 8 {
        let num_dirs = u32::from_le_bytes(opt[dir_count_off..dir_count_off + 4].try_into().ok()?);
        if num_dirs > 4 {
            let cert_offset =
                u32::from_le_bytes(opt[cert_dir_off..cert_dir_off + 4].try_into().ok()?);
            let cert_size =
                u32::from_le_bytes(opt[cert_dir_off + 4..cert_dir_off + 8].try_into().ok()?);
            cert_offset > 0 && cert_size > 0
        } else {
            false
        }
    } else {
        false
    };

    let section_table = &header[24 + optional_len..];
    let mut max_code_entropy = 0.0f64;
    let mut packer_section = None;

    for idx in 0..sections.min(96) {
        let sec = &section_table[idx * 40..(idx + 1) * 40];
        let raw_name = &sec[0..8];
        let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..end]).into_owned();
        if packer_section.is_none() && is_known_packer_section(&name) {
            packer_section = Some(name.clone());
        }

        let raw_size = u32::from_le_bytes(sec[16..20].try_into().ok()?) as usize;
        let raw_ptr = u32::from_le_bytes(sec[20..24].try_into().ok()?) as usize;
        let sec_chars = u32::from_le_bytes(sec[36..40].try_into().ok()?);
        let is_code = (sec_chars & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)) != 0
            && !name.eq_ignore_ascii_case(".rsrc");

        if is_code
            && raw_size >= MIN_ENTROPY_SECTION_BYTES
            && let Some(end_ptr) = raw_ptr.checked_add(raw_size)
            && let Some(slice) = bytes.get(raw_ptr..end_ptr.min(bytes.len()))
            && slice.len() >= MIN_ENTROPY_SECTION_BYTES
        {
            let ent = shannon_entropy(slice);
            if ent > max_code_entropy {
                max_code_entropy = ent;
            }
        }
    }

    Some(PeSummary {
        format: format.into(),
        is_dll: (characteristics & IMAGE_FILE_DLL) != 0,
        sections,
        has_authenticode_table,
        max_code_entropy,
        packer_section,
        signature: None,
    })
}
