use flate2::read::DeflateDecoder;
use std::io::Read;
use std::path::Path;

pub const MAX_ARCHIVE_ENTRIES: usize = 256;
pub const MAX_ENTRY_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_TOTAL_UNCOMPRESSED: usize = 32 * 1024 * 1024;

const EOCD_SIG: &[u8; 4] = b"PK\x05\x06";
const CD_SIG: &[u8; 4] = b"PK\x01\x02";
const LFH_SIG: &[u8; 4] = b"PK\x03\x04";

#[derive(Debug, Default)]
pub struct ArchiveStats {
    pub entries_inspected: usize,
    pub truncated: bool,
}

pub fn is_zip_candidate(path: &Path, bytes: &[u8]) -> bool {
    let is_zip_ext = path
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("zip"));
    is_zip_ext && bytes.len() >= 22 && (bytes.starts_with(LFH_SIG) || bytes.starts_with(EOCD_SIG))
}

fn find_eocd(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 22 {
        return None;
    }
    let min_pos = bytes.len().saturating_sub(22 + 65535);
    let mut pos = bytes.len() - 22;
    loop {
        if &bytes[pos..pos + 4] == EOCD_SIG {
            let comment_len = u16::from_le_bytes([bytes[pos + 20], bytes[pos + 21]]) as usize;
            if pos + 22 + comment_len == bytes.len() {
                return Some(pos);
            }
        }
        if pos == min_pos {
            break;
        }
        pos -= 1;
    }
    None
}

fn read_le_u16(slice: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        slice.get(off..off + 2)?.try_into().ok()?,
    ))
}

fn read_le_u32(slice: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        slice.get(off..off + 4)?.try_into().ok()?,
    ))
}

/// Safely inspect members inside a ZIP archive completely in memory with zip-bomb bounds.
pub fn inspect_zip(bytes: &[u8], mut on_entry: impl FnMut(&str, &[u8])) -> ArchiveStats {
    let mut stats = ArchiveStats::default();
    let Some(eocd_off) = find_eocd(bytes) else {
        return stats;
    };
    let Some(cd_size) = read_le_u32(bytes, eocd_off + 12).map(|v| v as usize) else {
        return stats;
    };
    let Some(cd_off) = read_le_u32(bytes, eocd_off + 16).map(|v| v as usize) else {
        return stats;
    };
    let Some(cd_end) = cd_off.checked_add(cd_size) else {
        return stats;
    };
    if cd_end > bytes.len() {
        return stats;
    }

    let mut pos = cd_off;
    let mut total_uncompressed = 0usize;

    while pos + 46 <= cd_end {
        if &bytes[pos..pos + 4] != CD_SIG {
            break;
        }
        if stats.entries_inspected >= MAX_ARCHIVE_ENTRIES {
            stats.truncated = true;
            break;
        }

        let Some(flags) = read_le_u16(bytes, pos + 8) else {
            break;
        };
        let Some(method) = read_le_u16(bytes, pos + 10) else {
            break;
        };
        let Some(comp_size) = read_le_u32(bytes, pos + 20).map(|v| v as usize) else {
            break;
        };
        let Some(name_len) = read_le_u16(bytes, pos + 28).map(|v| v as usize) else {
            break;
        };
        let Some(extra_len) = read_le_u16(bytes, pos + 30).map(|v| v as usize) else {
            break;
        };
        let Some(comment_len) = read_le_u16(bytes, pos + 32).map(|v| v as usize) else {
            break;
        };
        let Some(local_off) = read_le_u32(bytes, pos + 42).map(|v| v as usize) else {
            break;
        };

        let Some(name_end) = pos.checked_add(46).and_then(|n| n.checked_add(name_len)) else {
            break;
        };
        let Some(next_pos) = name_end
            .checked_add(extra_len)
            .and_then(|n| n.checked_add(comment_len))
        else {
            break;
        };
        if next_pos > cd_end {
            break;
        }

        let name = String::from_utf8_lossy(&bytes[pos + 46..name_end]).into_owned();
        pos = next_pos;

        // Skip directory entries and encrypted entries (bit 0 = encrypted).
        if name.ends_with('/') || name.ends_with('\\') || (flags & 1) != 0 {
            continue;
        }

        let Some(local) = bytes.get(local_off..) else {
            continue;
        };
        if local.len() < 30 || &local[0..4] != LFH_SIG {
            continue;
        }
        let Some(lfh_name_len) = read_le_u16(local, 26).map(|v| v as usize) else {
            continue;
        };
        let Some(lfh_extra_len) = read_le_u16(local, 28).map(|v| v as usize) else {
            continue;
        };
        let Some(data_start) = 30usize
            .checked_add(lfh_name_len)
            .and_then(|n| n.checked_add(lfh_extra_len))
        else {
            continue;
        };
        let Some(data_end) = data_start.checked_add(comp_size) else {
            continue;
        };
        let Some(comp_slice) = local.get(data_start..data_end) else {
            continue;
        };

        let remaining_budget = MAX_TOTAL_UNCOMPRESSED.saturating_sub(total_uncompressed);
        if remaining_budget == 0 {
            stats.truncated = true;
            break;
        }
        let entry_limit = MAX_ENTRY_BYTES.min(remaining_budget);

        let entry_bytes = match method {
            0 => {
                if comp_slice.len() > entry_limit {
                    stats.truncated = true;
                    continue;
                }
                comp_slice.to_vec()
            }
            8 => {
                let mut decoder = DeflateDecoder::new(comp_slice);
                let mut out = Vec::new();
                if decoder
                    .by_ref()
                    .take(entry_limit as u64 + 1)
                    .read_to_end(&mut out)
                    .is_err()
                {
                    continue;
                }
                if out.len() > entry_limit {
                    stats.truncated = true;
                    continue;
                }
                out
            }
            _ => continue,
        };

        total_uncompressed += entry_bytes.len();
        stats.entries_inspected += 1;
        on_entry(&name, &entry_bytes);
    }

    stats
}
