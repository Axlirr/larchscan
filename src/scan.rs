use crate::windows::{Amsi, regular_file};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use walkdir::WalkDir;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
use windows_sys::Win32::System::Antimalware::{
    AMSI_RESULT_BLOCKED_BY_ADMIN_END, AMSI_RESULT_BLOCKED_BY_ADMIN_START, AMSI_RESULT_DETECTED,
};

pub const MAX_BYTES: usize = 32 * 1024 * 1024;
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn read_bytes(file: &File) -> Result<Vec<u8>> {
    let len = file.metadata()?.len();
    ensure!(len <= MAX_BYTES as u64, "file exceeds 32 MiB limit");
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() == len as usize, "file changed during read");
    Ok(bytes)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    id: String,
    sha256: String,
    reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub reason: String,
}

pub struct Engine {
    rules: HashMap<String, Finding>,
    amsi: Option<Amsi>,
}

fn document_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "pdf" | "doc" | "docx" | "xls" | "xlsx" | "txt" | "jpg" | "jpeg" | "png"
            )
        })
}

fn document_named_pe(path: &Path, bytes: &[u8]) -> bool {
    let double_extension = path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("scr"))
        && path
            .file_stem()
            .is_some_and(|stem| document_extension(Path::new(stem)));
    if !(document_extension(path) || double_extension)
        || !bytes.starts_with(b"MZ")
        || bytes.len() < 64
    {
        return false;
    }
    let offset = u32::from_le_bytes(bytes[60..64].try_into().expect("four-byte offset")) as usize;
    let Some(header) = bytes.get(offset..).filter(|h| h.len() >= 26) else {
        return false;
    };
    let optional_len = u16::from_le_bytes([header[20], header[21]]) as usize;
    let sections = u16::from_le_bytes([header[6], header[7]]) as usize;
    offset >= 64
        && header.starts_with(b"PE\0\0")
        && (1..=96).contains(&sections)
        && (header[22] & 2) != 0
        && optional_len >= 2
        && header.len() >= 24 + optional_len + sections * 40
        && matches!(u16::from_le_bytes([header[24], header[25]]), 0x10b | 0x20b)
}

#[derive(Serialize)]
pub struct Verdict {
    pub sha256: String,
    pub findings: Vec<Finding>,
    pub amsi_result: Option<i32>,
    pub provider_error: Option<String>,
}

impl Engine {
    pub fn load(path: Option<&Path>, amsi: bool) -> Result<Self> {
        let demo = Rule {
            id: "demo.fixture".into(),
            sha256: digest(include_bytes!("../examples/demo.txt")),
            reason: "Harmless verification fixture matched the built-in SHA-256 rule".into(),
        };
        let mut loaded = vec![demo];
        if let Some(path) = path {
            let bytes = read_bytes(&regular_file(path, false)?)?;
            loaded
                .extend(serde_json::from_slice::<Vec<Rule>>(&bytes).context("invalid rule file")?);
        }
        let mut ids = HashSet::new();
        let mut rules = HashMap::new();
        for rule in loaded {
            ensure!(
                !rule.id.trim().is_empty()
                    && !rule.reason.trim().is_empty()
                    && !rule.id.starts_with("amsi.")
                    && !rule.id.starts_with("triage."),
                "invalid rule id or reason"
            );
            ensure!(
                rule.sha256.len() == 64 && rule.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                "invalid SHA-256 in {}",
                rule.id
            );
            ensure!(ids.insert(rule.id.clone()), "duplicate rule id {}", rule.id);
            ensure!(
                rules
                    .insert(
                        rule.sha256.to_ascii_lowercase(),
                        Finding {
                            id: rule.id,
                            reason: rule.reason
                        }
                    )
                    .is_none(),
                "duplicate SHA-256"
            );
        }
        Ok(Self {
            rules,
            amsi: if amsi { Some(Amsi::start()?) } else { None },
        })
    }

    pub fn inspect(&self, path: &Path, bytes: &[u8]) -> Verdict {
        let sha256 = digest(bytes);
        let mut findings: Vec<_> = self.rules.get(&sha256).cloned().into_iter().collect();
        if document_named_pe(path, bytes) {
            findings.push(Finding {
                id: "triage.document-named-pe".into(),
                reason: "Windows executable headers and a document or image filename; review the file type".into(),
            });
        }
        let mut provider_error = None;
        let mut amsi_result = None;
        if let Some(provider) = &self.amsi {
            match provider.scan(path, bytes) {
                Ok(value) => {
                    amsi_result = Some(value);
                    let rule = if value >= AMSI_RESULT_DETECTED {
                        Some((
                            "amsi.detected",
                            "Windows antimalware provider reported malware",
                        ))
                    } else if (AMSI_RESULT_BLOCKED_BY_ADMIN_START
                        ..=AMSI_RESULT_BLOCKED_BY_ADMIN_END)
                        .contains(&value)
                    {
                        Some((
                            "amsi.policy",
                            "Windows antimalware provider reported an administrator policy block",
                        ))
                    } else {
                        None
                    };
                    if let Some((id, reason)) = rule {
                        findings.push(Finding {
                            id: id.into(),
                            reason: reason.into(),
                        });
                    }
                }
                Err(error) => provider_error = Some(error.to_string()),
            }
        }
        Verdict {
            sha256,
            findings,
            amsi_result,
            provider_error,
        }
    }
}

pub fn tree(engine: &Engine, root: &Path) -> Result<u8> {
    let root = crate::windows::disk_path(root)?;
    let mut scanned = 0u64;
    let mut matches = 0u64;
    let mut incomplete = 0u64;
    let mut iter = WalkDir::new(&root)
        .follow_links(false)
        .follow_root_links(false)
        .sort_by_file_name()
        .into_iter();
    while let Some(entry) = iter.next() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                incomplete += 1;
                crate::emit(
                    json!({"event":"unscanned","path":error.path().map(|p| p.to_string_lossy()),"reason":error.to_string()}),
                )?;
                continue;
            }
        };
        let path = entry.path();
        let result: Result<Option<Verdict>> = (|| {
            let metadata = std::fs::symlink_metadata(path)?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                if entry.file_type().is_dir() {
                    iter.skip_current_dir();
                }
                anyhow::bail!("reparse point excluded");
            }
            if metadata.is_dir() {
                return Ok(None);
            }
            let bytes = read_bytes(&regular_file(path, false)?)?;
            Ok(Some(engine.inspect(path, &bytes)))
        })();
        match result {
            Ok(Some(verdict)) => {
                scanned += 1;
                matches += u64::from(!verdict.findings.is_empty());
                incomplete += u64::from(verdict.provider_error.is_some());
                crate::emit(
                    json!({"event":"file","path":path.to_string_lossy(),"verdict":verdict}),
                )?;
            }
            Ok(None) => (),
            Err(error) => {
                incomplete += 1;
                crate::emit(
                    json!({"event":"unscanned","path":path.to_string_lossy(),"reason":error.to_string()}),
                )?;
            }
        }
    }
    crate::emit(
        json!({"event":"summary","files_scanned":scanned,"files_with_findings":matches,"incomplete":incomplete}),
    )?;
    Ok(if incomplete > 0 {
        2
    } else if matches > 0 {
        1
    } else {
        0
    })
}
