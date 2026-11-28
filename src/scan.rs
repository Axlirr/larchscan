use crate::archive;
use crate::pe::{self, PeSummary, SignatureStatus};
use crate::rules::{BundleSummary, HashRule, RuleSet, load_ruleset};
use crate::windows::{Amsi, disk_path, paths_equal, regular_file, verify_authenticode};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
use windows_sys::Win32::System::Antimalware::{
    AMSI_RESULT_BLOCKED_BY_ADMIN_END, AMSI_RESULT_BLOCKED_BY_ADMIN_START, AMSI_RESULT_DETECTED,
};

pub const MAX_BYTES: usize = 32 * 1024 * 1024;
const READ_CHUNK: usize = 64 * 1024;
const MAX_ARCHIVE_FINDINGS: usize = 25;

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn read_bytes(file: &File) -> Result<Vec<u8>> {
    read_bytes_with_limit(file, MAX_BYTES, || false)?
        .ok_or_else(|| anyhow::anyhow!("scan cancelled"))
}

pub fn read_bytes_with_limit(
    file: &File,
    max_bytes: usize,
    cancelled: impl Fn() -> bool,
) -> Result<Option<Vec<u8>>> {
    let len = file.metadata()?.len();
    if len > max_bytes as u64 {
        if max_bytes == MAX_BYTES {
            anyhow::bail!("file exceeds 32 MiB limit");
        }
        anyhow::bail!("file exceeds {} MiB limit", max_bytes.div_ceil(1024 * 1024));
    }
    let expected = len as usize;
    let mut bytes = Vec::with_capacity(expected);
    let mut reader = file.take(max_bytes as u64 + 1);
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        if cancelled() {
            return Ok(None);
        }
        let n = reader.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..n]);
        if bytes.len() > max_bytes {
            anyhow::bail!("file grew beyond size limit during read");
        }
    }
    ensure!(bytes.len() == expected, "file changed during read");
    Ok(Some(bytes))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub id: String,
    pub reason: String,
}

pub struct Engine {
    ruleset: RuleSet,
    amsi: Option<Amsi>,
}

fn is_document_ext(ext: &str) -> bool {
    matches!(
        ext.to_ascii_lowercase().as_str(),
        "pdf"
            | "doc"
            | "docx"
            | "xls"
            | "xlsx"
            | "ppt"
            | "pptx"
            | "rtf"
            | "csv"
            | "odt"
            | "ods"
            | "txt"
            | "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "bmp"
            | "webp"
            | "svg"
            | "mp3"
            | "mp4"
            | "zip"
            | "rar"
            | "7z"
            | "html"
            | "htm"
            | "eml"
            | "msg"
    )
}

fn document_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .is_some_and(is_document_ext)
}

fn trimmed_stem_has_document_extension(path: &Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let trimmed = stem.trim_end_matches([' ', '.']);
    document_extension(Path::new(trimmed))
}

fn pe_launcher_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "exe" | "scr" | "com" | "pif" | "cpl" | "dll" | "ocx"
            )
        })
}

fn script_launcher_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "lnk"
                    | "bat"
                    | "cmd"
                    | "ps1"
                    | "vbs"
                    | "vbe"
                    | "js"
                    | "jse"
                    | "wsf"
                    | "hta"
                    | "msi"
            )
        })
}

fn has_bidi_override(path: &Path) -> bool {
    path.file_name().is_some_and(|name| {
        name.encode_wide()
            .any(|unit| matches!(unit, 0x202A..=0x202E | 0x2066..=0x2069))
    })
}

fn document_named_pe(path: &Path, pe: Option<&PeSummary>) -> bool {
    if pe.is_none() {
        return false;
    }
    let double_extension = pe_launcher_extension(path) && trimmed_stem_has_document_extension(path);
    document_extension(path) || double_extension
}

fn double_extension_script(path: &Path) -> bool {
    script_launcher_extension(path) && trimmed_stem_has_document_extension(path)
}

#[derive(Deserialize, Serialize)]
pub struct Verdict {
    pub sha256: String,
    pub findings: Vec<Finding>,
    pub amsi_result: Option<i32>,
    pub provider_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pe: Option<PeSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_entries: Option<usize>,
}

impl Engine {
    pub fn load(path: Option<&Path>, amsi: bool) -> Result<Self> {
        Self::load_with_options(path, None, amsi)
    }

    pub fn load_with_options(
        path: Option<&Path>,
        rules_pubkey_hex: Option<&str>,
        amsi: bool,
    ) -> Result<Self> {
        let demo = HashRule {
            id: "demo.fixture".into(),
            sha256: digest(include_bytes!("../examples/demo.txt")),
            reason: "Harmless verification fixture matched the built-in SHA-256 rule".into(),
        };
        let custom_bytes = match path {
            Some(path) => Some(read_bytes(&regular_file(path, false)?)?),
            None => None,
        };
        let pubkey = rules_pubkey_hex.map(str::trim).filter(|s| !s.is_empty());
        let ruleset = load_ruleset(demo, custom_bytes.as_deref(), pubkey)?;
        Ok(Self {
            ruleset,
            amsi: if amsi { Some(Amsi::start()?) } else { None },
        })
    }

    pub fn rules_summary(&self) -> &BundleSummary {
        &self.ruleset.summary
    }

    fn inspect_core(
        &self,
        path: &Path,
        bytes: &[u8],
        verify_disk_signature: bool,
    ) -> (String, Vec<Finding>, Option<PeSummary>) {
        let sha256 = digest(bytes);
        let mut findings: Vec<_> = self
            .ruleset
            .hashes
            .get(&sha256)
            .cloned()
            .into_iter()
            .collect();
        let mut pe_info = pe::analyze(bytes);

        if let Some(pe) = pe_info.as_mut() {
            if verify_disk_signature && pe.has_authenticode_table && path.is_file() {
                let sig = verify_authenticode(path);
                if sig == SignatureStatus::Invalid {
                    findings.push(Finding {
                        id: "triage.invalid-authenticode".into(),
                        reason: "Windows Authenticode signature is invalid or modified; review file integrity".into(),
                    });
                }
                pe.signature = Some(sig);
            } else if !pe.has_authenticode_table {
                pe.signature = Some(SignatureStatus::Unsigned);
            }

            if pe.is_packed_or_high_entropy() && pe.signature != Some(SignatureStatus::Valid) {
                let detail = match &pe.packer_section {
                    Some(sec) => format!("known packer section '{sec}'"),
                    None => format!("high executable code entropy ({:.2})", pe.max_code_entropy),
                };
                findings.push(Finding {
                    id: "triage.packed-unsigned-pe".into(),
                    reason: format!(
                        "Unsigned Windows executable with {detail}; review before running"
                    ),
                });
            }
        }

        if document_named_pe(path, pe_info.as_ref()) {
            findings.push(Finding {
                id: "triage.document-named-pe".into(),
                reason: "Windows executable headers and a document or image filename; review the file type".into(),
            });
        }
        if double_extension_script(path) {
            findings.push(Finding {
                id: "triage.double-extension-script".into(),
                reason: "Document or image name paired with a Windows script or shortcut extension; review before opening".into(),
            });
        }
        if has_bidi_override(path) {
            findings.push(Finding {
                id: "triage.bidi-filename".into(),
                reason: "Filename contains Unicode bidirectional control characters that can disguise the true extension".into(),
            });
        }

        for pattern in &self.ruleset.patterns {
            if pattern.matches(path, bytes, pe_info.as_ref()) {
                findings.push(pattern.finding());
            }
        }

        (sha256, findings, pe_info)
    }

    pub fn inspect(&self, path: &Path, bytes: &[u8]) -> Verdict {
        let (sha256, mut findings, pe) = self.inspect_core(path, bytes, true);

        let mut archive_entries = None;
        if archive::is_zip_candidate(path, bytes) {
            let mut added = 0usize;
            let stats = archive::inspect_zip(bytes, |entry_name, entry_bytes| {
                if added >= MAX_ARCHIVE_FINDINGS {
                    return;
                }
                let virtual_path = Path::new(entry_name);
                let (_, entry_findings, _) = self.inspect_core(virtual_path, entry_bytes, false);
                for ef in entry_findings {
                    if added >= MAX_ARCHIVE_FINDINGS {
                        break;
                    }
                    findings.push(Finding {
                        id: format!("archive.{}", ef.id),
                        reason: format!("Inside archive entry '{entry_name}': {}", ef.reason),
                    });
                    added += 1;
                }
            });
            archive_entries = Some(stats.entries_inspected);
        }

        let mut provider_error = None;
        let mut amsi_result = None;
        if let Some(provider) = &self.amsi
            && !bytes.is_empty()
        {
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
            pe,
            archive_entries,
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct Summary {
    pub files_scanned: u64,
    pub files_with_findings: u64,
    pub incomplete: u64,
    pub cancelled: bool,
}

impl Summary {
    pub fn exit_code(&self) -> u8 {
        if self.incomplete > 0 || self.cancelled {
            2
        } else if self.files_with_findings > 0 {
            1
        } else {
            0
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ScanEvent {
    File {
        path: PathBuf,
        verdict: Verdict,
    },
    Unscanned {
        path: Option<PathBuf>,
        reason: String,
    },
}

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub max_bytes: usize,
    pub exclude: Vec<PathBuf>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_bytes: MAX_BYTES,
            exclude: Vec::new(),
        }
    }
}

pub fn tree(
    engine: &Engine,
    root: &Path,
    cancelled: impl Fn() -> bool,
    emit: impl FnMut(ScanEvent) -> Result<()>,
) -> Result<Summary> {
    tree_with_options(engine, root, &ScanOptions::default(), cancelled, emit)
}

pub fn tree_excluding(
    engine: &Engine,
    root: &Path,
    exclude: Option<&Path>,
    cancelled: impl Fn() -> bool,
    emit: impl FnMut(ScanEvent) -> Result<()>,
) -> Result<Summary> {
    let options = ScanOptions {
        exclude: exclude.into_iter().map(Path::to_path_buf).collect(),
        ..ScanOptions::default()
    };
    tree_with_options(engine, root, &options, cancelled, emit)
}

pub fn tree_with_options(
    engine: &Engine,
    root: &Path,
    options: &ScanOptions,
    cancelled: impl Fn() -> bool,
    mut emit: impl FnMut(ScanEvent) -> Result<()>,
) -> Result<Summary> {
    let root = disk_path(root)?;
    let excluded: Vec<PathBuf> = options
        .exclude
        .iter()
        .filter_map(|p| disk_path(p).ok())
        .collect();
    let mut summary = Summary::default();
    let mut iter = WalkDir::new(&root)
        .follow_links(false)
        .follow_root_links(false)
        .sort_by_file_name()
        .into_iter();
    while let Some(entry) = iter.next() {
        if cancelled() {
            summary.cancelled = true;
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                summary.incomplete += 1;
                emit(ScanEvent::Unscanned {
                    path: error.path().map(Path::to_owned),
                    reason: error.to_string(),
                })?;
                continue;
            }
        };
        let path = entry.path();
        if excluded
            .iter()
            .any(|folder| path.ancestors().any(|part| paths_equal(part, folder)))
        {
            if entry.file_type().is_dir() {
                iter.skip_current_dir();
            }
            continue;
        }
        enum FileOutcome {
            Scanned(Verdict),
            SkippedDir,
            Cancelled,
        }
        let result: Result<FileOutcome> = (|| {
            let metadata = std::fs::symlink_metadata(path)?;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                if entry.file_type().is_dir() {
                    iter.skip_current_dir();
                }
                anyhow::bail!("reparse point excluded");
            }
            if metadata.is_dir() {
                return Ok(FileOutcome::SkippedDir);
            }
            let file = regular_file(path, false)?;
            let Some(bytes) = read_bytes_with_limit(&file, options.max_bytes, &cancelled)? else {
                return Ok(FileOutcome::Cancelled);
            };
            Ok(FileOutcome::Scanned(engine.inspect(path, &bytes)))
        })();
        match result {
            Ok(FileOutcome::Scanned(verdict)) => {
                summary.files_scanned += 1;
                summary.files_with_findings += u64::from(!verdict.findings.is_empty());
                summary.incomplete += u64::from(verdict.provider_error.is_some());
                emit(ScanEvent::File {
                    path: path.to_owned(),
                    verdict,
                })?;
            }
            Ok(FileOutcome::SkippedDir) => (),
            Ok(FileOutcome::Cancelled) => {
                summary.cancelled = true;
                break;
            }
            Err(error) => {
                summary.incomplete += 1;
                emit(ScanEvent::Unscanned {
                    path: Some(path.to_owned()),
                    reason: error.to_string(),
                })?;
            }
        }
    }
    Ok(summary)
}
