use crate::scan::{Engine, Finding, MAX_BYTES, digest, read_bytes};
use crate::windows::{
    MAX_ZONE_IDENTIFIER_BYTES, disk_path, paths_equal, quarantine_file, regular_file,
    remove_on_close,
};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD, write::EncoderWriter};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::NamedTempFile;
use uuid::Uuid;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

const HEADER_LIMIT: u64 = 128 * 1024;
const ENCODED_LIMIT: usize = MAX_BYTES.div_ceil(3) * 4;
const DEFAULT_ZONE_IDENTIFIER: &[u8] = b"[ZoneTransfer]\r\nZoneId=3\r\n";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Receipt {
    format: String,
    pub id: Uuid,
    pub original: PathBuf,
    pub sha256: String,
    pub bytes: usize,
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantined_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_identifier_b64: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VaultWarning {
    pub path: PathBuf,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ListReport {
    pub items: Vec<Receipt>,
    pub warnings: Vec<VaultWarning>,
}

fn item_path(dir: &Path, id: Uuid) -> PathBuf {
    dir.join(format!("{id}.lsq"))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn is_inside_dir(candidate: &Path, root: &Path) -> Result<bool> {
    let candidate = candidate.canonicalize()?;
    let root = root.canonicalize()?;
    Ok(candidate.ancestors().any(|part| paths_equal(part, &root)))
}

fn check_directories(path: &Path) -> Result<()> {
    for ancestor in disk_path(path)?.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) => ensure!(
                meta.is_dir() && meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
                "unexpected directory or reparse point at {}",
                ancestor.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn header<R: Read>(reader: &mut BufReader<R>, expected: Uuid) -> Result<Receipt> {
    let mut bytes = Vec::new();
    reader
        .take(HEADER_LIMIT + 1)
        .read_until(b'\n', &mut bytes)?;
    ensure!(
        bytes.len() as u64 <= HEADER_LIMIT && bytes.last() == Some(&b'\n'),
        "invalid archive header"
    );
    let receipt: Receipt = serde_json::from_slice(&bytes)?;
    ensure!(
        (receipt.format == "larchscan/1" || receipt.format == "larchscan/2")
            && receipt.id == expected
            && receipt.bytes <= MAX_BYTES,
        "invalid archive identity or size"
    );
    Ok(receipt)
}

fn verify_archive(
    path: &Path,
    expected: Uuid,
    expected_bytes: usize,
    expected_sha256: &str,
) -> Result<()> {
    let mut reader = BufReader::new(regular_file(path, false)?);
    let receipt = header(&mut reader, expected)?;
    ensure!(
        receipt.bytes == expected_bytes && receipt.sha256 == expected_sha256,
        "archive metadata mismatch on readback"
    );
    let encoded_len = receipt.bytes.div_ceil(3) * 4;
    ensure!(encoded_len <= ENCODED_LIMIT, "invalid archive length");

    let mut limited = reader.take((encoded_len + 1) as u64);
    let mut hasher = Sha256::new();
    let mut decoded_total = 0usize;
    let mut encoded_total = 0usize;
    let mut buf = [0u8; 64 * 1024];
    let mut carry = [0u8; 4];
    let mut carry_len = 0usize;
    let mut decoded_chunk = Vec::with_capacity(48 * 1024 + 4);

    loop {
        let n = limited.read(&mut buf)?;
        if n == 0 {
            break;
        }
        encoded_total += n;
        ensure!(encoded_total <= encoded_len, "invalid archive length");

        let mut slice = &buf[..n];
        if carry_len > 0 {
            let need = 4 - carry_len;
            let take = need.min(slice.len());
            carry[carry_len..carry_len + take].copy_from_slice(&slice[..take]);
            carry_len += take;
            slice = &slice[take..];
            if carry_len == 4 {
                decoded_chunk.clear();
                STANDARD.decode_vec(&carry[..4], &mut decoded_chunk)?;
                hasher.update(&decoded_chunk);
                decoded_total += decoded_chunk.len();
                carry_len = 0;
            }
        }
        let aligned = slice.len() - (slice.len() % 4);
        if aligned > 0 {
            decoded_chunk.clear();
            STANDARD.decode_vec(&slice[..aligned], &mut decoded_chunk)?;
            hasher.update(&decoded_chunk);
            decoded_total += decoded_chunk.len();
        }
        let rem = &slice[aligned..];
        if !rem.is_empty() {
            carry[..rem.len()].copy_from_slice(rem);
            carry_len = rem.len();
        }
    }

    ensure!(
        carry_len == 0
            && encoded_total == encoded_len
            && decoded_total == receipt.bytes
            && hex::encode(hasher.finalize()) == receipt.sha256,
        "archive readback failed"
    );
    Ok(())
}

fn unpack(path: &Path, expected: Uuid) -> Result<(Receipt, Vec<u8>)> {
    let mut reader = BufReader::new(regular_file(path, false)?);
    let receipt = header(&mut reader, expected)?;
    let encoded_len = receipt.bytes.div_ceil(3) * 4;
    let mut encoded = Vec::new();
    reader
        .take((encoded_len + 1) as u64)
        .read_to_end(&mut encoded)?;
    ensure!(
        encoded.len() == encoded_len && encoded.len() <= ENCODED_LIMIT,
        "invalid archive length"
    );
    let bytes = STANDARD.decode(encoded)?;
    ensure!(
        bytes.len() == receipt.bytes && digest(&bytes) == receipt.sha256,
        "archive integrity check failed"
    );
    Ok((receipt, bytes))
}

pub fn quarantine(dir: &Path, path: &Path, expected: &str, engine: &Engine) -> Result<Receipt> {
    let path = disk_path(path)?;
    let parent = path.parent().context("file needs a parent")?;
    check_directories(parent)?;
    check_directories(dir)?;
    let (file, zone) = quarantine_file(&path)?;
    let bytes = read_bytes(&file)?;
    let verdict = engine.inspect(&path, &bytes);
    ensure!(
        verdict.sha256.eq_ignore_ascii_case(expected),
        "reviewed SHA-256 differs from current bytes"
    );
    ensure!(
        !verdict.findings.is_empty(),
        "no matching rule or provider finding"
    );
    ensure!(
        verdict.provider_error.is_none(),
        "requested AMSI check incomplete"
    );
    fs::create_dir_all(dir)?;
    ensure!(!is_inside_dir(parent, dir)?, "file already inside vault");
    let id = Uuid::new_v4();
    let byte_len = bytes.len();
    let receipt = Receipt {
        format: "larchscan/2".into(),
        id,
        original: path,
        sha256: verdict.sha256,
        bytes: byte_len,
        findings: verdict.findings,
        quarantined_at: Some(unix_now()),
        zone_identifier_b64: zone.map(|z| STANDARD.encode(z)),
    };
    let dest = item_path(dir, id);
    let mut staged = NamedTempFile::new_in(dir)?;
    let metadata = serde_json::to_vec(&receipt)?;
    ensure!(
        (metadata.len() as u64) < HEADER_LIMIT,
        "archive metadata too large"
    );
    staged.write_all(&metadata)?;
    staged.write_all(b"\n")?;
    {
        let mut encoder = EncoderWriter::new(staged.as_file_mut(), &STANDARD);
        encoder.write_all(&bytes)?;
        encoder.finish()?;
    }
    staged.as_file().sync_all()?;
    drop(bytes);
    drop(staged.persist_noclobber(&dest)?);
    // The archive survives interrupted operations and failed source removal.
    verify_archive(&dest, id, byte_len, &receipt.sha256)?;
    remove_on_close(&file)
        .with_context(|| format!("archive {id} saved; original removal failed"))?;
    drop(file);
    Ok(receipt)
}

pub fn inspect(dir: &Path, id: Uuid) -> Result<Receipt> {
    check_directories(dir)?;
    let path = item_path(dir, id);
    header(&mut BufReader::new(regular_file(&path, false)?), id)
}

pub fn list_with_warnings(dir: &Path) -> Result<ListReport> {
    check_directories(dir)?;
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ListReport::default());
        }
        Err(error) => return Err(error.into()),
    };
    let mut report = ListReport::default();
    for entry in entries {
        let path = entry?.path();
        let is_lsq = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("lsq"));
        if !is_lsq {
            continue;
        }
        let parsed = (|| -> Result<Receipt> {
            let id = Uuid::parse_str(
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .context("invalid archive name")?,
            )?;
            header(&mut BufReader::new(regular_file(&path, false)?), id)
        })();
        match parsed {
            Ok(receipt) => report.items.push(receipt),
            Err(error) => report.warnings.push(VaultWarning {
                path,
                reason: format!("{error:#}"),
            }),
        }
    }
    report.items.sort_unstable_by(|a, b| {
        b.quarantined_at
            .cmp(&a.quarantined_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(report)
}

pub fn list(dir: &Path) -> Result<Vec<Receipt>> {
    Ok(list_with_warnings(dir)?.items)
}

pub fn delete(dir: &Path, id: Uuid) -> Result<Receipt> {
    check_directories(dir)?;
    let path = item_path(dir, id);
    let file = regular_file(&path, true).context("archive not found or ineligible for removal")?;
    let receipt = header(&mut BufReader::new(&file), id)?;
    remove_on_close(&file).context("could not remove quarantine archive")?;
    drop(file);
    Ok(receipt)
}

pub fn restore(dir: &Path, id: Uuid, dest: &Path) -> Result<String> {
    check_directories(dir)?;
    let dest = disk_path(dest)?;
    let parent = dest
        .parent()
        .context("destination needs a parent directory")?;
    check_directories(parent)?;
    ensure!(
        !is_inside_dir(parent, dir)?,
        "choose a destination outside the vault"
    );
    let (receipt, bytes) = unpack(&item_path(dir, id), id)?;
    let zone_bytes = match &receipt.zone_identifier_b64 {
        Some(encoded) => {
            let decoded = STANDARD
                .decode(encoded)
                .context("archive contains invalid Zone.Identifier data")?;
            ensure!(
                decoded.len() <= MAX_ZONE_IDENTIFIER_BYTES,
                "archive Zone.Identifier exceeds size limit"
            );
            if decoded.is_empty() {
                DEFAULT_ZONE_IDENTIFIER.to_vec()
            } else {
                decoded
            }
        }
        None => DEFAULT_ZONE_IDENTIFIER.to_vec(),
    };
    let mut staged = NamedTempFile::new_in(parent)?;
    staged.write_all(&bytes)?;
    staged.as_file().sync_all()?;
    // Publish only after writing the Internet-zone marker to the same NTFS file.
    let mut zone = staged.path().as_os_str().to_os_string();
    zone.push(":Zone.Identifier");
    let mut zone_file = File::create_new(PathBuf::from(zone)).context(
        "could not write Windows Zone.Identifier stream (destination must be on an NTFS volume)",
    )?;
    zone_file.write_all(&zone_bytes)?;
    zone_file.sync_all()?;
    drop(zone_file);
    drop(
        staged
            .persist_noclobber(&dest)
            .context("restore requires a new destination file")?,
    );
    Ok(receipt.sha256)
}
