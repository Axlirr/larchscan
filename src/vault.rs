use crate::scan::{Engine, Finding, MAX_BYTES, digest, read_bytes};
use crate::windows::{disk_path, regular_file, remove_on_close};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use uuid::Uuid;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

const HEADER_LIMIT: u64 = 128 * 1024;
const ENCODED_LIMIT: usize = MAX_BYTES.div_ceil(3) * 4;

#[derive(Debug, Deserialize, Serialize)]
pub struct Receipt {
    format: String,
    pub id: Uuid,
    pub original: PathBuf,
    pub sha256: String,
    pub bytes: usize,
    pub findings: Vec<Finding>,
}

fn item_path(dir: &Path, id: Uuid) -> PathBuf {
    dir.join(format!("{id}.lsq"))
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

fn header(reader: &mut BufReader<File>, expected: Uuid) -> Result<Receipt> {
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
        receipt.format == "larchscan/1" && receipt.id == expected && receipt.bytes <= MAX_BYTES,
        "invalid archive identity or size"
    );
    Ok(receipt)
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
    check_directories(path.parent().context("file needs a parent")?)?;
    check_directories(dir)?;
    let file = regular_file(&path, true)?;
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
    ensure!(
        !path
            .parent()
            .context("missing parent")?
            .canonicalize()?
            .starts_with(dir.canonicalize()?),
        "file already inside vault"
    );
    let id = Uuid::new_v4();
    let receipt = Receipt {
        format: "larchscan/1".into(),
        id,
        original: path,
        sha256: verdict.sha256,
        bytes: bytes.len(),
        findings: verdict.findings,
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
    staged.write_all(STANDARD.encode(&bytes).as_bytes())?;
    staged.as_file().sync_all()?;
    drop(staged.persist_noclobber(&dest)?);
    // The archive survives interrupted operations and failed source removal.
    let (verified, recovered) = unpack(&dest, id)?;
    ensure!(
        recovered == bytes && verified.sha256 == receipt.sha256,
        "archive readback failed"
    );
    remove_on_close(&file)
        .with_context(|| format!("archive {id} saved; original removal failed"))?;
    drop(file);
    Ok(receipt)
}

pub fn list(dir: &Path) -> Result<Vec<Receipt>> {
    check_directories(dir)?;
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut receipts = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == "lsq") {
            let id = Uuid::parse_str(
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .context("invalid archive name")?,
            )?;
            let receipt = header(&mut BufReader::new(regular_file(&path, false)?), id)?;
            receipts.push(receipt);
        }
    }
    Ok(receipts)
}

pub fn restore(dir: &Path, id: Uuid, dest: &Path) -> Result<String> {
    check_directories(dir)?;
    let dest = disk_path(dest)?;
    let parent = dest
        .parent()
        .context("destination needs a parent directory")?;
    check_directories(parent)?;
    ensure!(
        !parent.canonicalize()?.starts_with(dir.canonicalize()?),
        "choose a destination outside the vault"
    );
    let (receipt, bytes) = unpack(&item_path(dir, id), id)?;
    let mut staged = NamedTempFile::new_in(parent)?;
    staged.write_all(&bytes)?;
    staged.as_file().sync_all()?;
    // Publish only after writing the Internet-zone marker to the same NTFS file.
    let mut zone = staged.path().as_os_str().to_os_string();
    zone.push(":Zone.Identifier");
    let mut zone_file = File::create_new(PathBuf::from(zone))?;
    zone_file.write_all(b"[ZoneTransfer]\r\nZoneId=3\r\n")?;
    zone_file.sync_all()?;
    drop(zone_file);
    drop(
        staged
            .persist_noclobber(&dest)
            .context("restore requires a new destination file")?,
    );
    Ok(receipt.sha256)
}
