use anyhow::{Context, Result, ensure};
use larchscan::scan::Summary;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const RECORD_LIMIT: u64 = 16 * 1024 * 1024;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub amsi: bool,
    pub rules: Option<PathBuf>,
    pub schedule_minutes: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Report {
    pub id: Uuid,
    pub started: u64,
    pub scope: String,
    pub targets: Vec<String>,
    pub settings: Settings,
    pub summary: Summary,
    pub findings: Vec<serde_json::Value>,
    pub skipped: Vec<serde_json::Value>,
    pub error: Option<String>,
}

pub fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(RECORD_LIMIT + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= RECORD_LIMIT, "record is too large");
    serde_json::from_slice(&bytes).context("invalid local record")
}

pub fn write(path: &Path, data: &impl Serialize, replace: bool) -> Result<()> {
    let parent = path.parent().context("missing destination folder")?;
    let bytes = serde_json::to_vec_pretty(data)?;
    ensure!(
        bytes.len() as u64 <= RECORD_LIMIT,
        "report exceeds the storage limit"
    );
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&bytes)?;
    file.as_file().sync_all()?;
    if replace {
        file.persist(path)?;
    } else {
        file.persist_noclobber(path)
            .context("choose a new destination file")?;
    }
    Ok(())
}

pub fn history(dir: &Path) -> Result<Vec<serde_json::Value>> {
    let mut reports = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "json")
            && let Ok(report) = read::<Report>(&path)
        {
            reports.push(
                serde_json::json!({"id":report.id,"started":report.started,"scope":report.scope,
                "summary":report.summary,"error":report.error}),
            );
        }
    }
    reports.sort_unstable_by_key(|r| std::cmp::Reverse(r["started"].as_u64()));
    reports.truncate(100);
    Ok(reports)
}
