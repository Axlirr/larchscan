use anyhow::{Context, Result, ensure};
use larchscan::scan::Summary;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const MAX_HISTORY: usize = 100;
const RECORD_LIMIT: u64 = 16 * 1024 * 1024;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub amsi: bool,
    pub rules: Option<PathBuf>,
    pub rules_pubkey: Option<String>,
    pub schedule_minutes: u64,
    pub background_scheduler: bool,
    pub minimize_to_tray: bool,
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
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(reports),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let path = entry?.path();
        let is_json = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
        if is_json && let Ok(report) = read::<Report>(&path) {
            reports.push(serde_json::json!({
                "id": report.id,
                "started": report.started,
                "scope": report.scope,
                "summary": report.summary,
                "error": report.error
            }));
        }
    }
    reports.sort_unstable_by_key(|r| std::cmp::Reverse(r["started"].as_u64()));
    reports.truncate(MAX_HISTORY);
    Ok(reports)
}

pub fn prune_history(dir: &Path, keep: usize) -> Result<usize> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    let mut records: Vec<(u64, PathBuf)> = Vec::new();
    for entry in entries {
        let path = entry?.path();
        let is_json = path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"));
        if is_json && let Ok(report) = read::<Report>(&path) {
            records.push((report.started, path));
        }
    }
    if records.len() <= keep {
        return Ok(0);
    }
    records.sort_unstable_by_key(|b| std::cmp::Reverse(b.0));
    let mut removed = 0usize;
    for (_, path) in records.into_iter().skip(keep) {
        if fs::remove_file(path).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

pub fn delete_report(dir: &Path, id: Uuid) -> Result<()> {
    let path = dir.join(format!("{id}.json"));
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

pub fn clear_history(dir: &Path) -> Result<usize> {
    prune_history(dir, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report(started: u64) -> Report {
        Report {
            id: Uuid::new_v4(),
            started,
            scope: "Test scan".into(),
            targets: vec![r"C:\Temp".into()],
            settings: Settings::default(),
            summary: Summary::default(),
            findings: Vec::new(),
            skipped: Vec::new(),
            error: None,
        }
    }

    #[test]
    fn write_replace_and_noclobber_behave_as_expected() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("report.json");
        let first = sample_report(10);
        let second = sample_report(20);

        write(&target, &first, false).unwrap();
        assert!(write(&target, &second, false).is_err());
        write(&target, &second, true).unwrap();

        let loaded: Report = read(&target).unwrap();
        assert_eq!(loaded.started, 20);
    }

    #[test]
    fn history_sorts_newest_first_and_prunes_oldest() {
        let dir = tempfile::tempdir().unwrap();
        for ts in [100u64, 300, 200, 400] {
            let report = sample_report(ts);
            write(
                &dir.path().join(format!("{}.json", report.id)),
                &report,
                false,
            )
            .unwrap();
        }
        // Unrelated invalid JSON should not crash history() or be deleted by prune_history().
        fs::write(dir.path().join("notes.json"), b"not-a-report").unwrap();

        let rows = history(dir.path()).unwrap();
        let timestamps: Vec<u64> = rows
            .iter()
            .map(|r| r["started"].as_u64().unwrap())
            .collect();
        assert_eq!(timestamps, vec![400, 300, 200, 100]);

        let removed = prune_history(dir.path(), 2).unwrap();
        assert_eq!(removed, 2);
        assert!(dir.path().join("notes.json").exists());

        let remaining: Vec<u64> = history(dir.path())
            .unwrap()
            .iter()
            .map(|r| r["started"].as_u64().unwrap())
            .collect();
        assert_eq!(remaining, vec![400, 300]);

        let cleared = clear_history(dir.path()).unwrap();
        assert_eq!(cleared, 2);
        assert!(history(dir.path()).unwrap().is_empty());
    }
}
