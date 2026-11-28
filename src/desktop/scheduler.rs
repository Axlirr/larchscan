use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;

pub const TASK_NAME: &str = "LarchScan Quick Scan";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Clone, Debug, Default, Serialize)]
pub struct TaskStatus {
    pub registered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_run: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

pub fn sync_task(enabled: bool, minutes: u64, exe_path: &Path) -> Result<()> {
    if !enabled || minutes == 0 {
        let _ = Command::new("schtasks.exe")
            .args(["/Delete", "/TN", TASK_NAME, "/F"])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
        return Ok(());
    }

    let (schedule, modifier) = match minutes {
        30 => ("MINUTE", "30"),
        60 => ("HOURLY", "1"),
        240 => ("HOURLY", "4"),
        1440 => ("DAILY", "1"),
        _ => bail!("unsupported schedule interval"),
    };

    let task_run = format!("\"{}\" --background-quick", exe_path.display());
    let output = Command::new("schtasks.exe")
        .args([
            "/Create", "/F", "/TN", TASK_NAME, "/TR", &task_run, "/SC", schedule, "/MO", modifier,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .context("failed to run Windows Task Scheduler (schtasks.exe)")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        bail!("could not register Windows Task Scheduler job: {detail}");
    }
    Ok(())
}

pub fn query_status() -> TaskStatus {
    let Ok(output) = Command::new("schtasks.exe")
        .args(["/Query", "/TN", TASK_NAME, "/FO", "CSV", "/NH"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    else {
        return TaskStatus::default();
    };
    if !output.status.success() {
        return TaskStatus::default();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let Some(line) = text.lines().find(|l| !l.trim().is_empty()) else {
        return TaskStatus::default();
    };
    let cols: Vec<String> = line
        .split("\",\"")
        .map(|s| s.trim_matches('"').trim().to_owned())
        .collect();
    TaskStatus {
        registered: true,
        next_run: cols.get(1).cloned().filter(|s| !s.is_empty()),
        state: cols.get(2).cloned().filter(|s| !s.is_empty()),
    }
}
