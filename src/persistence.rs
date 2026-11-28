use crate::pe::SignatureStatus;
use crate::scan::{Engine, Finding, read_bytes};
use crate::windows::{read_registry_run_keys, regular_file, startup_folders};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StartupEntry {
    pub source: String,
    pub location: String,
    pub name: String,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureStatus>,
    pub target_missing: bool,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StartupReport {
    pub entries_checked: usize,
    pub flagged: usize,
    pub missing_targets: usize,
    pub entries: Vec<StartupEntry>,
}

pub fn expand_env_vars(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%'
            && let Some(end_rel) = chars[i + 1..].iter().position(|&c| c == '%')
        {
            let var_name: String = chars[i + 1..i + 1 + end_rel].iter().collect();
            if !var_name.is_empty()
                && let Ok(val) = std::env::var(&var_name)
            {
                out.push_str(&val);
                i += end_rel + 2;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

pub fn resolve_command_target(command: &str) -> Option<PathBuf> {
    let expanded = expand_env_vars(command);
    let trimmed = expanded.trim();
    if trimmed.is_empty() {
        return None;
    }
    let raw_exe = if let Some(rest) = trimmed.strip_prefix('"') {
        rest.split('"').next().unwrap_or("").trim()
    } else {
        // Handle unquoted paths that may contain spaces (e.g. C:\Program Files\App\app.exe /arg).
        let candidate = trimmed.split_whitespace().next().unwrap_or("");
        if Path::new(candidate).exists() {
            candidate
        } else {
            let lower = trimmed.to_ascii_lowercase();
            let mut found = None;
            for ext in [
                ".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".lnk", ".msi",
            ] {
                if let Some(pos) = lower.find(ext) {
                    let end = pos + ext.len();
                    let next_ok = trimmed
                        .as_bytes()
                        .get(end)
                        .is_none_or(|b| b.is_ascii_whitespace() || *b == b'"');
                    if next_ok {
                        found = Some(&trimmed[..end]);
                        break;
                    }
                }
            }
            found.unwrap_or(candidate)
        }
    };
    if raw_exe.is_empty() {
        return None;
    }
    let direct = PathBuf::from(raw_exe);
    if direct.is_absolute() {
        return Some(direct);
    }
    // Resolve bare executable names (e.g. powershell.exe) in System32/Windows.
    if let Ok(windir) = std::env::var("SystemRoot") {
        let sys32 = Path::new(&windir).join("System32").join(raw_exe);
        if sys32.exists() {
            return Some(sys32);
        }
        let sys32_exe = Path::new(&windir)
            .join("System32")
            .join(format!("{raw_exe}.exe"));
        if sys32_exe.exists() {
            return Some(sys32_exe);
        }
    }
    Some(direct)
}

fn is_script_host_name(exe_name: &str) -> bool {
    matches!(
        exe_name.to_ascii_lowercase().as_str(),
        "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
            | "wscript"
            | "wscript.exe"
            | "cscript"
            | "cscript.exe"
            | "mshta"
            | "mshta.exe"
            | "cmd"
            | "cmd.exe"
            | "rundll32"
            | "rundll32.exe"
            | "regsvr32"
            | "regsvr32.exe"
            | "certutil"
            | "certutil.exe"
    )
}

fn path_in_high_risk_drop_dir(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    lower.contains(r"\downloads\")
        || lower.contains(r"\appdata\local\temp\")
        || lower.contains(r"\windows\temp\")
        || lower.contains(r"\users\public\")
        || lower.contains(r"\$recycle.bin\")
}

fn path_in_user_writable_dir(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    lower.contains(r"\appdata\")
        || lower.contains(r"\downloads\")
        || lower.contains(r"\desktop\")
        || lower.contains(r"\temp\")
        || lower.contains(r"\users\public\")
}

pub fn evaluate_entry(
    source: &str,
    location: &str,
    name: &str,
    command: &str,
    explicit_target: Option<PathBuf>,
    engine: &Engine,
) -> StartupEntry {
    let target_path = explicit_target.or_else(|| resolve_command_target(command));
    let mut findings = Vec::new();
    let cmd_lower = command.to_ascii_lowercase();

    if let Some(exe_name) = target_path
        .as_ref()
        .and_then(|p| p.file_name())
        .and_then(|s| s.to_str())
        && is_script_host_name(exe_name)
    {
        let obfuscated = cmd_lower.contains("-enc")
            || cmd_lower.contains("-encodedcommand")
            || cmd_lower.contains("frombase64string")
            || cmd_lower.contains("-w hidden")
            || cmd_lower.contains("-windowstyle hidden")
            || cmd_lower.contains("http://")
            || cmd_lower.contains("https://");
        let reason = if obfuscated {
            format!(
                "Startup entry invokes script/system host '{exe_name}' with encoded, hidden, or remote URL arguments"
            )
        } else {
            format!(
                "Startup entry invokes script or system host '{exe_name}'; verify it is expected"
            )
        };
        findings.push(Finding {
            id: "persistence.script-host".into(),
            reason,
        });
    }

    let mut target_missing = false;
    let mut sha256 = None;
    let mut signature = None;

    if let Some(ref target) = target_path {
        if path_in_high_risk_drop_dir(target) {
            findings.push(Finding {
                id: "persistence.temp-or-downloads".into(),
                reason: "Startup target resides in a temporary, Downloads, or Public directory"
                    .into(),
            });
        }
        if target.is_absolute() && !target.exists() {
            target_missing = true;
            findings.push(Finding {
                id: "persistence.missing-target".into(),
                reason: "Startup entry references a file path that does not exist".into(),
            });
        } else if target.is_file()
            && let Ok(file) = regular_file(target, false)
            && let Ok(bytes) = read_bytes(&file)
        {
            let verdict = engine.inspect(target, &bytes);
            sha256 = Some(verdict.sha256);
            if let Some(pe) = &verdict.pe {
                signature = pe.signature.clone();
                if pe.signature == Some(SignatureStatus::Unsigned)
                    && path_in_user_writable_dir(target)
                {
                    findings.push(Finding {
                        id: "persistence.unsigned-user-binary".into(),
                        reason:
                            "Startup target is an unsigned executable in a user-writable directory"
                                .into(),
                    });
                }
            }
            findings.extend(verdict.findings);
        }
    }

    StartupEntry {
        source: source.into(),
        location: location.into(),
        name: name.into(),
        command: command.into(),
        target_path,
        sha256,
        signature,
        target_missing,
        findings,
    }
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = false;
                }
            }
            '"' => in_quotes = true,
            ',' if !in_quotes => {
                fields.push(std::mem::take(&mut current));
            }
            other => current.push(other),
        }
    }
    fields.push(current);
    fields
}

fn read_scheduled_tasks() -> Vec<(String, String)> {
    let Ok(output) = Command::new("schtasks.exe")
        .args(["/Query", "/FO", "CSV", "/V"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut lines = text.lines();
    let Some(header_line) = lines.next() else {
        return Vec::new();
    };
    let headers = parse_csv_line(header_line);
    let name_idx = headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case("TaskName"));
    let cmd_idx = headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case("Task To Run"));
    let status_idx = headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case("Status"));
    let (Some(name_idx), Some(cmd_idx)) = (name_idx, cmd_idx) else {
        return Vec::new();
    };

    let mut seen = HashSet::new();
    let mut tasks = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let cols = parse_csv_line(line);
        let Some(task_name) = cols.get(name_idx).map(|s| s.trim()) else {
            continue;
        };
        let Some(task_cmd) = cols.get(cmd_idx).map(|s| s.trim()) else {
            continue;
        };
        if task_name.is_empty()
            || task_name.eq_ignore_ascii_case("TaskName")
            || task_cmd.is_empty()
            || task_cmd.eq_ignore_ascii_case("N/A")
            || task_cmd.eq_ignore_ascii_case("COM handler")
        {
            continue;
        }
        if let Some(s_idx) = status_idx
            && cols
                .get(s_idx)
                .is_some_and(|s| s.trim().eq_ignore_ascii_case("Disabled"))
        {
            continue;
        }
        // Skip standard built-in Microsoft OS tasks unless they point into a high-risk drop folder.
        let is_ms_builtin = task_name
            .to_ascii_lowercase()
            .starts_with(r"\microsoft\windows\");
        let cmd_lower = task_cmd.to_ascii_lowercase();
        let suspicious_path = cmd_lower.contains(r"\downloads\")
            || cmd_lower.contains(r"\temp\")
            || cmd_lower.contains(r"\users\public\");
        if is_ms_builtin && !suspicious_path {
            continue;
        }
        if seen.insert((task_name.to_owned(), task_cmd.to_owned())) {
            tasks.push((task_name.to_owned(), task_cmd.to_owned()));
        }
    }
    tasks
}

pub fn scan_startup(engine: &Engine) -> StartupReport {
    let mut entries = Vec::new();

    // 1. Registry Run & RunOnce keys (HKCU + HKLM).
    for item in read_registry_run_keys() {
        entries.push(evaluate_entry(
            "Registry Run",
            &item.hive_key,
            &item.name,
            &item.command,
            None,
            engine,
        ));
    }

    // 2. Startup folders (User + Common).
    for folder in startup_folders() {
        if let Ok(read_dir) = fs::read_dir(&folder) {
            for entry in read_dir.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if name.eq_ignore_ascii_case("desktop.ini") {
                    continue;
                }
                let cmd = path.to_string_lossy().into_owned();
                entries.push(evaluate_entry(
                    "Startup folder",
                    &folder.to_string_lossy(),
                    &name,
                    &cmd,
                    Some(path),
                    engine,
                ));
            }
        }
    }

    // 3. Enabled non-OS (or suspicious-path) Windows Scheduled Tasks.
    for (task_name, task_cmd) in read_scheduled_tasks() {
        entries.push(evaluate_entry(
            "Scheduled Task",
            "Windows Task Scheduler",
            &task_name,
            &task_cmd,
            None,
            engine,
        ));
    }

    // Sort flagged entries first, then by source and name.
    entries.sort_by(|a, b| {
        b.findings
            .is_empty()
            .cmp(&a.findings.is_empty())
            .reverse()
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    let entries_checked = entries.len();
    let flagged = entries.iter().filter(|e| !e.findings.is_empty()).count();
    let missing_targets = entries.iter().filter(|e| e.target_missing).count();

    StartupReport {
        entries_checked,
        flagged,
        missing_targets,
        entries,
    }
}
