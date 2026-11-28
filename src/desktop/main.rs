#![windows_subsystem = "windows"]

mod scheduler;
mod storage;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use larchscan::{
    persistence::{self, StartupReport},
    rules::BundleSummary,
    scan::{self, Engine, ScanEvent, Summary},
    vault, windows,
};
use rfd::{FileDialog, MessageButtons, MessageDialog, MessageDialogResult, MessageLevel};
use scheduler::TaskStatus;
use serde::Deserialize;
use serde_json::{Value, json};
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use storage::{Report, Settings};
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy},
    window::{Icon, Window, WindowBuilder},
};
use tray_icon::{
    Icon as TrayIconImage, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};
use uuid::Uuid;
use wry::{WebContext, WebView, WebViewBuilder};

#[derive(Parser)]
#[command(
    version,
    about = "LarchScan explainable Windows file triage, startup inspection, and reversible quarantine"
)]
struct Launch {
    /// Open LarchScan and scan this file or folder.
    #[arg(long)]
    scan: Option<PathBuf>,
    /// Run a headless scheduled quick scan, save the report to local history, and exit.
    #[arg(long)]
    background_quick: bool,
}

const SAVED_ROWS: usize = 300;
const HTML: &str = include_str!("window.html");
const CSS: &str = include_str!("window.css");
const JS: &str = include_str!("window.js");
const ICON_RGBA: &[u8] = include_bytes!("../../assets/icon-32x32.rgba");
const UI_URL: &str = "http://larchscan.localhost/index.html";

enum Message {
    Request(String),
    Update(Value),
    Finished(Box<Report>),
    StartupFinished(Result<StartupReport>),
    VaultLoaded(Result<vault::ListReport>),
    HistoryLoaded(Result<Vec<Value>>),
    TaskStatusLoaded(TaskStatus),
    AmsiChecked {
        enabled: bool,
        result: Result<()>,
    },
    RulesChecked {
        path: Option<PathBuf>,
        pubkey: Option<String>,
        result: Result<BundleSummary>,
    },
    TaskSynced {
        enabled: bool,
        minutes: u64,
        result: Result<TaskStatus>,
    },
    Restored(Result<PathBuf>),
    Quarantined(Result<vault::Receipt>),
    DeletedArchive(Result<vault::Receipt>),
    TrayAction(TrayCommand),
}

enum TrayCommand {
    ShowWindow,
    QuickScan,
    StartupScan,
    Quit,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
enum Request {
    Ready,
    Quick,
    Deep,
    PickFile,
    PickFolder,
    Cancel,
    ScanStartup,
    Vault,
    History,
    OpenReport { id: Uuid },
    DeleteReport { id: Uuid },
    ClearHistory,
    Export { id: Uuid },
    SetAmsi { enabled: bool },
    SetSchedule { minutes: u64 },
    SetBackgroundScheduler { enabled: bool },
    SetMinimizeToTray { enabled: bool },
    PickRules,
    ClearRules,
    SetRulesPubkey { pubkey: String },
    Quarantine { id: Uuid, index: usize },
    QuarantineFile { path: String, sha256: String },
    Restore { id: Uuid },
    DeleteArchive { id: Uuid },
    RevealInExplorer { path: String },
    OpenDataDir,
}

struct App {
    root: PathBuf,
    history: PathBuf,
    vault: PathBuf,
    settings: Settings,
    rules_summary: Option<BundleSummary>,
    task_status: TaskStatus,
    scan: Option<Arc<AtomicBool>>,
    startup_busy: bool,
    vault_busy: bool,
    settings_busy: bool,
    next_scan: Option<Instant>,
    next_scan_epoch: Option<u64>,
    proxy: EventLoopProxy<Message>,
}

fn resolve_data_root() -> Result<PathBuf> {
    match std::env::var_os("LARCHSCAN_DATA_DIR") {
        Some(path) => windows::disk_path(Path::new(&path)),
        None => Ok(PathBuf::from(
            std::env::var_os("LOCALAPPDATA").context("missing LOCALAPPDATA")?,
        )
        .join("LarchScan")),
    }
}

fn load_settings_file(root: &Path) -> (Settings, Option<String>) {
    let config = root.join("desktop.json");
    if config.exists() {
        match storage::read::<Settings>(&config) {
            Ok(settings) => (settings, None),
            Err(error) => (
                Settings::default(),
                Some(format!(
                    "Using defaults. Settings could not be loaded ({error:#})."
                )),
            ),
        }
    } else {
        (Settings::default(), None)
    }
}

impl App {
    fn new(proxy: EventLoopProxy<Message>) -> Result<(Self, Option<String>)> {
        let root = resolve_data_root()?;
        let history = root.join("history");
        fs::create_dir_all(&history).context("cannot create local scan history")?;
        let (settings, settings_error) = load_settings_file(&root);
        let rules_summary = settings.rules.as_deref().and_then(|p| {
            Engine::load_with_options(Some(p), settings.rules_pubkey.as_deref(), false)
                .ok()
                .map(|e| e.rules_summary().clone())
        });
        let mut app = Self {
            vault: root.join("vault"),
            root,
            history,
            settings,
            rules_summary,
            task_status: TaskStatus::default(),
            scan: None,
            startup_busy: false,
            vault_busy: false,
            settings_busy: false,
            next_scan: None,
            next_scan_epoch: None,
            proxy,
        };
        app.reset_schedule();
        Ok((app, settings_error))
    }

    fn reset_schedule(&mut self) {
        match self.settings.schedule_minutes {
            minutes @ (30 | 60 | 240 | 1440) => {
                let delta = Duration::from_secs(minutes * 60);
                self.next_scan = Some(Instant::now() + delta);
                self.next_scan_epoch = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .map(|now| now.as_secs() + minutes * 60);
            }
            _ => {
                self.next_scan = None;
                self.next_scan_epoch = None;
            }
        }
    }

    fn settings_payload(&self) -> Value {
        json!({
            "amsi": self.settings.amsi,
            "rules": self.settings.rules,
            "rules_pubkey": self.settings.rules_pubkey,
            "rules_summary": self.rules_summary,
            "schedule_minutes": self.settings.schedule_minutes,
            "background_scheduler": self.settings.background_scheduler,
            "minimize_to_tray": self.settings.minimize_to_tray,
            "task_status": self.task_status,
            "next_scan_epoch": self.next_scan_epoch,
            "data_dir": self.root.to_string_lossy()
        })
    }

    fn send_settings(&self, web: &WebView) {
        send(web, "settings", self.settings_payload());
    }

    fn save_settings(&mut self, updated: Settings, web: &WebView) -> Result<()> {
        storage::write(&self.root.join("desktop.json"), &updated, true)?;
        let schedule_changed = updated.schedule_minutes != self.settings.schedule_minutes;
        self.settings = updated;
        if schedule_changed {
            self.reset_schedule();
        }
        self.send_settings(web);
        send(web, "notice", "Settings saved");
        Ok(())
    }

    fn report_file(&self, id: Uuid) -> PathBuf {
        self.history.join(format!("{id}.json"))
    }

    fn load_history_async(&self) {
        let dir = self.history.clone();
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let _ = proxy.send_event(Message::HistoryLoaded(storage::history(&dir)));
        });
    }

    fn load_vault_async(&self) {
        let dir = self.vault.clone();
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let _ = proxy.send_event(Message::VaultLoaded(vault::list_with_warnings(&dir)));
        });
    }

    fn load_task_status_async(&self) {
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let _ = proxy.send_event(Message::TaskStatusLoaded(scheduler::query_status()));
        });
    }

    fn sync_task_async(&mut self, enabled: bool, minutes: u64) -> Result<()> {
        let exe = std::env::current_exe().context("cannot determine LarchScan executable path")?;
        self.settings_busy = true;
        let proxy = self.proxy.clone();
        std::thread::spawn(move || {
            let result =
                scheduler::sync_task(enabled, minutes, &exe).map(|()| scheduler::query_status());
            let _ = proxy.send_event(Message::TaskSynced {
                enabled,
                minutes,
                result,
            });
        });
        Ok(())
    }

    fn quick(&mut self, scheduled: bool, web: &WebView) -> Result<()> {
        let paths = windows::quick_scan_folders();
        ensure!(
            !paths.is_empty(),
            "Downloads and Desktop were unavailable. Choose a folder to scan."
        );
        self.start(
            if scheduled {
                "Scheduled quick scan"
            } else {
                "Quick scan"
            },
            paths,
            scheduled,
            web,
        )
    }

    fn start_startup_scan(&mut self, web: &WebView) -> Result<()> {
        ensure!(
            !self.startup_busy && !self.vault_busy,
            "wait for the active operation"
        );
        self.startup_busy = true;
        send(web, "startup_busy", true);
        let settings = self.settings.clone();
        let proxy = self.proxy.clone();
        std::thread::Builder::new()
            .name("startup-scan".into())
            .spawn(move || {
                let result = Engine::load_with_options(
                    settings.rules.as_deref(),
                    settings.rules_pubkey.as_deref(),
                    settings.amsi,
                )
                .map(|engine| persistence::scan_startup(&engine));
                let _ = proxy.send_event(Message::StartupFinished(result));
            })?;
        Ok(())
    }

    fn start(
        &mut self,
        scope: &str,
        paths: Vec<PathBuf>,
        scheduled: bool,
        web: &WebView,
    ) -> Result<()> {
        ensure!(
            self.scan.is_none() && !self.vault_busy,
            "wait for the active operation"
        );
        let cancel = Arc::new(AtomicBool::new(false));
        let report = Report {
            id: Uuid::new_v4(),
            started: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            scope: scope.into(),
            targets: paths
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect(),
            settings: self.settings.clone(),
            summary: Summary::default(),
            findings: Vec::new(),
            skipped: Vec::new(),
            error: None,
        };
        let proxy = self.proxy.clone();
        let cancellation = cancel.clone();
        let private_root = self.root.clone();
        std::thread::Builder::new()
            .name("file-scan".into())
            .spawn(move || {
                let finished =
                    run_scan_collect(report, paths, &private_root, &cancellation, Some(&proxy));
                let _ = proxy.send_event(Message::Finished(Box::new(finished)));
            })?;
        self.scan = Some(cancel);
        send(
            web,
            "started",
            json!({"scope": scope, "scheduled": scheduled}),
        );
        Ok(())
    }

    fn launch_quarantine(
        &mut self,
        path: PathBuf,
        sha: String,
        settings: Settings,
        window: &Window,
        web: &WebView,
    ) -> Result<()> {
        ensure!(
            self.scan.is_none() && !self.vault_busy,
            "wait for the active operation"
        );
        let agreed = MessageDialog::new()
            .set_parent(window)
            .set_level(MessageLevel::Warning)
            .set_title("Quarantine file?")
            .set_description(format!(
                "Archive this file and remove it from its current location?\n\n{}",
                path.display()
            ))
            .set_buttons(MessageButtons::OkCancel)
            .show()
            == MessageDialogResult::Ok;
        if agreed {
            let proxy = self.proxy.clone();
            let dir = self.vault.clone();
            std::thread::spawn(move || {
                let result = Engine::load_with_options(
                    settings.rules.as_deref(),
                    settings.rules_pubkey.as_deref(),
                    settings.amsi,
                )
                .and_then(|engine| vault::quarantine(&dir, &path, &sha, &engine));
                let _ = proxy.send_event(Message::Quarantined(result));
            });
            self.vault_busy = true;
            send(web, "vault_busy", true);
        }
        Ok(())
    }

    fn handle(&mut self, request: Request, window: &Window, web: &WebView) -> Result<()> {
        match request {
            Request::Ready => {
                self.send_settings(web);
                self.load_history_async();
                self.load_vault_async();
                self.load_task_status_async();
            }
            Request::Quick => self.quick(false, web)?,
            Request::Deep => {
                let drive =
                    std::env::var("SystemDrive").context("Windows system drive unavailable")?;
                self.start(
                    "System drive scan",
                    vec![PathBuf::from(format!("{drive}\\"))],
                    false,
                    web,
                )?;
            }
            Request::PickFile | Request::PickFolder => {
                ensure!(
                    self.scan.is_none() && !self.vault_busy,
                    "wait for the active operation"
                );
                let dialog = FileDialog::new().set_parent(window);
                let folder = matches!(request, Request::PickFolder);
                let path = if folder {
                    dialog.set_title("Choose a folder to scan").pick_folder()
                } else {
                    dialog.set_title("Choose a file to scan").pick_file()
                };
                if let Some(path) = path {
                    self.start(
                        if folder { "Folder scan" } else { "File scan" },
                        vec![path],
                        false,
                        web,
                    )?;
                }
            }
            Request::Cancel => {
                if let Some(flag) = &self.scan {
                    flag.store(true, Ordering::Relaxed);
                }
            }
            Request::ScanStartup => self.start_startup_scan(web)?,
            Request::Vault => self.load_vault_async(),
            Request::History => self.load_history_async(),
            Request::OpenReport { id } => send(
                web,
                "report",
                storage::read::<Report>(&self.report_file(id))?,
            ),
            Request::DeleteReport { id } => {
                let agreed = MessageDialog::new()
                    .set_parent(window)
                    .set_level(MessageLevel::Warning)
                    .set_title("Delete scan report?")
                    .set_description("Remove this saved scan report from local history?")
                    .set_buttons(MessageButtons::OkCancel)
                    .show()
                    == MessageDialogResult::Ok;
                if agreed {
                    storage::delete_report(&self.history, id)?;
                    send(web, "report_deleted", id);
                    send(web, "notice", "Report removed from history");
                    self.load_history_async();
                }
            }
            Request::ClearHistory => {
                let agreed = MessageDialog::new()
                    .set_parent(window)
                    .set_level(MessageLevel::Warning)
                    .set_title("Clear scan history?")
                    .set_description(
                        "Delete all saved scan reports from local history? Quarantine archives are not affected.",
                    )
                    .set_buttons(MessageButtons::OkCancel)
                    .show()
                    == MessageDialogResult::Ok;
                if agreed {
                    let removed = storage::clear_history(&self.history)?;
                    send(web, "history_cleared", removed);
                    send(
                        web,
                        "notice",
                        format!("Cleared {removed} saved scan report(s)"),
                    );
                    self.load_history_async();
                }
            }
            Request::Export { id } => {
                let report = storage::read::<Report>(&self.report_file(id))?;
                let suggested = format!("larchscan-report-{}.json", &id.to_string()[..8]);
                if let Some(dest) = FileDialog::new()
                    .set_parent(window)
                    .set_file_name(suggested)
                    .add_filter("JSON report", &["json"])
                    .save_file()
                {
                    storage::write(&dest, &report, true)?;
                    send(web, "notice", "Report exported");
                }
            }
            Request::SetAmsi { enabled } => {
                ensure!(!self.settings_busy, "wait for settings check to finish");
                if enabled {
                    self.settings_busy = true;
                    let proxy = self.proxy.clone();
                    std::thread::spawn(move || {
                        let result = Engine::load(None, true).map(|_| ());
                        let _ = proxy.send_event(Message::AmsiChecked { enabled, result });
                    });
                } else {
                    let updated = Settings {
                        amsi: false,
                        ..self.settings.clone()
                    };
                    self.save_settings(updated, web)?;
                }
            }
            Request::SetSchedule { minutes } => {
                ensure!(
                    matches!(minutes, 0 | 30 | 60 | 240 | 1440),
                    "unsupported interval"
                );
                ensure!(!self.settings_busy, "wait for settings check to finish");
                if self.settings.background_scheduler {
                    let enable_bg = minutes > 0;
                    self.sync_task_async(enable_bg, minutes)?;
                } else {
                    let updated = Settings {
                        schedule_minutes: minutes,
                        ..self.settings.clone()
                    };
                    self.save_settings(updated, web)?;
                }
            }
            Request::SetBackgroundScheduler { enabled } => {
                ensure!(!self.settings_busy, "wait for settings check to finish");
                let minutes = if enabled && self.settings.schedule_minutes == 0 {
                    60
                } else {
                    self.settings.schedule_minutes
                };
                self.sync_task_async(enabled, minutes)?;
            }
            Request::SetMinimizeToTray { enabled } => {
                let updated = Settings {
                    minimize_to_tray: enabled,
                    ..self.settings.clone()
                };
                self.save_settings(updated, web)?;
            }
            Request::PickRules => {
                ensure!(!self.settings_busy, "wait for settings check to finish");
                let Some(path) = FileDialog::new()
                    .set_parent(window)
                    .add_filter("JSON rules", &["json"])
                    .pick_file()
                else {
                    return Ok(());
                };
                self.settings_busy = true;
                let pubkey = self.settings.rules_pubkey.clone();
                let proxy = self.proxy.clone();
                std::thread::spawn(move || {
                    let result = Engine::load_with_options(Some(&path), pubkey.as_deref(), false)
                        .context("unable to load the selected rules")
                        .map(|e| e.rules_summary().clone());
                    let _ = proxy.send_event(Message::RulesChecked {
                        path: Some(path),
                        pubkey,
                        result,
                    });
                });
            }
            Request::ClearRules => {
                ensure!(!self.settings_busy, "wait for settings check to finish");
                self.rules_summary = None;
                self.save_settings(
                    Settings {
                        rules: None,
                        ..self.settings.clone()
                    },
                    web,
                )?;
            }
            Request::SetRulesPubkey { pubkey } => {
                ensure!(!self.settings_busy, "wait for settings check to finish");
                let trimmed = pubkey.trim().to_ascii_lowercase();
                let normalized = if trimmed.is_empty() {
                    None
                } else {
                    ensure!(
                        trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()),
                        "Ed25519 public key must be 64 hex characters"
                    );
                    Some(trimmed)
                };
                if let Some(existing_rules) = self.settings.rules.clone() {
                    self.settings_busy = true;
                    let proxy = self.proxy.clone();
                    std::thread::spawn(move || {
                        let result = Engine::load_with_options(
                            Some(&existing_rules),
                            normalized.as_deref(),
                            false,
                        )
                        .context("current rule file failed verification with this public key")
                        .map(|e| e.rules_summary().clone());
                        let _ = proxy.send_event(Message::RulesChecked {
                            path: Some(existing_rules),
                            pubkey: normalized,
                            result,
                        });
                    });
                } else {
                    self.save_settings(
                        Settings {
                            rules_pubkey: normalized,
                            ..self.settings.clone()
                        },
                        web,
                    )?;
                }
            }
            Request::Quarantine { id, index } => {
                let report = storage::read::<Report>(&self.report_file(id))?;
                let finding = report
                    .findings
                    .get(index)
                    .context("finding no longer available")?;
                let path = PathBuf::from(finding["path"].as_str().context("finding has no path")?);
                let sha = finding["sha256"]
                    .as_str()
                    .context("finding has no digest")?
                    .to_owned();
                self.launch_quarantine(path, sha, report.settings, window, web)?;
            }
            Request::QuarantineFile { path, sha256 } => {
                let settings = self.settings.clone();
                self.launch_quarantine(PathBuf::from(path), sha256, settings, window, web)?;
            }
            Request::Restore { id } => {
                ensure!(
                    self.scan.is_none() && !self.vault_busy,
                    "wait for the active operation"
                );
                let item =
                    vault::inspect(&self.vault, id).context("archive no longer available")?;
                let name = item
                    .original
                    .file_name()
                    .context("archive has no original filename")?
                    .to_string_lossy();
                let Some(dest) = FileDialog::new()
                    .set_parent(window)
                    .set_title("Restore to a new file")
                    .set_file_name(name)
                    .save_file()
                else {
                    return Ok(());
                };
                let proxy = self.proxy.clone();
                let dir = self.vault.clone();
                std::thread::spawn(move || {
                    let result = vault::restore(&dir, id, &dest).map(|_| dest);
                    let _ = proxy.send_event(Message::Restored(result));
                });
                self.vault_busy = true;
                send(web, "vault_busy", true);
            }
            Request::DeleteArchive { id } => {
                ensure!(
                    self.scan.is_none() && !self.vault_busy,
                    "wait for the active operation"
                );
                let item =
                    vault::inspect(&self.vault, id).context("archive no longer available")?;
                let agreed = MessageDialog::new()
                    .set_parent(window)
                    .set_level(MessageLevel::Warning)
                    .set_title("Delete archived file permanently?")
                    .set_description(format!(
                        "Permanently delete this quarantine archive? It cannot be restored afterward.\n\n{}",
                        item.original.display()
                    ))
                    .set_buttons(MessageButtons::OkCancel)
                    .show()
                    == MessageDialogResult::Ok;
                if agreed {
                    let proxy = self.proxy.clone();
                    let dir = self.vault.clone();
                    std::thread::spawn(move || {
                        let _ = proxy.send_event(Message::DeletedArchive(vault::delete(&dir, id)));
                    });
                    self.vault_busy = true;
                    send(web, "vault_busy", true);
                }
            }
            Request::RevealInExplorer { path } => {
                let target = windows::disk_path(Path::new(&path))?;
                ensure!(target.exists(), "file no longer exists at that location");
                let mut arg = OsString::from("/select,");
                arg.push(&target);
                Command::new("explorer.exe")
                    .arg(arg)
                    .spawn()
                    .context("could not open File Explorer")?;
            }
            Request::OpenDataDir => {
                fs::create_dir_all(&self.root)?;
                Command::new("explorer.exe")
                    .arg(&self.root)
                    .spawn()
                    .context("could not open data folder")?;
            }
        }
        Ok(())
    }
}

fn run_scan_collect(
    mut report: Report,
    paths: Vec<PathBuf>,
    private_root: &Path,
    cancel: &AtomicBool,
    proxy: Option<&EventLoopProxy<Message>>,
) -> Report {
    let mut last_update = Instant::now();
    let stop = || cancel.load(Ordering::Relaxed);
    let result = (|| -> Result<()> {
        let engine = Engine::load_with_options(
            report.settings.rules.as_deref(),
            report.settings.rules_pubkey.as_deref(),
            report.settings.amsi,
        )?;
        for target in paths {
            if stop() {
                report.summary.cancelled = true;
                break;
            }
            let scope =
                scan::tree_excluding(&engine, &target, Some(private_root), stop, |event| {
                    let current = match event {
                        ScanEvent::File { path, verdict } => {
                            report.summary.files_scanned += 1;
                            if !verdict.findings.is_empty() {
                                report.summary.files_with_findings += 1;
                                if report.findings.len() < SAVED_ROWS {
                                    report.findings.push(json!({
                                        "path": path.to_string_lossy(),
                                        "sha256": verdict.sha256,
                                        "rules": verdict.findings,
                                        "amsi_result": verdict.amsi_result,
                                        "pe": verdict.pe,
                                        "archive_entries": verdict.archive_entries
                                    }));
                                }
                            }
                            if let Some(error) = verdict.provider_error {
                                report.summary.incomplete += 1;
                                if report.skipped.len() < SAVED_ROWS {
                                    report.skipped.push(
                                        json!({"path":path.to_string_lossy(),"reason":error}),
                                    );
                                }
                            }
                            path.to_string_lossy().into_owned()
                        }
                        ScanEvent::Unscanned { path, reason } => {
                            report.summary.incomplete += 1;
                            let name = path
                                .map(|path| path.to_string_lossy().into_owned())
                                .unwrap_or_default();
                            if report.skipped.len() < SAVED_ROWS {
                                report.skipped.push(json!({"path":name,"reason":reason}));
                            }
                            name
                        }
                    };
                    if let Some(proxy) = proxy
                        && last_update.elapsed() >= Duration::from_millis(180)
                    {
                        last_update = Instant::now();
                        let _ = proxy.send_event(Message::Update(
                            json!({"summary":report.summary,"current":current}),
                        ));
                    }
                    Ok(())
                })?;
            report.summary.cancelled |= scope.cancelled;
        }
        Ok(())
    })();
    if let Err(error) = result {
        report.error = Some(format!("{error:#}"));
    }
    report
}

fn run_background_quick_scan() -> Result<()> {
    let root = resolve_data_root()?;
    let history = root.join("history");
    fs::create_dir_all(&history)?;

    // Exclusive non-blocking lockfile prevents overlapping background scans.
    let lock_path = root.join("background-scan.lock");
    let Ok(_lock) = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(&lock_path)
    else {
        return Ok(());
    };

    let (settings, _) = load_settings_file(&root);
    let paths = windows::quick_scan_folders();
    if paths.is_empty() {
        return Ok(());
    }
    let report = Report {
        id: Uuid::new_v4(),
        started: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        scope: "Background quick scan".into(),
        targets: paths
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect(),
        settings,
        summary: Summary::default(),
        findings: Vec::new(),
        skipped: Vec::new(),
        error: None,
    };
    let cancel = AtomicBool::new(false);
    let finished = run_scan_collect(report, paths, &root, &cancel, None);
    let _ = storage::write(
        &history.join(format!("{}.json", finished.id)),
        &finished,
        false,
    );
    let _ = storage::prune_history(&history, storage::MAX_HISTORY);
    Ok(())
}

fn setup_tray(proxy: EventLoopProxy<Message>) -> Option<TrayIcon> {
    let open_item = MenuItem::with_id("open", "Open LarchScan", true, None);
    let quick_item = MenuItem::with_id("quick", "Start quick scan", true, None);
    let startup_item = MenuItem::with_id("startup", "Scan startup items", true, None);
    let quit_item = MenuItem::with_id("quit", "Quit LarchScan", true, None);
    let menu = Menu::new();
    let _ = menu.append(&open_item);
    let _ = menu.append(&quick_item);
    let _ = menu.append(&startup_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&quit_item);

    let icon = TrayIconImage::from_rgba(ICON_RGBA.to_vec(), 32, 32).ok()?;
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("LarchScan — Windows security tools")
        .with_icon(icon)
        .build()
        .ok()?;

    let proxy_click = proxy.clone();
    TrayIconEvent::set_event_handler(Some(move |event| {
        if let TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } = event
        {
            let _ = proxy_click.send_event(Message::TrayAction(TrayCommand::ShowWindow));
        }
    }));

    MenuEvent::set_event_handler(Some(Arc::new(move |event: MenuEvent| {
        let cmd = match event.id().as_ref() {
            "open" => Some(TrayCommand::ShowWindow),
            "quick" => Some(TrayCommand::QuickScan),
            "startup" => Some(TrayCommand::StartupScan),
            "quit" => Some(TrayCommand::Quit),
            _ => None,
        };
        if let Some(cmd) = cmd {
            let _ = proxy.send_event(Message::TrayAction(cmd));
        }
    })));

    Some(tray)
}

fn send(web: &WebView, event: &str, data: impl serde::Serialize) {
    if let Ok(value) = serde_json::to_string(&json!({"event":event,"data":data})) {
        let _ = web.evaluate_script(&format!("window.receive?.({value})"));
    }
}

fn reveal_window(window: &Window) {
    window.set_visible(true);
    window.set_minimized(false);
    window.set_focus();
}

fn run() -> Result<()> {
    let args = match Launch::try_parse() {
        Ok(args) => args,
        Err(error) => {
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                MessageDialog::new()
                    .set_title("LarchScan")
                    .set_level(MessageLevel::Info)
                    .set_description(error.to_string())
                    .show();
                return Ok(());
            }
            return Err(error.into());
        }
    };
    if args.background_quick {
        return run_background_quick_scan();
    }

    let mut launch_scan = args.scan;
    let events = EventLoopBuilder::<Message>::with_user_event().build();
    let proxy = events.create_proxy();
    let (mut app, settings_error) = App::new(proxy.clone())?;
    let window_icon = Icon::from_rgba(ICON_RGBA.to_vec(), 32, 32).ok();
    let window = WindowBuilder::new()
        .with_title("LarchScan")
        .with_window_icon(window_icon)
        .with_inner_size(LogicalSize::new(1180, 820))
        .with_min_inner_size(LogicalSize::new(760, 570))
        .build(&events)?;
    let _tray = setup_tray(proxy.clone());
    let icon = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        include_bytes!("../../docs/images/larchscan-icon.png"),
    );
    let html = HTML
        .replace("/* APP_CSS */", CSS)
        .replace("/* APP_JS */", JS)
        .replace("APP_ICON_BASE64", &icon);
    let mut context = WebContext::new(Some(app.root.join("webview")));
    let web = WebViewBuilder::new_with_web_context(&mut context)
        .with_custom_protocol("larchscan".into(), move |_, request| {
            if request.method() == wry::http::Method::GET && request.uri().path() == "/index.html" {
                let mut response = wry::http::Response::new(html.as_bytes().to_vec().into());
                response.headers_mut().insert(
                    wry::http::header::CONTENT_TYPE,
                    wry::http::HeaderValue::from_static("text/html; charset=utf-8"),
                );
                response
            } else {
                let mut response = wry::http::Response::new(std::borrow::Cow::Borrowed(&[][..]));
                *response.status_mut() = wry::http::StatusCode::NOT_FOUND;
                response
            }
        })
        .with_url("larchscan://localhost/index.html")
        .with_background_color((15, 25, 22, 255))
        .with_devtools(false)
        .with_back_forward_navigation_gestures(false)
        .with_navigation_handler(|url| url == UI_URL)
        .with_new_window_req_handler(|_, _| wry::NewWindowResponse::Deny)
        .with_ipc_handler(move |request| {
            if request.body().len() <= 8192 && request.uri() == UI_URL {
                let _ = proxy.send_event(Message::Request(request.into_body()));
            }
        })
        .build(&window)?;
    let mut settings_error = settings_error;
    events.run(move |event, _, flow| {
        if matches!(*flow, ControlFlow::Exit) {
            return;
        }
        let _keep_tray_alive = &_tray;
        *flow = app
            .next_scan
            .map_or(ControlFlow::Wait, ControlFlow::WaitUntil);
        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if app.settings.minimize_to_tray {
                    window.set_visible(false);
                } else if app.vault_busy {
                    send(
                        &web,
                        "error",
                        "Wait for the vault operation to finish before leaving.",
                    );
                } else if app.scan.is_some() {
                    send(
                        &web,
                        "error",
                        "Stop the scan and wait for its report before leaving.",
                    );
                } else {
                    *flow = ControlFlow::Exit;
                }
            }
            Event::UserEvent(Message::TrayAction(cmd)) => match cmd {
                TrayCommand::ShowWindow => reveal_window(&window),
                TrayCommand::QuickScan => {
                    reveal_window(&window);
                    if let Err(error) = app.quick(false, &web) {
                        send(&web, "error", format!("{error:#}"));
                    }
                }
                TrayCommand::StartupScan => {
                    reveal_window(&window);
                    send(&web, "navigate", "startup");
                    if let Err(error) = app.start_startup_scan(&web) {
                        send(&web, "error", format!("{error:#}"));
                    }
                }
                TrayCommand::Quit => {
                    if app.vault_busy || app.scan.is_some() {
                        reveal_window(&window);
                        send(
                            &web,
                            "error",
                            "Stop active scans or wait for vault operations before quitting.",
                        );
                    } else {
                        *flow = ControlFlow::Exit;
                    }
                }
            },
            Event::UserEvent(Message::Request(raw)) => {
                let request = serde_json::from_str::<Request>(&raw);
                let ready = matches!(request, Ok(Request::Ready));
                let result = request
                    .map_err(anyhow::Error::from)
                    .and_then(|req| app.handle(req, &window, &web));
                if let Err(error) = result {
                    send(&web, "error", format!("{error:#}"));
                }
                if ready && let Some(error) = settings_error.take() {
                    send(&web, "error", error);
                }
                if ready
                    && let Some(path) = launch_scan.take()
                    && let Err(error) = app.start("Custom scan", vec![path], false, &web)
                {
                    send(&web, "error", format!("{error:#}"));
                }
            }
            Event::UserEvent(Message::Update(data)) => send(&web, "progress", data),
            Event::UserEvent(Message::Finished(report)) => {
                app.scan = None;
                let saved = storage::write(&app.report_file(report.id), &report, false);
                if saved.is_ok() {
                    let _ = storage::prune_history(&app.history, storage::MAX_HISTORY);
                }
                send(
                    &web,
                    "finished",
                    json!({"report":report,"saved":saved.is_ok()}),
                );
                if let Err(error) = saved {
                    send(
                        &web,
                        "error",
                        format!("Could not save the scan report. {error:#}"),
                    );
                } else {
                    app.load_history_async();
                }
            }
            Event::UserEvent(Message::StartupFinished(result)) => {
                app.startup_busy = false;
                send(&web, "startup_busy", false);
                match result {
                    Ok(report) => send(&web, "startup_report", report),
                    Err(error) => send(&web, "error", format!("{error:#}")),
                }
            }
            Event::UserEvent(Message::VaultLoaded(result)) => match result {
                Ok(report) => send(&web, "vault", report),
                Err(error) => send(&web, "error", format!("{error:#}")),
            },
            Event::UserEvent(Message::HistoryLoaded(result)) => match result {
                Ok(rows) => send(&web, "history", rows),
                Err(error) => send(&web, "error", format!("{error:#}")),
            },
            Event::UserEvent(Message::TaskStatusLoaded(status)) => {
                app.task_status = status;
                app.send_settings(&web);
            }
            Event::UserEvent(Message::AmsiChecked { enabled, result }) => {
                app.settings_busy = false;
                match result {
                    Ok(()) => {
                        let updated = Settings {
                            amsi: enabled,
                            ..app.settings.clone()
                        };
                        if let Err(error) = app.save_settings(updated, &web) {
                            send(&web, "error", format!("{error:#}"));
                        }
                    }
                    Err(error) => {
                        app.send_settings(&web);
                        send(&web, "error", format!("{error:#}"));
                    }
                }
            }
            Event::UserEvent(Message::RulesChecked {
                path,
                pubkey,
                result,
            }) => {
                app.settings_busy = false;
                match result {
                    Ok(summary) => {
                        app.rules_summary = Some(summary);
                        let updated = Settings {
                            rules: path,
                            rules_pubkey: pubkey,
                            ..app.settings.clone()
                        };
                        if let Err(error) = app.save_settings(updated, &web) {
                            send(&web, "error", format!("{error:#}"));
                        }
                    }
                    Err(error) => {
                        app.send_settings(&web);
                        send(&web, "error", format!("{error:#}"));
                    }
                }
            }
            Event::UserEvent(Message::TaskSynced {
                enabled,
                minutes,
                result,
            }) => {
                app.settings_busy = false;
                match result {
                    Ok(status) => {
                        app.task_status = status;
                        let updated = Settings {
                            background_scheduler: enabled && minutes > 0,
                            schedule_minutes: minutes,
                            ..app.settings.clone()
                        };
                        if let Err(error) = app.save_settings(updated, &web) {
                            send(&web, "error", format!("{error:#}"));
                        }
                    }
                    Err(error) => {
                        app.send_settings(&web);
                        send(&web, "error", format!("{error:#}"));
                    }
                }
            }
            Event::UserEvent(Message::Quarantined(result)) => {
                app.vault_busy = false;
                send(&web, "vault_busy", false);
                match result {
                    Ok(item) => {
                        send(&web, "quarantined", item);
                        app.load_vault_async();
                    }
                    Err(error) => send(&web, "error", format!("{error:#}")),
                }
            }
            Event::UserEvent(Message::Restored(result)) => {
                app.vault_busy = false;
                send(&web, "vault_busy", false);
                match result {
                    Ok(dest) => send(&web, "notice", format!("Restored to {}", dest.display())),
                    Err(error) => send(&web, "error", format!("{error:#}")),
                }
            }
            Event::UserEvent(Message::DeletedArchive(result)) => {
                app.vault_busy = false;
                send(&web, "vault_busy", false);
                match result {
                    Ok(item) => {
                        send(
                            &web,
                            "notice",
                            format!("Deleted archived copy of {}", item.original.display()),
                        );
                        app.load_vault_async();
                    }
                    Err(error) => send(&web, "error", format!("{error:#}")),
                }
            }
            Event::MainEventsCleared
                if app.next_scan.is_some_and(|time| time <= Instant::now()) =>
            {
                app.reset_schedule();
                app.send_settings(&web);
                if app.scan.is_none()
                    && !app.vault_busy
                    && let Err(error) = app.quick(true, &web)
                {
                    send(
                        &web,
                        "error",
                        format!("Scheduled scan could not start. {error:#}"),
                    );
                }
            }
            _ => (),
        }
        if !matches!(*flow, ControlFlow::Exit) {
            *flow = app
                .next_scan
                .map_or(ControlFlow::Wait, ControlFlow::WaitUntil);
        }
    });
}

fn main() {
    if let Err(error) = run() {
        MessageDialog::new()
            .set_title("LarchScan could not start")
            .set_level(MessageLevel::Error)
            .set_description(format!("{error:#}"))
            .show();
    }
}
