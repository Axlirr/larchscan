use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use larchscan::{scan, vault, windows};
use serde_json::{Value, json};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use uuid::Uuid;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Private quarantine folder (default %LOCALAPPDATA%/LarchScan/vault).
    #[arg(long, global = true)]
    vault: Option<PathBuf>,
}

#[derive(Args)]
struct Detection {
    /// JSON file of analyst-supplied SHA-256 rules.
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Also submit file content to the installed Windows AMSI provider.
    #[arg(long)]
    amsi: bool,
}
impl Detection {
    fn load(&self) -> Result<scan::Engine> {
        scan::Engine::load(self.rules.as_deref(), self.amsi)
    }
}

#[derive(Subcommand)]
enum Command {
    /// Inspect a file or directory and emit JSON Lines evidence.
    Scan {
        path: PathBuf,
        #[command(flatten)]
        detection: Detection,
        /// Maximum file size to scan in MiB (default 32, range 1..=1024).
        #[arg(long, value_name = "MB")]
        max_mb: Option<usize>,
        /// Exclude a directory or file path from traversal (repeatable).
        #[arg(long, value_name = "PATH")]
        exclude: Vec<PathBuf>,
    },
    /// Recheck a finding and archive its bytes before removing the original.
    Quarantine {
        path: PathBuf,
        /// SHA-256 from the reviewed scan finding.
        #[arg(long)]
        expect: String,
        #[command(flatten)]
        detection: Detection,
    },
    /// List archived items and the evidence recorded for each one.
    List,
    /// Restore verified bytes to a new file and keep the archive.
    Restore {
        id: Uuid,
        #[arg(long)]
        to: PathBuf,
    },
    /// Permanently delete an archived item from the quarantine vault.
    Delete { id: Uuid },
}

fn vault_dir(override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = override_path {
        return windows::disk_path(path);
    }
    let local = std::env::var_os("LOCALAPPDATA").context("set --vault or LOCALAPPDATA")?;
    Ok(PathBuf::from(local).join("LarchScan").join("vault"))
}

fn emit(event: Value) -> Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &event)?;
    writeln!(stdout)?;
    Ok(())
}

fn run() -> Result<u8> {
    let cli = Cli::parse();
    let vault = || vault_dir(cli.vault.as_deref());
    match cli.command {
        Command::Scan {
            path,
            detection,
            max_mb,
            exclude,
        } => {
            let max_bytes = match max_mb {
                Some(mb) => {
                    ensure!(
                        (1..=1024).contains(&mb),
                        "--max-mb must be between 1 and 1024"
                    );
                    mb * 1024 * 1024
                }
                None => scan::MAX_BYTES,
            };
            let options = scan::ScanOptions { max_bytes, exclude };
            let summary = scan::tree_with_options(
                &detection.load()?,
                &path,
                &options,
                || false,
                |event| emit(serde_json::to_value(event)?),
            )?;
            emit(json!({
                "event":"summary", "files_scanned":summary.files_scanned,
                "files_with_findings":summary.files_with_findings, "incomplete":summary.incomplete
            }))?;
            return Ok(summary.exit_code());
        }
        Command::Quarantine {
            path,
            expect,
            detection,
        } => emit(
            json!({"event":"quarantined","receipt":vault::quarantine(&vault()?, &path, &expect, &detection.load()?)?}),
        )?,
        Command::List => {
            let report = vault::list_with_warnings(&vault()?)?;
            for warning in report.warnings {
                eprintln!(
                    "warning: skipped {}: {}",
                    warning.path.display(),
                    warning.reason
                );
            }
            for receipt in report.items {
                emit(json!({"event":"archived","receipt":receipt}))?;
            }
        }
        Command::Restore { id, to } => {
            let sha256 = vault::restore(&vault()?, id, &to)?;
            emit(json!({"event":"restored","id":id,"to":to,"sha256":sha256}))?;
        }
        Command::Delete { id } => {
            let receipt = vault::delete(&vault()?, id)?;
            emit(json!({"event":"deleted","receipt":receipt}))?;
        }
    }
    Ok(0)
}

fn main() -> ExitCode {
    match run() {
        Ok(status) => ExitCode::from(status),
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::from(2)
        }
    }
}
