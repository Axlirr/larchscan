use anyhow::{Context, Result};
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
        Command::Scan { path, detection } => {
            let summary = scan::tree(
                &detection.load()?,
                &path,
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
            for receipt in vault::list(&vault()?)? {
                emit(json!({"event":"archived","receipt":receipt}))?;
            }
        }
        Command::Restore { id, to } => {
            let sha256 = vault::restore(&vault()?, id, &to)?;
            emit(json!({"event":"restored","id":id,"to":to,"sha256":sha256}))?;
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
