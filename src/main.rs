mod scan;
mod vault;
mod windows;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use serde_json::Value;
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
        Command::Scan { path, detection } => return scan::tree(&detection.load()?, &path),
        Command::Quarantine {
            path,
            expect,
            detection,
        } => vault::quarantine(&vault()?, &path, &expect, &detection.load()?)?,
        Command::List => vault::list(&vault()?)?,
        Command::Restore { id, to } => vault::restore(&vault()?, id, &to)?,
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
