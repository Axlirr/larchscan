use anyhow::{Context, Result, ensure};
use clap::{Args, Parser, Subcommand};
use larchscan::{persistence, rules, scan, vault, windows};
use serde_json::{Value, json};
use std::fs;
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
    /// JSON file of SHA-256 rules or a larchscan-rules/1 pattern/hash bundle.
    #[arg(long)]
    rules: Option<PathBuf>,
    /// Require an Ed25519 signature on the rule bundle from this 64-hex public key.
    #[arg(long, value_name = "HEX")]
    rules_pubkey: Option<String>,
    /// Also submit non-empty file content to the installed Windows AMSI provider.
    #[arg(long)]
    amsi: bool,
}
impl Detection {
    fn load(&self) -> Result<scan::Engine> {
        scan::Engine::load_with_options(
            self.rules.as_deref(),
            self.rules_pubkey.as_deref(),
            self.amsi,
        )
    }
}

#[derive(Subcommand)]
enum RulesCommand {
    /// Generate an Ed25519 keypair for signing larchscan-rules/1 bundles.
    Keygen {
        /// Output directory for larchscan-rules.key and larchscan-rules.pub.
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a larchscan-rules/1 JSON bundle with an Ed25519 private key file.
    Sign {
        bundle: PathBuf,
        /// File containing the 64-character hex Ed25519 private key.
        #[arg(long)]
        key: PathBuf,
        /// Destination path for the signed bundle JSON.
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a signed larchscan-rules/1 JSON bundle against a trusted Ed25519 public key.
    Verify {
        bundle: PathBuf,
        /// 64-character hex Ed25519 public key.
        #[arg(long, value_name = "HEX")]
        pubkey: String,
    },
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
    /// Inspect Registry Run/RunOnce keys, Startup folders, and Scheduled Tasks.
    Startup {
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
    /// Permanently delete an archived item from the quarantine vault.
    Delete { id: Uuid },
    /// Generate keys, sign, and verify larchscan-rules/1 rule bundles.
    Rules {
        #[command(subcommand)]
        action: RulesCommand,
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
        Command::Startup { detection } => {
            let engine = detection.load()?;
            let report = persistence::scan_startup(&engine);
            for entry in &report.entries {
                emit(json!({"event": "startup_entry", "entry": entry}))?;
            }
            emit(json!({
                "event": "startup_summary",
                "entries_checked": report.entries_checked,
                "flagged": report.flagged,
                "missing_targets": report.missing_targets
            }))?;
            return Ok(if report.flagged > 0 { 1 } else { 0 });
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
        Command::Rules { action } => match action {
            RulesCommand::Keygen { out } => {
                let out = windows::disk_path(&out)?;
                fs::create_dir_all(&out)?;
                let (priv_hex, pub_hex) = rules::generate_keypair_hex()?;
                let key_path = out.join("larchscan-rules.key");
                let pub_path = out.join("larchscan-rules.pub");
                fs::write(&key_path, format!("{priv_hex}\n"))?;
                fs::write(&pub_path, format!("{pub_hex}\n"))?;
                emit(json!({
                    "event": "rules_keygen",
                    "private_key_file": key_path,
                    "public_key_file": pub_path,
                    "public_key_hex": pub_hex
                }))?;
            }
            RulesCommand::Sign { bundle, key, out } => {
                let raw = fs::read(&bundle).context("could not read rule bundle")?;
                let parsed: rules::RuleBundle =
                    serde_json::from_slice(&raw).context("invalid larchscan-rules/1 bundle")?;
                let priv_hex = fs::read_to_string(&key).context("could not read private key")?;
                let signed = rules::sign_bundle(parsed, &priv_hex)?;
                let out_path = windows::disk_path(&out)?;
                fs::write(&out_path, serde_json::to_vec_pretty(&signed)?)?;
                emit(json!({
                    "event": "rules_signed",
                    "out": out_path,
                    "public_key_hex": signed.signature.as_ref().map(|s| &s.public_key_hex)
                }))?;
            }
            RulesCommand::Verify { bundle, pubkey } => {
                let raw = fs::read(&bundle).context("could not read rule bundle")?;
                let parsed: rules::RuleBundle =
                    serde_json::from_slice(&raw).context("invalid larchscan-rules/1 bundle")?;
                rules::verify_bundle_signature(&parsed, &pubkey)?;
                emit(json!({
                    "event": "rules_verified",
                    "bundle": bundle,
                    "version": parsed.version,
                    "publisher": parsed.publisher,
                    "hashes": parsed.hashes.len(),
                    "patterns": parsed.patterns.len()
                }))?;
            }
        },
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
