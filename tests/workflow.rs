use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;
use uuid::Uuid;
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

const DEMO: &[u8] = include_bytes!("../examples/demo.txt");
const HASH: &str = "3d4d3fb8ab38ddc7a54e0eebcd574e7b4d74419d7877e206c86e9b688b8ebe8b";

struct Lab {
    root: TempDir,
    file: PathBuf,
}

impl Lab {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("sample.txt");
        fs::write(&file, DEMO).unwrap();
        Self { root, file }
    }
    fn run(&self, args: &[&OsStr], expected: i32) -> Output {
        let out = Command::new(env!("CARGO_BIN_EXE_larchscan"))
            .arg("--vault")
            .arg(self.root.path().join("vault"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(expected),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }
    fn quarantine(&self, expected: i32) -> Output {
        self.run(
            &[
                "quarantine".as_ref(),
                self.file.as_os_str(),
                "--expect".as_ref(),
                HASH.as_ref(),
            ],
            expected,
        )
    }
    fn archive(&self) -> String {
        let receipt: Value = serde_json::from_slice(&self.quarantine(0).stdout).unwrap();
        assert!(!self.file.exists());
        receipt["receipt"]["id"].as_str().unwrap().into()
    }
    fn restore(&self, id: &str, path: &Path, code: i32) {
        self.run(
            &[
                "restore".as_ref(),
                id.as_ref(),
                "--to".as_ref(),
                path.as_os_str(),
            ],
            code,
        );
    }
}

fn records(out: Output) -> Vec<Value> {
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn fixture_and_benign_neighbor_have_distinct_verdicts() {
    let lab = Lab::new();
    fs::write(lab.root.path().join("readme.txt"), b"hello").unwrap();
    let events = records(lab.run(&["scan".as_ref(), lab.root.path().as_os_str()], 1));
    assert_eq!(events[0]["verdict"]["findings"], json!([]));
    assert_eq!(events[1]["verdict"]["findings"][0]["id"], "demo.fixture");
    assert_eq!(events[1]["verdict"]["sha256"], HASH);
    assert_eq!(
        events[2],
        json!({"event":"summary","files_scanned":2,"files_with_findings":1,"incomplete":0})
    );
}

#[test]
fn quarantine_list_and_restore_bytes_without_clobbering() {
    let lab = Lab::new();
    let id = lab.archive();
    let items = records(lab.run(&["list".as_ref()], 0));
    assert_eq!(items[0]["receipt"]["id"], id);
    assert!(items[0]["receipt"]["quarantined_at"].as_u64().is_some());
    fs::write(&lab.file, b"replacement").unwrap();
    lab.restore(&id, &lab.file, 2);
    assert_eq!(fs::read(&lab.file).unwrap(), b"replacement");
    let restored = lab.root.path().join("restored.txt");
    lab.restore(&id, &restored, 0);
    assert_eq!(fs::read(&restored).unwrap(), DEMO);
    assert!(
        fs::read_to_string(format!("{}:Zone.Identifier", restored.display()))
            .unwrap()
            .contains("ZoneId=3")
    );
    assert_eq!(records(lab.run(&["list".as_ref()], 0)).len(), 1);
}

#[test]
fn zone_identifier_is_preserved_across_quarantine_restore_and_requarantine() {
    let lab = Lab::new();
    let zone = "[ZoneTransfer]\r\nZoneId=3\r\nHostUrl=https://example.invalid/demo.txt\r\n";
    fs::write(format!("{}:Zone.Identifier", lab.file.display()), zone).unwrap();

    let id = lab.archive();
    let restored = lab.root.path().join("restored-motw.txt");
    lab.restore(&id, &restored, 0);
    assert_eq!(fs::read(&restored).unwrap(), DEMO);
    let restored_zone =
        fs::read_to_string(format!("{}:Zone.Identifier", restored.display())).unwrap();
    assert_eq!(restored_zone, zone);

    // Restored files carry Zone.Identifier and can be re-quarantined cleanly.
    let second = lab.run(
        &[
            "quarantine".as_ref(),
            restored.as_os_str(),
            "--expect".as_ref(),
            HASH.as_ref(),
        ],
        0,
    );
    let second_receipt: Value = serde_json::from_slice(&second.stdout).unwrap();
    assert!(!restored.exists());
    assert!(
        second_receipt["receipt"]["zone_identifier_b64"]
            .as_str()
            .is_some()
    );
}

#[test]
fn legacy_v1_archive_can_still_be_listed_and_restored() {
    let lab = Lab::new();
    let vault = lab.root.path().join("vault");
    fs::create_dir_all(&vault).unwrap();
    let id = Uuid::new_v4();
    let header = json!({
        "format": "larchscan/1",
        "id": id,
        "original": lab.file,
        "sha256": HASH,
        "bytes": DEMO.len(),
        "findings": [{"id": "demo.fixture", "reason": "legacy fixture"}]
    });
    let archive_content = format!("{header}\n{}", STANDARD.encode(DEMO));
    fs::write(vault.join(format!("{id}.lsq")), archive_content).unwrap();

    let items = records(lab.run(&["list".as_ref()], 0));
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["receipt"]["id"], id.to_string());

    let restored = lab.root.path().join("legacy-restored.txt");
    lab.restore(&id.to_string(), &restored, 0);
    assert_eq!(fs::read(&restored).unwrap(), DEMO);
}

#[test]
fn delete_removes_archive_and_corrupt_lsq_does_not_break_healthy_items() {
    let lab = Lab::new();
    let id = lab.archive();
    fs::write(lab.root.path().join("vault").join("corrupt.lsq"), b"broken").unwrap();

    let list_out = lab.run(&["list".as_ref()], 0);
    let stderr = String::from_utf8_lossy(&list_out.stderr);
    assert!(stderr.contains("warning: skipped"));
    let items = records(list_out);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["receipt"]["id"], id);

    let del_out = lab.run(&["delete".as_ref(), id.as_ref()], 0);
    let deleted: Value = serde_json::from_slice(&del_out.stdout).unwrap();
    assert_eq!(deleted["event"], "deleted");
    assert_eq!(deleted["receipt"]["id"], id);

    assert!(records(lab.run(&["list".as_ref()], 0)).is_empty());
    lab.run(&["delete".as_ref(), id.as_ref()], 2);
}

#[test]
fn modified_archive_is_rejected_before_restoring() {
    let lab = Lab::new();
    let id = lab.archive();
    let archive = lab.root.path().join("vault").join(format!("{id}.lsq"));
    let mut bytes = fs::read(&archive).unwrap();
    let payload = bytes.iter().position(|byte| *byte == b'\n').unwrap() + 1;
    bytes[payload] = b'A';
    fs::write(&archive, bytes).unwrap();
    lab.restore(&id, &lab.file, 2);
    assert!(!lab.file.exists());
}

#[test]
fn changed_source_is_retained() {
    let lab = Lab::new();
    fs::write(&lab.file, b"replacement").unwrap();
    lab.quarantine(2);
    assert_eq!(fs::read(&lab.file).unwrap(), b"replacement");
    assert!(!lab.root.path().join("vault").exists());
}

#[test]
fn extra_stream_retains_the_original() {
    let lab = Lab::new();
    let stream = format!("{}:example", lab.file.display());
    fs::write(&stream, b"data").unwrap();
    lab.quarantine(2);
    assert_eq!(fs::read(&lab.file).unwrap(), DEMO);
    assert_eq!(fs::read(&stream).unwrap(), b"data");
}

#[test]
fn large_or_missing_input_reports_incomplete_coverage() {
    let lab = Lab::new();
    let big = lab.root.path().join("large.bin");
    fs::File::create(&big)
        .unwrap()
        .set_len(32 * 1024 * 1024 + 1)
        .unwrap();
    let events = records(lab.run(&["scan".as_ref(), lab.root.path().as_os_str()], 2));
    let summary = events.last().unwrap();
    assert_eq!(summary["incomplete"], 1);
    assert_eq!(summary["files_with_findings"], 1);
    let missing = lab.root.path().join("missing");
    let missing_events = records(lab.run(&["scan".as_ref(), missing.as_os_str()], 2));
    assert_eq!(missing_events[0]["event"], "unscanned");
}

#[test]
fn scan_supports_exclude_and_readwrite_shared_files() {
    let lab = Lab::new();
    let skipped_dir = lab.root.path().join("ignored");
    fs::create_dir(&skipped_dir).unwrap();
    fs::write(skipped_dir.join("demo-copy.txt"), DEMO).unwrap();

    let active = lab.root.path().join("active.log");
    let _writer = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&active)
        .unwrap();

    let events = records(lab.run(
        &[
            "scan".as_ref(),
            lab.root.path().as_os_str(),
            "--exclude".as_ref(),
            skipped_dir.as_os_str(),
        ],
        1,
    ));
    let summary = events.last().unwrap();
    assert_eq!(summary["files_scanned"], 2);
    assert_eq!(summary["files_with_findings"], 1);
    assert_eq!(summary["incomplete"], 0);
}

#[test]
fn empty_file_with_amsi_does_not_report_provider_error() {
    let lab = Lab::new();
    let empty = lab.root.path().join("empty.txt");
    fs::write(&empty, b"").unwrap();
    let events = records(lab.run(&["scan".as_ref(), empty.as_os_str(), "--amsi".as_ref()], 0));
    assert_eq!(events[0]["verdict"]["provider_error"], Value::Null);
    assert_eq!(events[1]["incomplete"], 0);
}

#[test]
fn custom_rules_and_invalid_digests() {
    let lab = Lab::new();
    fs::write(&lab.file, b"abc").unwrap();
    let rules = lab.root.path().join("rules.json");
    let mut rule = json!([{"id":"case.1","reason":"test indicator","sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}]);
    let args = [
        "scan".as_ref(),
        lab.file.as_os_str(),
        "--rules".as_ref(),
        rules.as_os_str(),
    ];
    fs::write(&rules, rule.to_string()).unwrap();
    assert_eq!(
        records(lab.run(&args, 1))[0]["verdict"]["findings"][0]["id"],
        "case.1"
    );
    rule[0]["sha256"] = json!("invalid");
    fs::write(&rules, rule.to_string()).unwrap();
    lab.run(&args, 2);
}

#[test]
fn document_named_executable_and_script_double_extensions_are_flagged() {
    let lab = Lab::new();
    let pe_cases = [
        "report.pdf.exe",
        "invoice.pdf .exe",
        "deck.pptx",
        "receipt.jpg.com",
    ];
    for name in pe_cases {
        let disguised = lab.root.path().join(name);
        fs::copy(env!("CARGO_BIN_EXE_larchscan"), &disguised).unwrap();
        let events = records(lab.run(&["scan".as_ref(), disguised.as_os_str()], 1));
        assert_eq!(
            events[0]["verdict"]["findings"][0]["id"], "triage.document-named-pe",
            "expected finding for {name}"
        );
    }

    let script = lab.root.path().join("statement.docx .ps1");
    fs::write(&script, b"Write-Host 'test'").unwrap();
    let script_events = records(lab.run(&["scan".as_ref(), script.as_os_str()], 1));
    assert_eq!(
        script_events[0]["verdict"]["findings"][0]["id"],
        "triage.double-extension-script"
    );

    let benign = lab.root.path().join("report.pdf.exe");
    fs::write(&benign, b"MZ just a text fixture").unwrap();
    lab.run(&["scan".as_ref(), benign.as_os_str()], 0);
}
