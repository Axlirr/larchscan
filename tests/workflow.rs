use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::{Compression, write::DeflateEncoder};
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
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

fn build_zip(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for &(name, data, deflate) in entries {
        let local_offset = out.len() as u32;
        let (method, payload) = if deflate {
            let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
            enc.write_all(data).unwrap();
            (8u16, enc.finish().unwrap())
        } else {
            (0u16, data.to_vec())
        };
        let name_bytes = name.as_bytes();
        // Local file header
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // crc unused by our reader
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(&payload);

        // Central directory entry
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&local_offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }
    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);

    // End of central directory
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
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
fn zip_archive_inspection_flags_nested_disguised_files_and_fixtures() {
    let lab = Lab::new();
    let bad_zip = lab.root.path().join("attachments.zip");
    let bytes = build_zip(&[
        ("readme.txt", b"normal notes", false),
        ("nested/invoice.pdf.lnk", b"shortcut bytes", true),
        ("nested/demo.txt", DEMO, true),
    ]);
    fs::write(&bad_zip, bytes).unwrap();

    let events = records(lab.run(&["scan".as_ref(), bad_zip.as_os_str()], 1));
    assert_eq!(events[0]["verdict"]["archive_entries"], 3);
    let ids: Vec<&str> = events[0]["verdict"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"archive.triage.double-extension-script"));
    assert!(ids.contains(&"archive.demo.fixture"));

    let clean_zip = lab.root.path().join("clean.zip");
    fs::write(&clean_zip, build_zip(&[("notes.txt", b"harmless", true)])).unwrap();
    let clean_events = records(lab.run(&["scan".as_ref(), clean_zip.as_os_str()], 0));
    assert_eq!(clean_events[0]["verdict"]["archive_entries"], 1);
    assert_eq!(clean_events[0]["verdict"]["findings"], json!([]));
}

#[test]
fn signed_pattern_rule_bundle_keygen_sign_verify_and_tamper_rejection() {
    let lab = Lab::new();
    let keys_dir = lab.root.path().join("keys");
    let kg = records(lab.run(
        &[
            "rules".as_ref(),
            "keygen".as_ref(),
            "--out".as_ref(),
            keys_dir.as_os_str(),
        ],
        0,
    ));
    let pubkey = kg[0]["public_key_hex"].as_str().unwrap().to_owned();
    let priv_file = keys_dir.join("larchscan-rules.key");

    let unsigned_bundle = lab.root.path().join("bundle.json");
    let signed_bundle = lab.root.path().join("bundle.signed.json");
    let bundle_json = json!({
        "format": "larchscan-rules/1",
        "version": "2026.11.28",
        "publisher": "Test Team",
        "hashes": [],
        "patterns": [
            {
                "id": "pat.demo-cradle",
                "reason": "Matched custom pattern test strings",
                "extensions": ["ps1", "txt"],
                "match_all": true,
                "strings": [
                    {"kind": "ascii_nocase", "value": "FromBase64String"},
                    {"kind": "hex", "value": "57 52 49 54 45"}
                ]
            }
        ]
    });
    fs::write(&unsigned_bundle, bundle_json.to_string()).unwrap();

    lab.run(
        &[
            "rules".as_ref(),
            "sign".as_ref(),
            unsigned_bundle.as_os_str(),
            "--key".as_ref(),
            priv_file.as_os_str(),
            "--out".as_ref(),
            signed_bundle.as_os_str(),
        ],
        0,
    );
    lab.run(
        &[
            "rules".as_ref(),
            "verify".as_ref(),
            signed_bundle.as_os_str(),
            "--pubkey".as_ref(),
            pubkey.as_ref(),
        ],
        0,
    );

    let script = lab.root.path().join("probe.ps1");
    fs::write(&script, b"WRITE [Convert]::frombase64string('ok')").unwrap();
    let matched = records(lab.run(
        &[
            "scan".as_ref(),
            script.as_os_str(),
            "--rules".as_ref(),
            signed_bundle.as_os_str(),
            "--rules-pubkey".as_ref(),
            pubkey.as_ref(),
        ],
        1,
    ));
    assert_eq!(
        matched[0]["verdict"]["findings"][0]["id"],
        "pat.demo-cradle"
    );

    // Unsigned bundle fails closed when --rules-pubkey is supplied.
    lab.run(
        &[
            "scan".as_ref(),
            script.as_os_str(),
            "--rules".as_ref(),
            unsigned_bundle.as_os_str(),
            "--rules-pubkey".as_ref(),
            pubkey.as_ref(),
        ],
        2,
    );

    // Tampered signed bundle fails closed.
    let tampered_text = fs::read_to_string(&signed_bundle)
        .unwrap()
        .replace("Test Team", "Evil Team");
    let tampered = lab.root.path().join("bundle.tampered.json");
    fs::write(&tampered, tampered_text).unwrap();
    lab.run(
        &[
            "scan".as_ref(),
            script.as_os_str(),
            "--rules".as_ref(),
            tampered.as_os_str(),
            "--rules-pubkey".as_ref(),
            pubkey.as_ref(),
        ],
        2,
    );
}

#[test]
fn startup_command_emits_valid_jsonl_summary() {
    let out = Command::new(env!("CARGO_BIN_EXE_larchscan"))
        .arg("startup")
        .output()
        .unwrap();
    let code = out.status.code().unwrap();
    assert!(
        code == 0 || code == 1,
        "unexpected startup exit code {code}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let events = records(out);
    assert_eq!(events.last().unwrap()["event"], "startup_summary");
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
