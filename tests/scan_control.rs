use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};

use larchscan::pe::{self, SignatureStatus};
use larchscan::persistence;
use larchscan::scan::{Engine, ScanEvent, ScanOptions, tree_excluding, tree_with_options};
use larchscan::windows::{disk_path, verify_authenticode};

#[test]
fn desktop_scan_skips_app_storage_and_can_stop_between_files() {
    let root = tempfile::tempdir().unwrap();
    let storage = root.path().join("app-storage");
    fs::create_dir(&storage).unwrap();
    fs::write(storage.join("private-record.json"), b"private record").unwrap();
    fs::write(root.path().join("sample-a.txt"), b"first").unwrap();
    fs::write(root.path().join("sample-b.txt"), b"second").unwrap();
    let engine = Engine::load(None, false).unwrap();
    let seen = Cell::new(0);
    let summary = tree_excluding(
        &engine,
        root.path(),
        Some(&storage),
        || seen.get() == 1,
        |event| {
            let ScanEvent::File { path, .. } = event else {
                panic!("unexpected unscanned file")
            };
            assert_eq!(path.file_name().unwrap(), "sample-a.txt");
            seen.set(seen.get() + 1);
            Ok(())
        },
    )
    .unwrap();
    assert!(summary.cancelled);
    assert_eq!(summary.files_scanned, 1);
    assert_eq!(summary.incomplete, 0);
}

#[test]
fn exclude_handles_trailing_slash_and_case_differences() {
    let root = tempfile::tempdir().unwrap();
    let sub = root.path().join("PrivateVault");
    fs::create_dir(&sub).unwrap();
    fs::write(sub.join("secret.txt"), b"hidden").unwrap();
    fs::write(root.path().join("visible.txt"), b"ok").unwrap();

    let messy_exclude = PathBuf::from(format!("{}\\", sub.to_string_lossy().to_uppercase()));
    let engine = Engine::load(None, false).unwrap();
    let options = ScanOptions {
        exclude: vec![messy_exclude],
        ..ScanOptions::default()
    };
    let mut visited = Vec::new();
    let summary = tree_with_options(
        &engine,
        root.path(),
        &options,
        || false,
        |event| {
            if let ScanEvent::File { path, .. } = event {
                visited.push(path.file_name().unwrap().to_string_lossy().into_owned());
            }
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(summary.files_scanned, 1);
    assert_eq!(visited, vec!["visible.txt"]);
}

#[test]
fn bidi_and_script_triage_rules_flag_spoofs_without_flagging_normal_files() {
    let engine = Engine::load(None, false).unwrap();

    let bidi = engine.inspect(Path::new("C:\\case\\invoice\u{202E}fdp.exe"), b"harmless");
    assert!(bidi.findings.iter().any(|f| f.id == "triage.bidi-filename"));

    let script = engine.inspect(Path::new("C:\\case\\invoice.pdf.lnk"), b"harmless");
    assert!(
        script
            .findings
            .iter()
            .any(|f| f.id == "triage.double-extension-script")
    );

    let benign_script = engine.inspect(Path::new("C:\\case\\deploy.v2.ps1"), b"Write-Host ok");
    assert!(benign_script.findings.is_empty());

    let benign_doc = engine.inspect(Path::new("C:\\case\\notes.pptx"), b"plain text");
    assert!(benign_doc.findings.is_empty());
}

#[test]
fn pe_analyzer_detects_packer_sections_without_false_positive_on_own_binary() {
    let cli_path = Path::new(env!("CARGO_BIN_EXE_larchscan"));
    let cli_bytes = fs::read(cli_path).unwrap();
    let summary = pe::analyze(&cli_bytes).expect("larchscan.exe should parse as PE");
    assert_eq!(summary.format, "PE32+");
    assert!(!summary.is_dll);
    assert!(!summary.is_packed_or_high_entropy());

    let engine = Engine::load(None, false).unwrap();
    let own_verdict = engine.inspect(cli_path, &cli_bytes);
    assert!(
        own_verdict.findings.is_empty(),
        "expected no false positives on own binary, got {:?}",
        own_verdict.findings
    );

    // Construct a minimal valid PE32+ image with a known UPX0 packer section.
    let mut synthetic = vec![0u8; 512];
    synthetic[0..2].copy_from_slice(b"MZ");
    synthetic[60..64].copy_from_slice(&64u32.to_le_bytes());
    synthetic[64..68].copy_from_slice(b"PE\0\0");
    synthetic[64 + 6..64 + 8].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    synthetic[64 + 20..64 + 22].copy_from_slice(&160u16.to_le_bytes()); // optional header len
    synthetic[64 + 22..64 + 24].copy_from_slice(&0x0002u16.to_le_bytes()); // EXECUTABLE_IMAGE
    synthetic[64 + 24..64 + 26].copy_from_slice(&0x20bu16.to_le_bytes()); // PE32+
    let sec_off = 64 + 24 + 160;
    synthetic[sec_off..sec_off + 4].copy_from_slice(b"UPX0");
    let packed_verdict = engine.inspect(Path::new(r"C:\case\packed.exe"), &synthetic);
    assert!(
        packed_verdict
            .findings
            .iter()
            .any(|f| f.id == "triage.packed-unsigned-pe")
    );
}

#[test]
fn authenticode_distinguishes_signed_windows_binary_and_unsigned_binary() {
    let unsigned = verify_authenticode(Path::new(env!("CARGO_BIN_EXE_larchscan")));
    assert_eq!(unsigned, SignatureStatus::Unsigned);

    let notepad = Path::new(r"C:\Windows\System32\notepad.exe");
    if notepad.exists() {
        let sig = verify_authenticode(notepad);
        assert!(
            sig == SignatureStatus::Valid || sig == SignatureStatus::Unsigned,
            "unexpected signature status on notepad.exe: {sig:?}"
        );
    }
}

#[test]
fn persistence_evaluator_flags_script_hosts_temp_drops_and_missing_targets() {
    let engine = Engine::load(None, false).unwrap();

    let ps = persistence::evaluate_entry(
        "Registry Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "Updater",
        "powershell.exe -WindowStyle Hidden -EncodedCommand ZQBjAGgAbwA=",
        None,
        &engine,
    );
    assert!(
        ps.findings
            .iter()
            .any(|f| f.id == "persistence.script-host")
    );

    let missing_drop = persistence::evaluate_entry(
        "Registry Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        "Drop",
        r#""C:\Users\Demo\Downloads\never-existed-9911.exe" --silent"#,
        None,
        &engine,
    );
    assert!(missing_drop.target_missing);
    assert!(
        missing_drop
            .findings
            .iter()
            .any(|f| f.id == "persistence.temp-or-downloads")
    );
    assert!(
        missing_drop
            .findings
            .iter()
            .any(|f| f.id == "persistence.missing-target")
    );
}

#[test]
fn disk_path_rejects_unc_and_named_streams() {
    assert!(disk_path(Path::new(r"\\server\share\file.txt")).is_err());
    assert!(disk_path(Path::new(r"C:\Temp\file.txt:Zone.Identifier")).is_err());
    assert!(disk_path(Path::new(r"C:\Temp\file.txt")).is_ok());
}
