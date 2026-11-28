use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};

use larchscan::scan::{Engine, ScanEvent, ScanOptions, tree_excluding, tree_with_options};
use larchscan::windows::disk_path;

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
fn disk_path_rejects_unc_and_named_streams() {
    assert!(disk_path(Path::new(r"\\server\share\file.txt")).is_err());
    assert!(disk_path(Path::new(r"C:\Temp\file.txt:Zone.Identifier")).is_err());
    assert!(disk_path(Path::new(r"C:\Temp\file.txt")).is_ok());
}
