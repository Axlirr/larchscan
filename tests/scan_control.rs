use std::{cell::Cell, fs};

use larchscan::scan::{Engine, ScanEvent, tree_excluding};

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
