use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets/larchscan.ico");
    println!("cargo:rerun-if-changed=assets/LarchScan.manifest");
    println!("cargo:rerun-if-changed=assets/desktop.rc");
    println!("cargo:rerun-if-changed=assets/cli.rc");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let assets_dir = manifest_dir.join("assets");

    let rc = find_rc().expect(
        "Windows Resource Compiler (rc.exe) not found. Install the Windows 10/11 SDK or run from a Visual Studio Developer shell.",
    );

    compile_rc(
        &rc,
        &assets_dir,
        &assets_dir.join("cli.rc"),
        &out_dir.join("larchscan-cli.res"),
        "larchscan",
    );

    if env::var_os("CARGO_FEATURE_DESKTOP").is_some() {
        compile_rc(
            &rc,
            &assets_dir,
            &assets_dir.join("desktop.rc"),
            &out_dir.join("larchscan-desktop.res"),
            "larchscan-desktop",
        );
    }
}

fn compile_rc(rc: &Path, include_dir: &Path, rc_file: &Path, res_file: &Path, bin_name: &str) {
    let status = Command::new(rc)
        .arg("/nologo")
        .arg("/fo")
        .arg(res_file)
        .arg("/i")
        .arg(include_dir)
        .arg(rc_file)
        .status()
        .unwrap_or_else(|e| panic!("failed to invoke {}: {e}", rc.display()));
    assert!(
        status.success(),
        "rc.exe failed compiling {} with status {status}",
        rc_file.display()
    );
    println!("cargo:rustc-link-arg-bin={bin_name}={}", res_file.display());
}

fn find_rc() -> Option<PathBuf> {
    let arch = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86") => "x86",
        _ => "x64",
    };

    if let Some(paths) = env::var_os("PATH") {
        for dir in env::split_paths(&paths) {
            let candidate = dir.join("rc.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    if let Some(sdk) = env::var_os("WindowsSdkDir")
        && let Some(ver) = env::var_os("WindowsSDKVersion")
    {
        let ver_str = ver.to_string_lossy();
        let candidate = PathBuf::from(&sdk)
            .join("bin")
            .join(ver_str.trim_end_matches('\\'))
            .join(arch)
            .join("rc.exe");
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    let kits_bin = Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin");
    if let Ok(entries) = fs::read_dir(kits_bin) {
        let mut versions: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        versions.sort();
        for dir in versions.into_iter().rev() {
            let candidate = dir.join(arch).join("rc.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    None
}
