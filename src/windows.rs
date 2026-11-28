use crate::pe::SignatureStatus;
use anyhow::{Result, bail, ensure};
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::mem::{align_of, offset_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, GENERIC_READ};
use windows_sys::Win32::Security::WinTrust::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Antimalware::*;
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Registry::*;
use windows_sys::Win32::UI::Shell::{
    FOLDERID_CommonStartup, FOLDERID_Desktop, FOLDERID_Downloads, FOLDERID_Startup,
    SHGetKnownFolderPath,
};
use windows_sys::core::GUID;

pub const MAX_ZONE_IDENTIFIER_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug)]
pub struct RegistryRunEntry {
    pub hive_key: String,
    pub name: String,
    pub command: String,
}

fn known_folder(id: &GUID) -> Option<PathBuf> {
    let mut raw = ptr::null_mut();
    // The shell allocates a null-terminated path, which must be freed even on failure.
    let status = unsafe { SHGetKnownFolderPath(id, 0, ptr::null_mut(), &mut raw) };
    if raw.is_null() {
        return None;
    }
    let path = if status >= 0 {
        let length = (0..)
            .take_while(|index| unsafe { *raw.add(*index) != 0 })
            .count();
        let wide = unsafe { std::slice::from_raw_parts(raw, length) };
        Some(PathBuf::from(OsString::from_wide(wide)))
    } else {
        None
    };
    unsafe { CoTaskMemFree(raw.cast()) };
    path
}

fn dedup_folders(ids: &[GUID]) -> Vec<PathBuf> {
    let mut folders: Vec<PathBuf> = Vec::new();
    for id in ids {
        if let Some(path) = known_folder(id)
            && !folders.iter().any(|existing| paths_equal(existing, &path))
        {
            folders.push(path);
        }
    }
    folders
}

pub fn quick_scan_folders() -> Vec<PathBuf> {
    dedup_folders(&[FOLDERID_Downloads, FOLDERID_Desktop])
}

pub fn startup_folders() -> Vec<PathBuf> {
    dedup_folders(&[FOLDERID_Startup, FOLDERID_CommonStartup])
}

pub fn paths_equal(a: &Path, b: &Path) -> bool {
    match (a.to_str(), b.to_str()) {
        (Some(sa), Some(sb)) => {
            let sa = sa.trim_end_matches(['\\', '/']);
            let sb = sb.trim_end_matches(['\\', '/']);
            sa.to_lowercase() == sb.to_lowercase()
        }
        _ => a.as_os_str().eq_ignore_ascii_case(b.as_os_str()),
    }
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// Accept ordinary local disk paths. Device namespaces and named streams have different semantics.
pub fn disk_path(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut components = absolute.components();
    ensure!(
        matches!(components.next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))),
        "expected a local drive path"
    );
    for component in components {
        if let Component::Normal(name) = component {
            ensure!(
                !name.encode_wide().any(|unit| unit == u16::from(b':')),
                "named stream paths are unsupported"
            );
        }
    }
    Ok(absolute)
}

/// Verify a file's Windows Authenticode signature without network revocation blocking or UI.
pub fn verify_authenticode(path: &Path) -> SignatureStatus {
    const TRUST_E_NOSIGNATURE_CODE: i32 = 0x800B_0100u32 as i32;
    const TRUST_E_SUBJECT_FORM_UNKNOWN_CODE: i32 = 0x800B_0003u32 as i32;
    const TRUST_E_PROVIDER_UNKNOWN_CODE: i32 = 0x800B_0001u32 as i32;
    const TRUST_E_BAD_DIGEST_CODE: i32 = 0x8009_6010u32 as i32;
    const CRYPT_E_HASH_VALUE_CODE: i32 = 0x8009_1007u32 as i32;
    const TRUST_E_EXPLICIT_DISTRUST_CODE: i32 = 0x800B_0111u32 as i32;

    let path_wide = wide(path.as_os_str());
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path_wide.as_ptr(),
        hFile: ptr::null_mut(),
        pgKnownSubject: ptr::null_mut(),
    };

    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous.pFile = &mut file_info;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    let mut action = GUID::from_u128(0x00aa_c56b_cd44_11d0_8cc2_00c0_4fc2_95ee);
    let status = unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        );
    }

    match status {
        0 => SignatureStatus::Valid,
        TRUST_E_NOSIGNATURE_CODE
        | TRUST_E_SUBJECT_FORM_UNKNOWN_CODE
        | TRUST_E_PROVIDER_UNKNOWN_CODE => SignatureStatus::Unsigned,
        TRUST_E_BAD_DIGEST_CODE | CRYPT_E_HASH_VALUE_CODE | TRUST_E_EXPLICIT_DISTRUST_CODE => {
            SignatureStatus::Invalid
        }
        _ => SignatureStatus::Untrusted,
    }
}

/// Read Windows Registry `Run` and `RunOnce` autorun entries (read-only, no admin required).
pub fn read_registry_run_keys() -> Vec<RegistryRunEntry> {
    let targets: [(HKEY, &str, &str); 4] = [
        (
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        ),
        (
            HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ),
    ];

    let mut out = Vec::new();
    for (root, subkey, label) in targets {
        let subkey_w = wide(OsStr::new(subkey));
        let mut hkey: HKEY = ptr::null_mut();
        let rc = unsafe { RegOpenKeyExW(root, subkey_w.as_ptr(), 0, KEY_READ, &mut hkey) };
        if rc != ERROR_SUCCESS || hkey.is_null() {
            continue;
        }

        let mut index = 0u32;
        loop {
            let mut name_buf = [0u16; 512];
            let mut name_len = name_buf.len() as u32;
            let mut value_type = 0u32;
            let mut data_buf = [0u8; 4096];
            let mut data_len = data_buf.len() as u32;

            let enum_rc = unsafe {
                RegEnumValueW(
                    hkey,
                    index,
                    name_buf.as_mut_ptr(),
                    &mut name_len,
                    ptr::null_mut(),
                    &mut value_type,
                    data_buf.as_mut_ptr(),
                    &mut data_len,
                )
            };
            if enum_rc == ERROR_NO_MORE_ITEMS {
                break;
            }
            index += 1;
            if enum_rc != ERROR_SUCCESS {
                continue;
            }
            if value_type != REG_SZ && value_type != REG_EXPAND_SZ {
                continue;
            }

            let name = String::from_utf16_lossy(&name_buf[..name_len as usize]);
            let u16_count = (data_len as usize) / 2;
            let mut wide_val = Vec::with_capacity(u16_count);
            let (pairs, _) = data_buf[..u16_count * 2].as_chunks::<2>();
            for &pair in pairs {
                wide_val.push(u16::from_le_bytes(pair));
            }
            while wide_val.last() == Some(&0) {
                wide_val.pop();
            }
            let command = String::from_utf16_lossy(&wide_val).trim().to_owned();
            if !command.is_empty() {
                out.push(RegistryRunEntry {
                    hive_key: label.into(),
                    name,
                    command,
                });
            }
        }
        unsafe { RegCloseKey(hkey) };
    }
    out
}

pub fn regular_file(path: &Path, quarantine: bool) -> Result<File> {
    if quarantine {
        Ok(quarantine_file(path)?.0)
    } else {
        open_regular_disk_file(path, false)
    }
}

/// Open a regular local disk file exclusively for quarantine and capture any `:Zone.Identifier` stream.
pub fn quarantine_file(path: &Path) -> Result<(File, Option<Vec<u8>>)> {
    let normalized = disk_path(path)?;
    let file = open_regular_disk_file(&normalized, true)?;
    let has_zone = check_streams_and_link(&file)?;
    let zone = if has_zone {
        Some(read_zone_identifier(&normalized)?)
    } else {
        None
    };
    Ok((file, zone))
}

fn open_regular_disk_file(path: &Path, quarantine: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    if quarantine {
        options.access_mode(GENERIC_READ | DELETE).share_mode(0);
    } else {
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    }
    let file = options.open(disk_path(path)?)?;
    ensure!(
        unsafe { GetFileType(file.as_raw_handle()) } == FILE_TYPE_DISK,
        "expected a disk file"
    );
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.file_attributes() & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE) == 0,
        "expected an ordinary file"
    );
    if quarantine {
        ensure!(
            meta.file_attributes() & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ENCRYPTED) == 0,
            "read-only or EFS-encrypted file"
        );
    }
    Ok(file)
}

fn utf16_eq_ignore_ascii_case(actual: &[u16], expected_ascii: &str) -> bool {
    if actual.len() != expected_ascii.len() {
        return false;
    }
    actual
        .iter()
        .zip(expected_ascii.bytes())
        .all(|(&unit, exp)| u8::try_from(unit).is_ok_and(|byte| byte.eq_ignore_ascii_case(&exp)))
}

fn check_streams_and_link(file: &File) -> Result<bool> {
    let handle = file.as_raw_handle();
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // The owned file handle remains open for both queries and the final removal.
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    ensure!(
        info.nNumberOfLinks == 1,
        "multiple hard links; cannot isolate this file"
    );
    // Aligned storage for the variable-size stream list. Fail closed on overflow.
    let mut storage = [0u64; 512];
    let total_bytes = size_of_val(&storage);
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStreamInfo,
            storage.as_mut_ptr().cast(),
            total_bytes as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }

    let name_offset = offset_of!(FILE_STREAM_INFO, StreamName);
    let mut saw_primary = false;
    let mut saw_zone = false;
    let mut offset = 0usize;

    loop {
        ensure!(
            offset.is_multiple_of(align_of::<FILE_STREAM_INFO>())
                && offset.saturating_add(size_of::<FILE_STREAM_INFO>()) <= total_bytes,
            "unexpected stream metadata layout"
        );
        let base = unsafe { storage.as_ptr().cast::<u8>().add(offset) };
        let stream = unsafe { &*base.cast::<FILE_STREAM_INFO>() };
        let name_bytes = stream.StreamNameLength as usize;
        ensure!(
            name_bytes.is_multiple_of(2)
                && offset
                    .checked_add(name_offset)
                    .and_then(|n| n.checked_add(name_bytes))
                    .is_some_and(|end| end <= total_bytes),
            "invalid stream name bounds"
        );
        let name = unsafe {
            std::slice::from_raw_parts(base.add(name_offset).cast::<u16>(), name_bytes / 2)
        };

        if utf16_eq_ignore_ascii_case(name, "::$DATA") {
            ensure!(!saw_primary, "duplicate primary data stream");
            saw_primary = true;
        } else if utf16_eq_ignore_ascii_case(name, ":Zone.Identifier:$DATA") {
            ensure!(!saw_zone, "duplicate Zone.Identifier stream");
            ensure!(
                stream.StreamSize >= 0 && stream.StreamSize as usize <= MAX_ZONE_IDENTIFIER_BYTES,
                "Zone.Identifier stream exceeds size limit; original retained"
            );
            saw_zone = true;
        } else {
            bail!("additional or unsupported data streams; original retained");
        }

        if stream.NextEntryOffset == 0 {
            break;
        }
        let step = stream.NextEntryOffset as usize;
        ensure!(
            step > 0 && offset.checked_add(step).is_some_and(|n| n < total_bytes),
            "invalid stream list offset"
        );
        offset += step;
    }

    ensure!(saw_primary, "missing primary data stream");
    Ok(saw_zone)
}

fn read_zone_identifier(path: &Path) -> Result<Vec<u8>> {
    let mut stream_path = path.as_os_str().to_os_string();
    stream_path.push(":Zone.Identifier");
    let mut options = OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(PathBuf::from(stream_path))?;
    let mut bytes = Vec::new();
    file.take(MAX_ZONE_IDENTIFIER_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_ZONE_IDENTIFIER_BYTES,
        "Zone.Identifier stream exceeds size limit; original retained"
    );
    Ok(bytes)
}

pub fn remove_on_close(file: &File) -> Result<()> {
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // Use the same exclusive handle that supplied the evidence and archived bytes.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

pub struct Amsi(HAMSICONTEXT);

impl Amsi {
    pub fn start() -> Result<Self> {
        let mut context = ptr::null_mut();
        let app_name = concat!("LarchScan/", env!("CARGO_PKG_VERSION"));
        let status = unsafe { AmsiInitialize(wide(OsStr::new(app_name)).as_ptr(), &mut context) };
        ensure!(
            status >= 0 && !context.is_null(),
            "AMSI initialization failed ({status:#010x})"
        );
        Ok(Self(context))
    }

    pub fn scan(&self, path: &Path, data: &[u8]) -> Result<i32> {
        if data.is_empty() {
            return Ok(AMSI_RESULT_NOT_DETECTED);
        }
        let name = wide(path.as_os_str());
        let mut verdict = 0;
        let length = u32::try_from(data.len())?;
        let status = unsafe {
            AmsiScanBuffer(
                self.0,
                data.as_ptr().cast(),
                length,
                name.as_ptr(),
                ptr::null_mut(),
                &mut verdict,
            )
        };
        if status < 0 {
            bail!("AMSI scan failed ({status:#010x})");
        }
        Ok(verdict)
    }
}

impl Drop for Amsi {
    fn drop(&mut self) {
        unsafe { AmsiUninitialize(self.0) };
    }
}
