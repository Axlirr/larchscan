use anyhow::{Result, bail, ensure};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Component, Path, Prefix};
use std::ptr;
use windows_sys::Win32::Foundation::GENERIC_READ;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Antimalware::*;

pub fn quick_scan_folders() -> Vec<std::path::PathBuf> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_Desktop, FOLDERID_Downloads, SHGetKnownFolderPath,
    };

    [FOLDERID_Downloads, FOLDERID_Desktop]
        .into_iter()
        .filter_map(|id| {
            let mut raw = ptr::null_mut();
            // The shell allocates a null-terminated path, which must be freed even on failure.
            let status = unsafe { SHGetKnownFolderPath(&id, 0, ptr::null_mut(), &mut raw) };
            if raw.is_null() {
                return None;
            }
            let path = if status >= 0 {
                let length = (0..)
                    .take_while(|index| unsafe { *raw.add(*index) != 0 })
                    .count();
                let wide = unsafe { std::slice::from_raw_parts(raw, length) };
                Some(std::path::PathBuf::from(OsString::from_wide(wide)))
            } else {
                None
            };
            unsafe { CoTaskMemFree(raw.cast()) };
            path
        })
        .collect()
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// Accept ordinary local disk paths. Device namespaces and named streams have different semantics.
pub fn disk_path(path: &Path) -> Result<std::path::PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut components = absolute.components();
    ensure!(
        matches!(components.next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))),
        "expected a local drive path"
    );
    for component in components {
        if let Component::Normal(name) = component {
            let name = name
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("unsupported path encoding"))?;
            ensure!(!name.contains(':'), "named stream paths are unsupported");
        }
    }
    Ok(absolute)
}

pub fn regular_file(path: &Path, quarantine: bool) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    if quarantine {
        options.access_mode(GENERIC_READ | DELETE).share_mode(0);
    } else {
        options.share_mode(FILE_SHARE_READ);
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
        check_single_stream_and_link(&file)?;
    }
    Ok(file)
}

fn check_single_stream_and_link(file: &File) -> Result<()> {
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
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStreamInfo,
            storage.as_mut_ptr().cast(),
            size_of_val(&storage) as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    let stream = unsafe { &*storage.as_ptr().cast::<FILE_STREAM_INFO>() };
    let name_bytes = offset_of!(FILE_STREAM_INFO, StreamName);
    let expected: Vec<u16> = "::$DATA".encode_utf16().collect();
    ensure!(
        stream.NextEntryOffset == 0 && stream.StreamNameLength as usize == expected.len() * 2,
        "additional or unsupported data streams; original retained"
    );
    let name = unsafe {
        std::slice::from_raw_parts(
            storage.as_ptr().cast::<u8>().add(name_bytes).cast::<u16>(),
            expected.len(),
        )
    };
    ensure!(name == expected, "unsupported data stream");
    Ok(())
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
        let status =
            unsafe { AmsiInitialize(wide(OsStr::new("LarchScan/0.1")).as_ptr(), &mut context) };
        ensure!(
            status >= 0 && !context.is_null(),
            "AMSI initialization failed ({status:#010x})"
        );
        Ok(Self(context))
    }

    pub fn scan(&self, path: &Path, data: &[u8]) -> Result<i32> {
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
