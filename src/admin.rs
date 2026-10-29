use std::process::Command;

#[cfg(windows)]
pub fn is_admin() -> bool {
    unsafe {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let mut token = Default::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() { return false; }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0u32;
        let ok = GetTokenInformation(token, TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut size).is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}
#[cfg(not(windows))]
pub fn is_admin() -> bool { false }

pub fn ensure_elevated() {
    if is_admin() { return; }
    #[cfg(windows)]
    unsafe {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::HWND;
        use windows::Win32::UI::Shell::ShellExecuteW;
        let exe = std::env::current_exe().unwrap();
        let e: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
        let v: Vec<u16> = std::ffi::OsStr::new("runas").encode_wide().chain(Some(0)).collect();
        let r = ShellExecuteW(None, PCWSTR(v.as_ptr()),
            PCWSTR(e.as_ptr()), PCWSTR::null(), PCWSTR::null(), 1);
        if r.0 as isize > 32 { std::process::exit(0); }
    }
}

pub fn ps(script: &str) -> anyhow::Result<String> {
    let o = Command::new("powershell.exe")
        .args(["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-Command",script])
        .output()?;
    if !o.status.success() { anyhow::bail!("{}", String::from_utf8_lossy(&o.stderr)); }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
}


