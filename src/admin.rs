use std::process::Command;

#[cfg(windows)]
pub fn is_admin() -> bool {
    unsafe {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Security::{
            GetTokenInformation, OpenProcessToken, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::GetCurrentProcess;

        let mut token = Default::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
        .is_ok();

        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_admin() -> bool {
    false
}

pub fn ensure_elevated() {
    if is_admin() {
        return;
    }

    #[cfg(windows)]
    {
        let exe = match std::env::current_exe() {
            Ok(path) => path,
            Err(_) => std::process::exit(1),
        };

        // Use PowerShell's documented RunAs verb here rather than binding directly
        // to ShellExecuteW. This avoids Windows crate API-location differences while
        // preserving the normal UAC consent prompt.
        let status = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Process",
                "-FilePath",
            ])
            .arg(exe.as_os_str())
            .args(["-Verb", "RunAs"])
            .status();

        match status {
            Ok(s) if s.success() => std::process::exit(0),
            _ => std::process::exit(1),
        }
    }
}

pub fn ps(script: &str) -> anyhow::Result<String> {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!(
            "PowerShell command failed (exit {}): {}",
            output.status,
            if stderr.is_empty() { "unknown error" } else { &stderr }
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
