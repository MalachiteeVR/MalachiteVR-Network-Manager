# MalachiteVR Network Manager

Windows-first Rust desktop network manager with a Microsoft Edge WebView2 interface.

## Features

- UAC administrator elevation without spawning a PowerShell window
- Hidden/background PowerShell helpers for Windows networking APIs
- Network adapter status, link speed, MAC address, and enable/disable
- Current TCP connection viewer
- Windows Defender Firewall rule listing, creation, and deletion
- SSDP UPnP Internet Gateway discovery
- UPnP TCP/UDP port mapping to a detected private IPv4 address
- Responsive MalachiteVR web UI rendered by Microsoft Edge WebView2
- Asynchronous command bridge so network and firewall operations do not freeze the UI
- MalachiteVR Windows application icon

## Architecture

The native shell is Rust. The interface is HTML/CSS/JavaScript rendered by WebView2 through the `wry` crate. JavaScript sends small JSON commands over Wry IPC, Rust performs the Windows/network operation on a worker thread, and the result is returned to the WebView.

This keeps expensive discovery, firewall enumeration, and PowerShell calls off the UI thread.

On Windows, Wry uses the Microsoft Edge WebView2 runtime as its rendering engine. A supported WebView2 Runtime installation is therefore required on the machine running the application.

## Build

Install Rust for Windows, then:

```powershell
cargo build --release
```

The executable is:

```text
target\release\malachite-network-manager.exe
```

The first build after the WebView2 migration may update `Cargo.lock` because the GUI dependency set changed.

## Security notes

- The application requests UAC elevation because firewall and adapter changes require administrator privileges.
- The UAC relaunch uses Windows' native `RunAs` shell verb. It does not use PowerShell for elevation.
- PowerShell is still used as a compatibility layer for several Windows networking cmdlets, but helper processes use `CREATE_NO_WINDOW` and never display a console window.
- UPnP operations only target private RFC1918 client addresses.
