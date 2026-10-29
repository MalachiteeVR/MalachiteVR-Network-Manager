# MalachiteVR Network Manager

Windows-first Rust desktop network manager with a Microsoft Edge WebView2 interface.

## Features

- Native Windows UAC administrator elevation
- Native Windows IP Helper APIs for adapter enumeration, state changes, TCP connections, and private IPv4 detection
- Native Windows Firewall COM API for listing, adding, and removing firewall rules
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

This keeps expensive discovery and firewall enumeration off the UI thread. Network and firewall features do not launch PowerShell.

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

The first build after this native API migration may update `Cargo.lock` to resolve the new Windows networking and firewall dependencies.

## Security notes

- The application requests UAC elevation because firewall and adapter changes require administrator privileges.
- The UAC relaunch uses Windows' native `RunAs` shell verb.
- Adapter, TCP, IP, and firewall operations use native Windows APIs. The app does not spawn PowerShell or other command-line shells for these operations.
- UPnP operations only target private RFC1918 client addresses.
