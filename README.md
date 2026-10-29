# MalachiteVR Network Manager

Windows-first Rust desktop network manager.

### Included in this MVP
- UAC administrator elevation
- Network adapter status and enable/disable
- Current TCP connection viewer
- Windows Defender Firewall rule listing, creation and deletion
- SSDP UPnP Internet Gateway discovery
- UPnP TCP/UDP port mapping to a chosen private IPv4 address
- MalachiteVR dark UI and Windows application icon

### Build
Install Rust for Windows, then:

```powershell
cargo build --release
```

The executable is `target\release\malachite-network-manager.exe`.

The UPnP portion uses SSDP discovery and the common `WANIPConnection:1` SOAP interface. Some routers use different UPnP services, so later versions should add WANPPPConnection, mapping enumeration/removal, and vendor fallbacks.
