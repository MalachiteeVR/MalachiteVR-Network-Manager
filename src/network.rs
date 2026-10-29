use serde::{Deserialize, Serialize};
use std::{net::{IpAddr, Ipv4Addr}, process::Command};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Adapter {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "InterfaceDescription")]
    pub description: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "LinkSpeed")]
    pub speed: String,
    #[serde(rename = "MacAddress")]
    pub mac: Option<String>,
}

fn format_speed(bits_per_second: Option<u64>) -> String {
    match bits_per_second {
        Some(speed) if speed >= 1_000_000_000 => format!("{:.2} Gbps", speed as f64 / 1_000_000_000.0),
        Some(speed) if speed >= 1_000_000 => format!("{:.0} Mbps", speed as f64 / 1_000_000.0),
        Some(speed) if speed > 0 => format!("{:.0} Kbps", speed as f64 / 1_000.0),
        _ => "Unknown".to_string(),
    }
}

/// Enumerate adapters through the platform networking APIs. No shell or
/// PowerShell process is started for discovery.
pub fn adapters() -> anyhow::Result<Vec<Adapter>> {
    let interfaces = netdev::get_interfaces()
        .map_err(|error| anyhow::anyhow!("Unable to enumerate network adapters: {error}"))?;

    Ok(interfaces.into_iter().map(|interface| Adapter {
        name: interface.friendly_name.clone().unwrap_or_else(|| interface.name.clone()),
        description: interface.description.clone().unwrap_or_else(|| interface.friendly_name.clone().unwrap_or_else(|| interface.name.clone())),
        status: if interface.is_oper_up() { "Up" } else { "Down" }.to_string(),
        speed: format_speed(interface.transmit_speed.or(interface.receive_speed)),
        mac: interface.mac_addr.map(|address| address.to_string()),
    }).collect())
}

/// Enable/disable a network interface. netsh is used as a compatibility bridge
/// for this one operation because Windows does not expose a supported simple
/// Win32 call to toggle an adapter by friendly name. The process is hidden.
pub fn toggle(name: &str, enable: bool) -> anyhow::Result<()> {
    if name.trim().is_empty() {
        anyhow::bail!("Adapter name cannot be empty");
    }
    let state = if enable { "enabled" } else { "disabled" };
    let output = Command::new("netsh.exe")
        .args(["interface", "set", "interface", &format!("name={name}"), &format!("admin={state}")])
        .creation_flags_hidden()
        .output()?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!("Windows could not set adapter state: {}", if detail.is_empty() {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        } else { detail });
    }
    Ok(())
}

#[cfg(windows)]
trait HiddenCommand {
    fn creation_flags_hidden(&mut self) -> &mut Self;
}
#[cfg(windows)]
impl HiddenCommand for Command {
    fn creation_flags_hidden(&mut self) -> &mut Self {
        use std::os::windows::process::CommandExt;
        self.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        self
    }
}
#[cfg(not(windows))]
trait HiddenCommand {
    fn creation_flags_hidden(&mut self) -> &mut Self;
}
#[cfg(not(windows))]
impl HiddenCommand for Command {
    fn creation_flags_hidden(&mut self) -> &mut Self { self }
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct TcpRowOwnerPid {
    state: u32,
    local_addr: u32,
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
    owning_pid: u32,
}
#[cfg(windows)]
#[repr(C)]
struct TcpTableOwnerPid {
    count: u32,
    rows: [TcpRowOwnerPid; 1],
}
#[cfg(windows)]
#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn GetExtendedTcpTable(
        table: *mut std::ffi::c_void,
        size: *mut u32,
        order: u32,
        family: u32,
        class: u32,
        reserved: u32,
    ) -> u32;
}

#[cfg(windows)]
pub fn connections() -> anyhow::Result<String> {
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
    const AF_INET: u32 = 2;
    const TCP_TABLE_OWNER_PID_ALL: u32 = 5;

    let mut size = 0u32;
    let first = unsafe {
        GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    };
    if first != ERROR_INSUFFICIENT_BUFFER && first != 0 {
        anyhow::bail!("GetExtendedTcpTable failed with Windows error {first}");
    }
    let mut buffer = vec![0u64; (size as usize + 7) / 8];
    let result = unsafe {
        GetExtendedTcpTable(buffer.as_mut_ptr().cast(), &mut size, 0, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    };
    if result != 0 {
        anyhow::bail!("GetExtendedTcpTable failed with Windows error {result}");
    }

    let table = buffer.as_ptr().cast::<TcpTableOwnerPid>();
    let count = unsafe { (*table).count as usize }.min(300);
    let rows = unsafe { std::slice::from_raw_parts((*table).rows.as_ptr(), count) };
    let mut output = String::from("Proto  Local Address          Remote Address         State        PID\n");
    output.push_str("-----  ---------------------  ---------------------  -----------  -----\n");
    for row in rows {
        let local_ip = Ipv4Addr::from(u32::from_le(row.local_addr));
        let remote_ip = Ipv4Addr::from(u32::from_le(row.remote_addr));
        let local_port = u16::from_be(row.local_port as u16);
        let remote_port = u16::from_be(row.remote_port as u16);
        let state = match row.state {
            1 => "CLOSED", 2 => "LISTEN", 3 => "SYN_SENT", 4 => "SYN_RCVD",
            5 => "ESTABLISHED", 6 => "FIN_WAIT1", 7 => "FIN_WAIT2", 8 => "CLOSE_WAIT",
            9 => "CLOSING", 10 => "LAST_ACK", 11 => "TIME_WAIT", 12 => "DELETE_TCB",
            _ => "UNKNOWN",
        };
        output.push_str(&format!("{:<5}  {:<21}  {:<21}  {:<11}  {}\n",
            "TCP", format!("{local_ip}:{local_port}"), format!("{remote_ip}:{remote_port}"), state, row.owning_pid));
    }
    Ok(output)
}

#[cfg(not(windows))]
pub fn connections() -> anyhow::Result<String> {
    anyhow::bail!("TCP connection enumeration is only supported on Windows")
}

/// Return a private IPv4 address, preferring the system's default interface.
pub fn private_ipv4() -> anyhow::Result<Option<Ipv4Addr>> {
    let interfaces = netdev::get_interfaces()
        .map_err(|error| anyhow::anyhow!("Unable to enumerate network interfaces: {error}"))?;

    let candidates = interfaces.iter().filter(|interface| interface.default && interface.is_oper_up())
        .chain(interfaces.iter().filter(|interface| interface.is_oper_up()));
    for interface in candidates {
        for address in interface.ipv4_addrs() {
            if address.is_private() && !address.is_loopback() {
                return Ok(Some(address));
            }
        }
    }
    Ok(None)
}
