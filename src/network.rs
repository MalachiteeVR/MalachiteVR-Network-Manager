use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

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

fn format_speed(speed: u64) -> String {
    if speed >= 1_000_000_000 { format!("{:.2} Gbps", speed as f64 / 1_000_000_000.0) }
    else if speed >= 1_000_000 { format!("{:.0} Mbps", speed as f64 / 1_000_000.0) }
    else if speed > 0 { format!("{:.0} Kbps", speed as f64 / 1_000.0) }
    else { "Unknown".into() }
}

#[cfg(windows)]
fn wide_string(value: &[u16]) -> String {
    let len = value.iter().position(|&c| c == 0).unwrap_or(value.len());
    String::from_utf16_lossy(&value[..len])
}

#[cfg(windows)]
fn native_rows() -> anyhow::Result<Vec<windows::Win32::NetworkManagement::IpHelper::MIB_IF_ROW2>> {
    use windows::Win32::NetworkManagement::IpHelper::{GetIfTable2, FreeMibTable, MIB_IF_TABLE2, MIB_IF_ROW2};
    let mut table: *mut MIB_IF_TABLE2 = std::ptr::null_mut();
    let status = unsafe { GetIfTable2(&mut table) };
    if status != 0 || table.is_null() {
        anyhow::bail!("Windows could not enumerate network adapters (error {})", status.0);
    }
    let result = unsafe {
        let count = (*table).NumEntries as usize;
        let first = (*table).Table.as_ptr();
        (0..count).map(|i| *first.add(i)).collect::<Vec<MIB_IF_ROW2>>()
    };
    unsafe { FreeMibTable(table as _) };
    Ok(result)
}

pub fn adapters() -> anyhow::Result<Vec<Adapter>> {
    #[cfg(windows)]
    {
        let rows = native_rows()?;
        return Ok(rows.into_iter().map(|row| {
            let name = wide_string(&row.Alias);
            let description = wide_string(&row.Description);
            let speed = format_speed(row.TransmitLinkSpeed.max(row.ReceiveLinkSpeed));
            let mac = if row.PhysicalAddressLength > 0 {
                Some(row.PhysicalAddress[..row.PhysicalAddressLength.min(32) as usize]
                    .iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join("-"))
            } else { None };
            let status = if format!("{:?}", row.OperStatus).to_ascii_lowercase().contains("up") { "Up" } else { "Down" };
            Adapter { name, description, status: status.into(), speed, mac }
        }).collect());
    }
    #[cfg(not(windows))]
    anyhow::bail!("Network adapter enumeration is only supported on Windows")
}

pub fn toggle(name: &str, enable: bool) -> anyhow::Result<()> {
    if name.trim().is_empty() { anyhow::bail!("Adapter name cannot be empty"); }
    #[cfg(windows)]
    {
        use windows::Win32::NetworkManagement::IpHelper::{GetIfEntry, SetIfEntry, MIB_IFROW};
        let rows = native_rows()?;
        let row2 = rows.into_iter().find(|row| wide_string(&row.Alias) == name || wide_string(&row.Description) == name)
            .ok_or_else(|| anyhow::anyhow!("Network adapter '{name}' was not found"))?;
        let mut row = MIB_IFROW::default();
        row.dwIndex = row2.InterfaceIndex;
        let get_status = unsafe { GetIfEntry(&mut row) };
        if get_status != 0 { anyhow::bail!("Windows could not read adapter state (error {})", get_status); }
        row.dwAdminStatus = if enable { 1 } else { 2 };
        let set_status = unsafe { SetIfEntry(&row) };
        if set_status != 0 { anyhow::bail!("Windows could not change adapter state (error {}). Try running as administrator.", set_status); }
        return Ok(());
    }
    #[cfg(not(windows))]
    anyhow::bail!("Adapter state changes are only supported on Windows")
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct TcpRowOwnerPid { state: u32, local_addr: u32, local_port: u32, remote_addr: u32, remote_port: u32, owning_pid: u32 }
#[cfg(windows)]
#[repr(C)]
struct TcpTableOwnerPid { count: u32, rows: [TcpRowOwnerPid; 1] }
#[cfg(windows)]
#[link(name = "iphlpapi")]
unsafe extern "system" { fn GetExtendedTcpTable(table:*mut std::ffi::c_void,size:*mut u32,order:u32,family:u32,class:u32,reserved:u32)->u32; }

#[cfg(windows)]
pub fn connections() -> anyhow::Result<String> {
    const ERROR_INSUFFICIENT_BUFFER:u32=122; const AF_INET:u32=2; const TCP_TABLE_OWNER_PID_ALL:u32=5;
    let mut size=0u32; let first=unsafe{GetExtendedTcpTable(std::ptr::null_mut(),&mut size,0,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)};
    if first!=ERROR_INSUFFICIENT_BUFFER && first!=0 { anyhow::bail!("GetExtendedTcpTable size query failed with Windows error {first}"); }
    let mut buffer=Vec::<u64>::new(); let mut result=0u32;
    for _ in 0..4 { buffer=vec![0u64;((size as usize+7)/8).max(1)]; result=unsafe{GetExtendedTcpTable(buffer.as_mut_ptr().cast(),&mut size,0,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)}; if result==0{break} if result!=ERROR_INSUFFICIENT_BUFFER{anyhow::bail!("GetExtendedTcpTable failed with Windows error {result}");} }
    if result!=0 { anyhow::bail!("TCP connection table kept changing; please refresh again (Windows error {result})"); }
    let table=buffer.as_ptr().cast::<TcpTableOwnerPid>(); let count=unsafe{(*table).count as usize}; let rows=unsafe{std::slice::from_raw_parts((*table).rows.as_ptr(),count)};
    let mut output=String::from("Proto  Local Address          Remote Address         State        PID\n-----  ---------------------  ---------------------  -----------  -----\n");
    for row in rows { let local_ip=Ipv4Addr::from(u32::from_be(row.local_addr)); let remote_ip=Ipv4Addr::from(u32::from_be(row.remote_addr)); let local_port=u16::from_be(row.local_port as u16); let remote_port=u16::from_be(row.remote_port as u16); let state=match row.state{1=>"CLOSED",2=>"LISTEN",3=>"SYN_SENT",4=>"SYN_RCVD",5=>"ESTABLISHED",6=>"FIN_WAIT1",7=>"FIN_WAIT2",8=>"CLOSE_WAIT",9=>"CLOSING",10=>"LAST_ACK",11=>"TIME_WAIT",12=>"DELETE_TCB",_=>"UNKNOWN"}; output.push_str(&format!("{:<5}  {:<21}  {:<21}  {:<11}  {}\n","TCP",format!("{local_ip}:{local_port}"),format!("{remote_ip}:{remote_port}"),state,row.owning_pid)); }
    Ok(output)
}
#[cfg(not(windows))]
pub fn connections()->anyhow::Result<String>{anyhow::bail!("TCP connection enumeration is only supported on Windows")}

pub fn private_ipv4()->anyhow::Result<Option<Ipv4Addr>>{
    let interfaces=netdev::get_interfaces();
    let candidates=interfaces.iter().filter(|i|i.default&&i.is_oper_up()).chain(interfaces.iter().filter(|i|i.is_oper_up()));
    for interface in candidates { for address in interface.ipv4_addrs(){if address.is_private()&&!address.is_loopback(){return Ok(Some(address));}} }
    Ok(None)
}
