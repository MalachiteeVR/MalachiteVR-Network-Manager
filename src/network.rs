use crate::admin::ps;
use serde::Deserialize;
use std::net::Ipv4Addr;

#[derive(Clone, Debug, Deserialize)]
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

fn ps_quote(value: &str) -> String {
    value.replace(''', "''")
}

pub fn adapters() -> anyhow::Result<Vec<Adapter>> {
    let script = r#"Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,@{N='LinkSpeed';E={$_.LinkSpeed}},MacAddress | ConvertTo-Json -Compress"#;
    let s = ps(script)?;
    if s.is_empty() {
        return Ok(Vec::new());
    }

    let value: serde_json::Value = serde_json::from_str(&s)?;
    if value.is_array() {
        Ok(serde_json::from_value(value)?)
    } else {
        Ok(vec![serde_json::from_value(value)?])
    }
}

pub fn toggle(name: &str, enable: bool) -> anyhow::Result<()> {
    let verb = if enable { "Enable-NetAdapter" } else { "Disable-NetAdapter" };
    ps(&format!(
        "{} -Name '{}' -Confirm:$false -ErrorAction Stop",
        verb,
        ps_quote(name)
    ))?;
    Ok(())
}

pub fn connections() -> anyhow::Result<String> {
    ps("Get-NetTCPConnection | Sort-Object State,RemotePort | Select-Object -First 300 | Format-Table -AutoSize | Out-String -Width 240")
}

/// Return a sensible private IPv4 address for the machine, preferring an active
/// adapter with a default route. Loopback and APIPA addresses are excluded.
pub fn private_ipv4() -> anyhow::Result<Option<Ipv4Addr>> {
    let script = r#"Get-NetIPConfiguration |
        Where-Object { $_.NetAdapter.Status -eq 'Up' -and $_.IPv4DefaultGateway } |
        ForEach-Object { $_.IPv4Address.IPAddress } |
        Where-Object { $_ -and $_ -notlike '169.254.*' -and $_ -ne '127.0.0.1' } |
        Select-Object -First 1"#;

    let output = ps(script)?;
    if output.is_empty() {
        return Ok(None);
    }

    Ok(output.parse().ok())
}
