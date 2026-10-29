use crate::admin::ps;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Rule {
    pub name: String,
    pub direction: String,
    pub action: String,
    pub enabled: String,
    pub profile: String,
    pub protocol: String,
    pub local_port: String,
}

fn quote(value: &str) -> String {
    value.replace('\'', "''")
}

fn value_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(items) => items
            .iter()
            .map(value_string)
            .collect::<Vec<_>>()
            .join(", "),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

pub fn rules() -> anyhow::Result<Vec<Rule>> {
    // Do not pass projected PSCustomObjects to -AssociatedNetFirewallRule.
    // Some Windows/PowerShell versions reject that conversion. Enumerate the
    // rule metadata directly so the firewall page remains usable on all hosts.
    let script = r#"Get-NetFirewallRule |
        Select-Object -First 1000 DisplayName,Direction,Action,Enabled,Profile |
        ConvertTo-Json -Compress"#;

    let output = ps(script)?;
    if output.trim().is_empty() {
        return Ok(Vec::new());
    }

    let value: serde_json::Value = serde_json::from_str(&output)?;
    let items = if value.is_array() {
        value.as_array().cloned().unwrap_or_default()
    } else {
        vec![value]
    };

    Ok(items
        .into_iter()
        .map(|item| Rule {
            name: value_string(&item["DisplayName"]),
            direction: value_string(&item["Direction"]),
            action: value_string(&item["Action"]),
            enabled: value_string(&item["Enabled"]),
            profile: value_string(&item["Profile"]),
            // Protocol and local-port details are omitted for now because
            // retrieving them through -AssociatedNetFirewallRule is not
            // reliable across Windows PowerShell object representations.
            protocol: String::new(),
            local_port: String::new(),
        })
        .collect())
}

pub fn add(name: &str, port: u16, protocol: &str) -> anyhow::Result<()> {
    let protocol = protocol.to_ascii_uppercase();
    if protocol != "TCP" && protocol != "UDP" {
        anyhow::bail!("Unsupported firewall protocol: {}", protocol);
    }

    ps(&format!(
        "New-NetFirewallRule -DisplayName '{}' -Direction Inbound -Action Allow -Protocol {} -LocalPort {} -Profile Private -Enabled True -ErrorAction Stop",
        quote(name), protocol, port
    ))?;
    Ok(())
}

pub fn remove(name: &str) -> anyhow::Result<()> {
    ps(&format!(
        "Get-NetFirewallRule -DisplayName '{}' -ErrorAction Stop | Remove-NetFirewallRule -Confirm:$false -ErrorAction Stop",
        quote(name)
    ))?;
    Ok(())
}
