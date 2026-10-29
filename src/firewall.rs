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
        serde_json::Value::Array(items) => items.iter().map(value_string).collect::<Vec<_>>().join(", "),
        serde_json::Value::Null => String::new(),
        other => other.to_string(),
    }
}

pub fn rules() -> anyhow::Result<Vec<Rule>> {
    // Preserve each original firewall-rule CIM object until its port filter
    // has been queried. Projecting properties first creates a PSCustomObject.
    let script = r#"$results = @(
        Get-NetFirewallRule -ErrorAction Stop |
        Select-Object -First 1000 |
        ForEach-Object {
            $rule = $_
            $portFilter = $null
            try {
                $portFilter = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop |
                    Select-Object -First 1
            } catch {
                # Some rules have no accessible port filter; still list the rule.
            }
            [PSCustomObject]@{
                DisplayName = $rule.DisplayName
                Direction = $rule.Direction
                Action = $rule.Action
                Enabled = $rule.Enabled
                Profile = $rule.Profile
                Protocol = if ($null -ne $portFilter) { $portFilter.Protocol } else { '' }
                LocalPort = if ($null -ne $portFilter) { $portFilter.LocalPort } else { '' }
            }
        }
    )
    ConvertTo-Json -InputObject $results -Compress"#;

    let output = ps(script)?;
    if output.trim().is_empty() {
        return Ok(Vec::new());
    }

    let value: serde_json::Value = serde_json::from_str(&output)?;
    let items = if value.is_array() { value.as_array().cloned().unwrap_or_default() } else { vec![value] };

    Ok(items.into_iter().map(|item| Rule {
        name: value_string(&item["DisplayName"]),
        direction: value_string(&item["Direction"]),
        action: value_string(&item["Action"]),
        enabled: value_string(&item["Enabled"]),
        profile: value_string(&item["Profile"]),
        protocol: value_string(&item["Protocol"]),
        local_port: value_string(&item["LocalPort"]),
    }).collect())
}

pub fn add(name: &str, port: u16, protocol: &str) -> anyhow::Result<()> {
    let protocol = protocol.to_ascii_uppercase();
    if protocol != "TCP" && protocol != "UDP" {
        anyhow::bail!("Unsupported firewall protocol: {}", protocol);
    }
    if name.trim().is_empty() {
        anyhow::bail!("Firewall rule name cannot be empty");
    }

    ps(&format!(
        "New-NetFirewallRule -DisplayName '{}' -Direction Inbound -Action Allow -Protocol {} -LocalPort {} -Profile Private -Enabled True -ErrorAction Stop | Out-Null",
        quote(name), protocol, port
    ))?;
    Ok(())
}

pub fn remove(name: &str) -> anyhow::Result<()> {
    if name.trim().is_empty() {
        anyhow::bail!("Firewall rule name cannot be empty");
    }

    // Match exact display names; -DisplayName accepts wildcard patterns.
    ps(&format!(
        "Get-NetFirewallRule -ErrorAction Stop | Where-Object {{ $_.DisplayName -eq '{}' }} | Remove-NetFirewallRule -Confirm:$false -ErrorAction Stop",
        quote(name)
    ))?;
    Ok(())
}
