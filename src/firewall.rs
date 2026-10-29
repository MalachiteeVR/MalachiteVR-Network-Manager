use crate::admin::ps;

#[derive(Clone, Debug)]
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
    value.replace(''', "''")
}

pub fn rules() -> anyhow::Result<Vec<Rule>> {
    let script = r#"Get-NetFirewallRule |
        Select-Object -First 1000 DisplayName,Direction,Action,Enabled,Profile,PrimaryStatus |
        ForEach-Object {
            $p = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue |
                 Select-Object -First 1 Protocol,LocalPort
            [PSCustomObject]@{
                DisplayName=$_.DisplayName
                Direction=$_.Direction
                Action=$_.Action
                Enabled=$_.Enabled
                Profile=$_.Profile
                Protocol=if($p){$p.Protocol}else{''}
                LocalPort=if($p){$p.LocalPort}else{''}
            }
        } | ConvertTo-Json -Compress"#;

    let s = ps(script)?;
    if s.is_empty() {
        return Ok(Vec::new());
    }

    let value: serde_json::Value = serde_json::from_str(&s)?;
    let items = if value.is_array() {
        value.as_array().cloned().unwrap_or_default()
    } else {
        vec![value]
    };

    Ok(items
        .into_iter()
        .map(|x| Rule {
            name: x["DisplayName"].as_str().unwrap_or_default().to_string(),
            direction: x["Direction"].as_str().unwrap_or_default().to_string(),
            action: x["Action"].as_str().unwrap_or_default().to_string(),
            enabled: x["Enabled"].as_str().unwrap_or_default().to_string(),
            profile: x["Profile"].as_str().unwrap_or_default().to_string(),
            protocol: x["Protocol"].as_str().unwrap_or_default().to_string(),
            local_port: x["LocalPort"].as_str().unwrap_or_else(|| {
                if x["LocalPort"].is_number() { "" } else { "" }
            }).to_string(),
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
