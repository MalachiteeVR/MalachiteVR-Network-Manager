use serde::Serialize;
use windows_firewall::{
    add_rule, list_rules, remove_rule, Action, Direction, FirewallRule, Profile, Protocol,
};

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

pub fn rules() -> anyhow::Result<Vec<Rule>> {
    let rules = list_rules()
        .map_err(|error| anyhow::anyhow!("Windows Firewall API could not list rules: {error}"))?;

    Ok(rules.into_iter().take(1000).map(|rule| Rule {
        name: rule.name().clone(),
        direction: format!("{:?}", rule.direction()),
        action: format!("{:?}", rule.action()),
        enabled: rule.enabled().to_string(),
        profile: rule.profiles().as_ref().map(|value| format!("{value:?}")).unwrap_or_else(|| "Any".to_string()),
        protocol: rule.protocol().as_ref().map(|value| format!("{value:?}")).unwrap_or_default(),
        local_port: rule.local_ports().as_ref().map(|ports| {
            let mut values: Vec<String> = ports.iter().map(|port| format!("{port:?}")).collect();
            values.sort();
            values.join(", ")
        }).unwrap_or_default(),
    }).collect())
}

pub fn add(name: &str, port: u16, protocol: &str) -> anyhow::Result<()> {
    if name.trim().is_empty() {
        anyhow::bail!("Firewall rule name cannot be empty");
    }
    if name.contains('|') || name.eq_ignore_ascii_case("all") {
        anyhow::bail!("Firewall rule name cannot contain '|' or be 'all'");
    }
    let protocol = match protocol.to_ascii_uppercase().as_str() {
        "TCP" => Protocol::Tcp,
        "UDP" => Protocol::Udp,
        other => anyhow::bail!("Unsupported firewall protocol: {other}"),
    };

    let rule = FirewallRule::builder()
        .name(name.to_string())
        .direction(Direction::In)
        .action(Action::Allow)
        .enabled(true)
        .protocol(protocol)
        .local_ports([port])
        .profiles(Profile::Private)
        .build();

    add_rule(&rule)
        .map_err(|error| anyhow::anyhow!("Windows Firewall API could not add rule: {error}"))?;
    Ok(())
}

pub fn remove(name: &str) -> anyhow::Result<()> {
    if name.trim().is_empty() {
        anyhow::bail!("Firewall rule name cannot be empty");
    }
    remove_rule(name)
        .map_err(|error| anyhow::anyhow!("Windows Firewall API could not remove rule '{name}': {error}"))?;
    Ok(())
}
