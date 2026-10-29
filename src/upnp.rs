use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde::Serialize;
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize)]
pub struct Device {
    pub location: String,
    pub server: String,
}

fn headers(response: &str) -> HashMap<String, String> {
    response
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect()
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn tag_value<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let lower = xml.to_ascii_lowercase();
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = lower.find(&open)? + open.len();
    let end = lower[start..].find(&close)? + start;
    Some(xml[start..end].trim())
}

pub fn discover() -> Result<Vec<Device>> {
    let socket = UdpSocket::bind("0.0.0.0:0")
        .context("Could not open a UDP socket for UPnP discovery")?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(250)))?;

    let destination = SocketAddr::new(Ipv4Addr::new(239, 255, 255, 250).into(), 1900);
    // Routers vary in which SSDP target they advertise. Query common IGD and
    // WAN connection service versions, plus ssdp:all for non-standard devices.
    let targets = [
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANIPConnection:2",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:2",
        "ssdp:all",
    ];
    for target in targets {
        let query = format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {target}\r\n\r\n"
        );
        socket.send_to(query.as_bytes(), destination)?;
    }

    let mut devices = Vec::new();
    let mut buffer = [0u8; 8192];
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_response = Instant::now();
    loop {
        if Instant::now() >= deadline {
            break;
        }
        match socket.recv_from(&mut buffer) {
            Ok((size, _)) => {
                last_response = Instant::now();
                let response = String::from_utf8_lossy(&buffer[..size]);
                let h = headers(&response);
                if let Some(location) = h.get("location") {
                    if !devices.iter().any(|d: &Device| d.location == *location) {
                        devices.push(Device {
                            location: location.clone(),
                            server: h.get("server").cloned().unwrap_or_default(),
                        });
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
                || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                if !devices.is_empty() && last_response.elapsed() >= Duration::from_millis(750) {
                    break;
                }
            }
            Err(error) => return Err(error).context("Failed while receiving UPnP discovery replies"),
        }
    }

    Ok(devices)
}

fn service_control_url(description_url: &str) -> Result<(String, &'static str)> {
    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let xml = client.get(description_url).send()?.error_for_status()?.text()?;
    let lower = xml.to_ascii_lowercase();

    for (service_type, needle) in [
        (
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:wanipconnection:1",
        ),
        (
            "urn:schemas-upnp-org:service:WANPPPConnection:1",
            "urn:schemas-upnp-org:service:wanpppconnection:1",
        ),
    ] {
        if let Some(type_pos) = lower.find(needle) {
            let service_start = lower[..type_pos].rfind("<service>").unwrap_or(0);
            let service_end = lower[type_pos..]
                .find("</service>")
                .map(|offset| type_pos + offset)
                .unwrap_or(xml.len());
            let section = &xml[service_start..service_end];

            if let Some(control) = tag_value(section, "controlURL") {
                return Ok((
                    reqwest::Url::parse(description_url)?.join(control)?.to_string(),
                    service_type,
                ));
            }
        }
    }

    Err(anyhow::anyhow!("No WANIPConnection/WANPPPConnection service found"))
}

pub fn add(
    device: &Device,
    external_port: u16,
    internal_port: u16,
    protocol: &str,
    client_ip: &str,
    description: &str,
) -> Result<()> {
    let protocol = protocol.to_ascii_uppercase();
    if protocol != "TCP" && protocol != "UDP" {
        anyhow::bail!("Unsupported UPnP protocol: {}", protocol);
    }

    let client_ip: Ipv4Addr = client_ip
        .parse()
        .context("Internal client must be a valid IPv4 address")?;

    let (control, service_type) = service_control_url(&device.location)?;
    let xml = format!(
        r#"<?xml version="1.0"?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:AddPortMapping xmlns:u="{service_type}">
      <NewRemoteHost></NewRemoteHost>
      <NewExternalPort>{external_port}</NewExternalPort>
      <NewProtocol>{protocol}</NewProtocol>
      <NewInternalPort>{internal_port}</NewInternalPort>
      <NewInternalClient>{client_ip}</NewInternalClient>
      <NewEnabled>1</NewEnabled>
      <NewPortMappingDescription>{}</NewPortMappingDescription>
      <NewLeaseDuration>0</NewLeaseDuration>
    </u:AddPortMapping>
  </s:Body>
</s:Envelope>"#,
        xml_escape(description)
    );

    let action = format!("\"{}#AddPortMapping\"", service_type);
    let response = Client::builder()
        .timeout(Duration::from_secs(8))
        .build()?
        .post(control)
        .header("Content-Type", "text/xml; charset=\"utf-8\"")
        .header("SOAPAction", action)
        .body(xml)
        .send()?;

    let status = response.status();
    let body = response.text().unwrap_or_default();
    if !status.is_success() {
        let detail = tag_value(&body, "errorDescription").unwrap_or("router rejected the request");
        anyhow::bail!("UPnP router error ({}): {}", status, detail);
    }

    let lower = body.to_ascii_lowercase();
    if lower.contains("<s:fault") || lower.contains(":fault>") {
        let detail = tag_value(&body, "errorDescription").unwrap_or("SOAP fault returned by router");
        anyhow::bail!("UPnP SOAP fault: {}", detail);
    }

    Ok(())
}
