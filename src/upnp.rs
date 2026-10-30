use anyhow::{Context, Result};
use reqwest::blocking::Client;
use serde::Serialize;
use std::{collections::HashMap, net::{Ipv4Addr, SocketAddr, UdpSocket}, time::{Duration, Instant}};

#[derive(Clone, Debug, Serialize)]
pub struct Mapping {
    pub index: u32,
    pub remote_host: String,
    pub external_port: u16,
    pub protocol: String,
    pub internal_port: u16,
    pub internal_client: String,
    pub enabled: bool,
    pub description: String,
    pub lease_duration: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct Device {
    pub location: String,
    pub server: String,
    pub rules: Vec<Mapping>,
    pub rules_error: Option<String>,
}

fn headers(response:&str)->HashMap<String,String>{response.lines().filter_map(|l|l.split_once(':')).map(|(k,v)|(k.trim().to_ascii_lowercase(),v.trim().to_string())).collect()}
fn xml_escape(v:&str)->String{v.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;").replace('"',"&quot;").replace('\'',"&apos;")}
fn tag_value<'a>(xml:&'a str,tag:&str)->Option<&'a str>{let lower=xml.to_ascii_lowercase();let open=format!("<{tag}>");let close=format!("</{tag}>");let start=lower.find(&open)?+open.len();let end=lower[start..].find(&close)?+start;Some(xml[start..end].trim())}
fn tag_string(xml:&str,tag:&str)->String{tag_value(xml,tag).unwrap_or_default().to_string()}
fn tag_u16(xml:&str,tag:&str)->u16{tag_string(xml,tag).parse().unwrap_or(0)}
fn tag_u32(xml:&str,tag:&str)->u32{tag_string(xml,tag).parse().unwrap_or(0)}

fn discover_locations()->Result<Vec<(String,String)>>{
    let socket=UdpSocket::bind("0.0.0.0:0").context("Could not open a UDP socket for UPnP discovery")?;
    socket.set_broadcast(true)?; socket.set_read_timeout(Some(Duration::from_millis(250)))?;
    let destination=SocketAddr::new(Ipv4Addr::new(239,255,255,250).into(),1900);
    let targets=["urn:schemas-upnp-org:device:InternetGatewayDevice:1","urn:schemas-upnp-org:device:InternetGatewayDevice:2","urn:schemas-upnp-org:service:WANIPConnection:1","urn:schemas-upnp-org:service:WANIPConnection:2","urn:schemas-upnp-org:service:WANPPPConnection:1","urn:schemas-upnp-org:service:WANPPPConnection:2","ssdp:all"];
    for target in targets {let query=format!("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: {target}\r\n\r\n");socket.send_to(query.as_bytes(),destination)?;}
    let mut devices=Vec::new();let mut buffer=[0u8;8192];let deadline=Instant::now()+Duration::from_secs(5);let mut last=Instant::now();
    loop{if Instant::now()>=deadline{break}match socket.recv_from(&mut buffer){Ok((size,_))=>{last=Instant::now();let h=headers(&String::from_utf8_lossy(&buffer[..size]));if let Some(location)=h.get("location"){if !devices.iter().any(|(l,_)|l==location){devices.push((location.clone(),h.get("server").cloned().unwrap_or_default()));}}}Err(e) if e.kind()==std::io::ErrorKind::WouldBlock||e.kind()==std::io::ErrorKind::TimedOut=>{if !devices.is_empty()&&last.elapsed()>=Duration::from_millis(750){break}}Err(e)=>return Err(e).context("Failed while receiving UPnP discovery replies")}}
    Ok(devices)
}

fn service_control_url(description_url:&str)->Result<(String,&'static str)>{
    let xml=Client::builder().timeout(Duration::from_secs(5)).build()?.get(description_url).send()?.error_for_status()?.text()?;let lower=xml.to_ascii_lowercase();
    for (service_type,needle) in [("urn:schemas-upnp-org:service:WANIPConnection:2","urn:schemas-upnp-org:service:wanipconnection:2"),("urn:schemas-upnp-org:service:WANIPConnection:1","urn:schemas-upnp-org:service:wanipconnection:1"),("urn:schemas-upnp-org:service:WANPPPConnection:2","urn:schemas-upnp-org:service:wanpppconnection:2"),("urn:schemas-upnp-org:service:WANPPPConnection:1","urn:schemas-upnp-org:service:wanpppconnection:1")] {
        if let Some(pos)=lower.find(needle){let start=lower[..pos].rfind("<service>").unwrap_or(0);let end=lower[pos..].find("</service>").map(|o|pos+o).unwrap_or(xml.len());let section=&xml[start..end];if let Some(control)=tag_value(section,"controlURL"){return Ok((reqwest::Url::parse(description_url)?.join(control)?.to_string(),service_type));}}
    }
    Err(anyhow::anyhow!("No WANIPConnection/WANPPPConnection service found"))
}

fn soap(control:&str,service_type:&str,action:&str,body:&str)->Result<String>{
    let envelope=format!(r#"<?xml version="1.0"?><s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:{action} xmlns:u="{service_type}">{body}</u:{action}></s:Body></s:Envelope>"#);
    let response=Client::builder().timeout(Duration::from_secs(8)).build()?.post(control).header("Content-Type","text/xml; charset=\"utf-8\"").header("SOAPAction",format!("\"{service_type}#{action}\"")).body(envelope).send()?;let status=response.status();let text=response.text().unwrap_or_default();
    if !status.is_success(){let detail=tag_string(&text,"errorDescription");anyhow::bail!("UPnP router error ({}): {}",status,if detail.is_empty(){"router rejected the request"}else{&detail});}
    if text.to_ascii_lowercase().contains("<s:fault")||text.to_ascii_lowercase().contains(":fault>"){let detail=tag_string(&text,"errorDescription");anyhow::bail!("UPnP SOAP fault: {}",if detail.is_empty(){"router returned a SOAP fault"}else{&detail});}
    Ok(text)
}

pub fn discover()->Result<Vec<Device>>{let mut out=Vec::new();for (location,server) in discover_locations()?{match list_mappings_at(&location){Ok(rules)=>out.push(Device{location,server,rules,rules_error:None}),Err(e)=>out.push(Device{location,server,rules:Vec::new(),rules_error:Some(e.to_string())})}}Ok(out)}
pub fn list_mappings(device:&Device)->Result<Vec<Mapping>>{list_mappings_at(&device.location)}
fn list_mappings_at(location:&str)->Result<Vec<Mapping>>{
    let (control,service_type)=service_control_url(location)?;let mut rules=Vec::new();
    for index in 0..4096u32 {
        let body=format!("<NewPortMappingIndex>{index}</NewPortMappingIndex><NewRemoteHost></NewRemoteHost><NewExternalPort>0</NewExternalPort><NewProtocol>TCP</NewProtocol>");
        let response=match soap(&control,&service_type,"GetListOfPortMappings",&body){Ok(v)=>v,Err(error)=>{if rules.is_empty(){return Err(error)}else{break}}};
        rules.push(Mapping{index,remote_host:tag_string(&response,"NewRemoteHost"),external_port:tag_u16(&response,"NewExternalPort"),protocol:tag_string(&response,"NewProtocol"),internal_port:tag_u16(&response,"NewInternalPort"),internal_client:tag_string(&response,"NewInternalClient"),enabled:tag_string(&response,"NewEnabled")=="1",description:tag_string(&response,"NewPortMappingDescription"),lease_duration:tag_u32(&response,"NewLeaseDuration")});
    }
    Ok(rules)
}

pub fn add(device:&Device,external_port:u16,internal_port:u16,protocol:&str,client_ip:&str,description:&str)->Result<()>{let protocol=protocol.to_ascii_uppercase();if protocol!="TCP"&&protocol!="UDP"{anyhow::bail!("Unsupported UPnP protocol: {}",protocol)}let client_ip:Ipv4Addr=client_ip.parse().context("Internal client must be a valid IPv4 address")?;let(control,service_type)=service_control_url(&device.location)?;let body=format!("<NewRemoteHost></NewRemoteHost><NewExternalPort>{external_port}</NewExternalPort><NewProtocol>{protocol}</NewProtocol><NewInternalPort>{internal_port}</NewInternalPort><NewInternalClient>{client_ip}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{}</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration>",xml_escape(description));soap(&control,&service_type,"AddPortMapping",&body)?;Ok(())}
