use anyhow::{Context,Result};
use std::{net::{Ipv4Addr,SocketAddr,UdpSocket},time::Duration};
#[derive(Clone,Debug)] pub struct Device{pub location:String,pub server:String}
fn headers(s:&str)->std::collections::HashMap<String,String>{s.lines().filter_map(|x|x.split_once(':')).map(|(a,b)|(a.trim().to_ascii_lowercase(),b.trim().into())).collect()}
pub fn discover()->Result<Vec<Device>>{
    let sock=UdpSocket::bind("0.0.0.0:0")?; sock.set_read_timeout(Some(Duration::from_millis(900)))?;
    let q="M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n";
    sock.send_to(q.as_bytes(),SocketAddr::new(Ipv4Addr::new(239,255,255,250).into(),1900))?;
    let mut out=vec![]; let mut b=[0u8;8192];
    loop{match sock.recv_from(&mut b){Ok((n,_))=>{let h=headers(&String::from_utf8_lossy(&b[..n]));if let Some(l)=h.get("location"){if !out.iter().any(|d:&Device|&d.location==l){out.push(Device{location:l.clone(),server:h.get("server").cloned().unwrap_or_default()});}}},Err(_)=>break}}
    Ok(out)
}
fn control(url:&str)->Result<String>{
    let body=reqwest::blocking::get(url)?.text()?;
    let low=body.to_ascii_lowercase(); let p=low.find("urn:schemas-upnp-org:service:wanipconnection:1").context("WANIPConnection not found")?;
    let a=body[..p].rfind("<service>").unwrap_or(0); let e=body[p..].find("</service>").map(|x|p+x).unwrap_or(body.len()); let sec=&body[a..e];
    let s=sec.find("<controlURL>").context("controlURL missing")?+12; let z=sec[s..].find("</controlURL>").context("controlURL end missing")?+s;
    Ok(reqwest::Url::parse(url)?.join(&sec[s..z])?.to_string())
}
pub fn add(d:&Device,ext:u16,int:u16,proto:&str,client:&str,desc:&str)->Result<()>{
    let xml=format!(r#"<?xml version="1.0"?><s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewRemoteHost></NewRemoteHost><NewExternalPort>{ext}</NewExternalPort><NewProtocol>{proto}</NewProtocol><NewInternalPort>{int}</NewInternalPort><NewInternalClient>{client}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>{desc}</NewPortMappingDescription><NewLeaseDuration>0</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>"#);
    reqwest::blocking::Client::new().post(control(&d.location)?).header("Content-Type","text/xml; charset=\"utf-8\"").header("SOAPAction","\"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping\"").body(xml).send()?.error_for_status()?; Ok(())
}
