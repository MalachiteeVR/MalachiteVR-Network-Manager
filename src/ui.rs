use crate::{firewall, network, upnp};
use anyhow::Context;
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::thread;
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, EventLoopProxy};
use winit::window::{Window, WindowId};
use wry::{WebView, WebViewBuilder};

const HTML: &str = r##"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>MalachiteVR Network Manager</title></head><body><div id="app"></div><script>window.ipc={postMessage:()=>{}};</script></body></html>"##;

enum UserEvent { Result(String) }

pub struct App { window: Option<Window>, webview: Option<WebView>, proxy: EventLoopProxy<UserEvent> }
impl App { pub fn new(proxy: EventLoopProxy<UserEvent>) -> Self { Self { window: None, webview: None, proxy } } }

fn run_command(message: &str, proxy: &EventLoopProxy<UserEvent>) {
    let parsed: Value = match serde_json::from_str(message) {
        Ok(v) => v,
        Err(e) => { let _ = proxy.send_event(UserEvent::Result(json!({"error":e.to_string()}).to_string())); return; }
    };
    let action = match parsed.get("action").and_then(Value::as_str) {
        Some(a) => a.to_owned(),
        None => { let _ = proxy.send_event(UserEvent::Result(json!({"error":"Missing action"}).to_string())); return; }
    };
    let proxy = proxy.clone();
    thread::spawn(move || {
        let result: anyhow::Result<Value> = (|| {
            match action.as_str() {
                "refresh" => { let adapters=network::adapters()?; let rules=firewall::rules()?; let ip=network::private_ipv4()?.map(|x|x.to_string()); Ok(json!({"kind":"refresh","adapters":adapters,"rules":rules,"ip":ip})) }
                "connections" => Ok(json!({"kind":"connections","text":network::connections()?})),
                "discover" => Ok(json!({"kind":"discover","devices":upnp::discover()?})),
                "toggle" => { let name=parsed.get("name").and_then(Value::as_str).context("Missing adapter name")?.to_owned(); let enable=parsed.get("enable").and_then(Value::as_bool).context("Missing enable state")?; network::toggle(&name,enable)?; Ok(json!({"message":format!("Adapter {}.",if enable{"enabled"}else{"disabled"})})) }
                "firewall_add" => { let name=parsed.get("name").and_then(Value::as_str).context("Missing rule name")?; let port=parsed.get("port").and_then(Value::as_u64).context("Missing port")?; let protocol=parsed.get("protocol").and_then(Value::as_str).context("Missing protocol")?; if name.trim().is_empty()||!(1..=65535).contains(&port){anyhow::bail!("Rule name and a valid port are required")}; if !matches!(protocol,"TCP"|"UDP"){anyhow::bail!("Protocol must be TCP or UDP")}; firewall::add(name,port as u16,protocol)?; Ok(json!({"message":"Firewall rule added."})) }
                "firewall_remove" => { let name=parsed.get("name").and_then(Value::as_str).context("Missing rule name")?; firewall::remove(name)?; Ok(json!({"message":"Firewall rule removed."})) }
                "upnp_add" => { let index=parsed.get("index").and_then(Value::as_u64).context("Missing gateway index")? as usize; let external=parsed.get("external").and_then(Value::as_u64).context("Missing external port")?; let internal=parsed.get("internal").and_then(Value::as_u64).context("Missing internal port")?; let protocol=parsed.get("protocol").and_then(Value::as_str).context("Missing protocol")?; let client=parsed.get("client").and_then(Value::as_str).context("Missing private IPv4")?; let description=parsed.get("description").and_then(Value::as_str).unwrap_or("MalachiteVR Network Manager"); if !(1..=65535).contains(&external)||!(1..=65535).contains(&internal){anyhow::bail!("Ports must be 1-65535")}; if !matches!(protocol,"TCP"|"UDP"){anyhow::bail!("Protocol must be TCP or UDP")}; let ip:Ipv4Addr=client.parse().context("Invalid private IPv4 address")?; if !ip.is_private(){anyhow::bail!("The target address must be a private IPv4 address")}; let devices=upnp::discover()?; let device=devices.get(index).context("Selected gateway no longer exists")?; upnp::add(device,external as u16,internal as u16,protocol,client,description)?; Ok(json!({"message":"UPnP port mapping added."})) }
                _ => anyhow::bail!("Unknown command: {action}"),
            }
        })();
        let payload=match result { Ok(value)=>value.to_string(), Err(error)=>json!({"error":error.to_string()}).to_string() };
        let _=proxy.send_event(UserEvent::Result(payload));
    });
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self,event_loop:&ActiveEventLoop){
        if self.window.is_some(){return;}
        let attrs=Window::default_attributes().with_title("MalachiteVR Network Manager").with_inner_size(winit::dpi::LogicalSize::new(1280.0,820.0));
        let window=event_loop.create_window(attrs).expect("Failed to create window");
        let webview=WebViewBuilder::new().with_html(HTML).with_ipc_handler({let proxy=self.proxy.clone();move |request|run_command(request.body(),&proxy)}).build(&window).expect("Failed to initialize Microsoft Edge WebView2");
        self.webview=Some(webview); self.window=Some(window);
    }
    fn user_event(&mut self,_event_loop:&ActiveEventLoop,event:UserEvent){let UserEvent::Result(payload)=event;if let Some(webview)=&self.webview{let script=format!("window.__nm_result({});",payload);let _=webview.evaluate_script(&script);}}
    fn window_event(&mut self,event_loop:&ActiveEventLoop,_window_id:WindowId,event:WindowEvent){if matches!(event,WindowEvent::CloseRequested){event_loop.exit();}}
}

pub fn run()->anyhow::Result<()>{let event_loop=winit::event_loop::EventLoop::<UserEvent>::with_user_event().build()?;let proxy=event_loop.create_proxy();let mut app=App::new(proxy);event_loop.run_app(&mut app)?;Ok(())}
