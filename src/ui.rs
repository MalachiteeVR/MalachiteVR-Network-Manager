use crate::{firewall, network, upnp};
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::thread;
use winit::application::ApplicationHandler;
use winit::event::WindowEvent;
use winit::event_loop::{ActiveEventLoop, EventLoopProxy};
use winit::window::{Window, WindowId};
use wry::{WebView, WebViewBuilder};

const HTML: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MalachiteVR Network Manager</title>
<style>
:root{font-family:Inter,Segoe UI,system-ui,sans-serif;color:#e9f4ed;background:#0b100e;--green:#4cbe73;--green2:#79d99a;--panel:#121b16;--panel2:#17221b;--line:#24372b;--muted:#91a59a;--danger:#e56b6f}
*{box-sizing:border-box}body{margin:0;height:100vh;overflow:hidden;background:radial-gradient(circle at 80% -10%,#193c27 0,#0b100e 42%);display:flex}
#app{display:flex;width:100%;height:100%}.side{width:250px;flex:none;background:rgba(9,14,11,.9);border-right:1px solid var(--line);padding:24px 16px;display:flex;flex-direction:column;backdrop-filter:blur(18px)}
.brand{padding:8px 12px 25px}.brand b{display:block;color:var(--green2);font-size:22px;letter-spacing:1.5px}.brand span{color:#718178;font-size:11px;letter-spacing:2px}.nav{display:grid;gap:7px}.nav button{border:1px solid transparent;background:transparent;color:#9cad9f;text-align:left;padding:13px 14px;border-radius:10px;font-size:14px;cursor:pointer}.nav button:hover{background:#142019;color:#e9f4ed}.nav button.active{background:linear-gradient(90deg,#193a27,#132219);border-color:#28543a;color:#fff;box-shadow:inset 3px 0 0 var(--green)}.sidefoot{margin-top:auto;color:#617168;font-size:11px;padding:10px 12px}.main{flex:1;min-width:0;overflow:auto;padding:34px 40px}.top{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:25px}.eyebrow{color:var(--green);font-size:11px;letter-spacing:2px;font-weight:700}.title{font-size:30px;font-weight:750;margin:5px 0}.sub{color:var(--muted);font-size:14px}.actions{display:flex;gap:8px}.btn{border:1px solid #31543f;background:#17271d;color:#dce9df;border-radius:9px;padding:10px 14px;cursor:pointer;font-weight:600}.btn:hover{background:#1d3426;border-color:#467557}.btn.primary{background:var(--green);border-color:var(--green);color:#07110a}.btn.primary:hover{background:var(--green2)}.btn.danger{color:#ffb7b9;border-color:#633337;background:#261416}.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.card{background:linear-gradient(145deg,rgba(23,34,27,.95),rgba(14,22,17,.95));border:1px solid var(--line);border-radius:15px;padding:18px;box-shadow:0 12px 35px #0003}.label{font-size:11px;color:#718178;letter-spacing:1.5px}.value{font-size:28px;font-weight:750;margin-top:7px}.hint{font-size:12px;color:#718178;margin-top:4px}.panel{margin-top:16px;background:rgba(15,24,19,.86);border:1px solid var(--line);border-radius:15px;padding:20px}.panel h2{font-size:16px;margin:0 0 5px}.panel p{color:var(--muted);font-size:13px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.field{display:grid;gap:7px}.field label{font-size:12px;color:#84968c}.input,select{width:100%;background:#0d1510;border:1px solid #2a3c31;border-radius:8px;color:#e8f1ea;padding:10px;outline:none}.input:focus,select:focus{border-color:#4b8d63;box-shadow:0 0 0 3px #4cbe7317}.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:11px;margin-top:15px}.table{width:100%;border-collapse:collapse;font-size:13px}.table th{color:#718178;text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:1px;background:#101912;position:sticky;top:0}.table th,.table td{padding:11px 12px;border-bottom:1px solid #1d2a22;white-space:nowrap}.table tr:last-child td{border-bottom:0}.pill{display:inline-flex;padding:4px 8px;border-radius:99px;background:#183321;color:#82dca1;font-size:11px;font-weight:700}.pill.off{background:#252b27;color:#849087}.status{position:fixed;right:24px;bottom:20px;background:#17251c;border:1px solid #31543f;border-radius:10px;padding:10px 14px;color:#c9d8ce;font-size:12px;box-shadow:0 10px 30px #0006;opacity:0;transform:translateY(8px);transition:.2s}.status.show{opacity:1;transform:none}.mono{font-family:Consolas,monospace;white-space:pre;line-height:1.55;color:#b9c9bf;font-size:12px}.empty{padding:35px;text-align:center;color:#718178}.gateway{padding:12px;border:1px solid var(--line);border-radius:10px;margin-top:8px;cursor:pointer}.gateway.selected{border-color:#3e7955;background:#14241a}.small{font-size:11px;color:#65766c;word-break:break-all}.section{display:none}.section.active{display:block}@media(max-width:900px){.side{width:200px}.main{padding:25px}.cards{grid-template-columns:repeat(2,1fr)}}
</style></head>
<body><div id="app">
<aside class="side"><div class="brand"><b>MALACHITEVR</b><span>NETWORK MANAGER</span></div><div class="nav">
<button data-page="overview" class="active">◈ &nbsp; Overview</button><button data-page="adapters">▦ &nbsp; Network Adapters</button><button data-page="connections">⇄ &nbsp; Connections</button><button data-page="firewall">◉ &nbsp; Windows Firewall</button><button data-page="upnp">↗ &nbsp; UPnP / Forwarding</button>
</div><div class="sidefoot">MalachiteeVR<br>Windows · WebView2</div></aside>
<main class="main">
<section id="overview" class="section active"><div class="top"><div><div class="eyebrow">SYSTEM STATUS</div><div class="title">Network overview</div><div class="sub">A quiet control center for your Windows networking stack.</div></div><div class="actions"><button class="btn" onclick="send('refresh')">Refresh</button><button class="btn primary" onclick="send('discover')">Discover UPnP</button></div></div><div class="cards"><div class="card"><div class="label">ADAPTERS</div><div class="value" id="cAdapters">0</div><div class="hint">detected</div></div><div class="card"><div class="label">ACTIVE</div><div class="value" id="cActive">0</div><div class="hint">online</div></div><div class="card"><div class="label">FIREWALL</div><div class="value" id="cRules">0</div><div class="hint">rules visible</div></div><div class="card"><div class="label">UPnP</div><div class="value" id="cUpnp">0</div><div class="hint">gateways found</div></div></div><div class="panel"><h2>Private network</h2><p>Your detected LAN address used for new port mappings.</p><div id="ip" class="value" style="font-size:21px">Detecting…</div></div></section>
<section id="adapters" class="section"><div class="top"><div><div class="eyebrow">NETWORK</div><div class="title">Network adapters</div><div class="sub">Interfaces and link state reported by Windows.</div></div><button class="btn" onclick="send('refresh')">Refresh</button></div><div class="tablewrap"><table class="table"><thead><tr><th>Name</th><th>Description</th><th>Status</th><th>Speed</th><th>MAC</th><th></th></tr></thead><tbody id="adapterRows"></tbody></table></div></section>
<section id="connections" class="section"><div class="top"><div><div class="eyebrow">SOCKETS</div><div class="title">Current TCP connections</div><div class="sub">The latest 300 connections reported by Windows.</div></div><button class="btn" onclick="send('connections')">Refresh</button></div><div class="panel"><div id="connectionsText" class="mono">Press Refresh to query Windows.</div></div></section>
<section id="firewall" class="section"><div class="top"><div><div class="eyebrow">SECURITY</div><div class="title">Windows Firewall</div><div class="sub">Inbound rules. Administrative changes are performed in the background.</div></div></div><div class="panel"><div class="grid"><div class="field"><label>Rule name</label><input id="ruleName" class="input" value="Malachite Allow"></div><div class="field"><label>Port</label><input id="rulePort" class="input" value="25565" inputmode="numeric"></div><div class="field"><label>Protocol</label><select id="ruleProto"><option>TCP</option><option>UDP</option></select></div></div><div style="margin-top:15px"><button class="btn primary" onclick="addFirewall()">Allow inbound</button></div></div><div class="tablewrap"><table class="table"><thead><tr><th>Rule</th><th>Direction</th><th>Action</th><th>Enabled</th><th>Protocol</th><th>Port</th><th>Profile</th><th></th></tr></thead><tbody id="firewallRows"></tbody></table></div></section>
<section id="upnp" class="section"><div class="top"><div><div class="eyebrow">NAT</div><div class="title">UPnP / port forwarding</div><div class="sub">Discover an Internet Gateway Device and create a NAT mapping.</div></div><button class="btn" onclick="send('discover')">Discover gateways</button></div><div id="gateways"></div><div class="panel"><div class="grid"><div class="field"><label>External port</label><input id="ext" class="input" value="25565"></div><div class="field"><label>Internal port</label><input id="intp" class="input" value="25565"></div><div class="field"><label>Private IPv4</label><input id="client" class="input"></div><div class="field"><label>Description</label><input id="desc" class="input" value="MalachiteVR Network Manager"></div></div><div style="display:flex;gap:8px;margin-top:15px"><button class="btn primary" onclick="addUpnp('TCP')">Add TCP mapping</button><button class="btn" onclick="addUpnp('UDP')">Add UDP mapping</button></div></div></section>
</main></div><div id="status" class="status"></div>
<script>
let gateways=[],selectedGateway=0;
const esc=s=>String(s??'').replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function send(action,data={}){window.ipc?.postMessage(JSON.stringify({action,...data}));toast('Working in background…')}
function toast(t){let e=document.getElementById('status');e.textContent=t;e.classList.add('show');clearTimeout(window._toast);window._toast=setTimeout(()=>e.classList.remove('show'),2600)}
function renderAdapters(a){document.getElementById('cAdapters').textContent=a.length;document.getElementById('cActive').textContent=a.filter(x=>x.status==='Up').length;document.getElementById('adapterRows').innerHTML=a.map(x=>`<tr><td>${esc(x.name)}</td><td>${esc(x.description)}</td><td><span class="pill ${x.status==='Up'?'':'off'}">${esc(x.status)}</span></td><td>${esc(x.speed)}</td><td>${esc(x.mac||'—')}</td><td><button class="btn" onclick="send('toggle',{name:${JSON.stringify(x.name)},enable:${x.status!=='Up'}})">${x.status==='Up'?'Disable':'Enable'}</button></td></tr>`).join('')||'<tr><td colspan="6" class="empty">No adapters found.</td></tr>'}
function renderFirewall(r){document.getElementById('cRules').textContent=r.length;document.getElementById('firewallRows').innerHTML=r.map(x=>`<tr><td>${esc(x.name)}</td><td>${esc(x.direction)}</td><td>${esc(x.action)}</td><td>${esc(x.enabled)}</td><td>${esc(x.protocol)}</td><td>${esc(x.local_port)}</td><td>${esc(x.profile)}</td><td><button class="btn danger" onclick="send('firewall_remove',{name:${JSON.stringify(x.name)}})">Delete</button></td></tr>`).join('')||'<tr><td colspan="8" class="empty">No firewall rules returned.</td></tr>'}
function renderGateways(g){gateways=g;document.getElementById('cUpnp').textContent=g.length;document.getElementById('gateways').innerHTML=g.map((x,i)=>`<div class="gateway ${i===selectedGateway?'selected':''}" onclick="selectedGateway=${i};renderGateways(gateways)"><b>Gateway ${i+1}</b><div class="small">${esc(x.server||'Unknown device')}</div><div class="small">${esc(x.location)}</div></div>`).join('')||'<div class="panel empty">No UPnP gateways discovered.</div>'}
window.__nm_result=function(v){if(v.error){toast(v.error);return}if(v.message)toast(v.message);if(v.kind==='refresh'){renderAdapters(v.adapters||[]);renderFirewall(v.rules||[]);document.getElementById('ip').textContent=v.ip||'Not detected';document.getElementById('client').value=v.ip||''}if(v.kind==='discover')renderGateways(v.devices||[]);if(v.kind==='connections')document.getElementById('connectionsText').textContent=v.text||'No connections returned.'};
function addFirewall(){let port=Number(document.getElementById('rulePort').value);if(!port||port>65535)return toast('Port must be 1-65535');send('firewall_add',{name:document.getElementById('ruleName').value,port,protocol:document.getElementById('ruleProto').value})}
function addUpnp(protocol){let external=Number(document.getElementById('ext').value),internal=Number(document.getElementById('intp').value),client=document.getElementById('client').value;if(!gateways.length)return toast('Discover a gateway first');if(!external||!internal||external>65535||internal>65535)return toast('Ports must be 1-65535');send('upnp_add',{index:selectedGateway,external,internal,protocol,client,description:document.getElementById('desc').value})}
document.querySelectorAll('.nav button').forEach(b=>b.onclick=()=>{document.querySelectorAll('.nav button').forEach(x=>x.classList.remove('active'));document.querySelectorAll('.section').forEach(x=>x.classList.remove('active'));b.classList.add('active');document.getElementById(b.dataset.page).classList.add('active')});
send('refresh');
</script></body></html>"##;

enum UserEvent { Result(String) }

pub struct App {
    window: Option<Window>,
    webview: Option<WebView>,
    proxy: EventLoopProxy<UserEvent>,
}

impl App {
    pub fn new(proxy: EventLoopProxy<UserEvent>) -> Self { Self { window: None, webview: None, proxy } }
}

fn run_command(message: &str, proxy: &EventLoopProxy<UserEvent>) {
    let parsed: Value = match serde_json::from_str(message) {
        Ok(v) => v,
        Err(e) => { let _ = proxy.send_event(UserEvent::Result(json!({"error": format!("Invalid command: {e}")}).to_string())); return; }
    };
    let action = parsed.get("action").and_then(Value::as_str).unwrap_or("").to_string();
    let proxy = proxy.clone();
    thread::spawn(move || {
        let result = match action.as_str() {
            "refresh" => {
                let adapters = network::adapters()?;
                let rules = firewall::rules()?;
                let ip = network::private_ipv4()?.map(|x| x.to_string());
                Ok(json!({"kind":"refresh","adapters":adapters.iter().map(|a| json!({"name":a.name,"description":a.description,"status":a.status,"speed":a.speed,"mac":a.mac})).collect::<Vec<_>>(),"rules":rules.iter().map(|r| json!({"name":r.name,"direction":r.direction,"action":r.action,"enabled":r.enabled,"profile":r.profile,"protocol":r.protocol,"local_port":r.local_port})).collect::<Vec<_>>(),"ip":ip}))
            }
            "connections" => Ok(json!({"kind":"connections","text":network::connections()?})),
            "discover" => {
                let devices = upnp::discover()?;
                Ok(json!({"kind":"discover","devices":devices.iter().map(|d| json!({"location":d.location,"server":d.server})).collect::<Vec<_>>()}))
            }
            "toggle" => {
                let name = parsed.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                let enable = parsed.get("enable").and_then(Value::as_bool).unwrap_or(false);
                network::toggle(&name, enable)?;
                Ok(json!({"message":format!("Adapter '{}' updated", name)}))
            }
            "firewall_add" => {
                let name=parsed.get("name").and_then(Value::as_str).unwrap_or("");
                let port=parsed.get("port").and_then(Value::as_u64).unwrap_or(0) as u16;
                let proto=parsed.get("protocol").and_then(Value::as_str).unwrap_or("TCP");
                if name.trim().is_empty() || port==0 { anyhow::bail!("Rule name and a valid port are required"); }
                firewall::add(name.trim(),port,proto)?;
                Ok(json!({"message":"Firewall rule created"}))
            }
            "firewall_remove" => { let name=parsed.get("name").and_then(Value::as_str).unwrap_or(""); firewall::remove(name)?; Ok(json!({"message":"Firewall rule removed"})) }
            "upnp_add" => {
                let index=parsed.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                let devices=upnp::discover()?;
                if index>=devices.len(){ anyhow::bail!("Selected UPnP gateway is no longer available"); }
                let external=parsed.get("external").and_then(Value::as_u64).unwrap_or(0) as u16;
                let internal=parsed.get("internal").and_then(Value::as_u64).unwrap_or(0) as u16;
                let protocol=parsed.get("protocol").and_then(Value::as_str).unwrap_or("TCP");
                let client=parsed.get("client").and_then(Value::as_str).unwrap_or("");
                let description=parsed.get("description").and_then(Value::as_str).unwrap_or("");
                let ip: Ipv4Addr=client.parse().map_err(|_| anyhow::anyhow!("Private IP must be a valid IPv4 address"))?;
                if !ip.is_private(){ anyhow::bail!("Private IP must be an RFC1918 address"); }
                if external==0 || internal==0 { anyhow::bail!("Ports must be 1-65535"); }
                upnp::add(&devices[index],external,internal,protocol,&ip.to_string(),description)?;
                Ok(json!({"message":format!("{} port mapping created",protocol)}))
            }
            _ => anyhow::bail!("Unknown command: {action}"),
        };
        let payload = match result { Ok(v)=>v.to_string(), Err(e)=>json!({"error":e.to_string()}).to_string() };
        let _=proxy.send_event(UserEvent::Result(payload));
    });
}

impl ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() { return; }
        let attrs = Window::default_attributes()
            .with_title("MalachiteVR Network Manager")
            .with_inner_size(winit::dpi::LogicalSize::new(1280.0, 820.0))
            .with_min_inner_size(winit::dpi::LogicalSize::new(980.0, 640.0));
        let window = event_loop.create_window(attrs).expect("Failed to create window");
        let proxy = self.proxy.clone();
        let webview = WebViewBuilder::new()
            .with_html(HTML)
            .with_ipc_handler(move |request| run_command(request.body(), &proxy))
            .build(&window)
            .expect("Failed to initialize Microsoft Edge WebView2");
        self.window=Some(window);
        self.webview=Some(webview);
    }

    fn user_event(&mut self, _event_loop: &ActiveEventLoop, event: UserEvent) {
        if let (Some(webview), UserEvent::Result(payload)) = (&self.webview, event) {
            let script = format!("window.__nm_result({});", payload);
            let _ = webview.evaluate_script(&script);
        }
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _window_id: WindowId, event: WindowEvent) {
        if matches!(event, WindowEvent::CloseRequested) { event_loop.exit(); }
    }
}

pub fn run() -> anyhow::Result<()> {
    let event_loop = winit::event_loop::EventLoop::<UserEvent>::with_user_event().build()?;
    let proxy = event_loop.create_proxy();
    let mut app = App::new(proxy);
    event_loop.run_app(&mut app)?;
    Ok(())
}
