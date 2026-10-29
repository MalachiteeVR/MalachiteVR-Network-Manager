use crate::{firewall, network, upnp};
use eframe::egui::{self, Color32, RichText};
use std::net::Ipv4Addr;

const GREEN: Color32 = Color32::from_rgb(76, 190, 115);
const BG: Color32 = Color32::from_rgb(12, 16, 21);
const PANEL: Color32 = Color32::from_rgb(20, 26, 34);

#[derive(PartialEq, Clone, Copy)]
enum Page {
    Overview,
    Adapters,
    Connections,
    Firewall,
    Upnp,
}

pub struct NetworkManagerApp {
    page: Page,
    adapters: Vec<network::Adapter>,
    rules: Vec<firewall::Rule>,
    connections: String,
    devices: Vec<upnp::Device>,
    selected: usize,
    status: String,
    rule_name: String,
    rule_port: String,
    proto: String,
    ext: String,
    intp: String,
    client: String,
    desc: String,
}

impl NetworkManagerApp {
    pub fn new(_: &eframe::CreationContext<'_>) -> Self {
        let client = network::private_ipv4()
            .ok()
            .flatten()
            .unwrap_or(Ipv4Addr::new(192, 168, 1, 100));

        let mut app = Self {
            page: Page::Overview,
            adapters: Vec::new(),
            rules: Vec::new(),
            connections: String::new(),
            devices: Vec::new(),
            selected: 0,
            status: "Ready".into(),
            rule_name: "Malachite Allow".into(),
            rule_port: "25565".into(),
            proto: "TCP".into(),
            ext: "25565".into(),
            intp: "25565".into(),
            client: client.to_string(),
            desc: "MalachiteVR Network Manager".into(),
        };
        app.reload();
        app
    }

    fn reload(&mut self) {
        match network::adapters() {
            Ok(adapters) => self.adapters = adapters,
            Err(error) => self.status = format!("Adapter refresh failed: {error}"),
        }
        match firewall::rules() {
            Ok(rules) => self.rules = rules,
            Err(error) => self.status = format!("Firewall refresh failed: {error}"),
        }
        if let Ok(Some(ip)) = network::private_ipv4() {
            self.client = ip.to_string();
        }
        if self.status == "Ready" {
            self.status = "Refreshed".into();
        }
    }

    fn side(&mut self, ui: &mut egui::Ui) {
        ui.set_width(230.0);
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.label(RichText::new("MALACHITEVR").size(25.0).strong().color(GREEN));
            ui.label(RichText::new("NETWORK MANAGER").small().color(Color32::GRAY));
        });
        ui.add_space(25.0);

        for (page, name) in [
            (Page::Overview, "Overview"),
            (Page::Adapters, "Network Adapters"),
            (Page::Connections, "Connections"),
            (Page::Firewall, "Windows Firewall"),
            (Page::Upnp, "UPnP / Port Forwarding"),
        ] {
            let selected = self.page == page;
            if ui
                .add_sized(
                    [210.0, 42.0],
                    egui::Button::new(
                        RichText::new(name)
                            .color(if selected { Color32::WHITE } else { Color32::from_gray(175) })
                            .strong(),
                    )
                    .fill(if selected {
                        Color32::from_rgb(32, 62, 48)
                    } else {
                        Color32::TRANSPARENT
                    }),
                )
                .clicked()
            {
                self.page = page;
            }
        }

        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            ui.separator();
            ui.label(RichText::new("MalachiteeVR • Windows").small().color(Color32::GRAY));
        });
    }

    fn card(ui: &mut egui::Ui, title: &str, value: &str, subtitle: &str) {
        egui::Frame::group(ui.style())
            .fill(PANEL)
            .corner_radius(10)
            .inner_margin(16.0)
            .show(ui, |ui| {
                ui.label(RichText::new(title).small().color(Color32::GRAY));
                ui.label(RichText::new(value).size(25.0).strong());
                ui.label(RichText::new(subtitle).small().color(Color32::GRAY));
            });
    }

    fn discover_upnp(&mut self) {
        match upnp::discover() {
            Ok(devices) => {
                self.devices = devices;
                self.selected = 0;
                self.status = format!("Found {} UPnP gateway(s)", self.devices.len());
            }
            Err(error) => self.status = format!("UPnP discovery failed: {error}"),
        }
    }

    fn overview(&mut self, ui: &mut egui::Ui) {
        ui.heading("Network overview");
        ui.label("One control center for your Windows networking stack.");
        ui.add_space(18.0);
        ui.horizontal(|ui| {
            Self::card(ui, "ADAPTERS", &self.adapters.len().to_string(), "detected");
            ui.add_space(10.0);
            Self::card(
                ui,
                "ACTIVE",
                &self.adapters.iter().filter(|a| a.status == "Up").count().to_string(),
                "online",
            );
            ui.add_space(10.0);
            Self::card(ui, "FIREWALL", &self.rules.len().to_string(), "rules visible");
            ui.add_space(10.0);
            Self::card(ui, "UPnP", &self.devices.len().to_string(), "gateways found");
        });
        ui.add_space(22.0);
        egui::Frame::group(ui.style())
            .fill(PANEL)
            .corner_radius(10)
            .inner_margin(18.0)
            .show(ui, |ui| {
                ui.heading("Quick actions");
                ui.horizontal(|ui| {
                    if ui.button("Refresh").clicked() {
                        self.reload();
                    }
                    if ui.button("Discover UPnP").clicked() {
                        self.discover_upnp();
                    }
                    if ui.button("Connections").clicked() {
                        self.page = Page::Connections;
                    }
                    if ui.button("Firewall").clicked() {
                        self.page = Page::Firewall;
                    }
                });
            });
        ui.add_space(15.0);
        ui.label(RichText::new(&self.status).small().color(Color32::GRAY));
    }

    fn adapters(&mut self, ui: &mut egui::Ui) {
        ui.heading("Network adapters");
        if ui.button("Refresh").clicked() {
            self.reload();
        }
        ui.add_space(12.0);
        egui::Grid::new("adapters_grid").striped(true).show(ui, |ui| {
            for header in ["Name", "Status", "Speed", "MAC", "Actions"] {
                ui.strong(header);
            }
            ui.end_row();

            for adapter in self.adapters.clone() {
                ui.label(&adapter.name);
                ui.label(
                    RichText::new(&adapter.status).color(if adapter.status == "Up" {
                        GREEN
                    } else {
                        Color32::GRAY
                    }),
                );
                ui.label(&adapter.speed);
                ui.label(adapter.mac.unwrap_or_else(|| "—".into()));

                let enable = adapter.status != "Up";
                if ui.button(if enable { "Enable" } else { "Disable" }).clicked() {
                    match network::toggle(&adapter.name, enable) {
                        Ok(()) => {
                            self.status = format!("Adapter '{}' updated", adapter.name);
                            self.reload();
                        }
                        Err(error) => {
                            self.status = format!("Adapter '{}' failed: {error}", adapter.name)
                        }
                    }
                }
                ui.end_row();
            }
        });
    }

    fn connections(&mut self, ui: &mut egui::Ui) {
        ui.heading("Current TCP connections");
        if ui.button("Refresh").clicked() {
            match network::connections() {
                Ok(text) => {
                    self.connections = text;
                    self.status = "Connections refreshed".into();
                }
                Err(error) => self.status = format!("Connection query failed: {error}"),
            }
        }
        ui.add_space(10.0);
        egui::ScrollArea::both().show(ui, |ui| {
            ui.monospace(if self.connections.is_empty() {
                "Press Refresh."
            } else {
                &self.connections
            });
        });
    }

    fn firewall(&mut self, ui: &mut egui::Ui) {
        ui.heading("Windows Firewall");
        ui.label("Administrator access is required for changes.");
        ui.add_space(10.0);

        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.rule_name);
            ui.text_edit_singleline(&mut self.rule_port);
            egui::ComboBox::from_id_salt("firewall_proto")
                .selected_text(&self.proto)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.proto, "TCP".into(), "TCP");
                    ui.selectable_value(&mut self.proto, "UDP".into(), "UDP");
                });

            if ui.button("Allow inbound").clicked() {
                let result = (|| -> anyhow::Result<()> {
                    let name = self.rule_name.trim();
                    if name.is_empty() {
                        anyhow::bail!("Rule name cannot be empty");
                    }
                    let port: u16 = self.rule_port.trim().parse().map_err(|_| anyhow::anyhow!("Port must be 1-65535"))?;
                    if port == 0 {
                        anyhow::bail!("Port must be 1-65535");
                    }
                    firewall::add(name, port, &self.proto)
                })();

                match result {
                    Ok(()) => {
                        self.status = "Firewall rule created".into();
                        self.reload();
                    }
                    Err(error) => self.status = format!("Firewall error: {error}"),
                }
            }
        });

        ui.add_space(12.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("firewall_grid").striped(true).show(ui, |ui| {
                for header in ["Rule", "Direction", "Action", "Enabled", "Protocol", "Port", "Profile", ""] {
                    ui.strong(header);
                }
                ui.end_row();

                for rule in self.rules.clone() {
                    ui.label(&rule.name);
                    ui.label(&rule.direction);
                    ui.label(&rule.action);
                    ui.label(&rule.enabled);
                    ui.label(&rule.protocol);
                    ui.label(&rule.local_port);
                    ui.label(&rule.profile);
                    if ui.button("Delete").clicked() {
                        match firewall::remove(&rule.name) {
                            Ok(()) => {
                                self.status = format!("Removed firewall rule '{}'", rule.name);
                                self.reload();
                            }
                            Err(error) => self.status = format!("Firewall delete failed: {error}"),
                        }
                    }
                    ui.end_row();
                }
            });
        });
    }

    fn upnp(&mut self, ui: &mut egui::Ui) {
        ui.heading("UPnP / port forwarding");
        ui.label("Discover compatible Internet Gateway Devices and create NAT mappings.");
        if ui.button("Discover gateways").clicked() {
            self.discover_upnp();
        }
        ui.add_space(10.0);

        for (index, device) in self.devices.iter().enumerate() {
            ui.selectable_value(
                &mut self.selected,
                index,
                format!("Gateway {} • {}", index + 1, device.server),
            );
            ui.small(&device.location);
        }

        if !self.devices.is_empty() && self.selected < self.devices.len() {
            ui.add_space(10.0);
            egui::Frame::group(ui.style())
                .fill(PANEL)
                .corner_radius(10)
                .inner_margin(15.0)
                .show(ui, |ui| {
                    egui::Grid::new("upnp_grid").num_columns(2).show(ui, |ui| {
                        ui.label("External");
                        ui.text_edit_singleline(&mut self.ext);
                        ui.end_row();
                        ui.label("Internal");
                        ui.text_edit_singleline(&mut self.intp);
                        ui.end_row();
                        ui.label("Private IP");
                        ui.text_edit_singleline(&mut self.client);
                        ui.end_row();
                        ui.label("Description");
                        ui.text_edit_singleline(&mut self.desc);
                        ui.end_row();
                    });

                    ui.horizontal(|ui| {
                        for protocol in ["TCP", "UDP"] {
                            if ui.button(format!("Add {protocol} mapping")).clicked() {
                                let result = (|| -> anyhow::Result<()> {
                                    let external: u16 = self.ext.trim().parse().map_err(|_| anyhow::anyhow!("External port must be 1-65535"))?;
                                    let internal: u16 = self.intp.trim().parse().map_err(|_| anyhow::anyhow!("Internal port must be 1-65535"))?;
                                    if external == 0 || internal == 0 {
                                        anyhow::bail!("Ports must be 1-65535");
                                    }
                                    let client: Ipv4Addr = self.client.trim().parse().map_err(|_| anyhow::anyhow!("Private IP must be a valid IPv4 address"))?;
                                    if !client.is_private() {
                                        anyhow::bail!("Private IP must be an RFC1918 address");
                                    }
                                    if self.desc.trim().is_empty() {
                                        anyhow::bail!("Description cannot be empty");
                                    }
                                    upnp::add(
                                        &self.devices[self.selected],
                                        external,
                                        internal,
                                        protocol,
                                        &client.to_string(),
                                        self.desc.trim(),
                                    )
                                })();

                                self.status = match result {
                                    Ok(()) => "UPnP mapping created".into(),
                                    Err(error) => format!("UPnP error: {error}"),
                                };
                            }
                        }
                    });
                });
        }

        ui.add_space(10.0);
        ui.label(RichText::new(&self.status).small().color(Color32::GRAY));
    }
}

impl eframe::App for NetworkManagerApp {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        ctx.set_visuals(egui::Visuals::dark());
        egui::SidePanel::left("side")
            .resizable(false)
            .frame(egui::Frame::NONE.fill(BG).inner_margin(10.0))
            .show(ctx, |ui| self.side(ui));
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(BG).inner_margin(28.0))
            .show(ctx, |ui| match self.page {
                Page::Overview => self.overview(ui),
                Page::Adapters => self.adapters(ui),
                Page::Connections => self.connections(ui),
                Page::Firewall => self.firewall(ui),
                Page::Upnp => self.upnp(ui),
            });
    }
}
