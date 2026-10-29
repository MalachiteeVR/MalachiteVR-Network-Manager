#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod app;
mod admin;
mod network;
mod firewall;
mod upnp;

fn main() -> eframe::Result<()> {
    admin::ensure_elevated();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1180.0, 760.0])
            .with_min_inner_size([900.0, 600.0])
            .with_title("MalachiteVR Network Manager"),
        ..Default::default()
    };
    eframe::run_native("MalachiteVR Network Manager", options,
        Box::new(|cc| Ok(Box::new(app::NetworkManagerApp::new(cc)))))
}
