#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod admin;
mod firewall;
mod network;
mod ui;
mod upnp;

fn main() {
    admin::ensure_elevated();
    if let Err(error) = ui::run() {
        eprintln!("MalachiteVR Network Manager failed: {error:#}");
    }
}
