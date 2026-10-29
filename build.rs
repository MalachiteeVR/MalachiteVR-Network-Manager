fn main() {
    #[cfg(windows)] {
        let mut r = winres::WindowsResource::new();
        r.set_icon("assets/malachite.ico");
        r.set("ProductName", "MalachiteVR Network Manager");
        r.set("FileDescription", "Network, firewall and UPnP manager");
        r.set("CompanyName", "MalachiteeVR");
        r.compile().expect("Windows resource compilation failed");
    }
}
