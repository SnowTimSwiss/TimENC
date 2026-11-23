//! Gives the Windows executable its icon and version information.

fn main() {
    #[cfg(windows)]
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut resource = winresource::WindowsResource::new();
        resource
            .set_icon("../packaging/icons/icon.ico")
            .set("ProductName", "TimENC")
            .set("FileDescription", "TimENC - Secure Encryption")
            .set("LegalCopyright", "GPL-3.0, TimENC Contributors");
        resource
            .compile()
            .expect("failed to embed the Windows resources");
    }
}
