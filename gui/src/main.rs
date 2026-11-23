// No console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod config;
mod i18n;
mod paths;
mod secret;
mod single_instance;
mod theme;
mod widgets;
mod worker;

use eframe::egui;

const APP_ID: &str = "io.github.SnowTimSwiss.TimENC";

fn icon() -> egui::IconData {
    egui::IconData {
        rgba: include_bytes!("../assets/icon-128.rgba").to_vec(),
        width: 128,
        height: 128,
    }
}

fn main() -> eframe::Result {
    // Passwords and keys are in memory while an operation runs; a core dump
    // would write them to disk. (Not PR_SET_DUMPABLE: sandbox portals identify
    // a Flatpak app through /proc/<pid>, which that would make unreadable.)
    timenc::hardening::disable_core_dumps();

    let open_file = paths::find_timenc_path(std::env::args_os().skip(1));
    let server = match single_instance::start(open_file.as_deref()) {
        single_instance::Startup::Forwarded => return Ok(()),
        single_instance::Startup::Primary(server) => server,
    };

    #[cfg(target_os = "linux")]
    let theme_watcher = theme::system::watch();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("TimENC")
            .with_app_id(APP_ID)
            .with_inner_size([1000.0, 620.0])
            .with_min_inner_size([560.0, 480.0])
            .with_icon(icon())
            .with_drag_and_drop(true),
        ..Default::default()
    };

    eframe::run_native(
        "TimENC",
        options,
        Box::new(move |cc| {
            Ok(Box::new(app::TimencApp::new(
                cc,
                open_file,
                server,
                #[cfg(target_os = "linux")]
                theme_watcher,
            )))
        }),
    )
}
