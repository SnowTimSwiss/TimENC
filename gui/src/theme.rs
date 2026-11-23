//! Colours, text sizes, and following the desktop's light/dark preference.

use eframe::egui::{
    self, Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle, Theme, Visuals,
};

/// The colour tokens of the original web UI (GitHub's palettes).
#[derive(Clone, Copy)]
pub struct Palette {
    /// Inputs and cards.
    pub bg_primary: Color32,
    /// The window.
    pub bg_secondary: Color32,
    /// Buttons, hover states, empty bars.
    pub bg_tertiary: Color32,
    pub border: Color32,
    pub text: Color32,
    pub text_weak: Color32,
    pub accent: Color32,
    pub accent_hover: Color32,
    /// Text on an accent-coloured button.
    pub on_accent: Color32,
    pub success: Color32,
    pub success_hover: Color32,
    pub warning: Color32,
    pub danger: Color32,
}

pub const DARK: Palette = Palette {
    bg_primary: Color32::from_rgb(0x0d, 0x11, 0x17),
    bg_secondary: Color32::from_rgb(0x16, 0x1b, 0x22),
    bg_tertiary: Color32::from_rgb(0x21, 0x26, 0x2d),
    border: Color32::from_rgb(0x30, 0x36, 0x3d),
    text: Color32::from_rgb(0xf0, 0xf6, 0xfc),
    text_weak: Color32::from_rgb(0x8b, 0x94, 0x9e),
    accent: Color32::from_rgb(0x58, 0xa6, 0xff),
    accent_hover: Color32::from_rgb(0x79, 0xc0, 0xff),
    on_accent: Color32::from_rgb(0x0d, 0x11, 0x17),
    success: Color32::from_rgb(0x3f, 0xb9, 0x50),
    success_hover: Color32::from_rgb(0x2e, 0xa0, 0x43),
    warning: Color32::from_rgb(0xd2, 0x99, 0x22),
    danger: Color32::from_rgb(0xf8, 0x51, 0x49),
};

pub const LIGHT: Palette = Palette {
    bg_primary: Color32::from_rgb(0xf6, 0xf8, 0xfa),
    bg_secondary: Color32::from_rgb(0xff, 0xff, 0xff),
    bg_tertiary: Color32::from_rgb(0xea, 0xee, 0xf2),
    border: Color32::from_rgb(0xd0, 0xd7, 0xde),
    text: Color32::from_rgb(0x1f, 0x23, 0x28),
    text_weak: Color32::from_rgb(0x59, 0x63, 0x6e),
    accent: Color32::from_rgb(0x09, 0x69, 0xda),
    accent_hover: Color32::from_rgb(0x05, 0x50, 0xae),
    on_accent: Color32::WHITE,
    success: Color32::from_rgb(0x1f, 0x88, 0x3d),
    success_hover: Color32::from_rgb(0x1a, 0x7f, 0x37),
    warning: Color32::from_rgb(0x9a, 0x67, 0x00),
    danger: Color32::from_rgb(0xcf, 0x22, 0x2e),
};

pub fn palette(theme: Theme) -> &'static Palette {
    match theme {
        Theme::Dark => &DARK,
        Theme::Light => &LIGHT,
    }
}

/// Installs text sizes and both colour schemes; egui picks one per frame.
pub fn install(ctx: &egui::Context) {
    ctx.all_styles_mut(|style| {
        style.text_styles = [
            (
                TextStyle::Heading,
                FontId::new(21.0, FontFamily::Proportional),
            ),
            (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
            (
                TextStyle::Button,
                FontId::new(14.0, FontFamily::Proportional),
            ),
            (
                TextStyle::Small,
                FontId::new(12.0, FontFamily::Proportional),
            ),
            (
                TextStyle::Monospace,
                FontId::new(13.0, FontFamily::Monospace),
            ),
        ]
        .into();
        style.spacing.item_spacing = egui::vec2(8.0, 8.0);
        style.spacing.button_padding = egui::vec2(14.0, 8.0);
        style.spacing.interact_size.y = 36.0;
        // Nothing here benefits from fades, and every animation frame is a repaint.
        style.animation_time = 0.0;
    });
    ctx.set_visuals_of(Theme::Dark, visuals(&DARK, true));
    ctx.set_visuals_of(Theme::Light, visuals(&LIGHT, false));
}

fn visuals(p: &Palette, dark: bool) -> Visuals {
    let mut v = if dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };
    let radius = CornerRadius::same(6);

    v.override_text_color = Some(p.text);
    v.weak_text_color = Some(p.text_weak);
    v.panel_fill = p.bg_secondary;
    v.window_fill = p.bg_secondary;
    v.window_stroke = Stroke::new(1.0, p.border);
    v.extreme_bg_color = p.bg_primary;
    v.text_edit_bg_color = Some(p.bg_primary);
    v.faint_bg_color = p.bg_tertiary;
    v.hyperlink_color = p.accent;
    v.error_fg_color = p.danger;
    v.warn_fg_color = p.warning;
    v.selection.bg_fill = p.accent.gamma_multiply(0.35);
    v.selection.stroke = Stroke::new(1.0, p.accent);

    let w = &mut v.widgets;
    w.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    w.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    w.noninteractive.corner_radius = radius;

    w.inactive.bg_fill = p.bg_tertiary;
    w.inactive.weak_bg_fill = p.bg_tertiary;
    w.inactive.bg_stroke = Stroke::new(1.0, p.border);
    w.inactive.fg_stroke = Stroke::new(1.0, p.text);
    w.inactive.corner_radius = radius;

    w.hovered.bg_fill = p.border;
    w.hovered.weak_bg_fill = p.border;
    w.hovered.bg_stroke = Stroke::new(1.0, p.text_weak);
    w.hovered.fg_stroke = Stroke::new(1.0, p.text);
    w.hovered.corner_radius = radius;
    w.hovered.expansion = 0.0;

    w.active.bg_fill = p.border;
    w.active.weak_bg_fill = p.border;
    w.active.bg_stroke = Stroke::new(1.0, p.accent);
    w.active.fg_stroke = Stroke::new(1.0, p.text);
    w.active.corner_radius = radius;
    w.active.expansion = 0.0;

    w.open = w.active;
    v
}

/// The desktop's colour preference, read from the XDG settings portal.
///
/// winit reports no system theme on Linux, so egui cannot follow it there by
/// itself. The portal works on GNOME, KDE and others, and inside Flatpak.
#[cfg(target_os = "linux")]
pub mod system {
    use eframe::egui::{self, Theme};
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;
    use zbus::zvariant::{OwnedValue, Value};

    const UNKNOWN: u8 = 0;
    const DARK: u8 = 1;
    const LIGHT: u8 = 2;

    /// The latest preference; written by the watcher thread.
    #[derive(Clone)]
    pub struct Watcher {
        state: Arc<AtomicU8>,
        ctx: Arc<OnceLock<egui::Context>>,
    }

    impl Watcher {
        pub fn theme(&self) -> Option<Theme> {
            match self.state.load(Ordering::Relaxed) {
                DARK => Some(Theme::Dark),
                LIGHT => Some(Theme::Light),
                _ => None,
            }
        }

        /// Lets the watcher wake the UI when the preference changes.
        pub fn attach(&self, ctx: &egui::Context) {
            let _ = self.ctx.set(ctx.clone());
        }
    }

    /// Starts watching the portal, waiting briefly for the first answer so
    /// the window opens in the right colours instead of flashing.
    pub fn watch() -> Watcher {
        let watcher = Watcher {
            state: Arc::new(AtomicU8::new(UNKNOWN)),
            ctx: Arc::new(OnceLock::new()),
        };
        // TIMENC_THEME=light|dark overrides the desktop (and skips the portal).
        match std::env::var("TIMENC_THEME").as_deref() {
            Ok("dark") => {
                watcher.state.store(DARK, Ordering::Relaxed);
                return watcher;
            }
            Ok("light") => {
                watcher.state.store(LIGHT, Ordering::Relaxed);
                return watcher;
            }
            _ => {}
        }
        let (first_tx, first_rx) = mpsc::channel();
        let thread_watcher = watcher.clone();
        let spawned = std::thread::Builder::new()
            .name("timenc-theme".into())
            .spawn(move || {
                let _ = run(&thread_watcher, first_tx);
            });
        if spawned.is_ok() {
            let _ = first_rx.recv_timeout(Duration::from_millis(250));
        }
        watcher
    }

    /// Portal values: 0 = no preference, 1 = prefer dark, 2 = prefer light.
    /// "No preference" means the desktop's default, which is light.
    fn encode(color_scheme: u32) -> u8 {
        if color_scheme == 1 {
            DARK
        } else {
            LIGHT
        }
    }

    fn as_u32(value: &Value<'_>) -> Option<u32> {
        match value {
            Value::U32(n) => Some(*n),
            // `Read` (the older call) wraps the value in an extra variant.
            Value::Value(inner) => as_u32(inner),
            _ => None,
        }
    }

    fn run(watcher: &Watcher, first: mpsc::Sender<()>) -> zbus::Result<()> {
        const NAMESPACE: &str = "org.freedesktop.appearance";
        const KEY: &str = "color-scheme";

        let set = |color_scheme: u32| {
            watcher.state.store(encode(color_scheme), Ordering::Relaxed);
            if let Some(ctx) = watcher.ctx.get() {
                ctx.request_repaint();
            }
        };

        let connection = zbus::blocking::Connection::session()?;
        let proxy = zbus::blocking::Proxy::new(
            &connection,
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.Settings",
        )?;

        // Subscribe before reading, so a change in between is not missed.
        let changes = proxy.receive_signal("SettingChanged")?;

        let initial: Option<OwnedValue> = proxy
            .call("ReadOne", &(NAMESPACE, KEY))
            .or_else(|_| proxy.call("Read", &(NAMESPACE, KEY)))
            .ok();
        if let Some(value) = initial.as_deref().and_then(as_u32) {
            set(value);
        }
        let _ = first.send(());

        for message in changes {
            let Ok((namespace, key, value)) =
                message.body().deserialize::<(String, String, OwnedValue)>()
            else {
                continue;
            };
            if namespace == NAMESPACE && key == KEY {
                if let Some(value) = as_u32(&value) {
                    set(value);
                }
            }
        }
        Ok(())
    }
}
