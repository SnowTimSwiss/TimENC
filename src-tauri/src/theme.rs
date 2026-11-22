//! Makes the window decorations follow the desktop's light/dark preference.
//!
//! The window is a GTK3 window. GTK3 does not read GNOME's `color-scheme`
//! setting (only GTK4/libadwaita do), so without help the title bar stays light
//! on a dark desktop. This reads the preference from the XDG settings portal,
//! which works inside Flatpak and on GNOME, KDE and others, falls back to
//! GNOME's own setting, applies it to GTK, and follows later changes.

/// Maps the portal's `color-scheme` value to "wants a dark window":
/// 0 = no preference, 1 = prefer dark, 2 = prefer light.
pub fn wants_dark(color_scheme: u32) -> bool {
    color_scheme == 1
}

#[cfg(target_os = "linux")]
pub use linux::follow_system_color_scheme;

/// Does nothing on platforms whose native window frame already follows the system.
#[cfg(not(target_os = "linux"))]
pub fn follow_system_color_scheme() {}

#[cfg(target_os = "linux")]
mod linux {
    use super::wants_dark;
    use gtk::gio::{self, prelude::*};
    use gtk::glib;
    use gtk::prelude::GtkSettingsExt;

    const PORTAL_NAME: &str = "org.freedesktop.portal.Desktop";
    const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
    const PORTAL_SETTINGS: &str = "org.freedesktop.portal.Settings";
    const APPEARANCE: &str = "org.freedesktop.appearance";
    const COLOR_SCHEME: &str = "color-scheme";

    thread_local! {
        static KEEP_ALIVE: std::cell::RefCell<Option<gio::DBusConnection>> =
            const { std::cell::RefCell::new(None) };
    }

    /// Applies the system's colour scheme to GTK now, and again whenever it
    /// changes. Must be called on the GTK main thread after GTK is initialised.
    pub fn follow_system_color_scheme() {
        let Some(settings) = gtk::Settings::default() else {
            return;
        };

        let connection = gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE).ok();

        let initial = connection
            .as_ref()
            .and_then(read_portal)
            .map(wants_dark)
            .or_else(read_gnome_setting);
        if let Some(dark) = initial {
            settings.set_gtk_application_prefer_dark_theme(dark);
        }

        if let Some(connection) = connection {
            // The subscription only lives as long as the connection does, and
            // nothing else is guaranteed to hold it: keep it for the lifetime
            // of the app (this runs on the GTK main thread, once). The returned
            // subscription id is not needed, as we never unsubscribe.
            KEEP_ALIVE.with(|slot| *slot.borrow_mut() = Some(connection.clone()));
            connection.signal_subscribe(
                Some(PORTAL_NAME),
                Some(PORTAL_SETTINGS),
                Some("SettingChanged"),
                Some(PORTAL_PATH),
                None,
                gio::DBusSignalFlags::NONE,
                move |_, _, _, _, _, parameters| {
                    // (namespace: s, key: s, value: v)
                    let namespace = parameters.child_value(0).get::<String>();
                    let key = parameters.child_value(1).get::<String>();
                    if namespace.as_deref() == Some(APPEARANCE) && key.as_deref() == Some(COLOR_SCHEME) {
                        if let Some(value) = unwrap_u32(parameters.child_value(2)) {
                            settings.set_gtk_application_prefer_dark_theme(wants_dark(value));
                        }
                    }
                },
            );
        }
    }

    /// Asks the settings portal for the current colour scheme.
    fn read_portal(connection: &gio::DBusConnection) -> Option<u32> {
        let reply = connection
            .call_sync(
                Some(PORTAL_NAME),
                PORTAL_PATH,
                PORTAL_SETTINGS,
                "Read",
                Some(&(APPEARANCE, COLOR_SCHEME).to_variant()),
                None,
                gio::DBusCallFlags::NONE,
                1000,
                gio::Cancellable::NONE,
            )
            .ok()?;
        unwrap_u32(reply.child_value(0))
    }

    /// Strips any number of variant wrappers (version 1 of the portal wrapped
    /// the value twice, later versions once) and reads a `u32`.
    fn unwrap_u32(mut value: glib::Variant) -> Option<u32> {
        while value.type_() == glib::VariantTy::VARIANT {
            value = value.as_variant()?;
        }
        value.get::<u32>()
    }

    /// GNOME's own setting, for sessions that have no settings portal.
    fn read_gnome_setting() -> Option<bool> {
        const SCHEMA: &str = "org.gnome.desktop.interface";
        let source = gio::SettingsSchemaSource::default()?;
        let schema = source.lookup(SCHEMA, true)?;
        if !schema.has_key(COLOR_SCHEME) {
            return None;
        }
        let value = gio::Settings::new(SCHEMA).string(COLOR_SCHEME);
        Some(value == "prefer-dark")
    }
}

#[cfg(test)]
mod tests {
    use super::wants_dark;

    #[test]
    fn only_an_explicit_dark_preference_asks_for_a_dark_window() {
        assert!(wants_dark(1)); // prefer dark
        assert!(!wants_dark(0)); // no preference
        assert!(!wants_dark(2)); // prefer light
        assert!(!wants_dark(7)); // unknown future value
    }
}
