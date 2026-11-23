//! Keeps one window: a second launch hands its file to the running instance.
//!
//! The running instance listens on a Unix socket in the user's private
//! runtime directory (mode 0700, so only the same user can connect). A new
//! launch first tries to connect; if that works it sends the path it was
//! opened with (or nothing, meaning "just come to the front") and exits.
//!
//! Other platforms start a separate window, as there is no runtime directory
//! to put the socket in.

#[cfg(not(unix))]
use std::path::{Path, PathBuf};

pub enum Startup {
    /// Run the app. `None` when no socket could be set up (then every launch
    /// gets its own window, which still works).
    Primary(Option<Server>),
    /// Another instance has the request; exit.
    Forwarded,
}

#[cfg(unix)]
pub use unix::{start, Server};

#[cfg(not(unix))]
pub struct Server;

#[cfg(not(unix))]
pub fn start(_open: Option<&Path>) -> Startup {
    Startup::Primary(None)
}

#[cfg(not(unix))]
impl Server {
    pub fn serve(self, _on_request: impl Fn(Option<PathBuf>) + Send + 'static) -> Guard {
        Guard
    }
}

#[cfg(not(unix))]
pub struct Guard;

#[cfg(unix)]
pub use unix::Guard;

#[cfg(unix)]
mod unix {
    use super::Startup;
    use crate::paths::is_timenc_file;
    use std::ffi::OsString;
    use std::io::{Read, Write};
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    /// Paths are short; anything longer is not a request from TimENC.
    const MAX_REQUEST: u64 = 16 * 1024;

    pub struct Server {
        listener: UnixListener,
        path: PathBuf,
    }

    /// Removes the socket when the app exits normally.
    pub struct Guard {
        path: PathBuf,
    }

    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn socket_path() -> Option<PathBuf> {
        let mut dir = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?);
        if !dir.is_absolute() {
            return None;
        }
        // Inside Flatpak each instance gets its own runtime directory; this
        // subdirectory is the one all instances of the app share.
        if let Some(app_id) = std::env::var_os("FLATPAK_ID") {
            dir = dir.join("app").join(app_id);
        }
        dir.is_dir().then(|| dir.join("timenc-gui.sock"))
    }

    pub fn start(open: Option<&Path>) -> Startup {
        let Some(path) = socket_path() else {
            return Startup::Primary(None);
        };

        if let Ok(mut stream) = UnixStream::connect(&path) {
            let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
            let payload = open.map(|p| p.as_os_str().as_bytes()).unwrap_or_default();
            return if stream.write_all(payload).is_ok() {
                Startup::Forwarded
            } else {
                Startup::Primary(None)
            };
        }

        // Nobody is listening: a socket left behind by a crash, or none at all.
        let _ = std::fs::remove_file(&path);
        match UnixListener::bind(&path) {
            Ok(listener) => Startup::Primary(Some(Server { listener, path })),
            Err(_) => Startup::Primary(None),
        }
    }

    impl Server {
        /// Handles requests on a background thread. `on_request` gets the
        /// `.timenc` file to open, or `None` for "come to the front".
        pub fn serve(self, on_request: impl Fn(Option<PathBuf>) + Send + 'static) -> Guard {
            let guard = Guard {
                path: self.path.clone(),
            };
            let listener = self.listener;
            let _ = std::thread::Builder::new()
                .name("timenc-instance".into())
                .spawn(move || {
                    for stream in listener.incoming() {
                        let Ok(stream) = stream else { continue };
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                        let mut request = Vec::new();
                        if stream.take(MAX_REQUEST).read_to_end(&mut request).is_err() {
                            continue;
                        }
                        let path = (!request.is_empty())
                            .then(|| PathBuf::from(OsString::from_vec(request)))
                            .filter(|path| is_timenc_file(path));
                        on_request(path);
                    }
                });
            guard
        }
    }
}
