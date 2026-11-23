//! The window: four pages (Encrypt, Decrypt, Tools, Settings) under a tab bar.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};

#[cfg(target_os = "linux")]
use eframe::egui::Theme;
use eframe::egui::{
    self, vec2, Align, CentralPanel, Color32, Frame, Key, Layout, Margin, Panel, RichText,
    ScrollArea, Ui,
};
use timenc::{DecryptOptions, EncryptOptions, KdfProfile};

use crate::config;
use crate::i18n::{Language, Strings};
use crate::paths::{suggest_decrypted_output, suggest_encrypted_output};
use crate::secret::SecretString;
use crate::single_instance;
use crate::theme::{self, Palette};
use crate::widgets::{self, StatusKind};
use crate::worker::{self, Job, JobKind, Outcome, Poll, Running};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Encrypt,
    Decrypt,
    Tools,
    Settings,
}

#[derive(Default)]
struct EncryptForm {
    input: String,
    output: String,
    /// Stop overwriting the output with suggestions once the user typed one.
    output_edited: bool,
    password: SecretString,
    confirm: SecretString,
    show_password: bool,
    show_confirm: bool,
    keyfile: String,
    advanced_open: bool,
    compress: bool,
    pad: bool,
    paranoid: bool,
    delete_source: bool,
}

#[derive(Default)]
struct DecryptForm {
    input: String,
    output: String,
    output_edited: bool,
    password: SecretString,
    show_password: bool,
    keyfile: String,
    delete_source: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DialogTarget {
    EncInputFile,
    EncInputFolder,
    EncOutput,
    EncKeyfile,
    DecInput,
    DecOutput,
    DecKeyfile,
    KeyfileOutput,
}

struct PendingDialog {
    target: DialogTarget,
    receiver: Receiver<Option<PathBuf>>,
}

pub struct TimencApp {
    /// Set by Enter in any field of the current form.
    submit: bool,
    language: Language,
    page: Page,
    status_kind: StatusKind,
    /// `None` shows the localised "Ready".
    status_text: Option<String>,
    result: Option<String>,
    enc: EncryptForm,
    dec: DecryptForm,
    keyfile_output: String,
    focus_keyfile_output: bool,
    running: Option<Running>,
    dialog: Option<PendingDialog>,
    open_requests: Receiver<Option<PathBuf>>,
    _instance: Option<single_instance::Guard>,
    #[cfg(target_os = "linux")]
    theme_watcher: theme::system::Watcher,
    #[cfg(target_os = "linux")]
    applied_theme: Option<Theme>,
}

impl TimencApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        open_file: Option<PathBuf>,
        server: Option<single_instance::Server>,
        #[cfg(target_os = "linux")] theme_watcher: theme::system::Watcher,
    ) -> Self {
        let ctx = &cc.egui_ctx;
        theme::install(ctx);
        #[cfg(not(target_os = "linux"))]
        ctx.set_theme(egui::ThemePreference::System);
        #[cfg(target_os = "linux")]
        theme_watcher.attach(ctx);

        let (open_tx, open_requests): (Sender<Option<PathBuf>>, _) = mpsc::channel();
        let instance = server.map(|server| {
            let ctx = ctx.clone();
            server.serve(move |path| {
                let _ = open_tx.send(path);
                ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                ctx.request_repaint();
            })
        });

        let mut app = Self {
            submit: false,
            language: config::load_language(),
            page: Page::Encrypt,
            status_kind: StatusKind::Neutral,
            status_text: None,
            result: None,
            enc: EncryptForm::default(),
            dec: DecryptForm::default(),
            keyfile_output: String::new(),
            focus_keyfile_output: false,
            running: None,
            dialog: None,
            open_requests,
            _instance: instance,
            #[cfg(target_os = "linux")]
            theme_watcher,
            #[cfg(target_os = "linux")]
            applied_theme: None,
        };
        if let Some(path) = open_file {
            app.open_encrypted(path);
        }
        app
    }

    fn s(&self) -> &'static Strings {
        self.language.strings()
    }

    fn busy(&self) -> bool {
        self.running.is_some()
    }

    fn set_status(&mut self, kind: StatusKind, text: impl Into<String>) {
        self.status_kind = kind;
        self.status_text = Some(text.into());
    }

    fn fail(&mut self, message: &str) {
        self.set_status(StatusKind::Error, message);
        self.result = Some(message.to_string());
    }

    /// A `.timenc` file from the command line, a second launch, or a drop.
    fn open_encrypted(&mut self, path: PathBuf) {
        let text = path.to_string_lossy().into_owned();
        self.set_decrypt_input(text.clone());
        self.page = Page::Decrypt;
        self.result = Some(text);
    }

    fn set_encrypt_input(&mut self, value: String) {
        self.enc.input = value;
        if !self.enc.output_edited {
            self.enc.output = suggest_encrypted_output(&self.enc.input);
        }
    }

    fn set_decrypt_input(&mut self, value: String) {
        self.dec.input = value;
        if !self.dec.output_edited {
            self.dec.output = suggest_decrypted_output(&self.dec.input);
        }
    }

    fn handle_drop(&mut self, path: PathBuf) {
        let looks_encrypted = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("timenc"));
        let text = path.to_string_lossy().into_owned();
        if self.page == Page::Decrypt || looks_encrypted {
            self.set_decrypt_input(text);
            self.page = Page::Decrypt;
        } else {
            self.set_encrypt_input(text);
            self.page = Page::Encrypt;
        }
    }

    // ----- file dialogs -------------------------------------------------

    /// Opens a native file dialog without blocking the UI. With the XDG
    /// portal the dialog is another process; waiting for it on the UI thread
    /// would freeze the window (and make the desktop call it unresponsive).
    fn open_dialog(&mut self, ctx: &egui::Context, target: DialogTarget) {
        if self.dialog.is_some() {
            return;
        }
        let timenc_filter = |d: rfd::AsyncFileDialog| d.add_filter("TimENC", &["timenc"]);
        let with_start = |d: rfd::AsyncFileDialog, current: &str| {
            let current = PathBuf::from(current.trim());
            let dir = if current.is_dir() {
                Some(current)
            } else {
                current.parent().filter(|p| p.is_dir()).map(PathBuf::from)
            };
            match dir {
                Some(dir) => d.set_directory(dir),
                None => d,
            }
        };
        let file_name = |value: &str| {
            PathBuf::from(value.trim())
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
        };
        let new = rfd::AsyncFileDialog::new;

        type Pick = std::pin::Pin<Box<dyn std::future::Future<Output = Option<PathBuf>> + Send>>;
        fn file(
            f: impl std::future::Future<Output = Option<rfd::FileHandle>> + Send + 'static,
        ) -> Pick {
            Box::pin(async move { f.await.map(|h| h.path().to_path_buf()) })
        }

        let future: Pick = match target {
            DialogTarget::EncInputFile => file(with_start(new(), &self.enc.input).pick_file()),
            DialogTarget::EncInputFolder => file(with_start(new(), &self.enc.input).pick_folder()),
            DialogTarget::EncOutput => {
                let suggested = if self.enc.output.trim().is_empty() {
                    suggest_encrypted_output(&self.enc.input)
                } else {
                    self.enc.output.clone()
                };
                let name = file_name(&suggested).unwrap_or_else(|| "encrypted.timenc".into());
                file(
                    timenc_filter(with_start(new(), &suggested))
                        .set_file_name(name)
                        .save_file(),
                )
            }
            DialogTarget::EncKeyfile => file(with_start(new(), &self.enc.keyfile).pick_file()),
            DialogTarget::DecInput => {
                file(timenc_filter(with_start(new(), &self.dec.input)).pick_file())
            }
            DialogTarget::DecOutput => file(with_start(new(), &self.dec.output).pick_folder()),
            DialogTarget::DecKeyfile => file(with_start(new(), &self.dec.keyfile).pick_file()),
            DialogTarget::KeyfileOutput => {
                let name = file_name(&self.keyfile_output).unwrap_or_else(|| "timenc.key".into());
                file(
                    with_start(new(), &self.keyfile_output)
                        .set_file_name(name)
                        .save_file(),
                )
            }
        };

        let (sender, receiver) = mpsc::channel();
        let ctx = ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("timenc-dialog".into())
            .spawn(move || {
                let _ = sender.send(pollster::block_on(future));
                ctx.request_repaint();
            });
        if spawned.is_ok() {
            self.dialog = Some(PendingDialog { target, receiver });
        }
    }

    fn poll_dialog(&mut self) {
        let Some(pending) = &self.dialog else { return };
        let picked = match pending.receiver.try_recv() {
            Ok(picked) => picked,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => None,
        };
        let target = pending.target;
        self.dialog = None;
        let Some(path) = picked else { return };
        let text = path.to_string_lossy().into_owned();
        match target {
            DialogTarget::EncInputFile | DialogTarget::EncInputFolder => {
                self.set_encrypt_input(text)
            }
            DialogTarget::EncOutput => {
                self.enc.output = text;
                self.enc.output_edited = false;
            }
            DialogTarget::EncKeyfile => self.enc.keyfile = text,
            DialogTarget::DecInput => self.set_decrypt_input(text),
            DialogTarget::DecOutput => {
                self.dec.output = text;
                self.dec.output_edited = false;
            }
            DialogTarget::DecKeyfile => self.dec.keyfile = text,
            DialogTarget::KeyfileOutput => self.keyfile_output = text,
        }
    }

    // ----- running operations -------------------------------------------

    fn start(&mut self, ctx: &egui::Context, job: Job) {
        let ctx = ctx.clone();
        self.running = Some(worker::spawn(job, move || ctx.request_repaint()));
        self.status_kind = StatusKind::Neutral;
        self.status_text = Some(self.s().working.to_string());
    }

    fn submit_encrypt(&mut self, ctx: &egui::Context) {
        let s = self.s();
        if self.busy() {
            return;
        }
        let input = self.enc.input.trim();
        let output = self.enc.output.trim();
        if input.is_empty() {
            return self.fail(s.missing_input);
        }
        if output.is_empty() {
            return self.fail(s.missing_output);
        }
        if self.enc.password.is_empty() {
            return self.fail(s.missing_password);
        }
        if self.enc.password != self.enc.confirm {
            return self.fail(s.passwords_differ);
        }
        let options = EncryptOptions {
            password: self.enc.password.to_unprotected_string(),
            keyfile_path: optional_path(&self.enc.keyfile),
            output_path: PathBuf::from(output),
            compress: self.enc.compress,
            kdf_profile: if self.enc.paranoid {
                KdfProfile::Paranoid
            } else {
                KdfProfile::Balanced
            },
            pad: self.enc.pad,
            delete_source: self.enc.delete_source,
        };
        let input = PathBuf::from(input);
        self.start(ctx, Job::Encrypt { input, options });
    }

    fn submit_decrypt(&mut self, ctx: &egui::Context) {
        let s = self.s();
        if self.busy() {
            return;
        }
        let input = self.dec.input.trim();
        let output = self.dec.output.trim();
        if input.is_empty() {
            return self.fail(s.missing_input);
        }
        if output.is_empty() {
            return self.fail(s.missing_output);
        }
        if self.dec.password.is_empty() {
            return self.fail(s.missing_password);
        }
        let options = DecryptOptions {
            password: self.dec.password.to_unprotected_string(),
            keyfile_path: optional_path(&self.dec.keyfile),
            output_dir: PathBuf::from(output),
            delete_source: self.dec.delete_source,
        };
        let input = PathBuf::from(input);
        self.start(ctx, Job::Decrypt { input, options });
    }

    fn submit_keyfile(&mut self, ctx: &egui::Context) {
        if self.busy() {
            return;
        }
        let output = self.keyfile_output.trim();
        if output.is_empty() {
            return self.fail(self.s().missing_keyfile_path);
        }
        let output = PathBuf::from(output);
        self.start(ctx, Job::Keyfile { output });
    }

    fn poll_running(&mut self) {
        let Some(running) = &self.running else { return };
        let kind = running.kind;
        let outcome = match running.poll() {
            Poll::Pending => return,
            Poll::Done(outcome) => outcome,
            Poll::Lost => Outcome::Failure(self.s().worker_crashed.to_string()),
        };
        self.running = None;
        let s = self.s();
        match outcome {
            Outcome::Success {
                path,
                legacy_version,
            } => {
                let mut message = match kind {
                    JobKind::Encrypt => s.encrypted_ok,
                    JobKind::Decrypt => s.decrypted_ok,
                    JobKind::Keyfile => s.keyfile_ok,
                }
                .to_string();
                if let Some(version) = legacy_version {
                    message.push_str(&s.legacy_warning.replace("{v}", &version.to_string()));
                }
                self.result = Some(format!("{message}\n{}: {}", s.path_prefix, path.display()));
                self.set_status(StatusKind::Success, message);
                match kind {
                    // The passwords are not needed any more; wipe them.
                    JobKind::Encrypt => {
                        self.enc.password.clear();
                        self.enc.confirm.clear();
                        self.enc.show_password = false;
                        self.enc.show_confirm = false;
                    }
                    JobKind::Decrypt => {
                        self.dec.password.clear();
                        self.dec.show_password = false;
                    }
                    JobKind::Keyfile => {
                        let text = path.to_string_lossy().into_owned();
                        self.enc.keyfile = text.clone();
                        self.dec.keyfile = text;
                    }
                }
            }
            // On failure the passwords stay, so a wrong keyfile can be fixed
            // without typing everything again.
            Outcome::Failure(message) => self.fail(&message),
        }
    }

    // ----- pages ---------------------------------------------------------

    fn encrypt_page(&mut self, ui: &mut Ui, p: &Palette) {
        let s = self.s();
        let ctx = ui.ctx().clone();
        self.submit = false;
        widgets::page_title(ui, s.enc_title);

        ui.add_enabled_ui(!self.busy(), |ui| {
            pair(
                self,
                ui,
                |ui, this| {
                    widgets::form_label(ui, s.enc_input_label);
                    let (field, clicked) =
                        widgets::input_row(ui, &[s.file_btn, s.folder_btn], |ui| {
                            widgets::path_field(ui, &mut this.enc.input, s.enc_input_hint)
                        });
                    if field.changed() && !this.enc.output_edited {
                        this.enc.output = suggest_encrypted_output(&this.enc.input);
                    }
                    this.submit |= entered(ui, &field);
                    match clicked {
                        Some(0) => this.open_dialog(&ctx, DialogTarget::EncInputFile),
                        Some(_) => this.open_dialog(&ctx, DialogTarget::EncInputFolder),
                        None => {}
                    }
                },
                |ui, this| {
                    widgets::form_label(ui, s.enc_output_label);
                    let (field, clicked) = widgets::input_row(ui, &[s.save_as_btn], |ui| {
                        widgets::path_field(ui, &mut this.enc.output, s.auto_suggested)
                    });
                    if field.changed() {
                        this.enc.output_edited = !this.enc.output.trim().is_empty();
                    }
                    this.submit |= entered(ui, &field);
                    if clicked.is_some() {
                        this.open_dialog(&ctx, DialogTarget::EncOutput);
                    }
                },
            );

            pair(
                self,
                ui,
                |ui, this| {
                    widgets::form_label(ui, s.password_label);
                    this.submit |= secret_row(
                        ui,
                        p,
                        s,
                        "enc-password",
                        s.password_label,
                        &mut this.enc.password,
                        &mut this.enc.show_password,
                    );
                    let (score, label, color) = strength(s, p, this.enc.password.as_str());
                    widgets::strength_bar(ui, p, score, color);
                    widgets::small_text(ui, label, p.text_weak);
                },
                |ui, this| {
                    widgets::form_label(ui, s.confirm_label);
                    this.submit |= secret_row(
                        ui,
                        p,
                        s,
                        "enc-confirm",
                        s.confirm_label,
                        &mut this.enc.confirm,
                        &mut this.enc.show_confirm,
                    );
                    if !this.enc.confirm.is_empty() {
                        let matches = this.enc.password == this.enc.confirm;
                        let (text, color) = if matches {
                            (s.passwords_match, p.success)
                        } else {
                            (s.passwords_differ, p.danger)
                        };
                        ui.add_space(3.0);
                        widgets::small_text(ui, text, color);
                    }
                },
            );

            widgets::form_label(ui, s.keyfile_label);
            let (field, clicked) = widgets::input_row(ui, &[s.browse_btn, s.create_btn], |ui| {
                widgets::path_field(ui, &mut self.enc.keyfile, s.keyfile_hint)
            });
            self.submit |= entered(ui, &field);
            match clicked {
                Some(0) => self.open_dialog(&ctx, DialogTarget::EncKeyfile),
                Some(_) => {
                    self.page = Page::Tools;
                    self.focus_keyfile_output = true;
                }
                None => {}
            }
            ui.add_space(4.0);

            let on = [
                self.enc.compress,
                self.enc.pad,
                self.enc.paranoid,
                self.enc.delete_source,
            ]
            .iter()
            .filter(|on| **on)
            .count();
            let badge = (on > 0).then(|| s.advanced_badge.replace("{n}", &on.to_string()));
            widgets::disclosure(
                ui,
                p,
                &mut self.enc.advanced_open,
                s.advanced_label,
                badge.as_deref(),
            );
            if self.enc.advanced_open {
                ui.spacing_mut().item_spacing.y = 6.0;
                widgets::switch_row(
                    ui,
                    p,
                    &mut self.enc.compress,
                    s.compress_label,
                    s.compress_hint,
                );
                widgets::switch_row(ui, p, &mut self.enc.pad, s.pad_label, s.pad_hint);
                widgets::switch_row(
                    ui,
                    p,
                    &mut self.enc.paranoid,
                    s.paranoid_label,
                    s.paranoid_hint,
                );
                widgets::switch_row(
                    ui,
                    p,
                    &mut self.enc.delete_source,
                    s.enc_delete_label,
                    s.enc_delete_hint,
                );
            }
        });

        ui.add_space(8.0);
        let busy =
            (self.running.as_ref().map(|r| r.kind) == Some(JobKind::Encrypt)).then_some(s.working);
        let button = ui
            .add_enabled_ui(!self.busy() || busy.is_some(), |ui| {
                widgets::primary_button(ui, p, s.enc_submit, p.accent, p.accent_hover, busy)
            })
            .inner;
        if button.clicked() || self.submit {
            self.submit_encrypt(&ctx);
        }
    }

    fn decrypt_page(&mut self, ui: &mut Ui, p: &Palette) {
        let s = self.s();
        let ctx = ui.ctx().clone();
        self.submit = false;
        widgets::page_title(ui, s.dec_title);
        widgets::page_hint(ui, p, s.dec_hint);

        ui.add_enabled_ui(!self.busy(), |ui| {
            pair(
                self,
                ui,
                |ui, this| {
                    widgets::form_label(ui, s.dec_input_label);
                    let (field, clicked) = widgets::input_row(ui, &[s.browse_btn], |ui| {
                        widgets::path_field(ui, &mut this.dec.input, s.dec_input_hint)
                    });
                    if field.changed() && !this.dec.output_edited {
                        this.dec.output = suggest_decrypted_output(&this.dec.input);
                    }
                    this.submit |= entered(ui, &field);
                    if clicked.is_some() {
                        this.open_dialog(&ctx, DialogTarget::DecInput);
                    }
                },
                |ui, this| {
                    widgets::form_label(ui, s.dec_output_label);
                    let (field, clicked) = widgets::input_row(ui, &[s.folder_btn], |ui| {
                        widgets::path_field(ui, &mut this.dec.output, s.auto_suggested)
                    });
                    if field.changed() {
                        this.dec.output_edited = !this.dec.output.trim().is_empty();
                    }
                    this.submit |= entered(ui, &field);
                    if clicked.is_some() {
                        this.open_dialog(&ctx, DialogTarget::DecOutput);
                    }
                },
            );
            pair(
                self,
                ui,
                |ui, this| {
                    widgets::form_label(ui, s.password_label);
                    this.submit |= secret_row(
                        ui,
                        p,
                        s,
                        "dec-password",
                        s.password_label,
                        &mut this.dec.password,
                        &mut this.dec.show_password,
                    );
                },
                |ui, this| {
                    widgets::form_label(ui, s.keyfile_label);
                    let (field, clicked) = widgets::input_row(ui, &[s.browse_btn], |ui| {
                        widgets::path_field(ui, &mut this.dec.keyfile, s.keyfile_hint)
                    });
                    this.submit |= entered(ui, &field);
                    if clicked.is_some() {
                        this.open_dialog(&ctx, DialogTarget::DecKeyfile);
                    }
                },
            );
            ui.add_space(4.0);
            widgets::switch_row(
                ui,
                p,
                &mut self.dec.delete_source,
                s.dec_delete_label,
                s.dec_delete_hint,
            );
        });

        ui.add_space(8.0);
        let busy =
            (self.running.as_ref().map(|r| r.kind) == Some(JobKind::Decrypt)).then_some(s.working);
        let button = ui
            .add_enabled_ui(!self.busy() || busy.is_some(), |ui| {
                widgets::primary_button(ui, p, s.dec_submit, p.success, p.success_hover, busy)
            })
            .inner;
        if button.clicked() || self.submit {
            self.submit_decrypt(&ctx);
        }
    }

    fn tools_page(&mut self, ui: &mut Ui, p: &Palette) {
        let s = self.s();
        let ctx = ui.ctx().clone();
        widgets::page_title(ui, s.tools_title);
        widgets::page_hint(ui, p, s.tools_hint);
        let result = self.result.clone();
        pair(
            self,
            ui,
            |ui, this| {
                this.submit = false;
                ui.add_enabled_ui(!this.busy(), |ui| {
                    widgets::form_label(ui, s.keyfile_path_label);
                    let (field, clicked) = widgets::input_row(ui, &[s.save_as_btn], |ui| {
                        widgets::path_field(ui, &mut this.keyfile_output, s.keyfile_path_hint)
                    });
                    if std::mem::take(&mut this.focus_keyfile_output) {
                        field.request_focus();
                    }
                    this.submit |= entered(ui, &field);
                    if clicked.is_some() {
                        this.open_dialog(&ctx, DialogTarget::KeyfileOutput);
                    }
                });
                ui.add_space(6.0);
                let busy = (this.running.as_ref().map(|r| r.kind) == Some(JobKind::Keyfile))
                    .then_some(s.working);
                let button = ui
                    .add_enabled_ui(!this.busy() || busy.is_some(), |ui| {
                        widgets::primary_button(
                            ui,
                            p,
                            s.keyfile_submit,
                            p.accent,
                            p.accent_hover,
                            busy,
                        )
                    })
                    .inner;
                if button.clicked() || this.submit {
                    this.submit_keyfile(&ctx);
                }
            },
            |ui, _| {
                widgets::form_label(ui, s.result_label);
                widgets::result_box(ui, p, result.as_deref().unwrap_or(s.no_result));
            },
        );
    }

    fn settings_page(&mut self, ui: &mut Ui, p: &Palette) {
        let s = self.s();
        widgets::page_title(ui, s.settings_title);
        let mut language = self.language;
        pair(
            self,
            ui,
            |ui, _| {
                widgets::card(ui, p, |ui| {
                    widgets::form_label(ui, s.language_label);
                    egui::ComboBox::from_id_salt("language")
                        .selected_text(language.native_name())
                        .width(ui.available_width())
                        .height(200.0)
                        .show_ui(ui, |ui| {
                            for option in Language::ALL {
                                ui.selectable_value(&mut language, option, option.native_name());
                            }
                        });
                });
            },
            |ui, _| {
                widgets::card(ui, p, |ui| {
                    widgets::form_label(ui, s.version_label);
                    ui.label(
                        RichText::new(format!(
                            "TimENC v{} - {}",
                            env!("CARGO_PKG_VERSION"),
                            s.version_desc
                        ))
                        .size(12.5)
                        .color(p.text_weak),
                    );
                });
            },
        );
        if language != self.language {
            self.language = language;
            config::save_language(language);
            // "Working..." / "Ready" follow the language; results stay as they are.
            if self.running.is_some() {
                self.status_text = Some(self.s().working.to_string());
            }
        }
    }

    fn sync_theme(&mut self, ctx: &egui::Context) {
        #[cfg(target_os = "linux")]
        {
            // Without a portal answer keep the original dark look.
            let wanted = self.theme_watcher.theme().unwrap_or(Theme::Dark);
            if self.applied_theme != Some(wanted) {
                self.applied_theme = Some(wanted);
                ctx.set_theme(wanted);
                // Also recolours the title bar (Wayland CSD and X11 hint).
                ctx.send_viewport_cmd(egui::ViewportCommand::SetTheme(match wanted {
                    Theme::Dark => egui::SystemTheme::Dark,
                    Theme::Light => egui::SystemTheme::Light,
                }));
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = ctx;
    }
}

impl eframe::App for TimencApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.sync_theme(&ctx);
        self.poll_running();
        self.poll_dialog();
        while let Ok(request) = self.open_requests.try_recv() {
            if let Some(path) = request {
                self.open_encrypted(path);
            }
        }
        let dropped = ctx.input(|i| {
            i.raw
                .dropped_files
                .first()
                .map(|f| f.path().to_path_buf())
                .filter(|p| !p.as_os_str().is_empty())
        });
        if let Some(path) = dropped {
            if !self.busy() {
                self.handle_drop(path);
            }
        }

        let p = theme::palette(ctx.theme());
        let s = self.s();

        Panel::top("nav")
            .frame(
                Frame::new()
                    .fill(p.bg_secondary)
                    .inner_margin(Margin::symmetric(14, 0)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    for (page, label) in [
                        (Page::Encrypt, s.nav_encrypt),
                        (Page::Decrypt, s.nav_decrypt),
                        (Page::Tools, s.nav_tools),
                        (Page::Settings, s.nav_settings),
                    ] {
                        if widgets::nav_tab(ui, p, label, self.page == page).clicked() {
                            self.page = page;
                        }
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let text = self.status_text.as_deref().unwrap_or(s.ready);
                        let max = (ui.available_width() - 30.0).max(60.0);
                        widgets::status_pill(ui, p, self.status_kind, text, max);
                    });
                });
            });

        CentralPanel::default()
            .frame(Frame::new().fill(p.bg_secondary))
            .show(ui, |ui| {
                ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
                    Frame::new()
                        .inner_margin(Margin::symmetric(24, 18))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            match self.page {
                                Page::Encrypt => self.encrypt_page(ui, p),
                                Page::Decrypt => self.decrypt_page(ui, p),
                                Page::Tools => self.tools_page(ui, p),
                                Page::Settings => self.settings_page(ui, p),
                            }
                        });
                });
            });

        if ctx.input(|i| !i.raw.hovered_files.is_empty()) {
            drop_overlay(&ctx, p, s.drop_hint);
        }
    }
}

/// Two form groups side by side on a wide window, stacked on a narrow one.
fn pair<T>(
    state: &mut T,
    ui: &mut Ui,
    left: impl FnOnce(&mut Ui, &mut T),
    right: impl FnOnce(&mut Ui, &mut T),
) {
    const GAP: f32 = 20.0;
    if ui.available_width() >= 640.0 {
        let width = (ui.available_width() - GAP) / 2.0;
        let column = |ui: &mut Ui, state: &mut T, add: &mut dyn FnMut(&mut Ui, &mut T)| {
            ui.allocate_ui_with_layout(vec2(width, 0.0), Layout::top_down(Align::Min), |ui| {
                ui.set_width(width);
                add(ui, state);
            });
        };
        let (mut left, mut right) = (Some(left), Some(right));
        ui.horizontal_top(|ui| {
            column(ui, state, &mut |ui, st| (left.take().unwrap())(ui, st));
            ui.add_space(GAP - ui.spacing().item_spacing.x);
            column(ui, state, &mut |ui, st| (right.take().unwrap())(ui, st));
        });
    } else {
        left(ui, state);
        ui.add_space(4.0);
        right(ui, state);
    }
    ui.add_space(8.0);
}

/// A password field with its Show/Hide button. Returns true on Enter.
fn secret_row(
    ui: &mut Ui,
    p: &Palette,
    s: &Strings,
    id: &str,
    label: &str,
    secret: &mut SecretString,
    visible: &mut bool,
) -> bool {
    let toggle = if *visible { s.hide_btn } else { s.show_btn };
    let (submitted, clicked) = widgets::input_row(ui, &[toggle], |ui| {
        widgets::secret_field(ui, p, id, label, secret, *visible).submitted
    });
    if clicked.is_some() {
        *visible = !*visible;
    }
    submitted
}

fn entered(ui: &Ui, field: &egui::Response) -> bool {
    field.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter))
}

fn optional_path(value: &str) -> Option<PathBuf> {
    let value = value.trim();
    (!value.is_empty()).then(|| PathBuf::from(value))
}

/// The same rough score the web UI used: length and character classes.
fn strength(s: &'static Strings, p: &Palette, password: &str) -> (u32, &'static str, Color32) {
    let mut score = 0;
    if !password.is_empty() {
        let length = password.chars().count();
        if length >= 8 {
            score += 25;
        }
        if length >= 12 {
            score += 15;
        }
        for class in [
            |c: char| c.is_ascii_lowercase(),
            |c: char| c.is_ascii_uppercase(),
            |c: char| c.is_ascii_digit(),
            |c: char| !c.is_ascii_alphanumeric(),
        ] {
            if password.chars().any(class) {
                score += 15;
            }
        }
    }
    let score = score.min(100);
    match score {
        0 => (0, s.strength_empty, p.danger),
        1..=34 => (score, s.strength_weak, p.danger),
        35..=59 => (score, s.strength_fair, p.warning),
        60..=79 => (score, s.strength_strong, p.success),
        _ => (score, s.strength_very_strong, p.success_hover),
    }
}

fn drop_overlay(ctx: &egui::Context, p: &Palette, hint: &str) {
    let screen = ctx.content_rect();
    let painter = ctx.layer_painter(egui::LayerId::new(
        egui::Order::Foreground,
        egui::Id::unique("drop-overlay"),
    ));
    painter.rect_filled(screen, 0, p.bg_primary.gamma_multiply(0.85));
    painter.rect_stroke(
        screen.shrink(10.0),
        8,
        egui::Stroke::new(2.0, p.accent),
        egui::StrokeKind::Inside,
    );
    painter.text(
        screen.center(),
        egui::Align2::CENTER_CENTER,
        hint,
        egui::FontId::proportional(18.0),
        p.accent,
    );
}
