//! English and German UI text.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Language {
    English,
    German,
}

impl Language {
    pub const ALL: [Language; 2] = [Language::English, Language::German];

    pub fn code(self) -> &'static str {
        match self {
            Language::English => "en",
            Language::German => "de",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        match code.trim() {
            "en" => Some(Language::English),
            "de" => Some(Language::German),
            _ => None,
        }
    }

    pub fn native_name(self) -> &'static str {
        match self {
            Language::English => "English",
            Language::German => "Deutsch",
        }
    }

    /// German if the desktop's locale is German, English otherwise.
    pub fn from_environment() -> Self {
        let german = ["LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .filter_map(|var| std::env::var(var).ok())
            .find(|value| !value.is_empty())
            .is_some_and(|value| value.starts_with("de"));
        if german {
            Language::German
        } else {
            Language::English
        }
    }

    pub fn strings(self) -> &'static Strings {
        match self {
            Language::English => &EN,
            Language::German => &DE,
        }
    }
}

pub struct Strings {
    pub nav_encrypt: &'static str,
    pub nav_decrypt: &'static str,
    pub nav_tools: &'static str,
    pub nav_settings: &'static str,

    pub ready: &'static str,
    pub working: &'static str,

    pub enc_title: &'static str,
    pub enc_input_label: &'static str,
    pub enc_input_hint: &'static str,
    pub file_btn: &'static str,
    pub folder_btn: &'static str,
    pub enc_output_label: &'static str,
    pub auto_suggested: &'static str,
    pub save_as_btn: &'static str,
    pub password_label: &'static str,
    pub confirm_label: &'static str,
    pub show_btn: &'static str,
    pub hide_btn: &'static str,
    pub passwords_match: &'static str,
    pub passwords_differ: &'static str,
    pub keyfile_label: &'static str,
    pub keyfile_hint: &'static str,
    pub browse_btn: &'static str,
    pub create_btn: &'static str,
    pub advanced_label: &'static str,
    pub advanced_badge: &'static str,
    pub compress_label: &'static str,
    pub compress_hint: &'static str,
    pub pad_label: &'static str,
    pub pad_hint: &'static str,
    pub paranoid_label: &'static str,
    pub paranoid_hint: &'static str,
    pub enc_delete_label: &'static str,
    pub enc_delete_hint: &'static str,
    pub enc_submit: &'static str,

    pub dec_title: &'static str,
    pub dec_hint: &'static str,
    pub dec_input_label: &'static str,
    pub dec_input_hint: &'static str,
    pub dec_output_label: &'static str,
    pub dec_delete_label: &'static str,
    pub dec_delete_hint: &'static str,
    pub dec_submit: &'static str,

    pub tools_title: &'static str,
    pub tools_hint: &'static str,
    pub keyfile_path_label: &'static str,
    pub keyfile_path_hint: &'static str,
    pub keyfile_submit: &'static str,
    pub result_label: &'static str,
    pub no_result: &'static str,

    pub settings_title: &'static str,
    pub language_label: &'static str,
    pub version_label: &'static str,
    pub version_desc: &'static str,

    pub strength_empty: &'static str,
    pub strength_weak: &'static str,
    pub strength_fair: &'static str,
    pub strength_strong: &'static str,
    pub strength_very_strong: &'static str,

    pub drop_hint: &'static str,

    pub encrypted_ok: &'static str,
    pub decrypted_ok: &'static str,
    pub keyfile_ok: &'static str,
    pub path_prefix: &'static str,
    /// `{v}` is replaced by the format version.
    pub legacy_warning: &'static str,
    pub missing_input: &'static str,
    pub missing_output: &'static str,
    pub missing_password: &'static str,
    pub missing_keyfile_path: &'static str,
    pub worker_crashed: &'static str,
}

pub static EN: Strings = Strings {
    nav_encrypt: "Encrypt",
    nav_decrypt: "Decrypt",
    nav_tools: "Tools",
    nav_settings: "Settings",

    ready: "Ready",
    working: "Working...",

    enc_title: "Encrypt",
    enc_input_label: "File or folder",
    enc_input_hint: "Select...",
    file_btn: "File",
    folder_btn: "Folder",
    enc_output_label: "Output file",
    auto_suggested: "Auto-suggested",
    save_as_btn: "Save As",
    password_label: "Password",
    confirm_label: "Repeat password",
    show_btn: "Show",
    hide_btn: "Hide",
    passwords_match: "Passwords match",
    passwords_differ: "Passwords do not match",
    keyfile_label: "Keyfile (optional)",
    keyfile_hint: "Select keyfile",
    browse_btn: "Browse",
    create_btn: "Create",
    advanced_label: "Advanced options",
    advanced_badge: "{n} on",
    compress_label: "Compress before encrypting",
    compress_hint: "Smaller output for compressible files",
    pad_label: "Hide the exact file size",
    pad_hint: "Pads the output, up to 12% larger",
    paranoid_label: "Paranoid mode",
    paranoid_hint: "Key derivation with 1 GB instead of 256 MB - slower, for long-term archives",
    enc_delete_label: "Delete the original afterwards",
    enc_delete_hint: "Only once the encrypted file has been written and verified. Overwritten first, best-effort.",
    enc_submit: "Encrypt",

    dec_title: "Decrypt",
    dec_hint: "Handles every format TimENC has written: v3, v4, v4.5 and v6.",
    dec_input_label: "Encrypted file",
    dec_input_hint: "Select .timenc file",
    dec_output_label: "Output folder",
    dec_delete_label: "Delete the encrypted file afterwards",
    dec_delete_hint: "Only once decryption has succeeded and the output is on disk.",
    dec_submit: "Decrypt",

    tools_title: "Tools",
    tools_hint: "A keyfile is 32 random bytes used alongside your password. Both are needed to decrypt - keep it somewhere separate.",
    keyfile_path_label: "Keyfile path",
    keyfile_path_hint: "Select location",
    keyfile_submit: "Generate Keyfile",
    result_label: "Last Result",
    no_result: "No operation run yet.",

    settings_title: "Settings",
    language_label: "Language",
    version_label: "Version",
    version_desc: "v6 format, key-committing + Argon2id",

    strength_empty: "Enter a password",
    strength_weak: "Weak",
    strength_fair: "Fair",
    strength_strong: "Strong",
    strength_very_strong: "Very strong",

    drop_hint: "Drop to select",

    encrypted_ok: "File encrypted successfully",
    decrypted_ok: "File decrypted successfully",
    keyfile_ok: "Keyfile created successfully",
    path_prefix: "Path",
    legacy_warning: " - but this file uses the old v{v} format, which cannot detect a truncated file. Encrypt the result again to upgrade it.",
    missing_input: "Select a file or folder first.",
    missing_output: "Choose where to save the result.",
    missing_password: "Enter a password.",
    missing_keyfile_path: "Choose where to save the keyfile.",
    worker_crashed: "The operation stopped unexpectedly.",
};

pub static DE: Strings = Strings {
    nav_encrypt: "Verschlüsseln",
    nav_decrypt: "Entschlüsseln",
    nav_tools: "Werkzeuge",
    nav_settings: "Einstellungen",

    ready: "Bereit",
    working: "In Arbeit...",

    enc_title: "Verschlüsseln",
    enc_input_label: "Datei oder Ordner",
    enc_input_hint: "Auswählen...",
    file_btn: "Datei",
    folder_btn: "Ordner",
    enc_output_label: "Ausgabedatei",
    auto_suggested: "Automatisch vorgeschlagen",
    save_as_btn: "Speichern als",
    password_label: "Passwort",
    confirm_label: "Passwort wiederholen",
    show_btn: "Anzeigen",
    hide_btn: "Verbergen",
    passwords_match: "Passwörter stimmen überein",
    passwords_differ: "Passwörter stimmen nicht überein",
    keyfile_label: "Keyfile (optional)",
    keyfile_hint: "Keyfile auswählen",
    browse_btn: "Durchsuchen",
    create_btn: "Erstellen",
    advanced_label: "Erweiterte Optionen",
    advanced_badge: "{n} aktiv",
    compress_label: "Vor der Verschlüsselung komprimieren",
    compress_hint: "Kleinere Ausgabe bei komprimierbaren Dateien",
    pad_label: "Genaue Dateigröße verbergen",
    pad_hint: "Füllt die Ausgabe auf, bis zu 12% größer",
    paranoid_label: "Paranoid-Modus",
    paranoid_hint: "Schlüsselableitung mit 1 GB statt 256 MB - langsamer, für Langzeitarchive",
    enc_delete_label: "Original danach löschen",
    enc_delete_hint: "Erst wenn die verschlüsselte Datei geschrieben und geprüft ist. Wird vorher überschrieben (best-effort).",
    enc_submit: "Verschlüsseln",

    dec_title: "Entschlüsseln",
    dec_hint: "Liest jedes Format, das TimENC je geschrieben hat: v3, v4, v4.5 und v6.",
    dec_input_label: "Verschlüsselte Datei",
    dec_input_hint: ".timenc-Datei auswählen",
    dec_output_label: "Zielordner",
    dec_delete_label: "Verschlüsselte Datei danach löschen",
    dec_delete_hint: "Erst wenn die Entschlüsselung geklappt hat und die Ausgabe auf der Festplatte ist.",
    dec_submit: "Entschlüsseln",

    tools_title: "Werkzeuge",
    tools_hint: "Ein Keyfile sind 32 zufällige Bytes zusätzlich zum Passwort. Zum Entschlüsseln braucht es beides - bewahre es getrennt auf.",
    keyfile_path_label: "Keyfile-Pfad",
    keyfile_path_hint: "Speicherort auswählen",
    keyfile_submit: "Keyfile erstellen",
    result_label: "Letztes Ergebnis",
    no_result: "Noch kein Vorgang.",

    settings_title: "Einstellungen",
    language_label: "Sprache",
    version_label: "Version",
    version_desc: "v6-Format, schlüsselbindend + Argon2id",

    strength_empty: "Passwort eingeben",
    strength_weak: "Schwach",
    strength_fair: "Mittel",
    strength_strong: "Stark",
    strength_very_strong: "Sehr stark",

    drop_hint: "Loslassen zum Auswählen",

    encrypted_ok: "Datei erfolgreich verschlüsselt",
    decrypted_ok: "Datei erfolgreich entschlüsselt",
    keyfile_ok: "Keyfile erfolgreich erstellt",
    path_prefix: "Pfad",
    legacy_warning: " - aber diese Datei nutzt das alte v{v}-Format, das eine abgeschnittene Datei nicht erkennen kann. Verschlüssle das Ergebnis erneut, um es zu aktualisieren.",
    missing_input: "Wähle zuerst eine Datei oder einen Ordner.",
    missing_output: "Wähle, wo das Ergebnis gespeichert werden soll.",
    missing_password: "Gib ein Passwort ein.",
    missing_keyfile_path: "Wähle, wo das Keyfile gespeichert werden soll.",
    worker_crashed: "Der Vorgang wurde unerwartet abgebrochen.",
};
