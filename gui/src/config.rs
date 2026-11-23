//! The one persisted setting: the UI language.
//!
//! Stored as a one-line text file in the platform's config directory, so no
//! serialisation library is needed.

use std::path::PathBuf;

use crate::i18n::Language;

fn path() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("timenc").join("gui-language"))
}

pub fn load_language() -> Language {
    path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|code| Language::from_code(&code))
        .unwrap_or_else(Language::from_environment)
}

pub fn save_language(language: Language) {
    let Some(path) = path() else { return };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::fs::write(path, language.code());
}
