//! Path helpers shared by the UI and the launch-argument handling.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub fn is_timenc_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("timenc"))
        && path.is_file()
}

/// Picks the first existing `.timenc` file out of the launch arguments, for
/// "Open with TimENC" and file associations.
pub fn find_timenc_path<I>(args: I) -> Option<PathBuf>
where
    I: IntoIterator<Item = OsString>,
{
    args.into_iter()
        .map(PathBuf::from)
        .find(|path| is_timenc_file(path))
}

fn trim_separators(input: &str) -> &str {
    input.trim().trim_end_matches(['/', '\\'])
}

/// `dir/name.ext` -> `dir/name.timenc`; a folder `dir/name` -> `dir/name.timenc`.
pub fn suggest_encrypted_output(input: &str) -> String {
    let norm = trim_separators(input);
    if norm.is_empty() {
        return String::new();
    }
    let name_start = norm.rfind(['/', '\\']).map_or(0, |i| i + 1);
    let name = &norm[name_start..];
    let stem = match name.rfind('.') {
        Some(dot) if dot > 0 && dot + 1 < name.len() => &name[..dot],
        _ => name,
    };
    let stem = if stem.is_empty() { "encrypted" } else { stem };
    format!("{}{}.timenc", &norm[..name_start], stem)
}

/// The folder an encrypted file sits in, as the default output folder.
pub fn suggest_decrypted_output(input: &str) -> String {
    let norm = trim_separators(input);
    if norm.is_empty() {
        return String::new();
    }
    match norm.rfind(['/', '\\']) {
        Some(0) => "/".to_string(),
        Some(i) => norm[..i].to_string(),
        None => ".".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_output_names() {
        assert_eq!(
            suggest_encrypted_output("/home/a/doc.pdf"),
            "/home/a/doc.timenc"
        );
        assert_eq!(
            suggest_encrypted_output("/home/a/photos/"),
            "/home/a/photos.timenc"
        );
        assert_eq!(
            suggest_encrypted_output("/home/a/archive.tar.gz"),
            "/home/a/archive.tar.timenc"
        );
        assert_eq!(
            suggest_encrypted_output("/home/a/.bashrc"),
            "/home/a/.bashrc.timenc"
        );
        assert_eq!(
            suggest_encrypted_output(r"C:\Users\a\x.txt"),
            r"C:\Users\a\x.timenc"
        );
        assert_eq!(suggest_encrypted_output("file"), "file.timenc");
        assert_eq!(suggest_encrypted_output("  "), "");
    }

    #[test]
    fn decrypted_output_folders() {
        assert_eq!(suggest_decrypted_output("/home/a/x.timenc"), "/home/a");
        assert_eq!(suggest_decrypted_output("/x.timenc"), "/");
        assert_eq!(suggest_decrypted_output("x.timenc"), ".");
        assert_eq!(suggest_decrypted_output(r"C:\a\x.timenc"), r"C:\a");
    }
}
