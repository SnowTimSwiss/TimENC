//! A password buffer that never leaves stray copies of the secret behind.
//!
//! A plain `String` reallocates as it grows and leaves the old buffer to the
//! allocator, and egui's `TextEdit` keeps undo snapshots of whatever it edits.
//! Both would scatter un-wiped copies of the password over the heap. This
//! buffer grows by copying into a fresh allocation and wiping the old one, and
//! wipes removed characters and the whole buffer on drop. It is edited only by
//! [`crate::widgets::secret_field`], which keeps no copies of its own.

use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Enough for any realistic password, so a normal one never reallocates.
const INITIAL_CAPACITY: usize = 128;

pub struct SecretString {
    buf: Zeroizing<String>,
}

impl SecretString {
    pub fn new() -> Self {
        Self {
            buf: Zeroizing::new(String::with_capacity(INITIAL_CAPACITY)),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.buf
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn char_count(&self) -> usize {
        self.buf.chars().count()
    }

    /// Appends text, moving to a larger buffer (and wiping the old one) when
    /// the current one is full.
    pub fn push_str(&mut self, text: &str) {
        let needed = self.buf.len() + text.len();
        if needed > self.buf.capacity() {
            let capacity = needed.next_power_of_two().max(INITIAL_CAPACITY);
            let mut grown = Zeroizing::new(String::with_capacity(capacity));
            grown.push_str(&self.buf);
            grown.push_str(text);
            // The old buffer is wiped as `Zeroizing` drops it.
            self.buf = grown;
        } else {
            self.buf.push_str(text);
        }
    }

    /// Removes the last character and wipes the bytes it occupied.
    pub fn pop(&mut self) {
        let Some(last) = self.buf.chars().next_back() else {
            return;
        };
        let new_len = self.buf.len() - last.len_utf8();
        let mut bytes = std::mem::take(&mut *self.buf).into_bytes();
        bytes[new_len..].zeroize();
        bytes.truncate(new_len);
        // A prefix ending on a char boundary is valid UTF-8, so this cannot
        // fail; the capacity (and so the allocation) is kept.
        *self.buf = String::from_utf8(bytes).unwrap_or_default();
    }

    /// Wipes the whole buffer.
    pub fn clear(&mut self) {
        // Zeroizes the full capacity, then sets the length to zero.
        self.buf.zeroize();
        if self.buf.capacity() < INITIAL_CAPACITY {
            self.buf.reserve(INITIAL_CAPACITY);
        }
    }

    /// A copy for handing to the encryption library, which wipes its own copy
    /// when the operation's options are dropped.
    pub fn to_unprotected_string(&self) -> String {
        let mut copy = String::with_capacity(self.buf.len());
        copy.push_str(&self.buf);
        copy
    }
}

impl Default for SecretString {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pop_and_clear() {
        let mut s = SecretString::new();
        s.push_str("pässword");
        assert_eq!(s.as_str(), "pässword");
        assert_eq!(s.char_count(), 8);
        s.pop();
        assert_eq!(s.as_str(), "pässwor");
        for _ in 0..5 {
            s.pop();
        }
        assert_eq!(s.as_str(), "pä");
        s.pop();
        assert_eq!(s.as_str(), "p");
        s.clear();
        assert!(s.is_empty());
        s.pop();
        assert!(s.is_empty());
    }

    #[test]
    fn grows_past_initial_capacity() {
        let mut s = SecretString::new();
        let long = "x".repeat(300);
        s.push_str(&long);
        s.push_str("ü");
        assert_eq!(s.as_str().len(), 302);
        assert!(s.as_str().ends_with('ü'));
    }

    #[test]
    fn debug_is_redacted() {
        let mut s = SecretString::new();
        s.push_str("hunter2");
        assert!(!format!("{s:?}").contains("hunter2"));
    }
}
