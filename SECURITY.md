# Security

TimENC aims to be hard to misuse and hard to break, and to be honest about where
that stops. This page describes what it protects, what it does not, what the
last security review found, and how to report a problem.

## Reporting a vulnerability

Please use GitHub's private
[security advisory form](https://github.com/SnowTimSwiss/TimENC/security/advisories/new)
rather than a public issue. Include the version, how to reproduce, and what an
attacker gains.

## Threat model

**Protected.** Someone who gets a `.timenc` file (a stolen laptop, a cloud
backup, an email attachment) and can try as many passwords as they have
compute for:

* contents, file name and directory structure are confidential;
* any modification, truncation, reordering or extension of the file is detected
  (v6 files; see below for older versions);
* a wrong password or keyfile is rejected immediately, and one file cannot be
  made to open under two different passwords (key commitment);
* a hostile file cannot make TimENC read or write outside the folder you chose,
  allocate unbounded memory while parsing, or crash it with a malformed header.

**Not protected.**

* **A weak password.** Argon2id slows guessing down; it does not stop a
  guessable password. Use a long random passphrase, a keyfile, or both.
* **A compromised machine.** Malware, a keylogger, or someone with a debugger
  on your account sees the password and plaintext. TimENC wipes secrets from its
  own memory and disables core dumps, but it cannot defend a hostile host.
* **What the file system shows.** The `.timenc` file's name, size (unless you
  use `--pad`), and timestamps are visible. Name it something neutral.
* **Secure deletion.** `--delete-source` overwrites then removes the source, but
  SSDs, copy-on-write file systems and backups can keep old copies. Full-disk
  encryption is the real answer.
* **A sender who knows the password.** If someone gives you a `.timenc` file
  *and* its password, the archive is authentic by construction. TimENC refuses
  the dangerous archive tricks (see findings), but an extracted folder can still
  contain symlinks that point anywhere, exactly as with `tar`. Treat extracted
  folders from untrusted senders like any untrusted download.

## Review of 3.1.0

A code review of the whole crate and GUI backend, plus fuzzing and a dependency
audit. This was done by the project's own maintainers and tooling, **not by an
independent third party**; if you depend on TimENC for something high-stakes,
get an external review of the format first.

The cryptographic design itself (ChaCha20-Poly1305 chunks with index and
final-chunk binding, Argon2id, subkey separation, key commitment) held up: no
way to forge, reorder, truncate or silently alter a v6 file was found, and
single-byte flips, every truncation point and appended data are covered by tests
and a fuzz target. The findings were in the code *around* the cipher.

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | Medium | `generate-keyfile` created the keyfile with the default umask (`0644`), so every local user could read the second factor. It also followed a symlink at the destination. | Fixed: created exclusively, mode `0600` |
| 2 | Low | A hostile archive (sender knows the password) could contain FIFOs, device nodes or hard links, which were recreated on extraction. | Fixed: only files, folders and symlinks are extracted. Writing through a planted symlink or hard link was already blocked by the `tar` crate; regression tests now pin that |
| 3 | Low | Keyfiles were read with no size limit (`/dev/zero`, a huge video) and an empty keyfile was accepted as "a second factor" that adds nothing. | Fixed: 16 MiB cap, empty keyfiles refused |
| 4 | Low | `sanitize_output_name` accepted `name/` and `name/.` because `Path` normalises the trailing separator away. Not exploitable (the later rename fails), found by fuzzing. | Fixed |
| 5 | Low | The 256 MiB – 1 GiB Argon2 working memory, which holds password-derived data, was freed without being wiped. | Fixed: `argon2`'s `zeroize` feature |
| 6 | Low | GUI request types derived `Debug` and `Serialize` with the password inside, so one `{:?}` or serializer call would log it. Password fields also stayed filled after a successful operation. | Fixed |
| 7 | Low | The GUI trimmed whitespace from passwords, silently changing one with a leading or trailing space and making such files unreadable from the CLI. | Fixed, with a retry so files written by older GUI versions still open |
| 8 | Low | A crash could write a core dump containing keys or the password. | Mitigated: core dumps disabled; CLI also non-dumpable |
| 9 | Medium | `cargo audit` reported advisories in `zstd`, `zstd-safe` and `zstd-sys` (used to decompress decrypted data) and in `url`, `rand`, `rustix`, `tokio`, `anyhow`, `event-listener`. | Fixed by updating the lockfile; Flatpak sources regenerated |
| 10 | Info | Nothing ran the tests or audited dependencies. | CI added |

The multithreaded stream code added afterwards (see Performance in the README)
is checked against an independent, sequential implementation of the format
written from its description: the ciphertext must be byte-for-byte identical at
every batch edge and for 1, 3 and 8 threads, and truncation, reordering and
bit flips across batch boundaries must fail exactly as before. Files written
before and after that change were also confirmed to open with either version
in every mode.

### Known limitations (deliberately not changed)

* **Formats v3, v4 and v4.5 cannot detect truncation at a chunk boundary.** They
  still decrypt so that old files stay readable, and TimENC now warns when you
  open one. Encrypt the result again to upgrade it.
* **Unicode normalisation.** The password is hashed as the bytes you type. The
  same visible password typed on two systems or input methods can differ in
  composition (`é` as one code point or two). Using plain ASCII, or the same
  input method everywhere, avoids this. Normalising would be the right fix but
  needs a new dependency and a compatibility path for existing files.
* **Password and keyfile are joined with text separators** (`|keyfile|`) rather
  than length prefixes, so the password `a|keyfile|b` with no keyfile derives
  the same key as password `a` with keyfile bytes `b`. This gives an attacker
  nothing without the keyfile bytes, but a length-prefixed encoding would be
  cleaner and belongs in the next format version.
* **Header-supplied Argon2 costs** are bounded (up to 4 GiB and 64 passes) but
  that is still minutes of CPU and a lot of memory, spent before the wrong
  password is noticed. Opening a hostile file can therefore be slow, though not
  unsafe.
* **Extracted symlinks are restored as written**, including absolute targets, so
  that backing up and restoring a folder works.
* **Decryption writes plaintext to a temporary file** next to the output before
  extracting, so the whole stream is authenticated first. On failure the file is
  unlinked, not wiped.
* **The GUI password lives in the webview** while you type it and cannot be
  zeroed from Rust. The CLI's `-p` flag exposes it in the process list.
* **No `mlock`.** Keys can be swapped to disk unless swap is encrypted.
* **Accepted advisories**: RUSTSEC-2026-0194 and -0195 (`quick-xml` via `plist`,
  build-time parsing of a file Tauri generated itself). See `.cargo/audit.toml`.

## Checking it yourself

```bash
cargo test                                      # unit, integration, hostile-input tests
cargo clippy --all-targets -- -D warnings
cargo audit --file src-tauri/Cargo.lock         # dependency advisories

# Fuzzing (needs a nightly toolchain and `cargo install cargo-fuzz`)
cd fuzz
cargo +nightly fuzz run parse_headers -- -max_len=512
cargo +nightly fuzz run v6_roundtrip  -- -max_len=300000
cargo +nightly fuzz run decrypt_file  -- -max_len=4096
```

CI runs all of these on every push and weekly.
