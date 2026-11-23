# Security

TimENC tries to be hard to misuse and hard to break, and to be honest about
where that stops. This page says what it protects, what it doesn't, what the
reviews found, and how to report a problem.

## Challenge: try to break it

Nobody outside the project has audited the design yet, so please try. There is
no bounty, only credit in the release notes if you want it.

**Counts as a break** (against files made by the current version, v6):

* recovering plaintext, the file name or the folder structure without the
  password and keyfile, or faster than guessing the password
* modifying, truncating, reordering or extending a file without decryption
  failing
* making one file open under two different passwords with different content
* making TimENC read or write outside the output folder, run out of memory
  during parsing, or crash on a malformed file
* finding a flaw in the Argon2id / subkey / commitment construction (the
  format is described in the [README](README.md#file-format-v6) and
  implemented in `src/format/mod.rs`)

**Doesn't count:** guessing a weak password, malware or a debugger on the
machine that runs TimENC, what the file system shows (name, size, timestamps),
SSDs keeping old copies of a deleted source, and the limitations listed below.

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
  own memory and switches off core dumps (Unix; the command-line tool also
  becomes non-dumpable on Linux), but it cannot defend a hostile host.
* **What the file system shows.** The `.timenc` file's name, size (unless you
  use `--pad`), and timestamps are visible. Name it something neutral.
* **Secure deletion.** `--delete-source` overwrites then removes the source, but
  SSDs, copy-on-write file systems and backups can keep old copies. Full-disk
  encryption is the real answer.
* **A sender who knows the password.** If someone gives you a `.timenc` file
  *and* its password, the archive is authentic by construction. TimENC refuses
  the dangerous archive tricks (see findings), but an extracted folder can still
  contain symlinks that point anywhere, exactly as with `tar`, and a compressed
  file or archive can expand to far more than its size on disk. Treat extracted
  folders from untrusted senders like any untrusted download.

## Review of 4.0.0

Version 4.0.0 swapped the Tauri/web front end for the egui GUI. The core
crate and file format were not changed, so this pass re-read the file
operations, the v6 format code, the command-line tool and the new GUI code
(password buffer, worker thread, single-instance socket, file association
handling), and re-ran the hostile-archive probes. Like the 3.1.0 review, it was
done by the project itself, not by an independent third party.

| # | Severity | Finding | Status |
|---|----------|---------|--------|
| 1 | Low | Decrypting a single file checked `exists()` and then renamed the temporary file into place. `exists()` is false for a dangling symlink and a rename replaces whatever is there, so something that appeared at the target in between (or a dangling symlink) was silently replaced. Needs write access to the output folder. | Fixed: the file is linked into place, which fails if anything is there; file systems without hard links fall back to a check and rename. Regression test added. |
| 2 | Info | A sender who knows the password can send a zstd stream or tar archive that expands to a lot of data and fills the disk. | Documented, see limitations. |

Checked and found fine: setuid/setgid bits in an archive are not applied, a
directory entry below a planted symlink is refused, hard links, FIFOs and
devices are refused, header parameters are bounded before any allocation, the
GUI's single-instance socket only lives in the user's private runtime
directory and only ever opens `.timenc` files, and the password buffer wipes
what it replaces.

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
* **No limit on the decompressed size.** Someone who knows the password can send
  a file that expands to more than your disk holds. Decryption then fails with
  an I/O error and the temporary file is removed.
* **GUI passwords** are typed into a buffer that is wiped when it grows, when a
  character is deleted and after each operation, and the password fields keep
  no copies. Pressing "Show" lays the text out for display, and that copy sits
  in egui's text cache until it is evicted. The CLI's `-p` flag exposes the
  password in the process list.
* **No `mlock`.** Keys can be swapped to disk unless swap is encrypted.
* **Windows and macOS hardening is thinner.** Core dumps are switched off on
  Unix only, and the non-dumpable flag is Linux only.
* **No accepted advisories.** `cargo audit` warns that `zbus`'s `zvariant`
  crates and `ttf-parser` are unmaintained. `zbus` only talks to the user's own
  session bus (accessibility, theme portal); `ttf-parser` only reads the fonts
  compiled into the program. Neither sees data from a `.timenc` file.

## Checking it yourself

```bash
cargo test                                      # unit, integration, hostile-input tests
cargo clippy --all-targets -- -D warnings
cargo audit --file gui/Cargo.lock               # dependency advisories

# Fuzzing (needs a nightly toolchain and `cargo install cargo-fuzz`)
cd fuzz
cargo +nightly fuzz run parse_headers -- -max_len=512
cargo +nightly fuzz run v6_roundtrip  -- -max_len=300000
cargo +nightly fuzz run decrypt_file  -- -max_len=4096
```

CI runs the tests on Linux, Windows and macOS, and the audit and a short fuzz run on every push and weekly.
