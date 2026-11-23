# Flathub submission guide

This folder builds TimENC as a Flatpak **from source**, the way Flathub
requires (offline build, all Cargo crates vendored). The GUI is pure Rust
(`gui/`), so there is nothing to vendor but Cargo crates.

## Files

| File | Purpose |
|------|---------|
| `io.github.SnowTimSwiss.TimENC.yml` | The manifest (build-from-source). |
| `cargo-sources.json` | Vendored Cargo registry, generated from `gui/Cargo.lock`. |
| `../packaging/linux/io.github.SnowTimSwiss.TimENC.metainfo.xml` | AppStream metadata (required by Flathub; shared with the DEB/RPM/AppImage). |
| `../packaging/linux/io.github.SnowTimSwiss.TimENC.desktop` | Desktop entry (shared too). |

## What CI already does

`.github/workflows/flatpak.yml` builds this manifest from source on every push/PR
and validates the metainfo + desktop file. If that workflow is green, the Flatpak
builds correctly. **This is the proof Flathub reviewers want.**

## The one difference for the Flathub submission

The in-repo manifest uses a local source so CI can build the working tree:

```yaml
    sources:
      - type: dir
        path: ..
      - cargo-sources.json
```

Flathub requires a **pinned git source** instead. In the copy that goes to the
Flathub repo, replace that `type: dir` block with:

```yaml
    sources:
      - type: git
        url: https://github.com/SnowTimSwiss/TimENC.git
        tag: v3.3.0
        commit: <full-40-char-sha-of-the-v3.3.0-tag>
      - cargo-sources.json
```

Everything else stays identical.

## Submission steps

1. **Tag a release** on GitHub (e.g. `v3.3.0`) and note the commit SHA.
2. **Fork** https://github.com/flathub/flathub and create a branch named exactly
   `io.github.SnowTimSwiss.TimENC` (new-app submissions use a branch, not `master`).
3. Copy into the fork root:
   - `io.github.SnowTimSwiss.TimENC.yml` (with the git source from above)
   - `cargo-sources.json`
   - The metainfo and desktop files are installed from the checked-out source
     (`packaging/linux/...`), so they need not be copied. With a git source the
     repository is checked out under the build dir and those paths resolve.
4. **Open a PR** against `flathub/flathub`. The Flathub buildbot will build it.
5. Address reviewer comments (see below), then it gets merged and published.

## Regenerating cargo-sources.json

Any time `gui/Cargo.lock` changes (new/updated dependency):

```sh
python3 flatpak/generate-cargo-sources.py gui/Cargo.lock flatpak/cargo-sources.json > /tmp/sources.json
mv /tmp/sources.json flatpak/cargo-sources.json
```

The script covers registry-only lockfiles, which is all this project has, and
CI fails if the committed file does not match the lockfile. If a git dependency
is ever added it refuses to run; use `flatpak-cargo-generator.py` from
https://github.com/flatpak/flatpak-builder-tools/tree/master/cargo then.

## Likely reviewer questions

- **`--filesystem=home`**: justified because encryption reads the input, writes
  the `.timenc` output beside it, and securely deletes the original — sibling-file
  operations the file-chooser portal does not cover. Be ready to explain this; if
  reviewers insist, the fallback is `--filesystem=home` → document the rationale in
  the PR description.
- **Network**: the app needs none at runtime, and the build is offline. Good.
- **Runtime version**: `org.freedesktop.Platform//25.08`. The GUI draws itself
  with OpenGL and needs no toolkit, so the small freedesktop runtime is enough.
  Bump it as new versions come out; old runtimes get end-of-lifed.

## Local test on a Linux box (before submitting)

```sh
flatpak install -y flathub org.freedesktop.Platform//25.08 org.freedesktop.Sdk//25.08 \
  org.freedesktop.Sdk.Extension.rust-stable//25.08
flatpak-builder --user --force-clean --install build-dir \
  flatpak/io.github.SnowTimSwiss.TimENC.yml
flatpak run io.github.SnowTimSwiss.TimENC
```
