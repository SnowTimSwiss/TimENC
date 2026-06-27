# Flathub submission guide

This folder builds TimENC as a Flatpak **from source**, the way Flathub
requires (offline build, all Cargo crates vendored). The static HTML frontend is
embedded by `tauri-build`, so there is **no Node/npm vendoring** — only Cargo.

## Files

| File | Purpose |
|------|---------|
| `io.github.SnowTimSwiss.TimENC.yml` | The manifest (build-from-source). |
| `cargo-sources.json` | Vendored Cargo registry, generated from `src-tauri/Cargo.lock`. |
| `io.github.SnowTimSwiss.TimENC.metainfo.xml` | AppStream metadata (required by Flathub). |
| `io.github.SnowTimSwiss.TimENC.desktop` | Desktop entry. |
| `timenc-wrapper.sh` | Sets `WEBKIT_DISABLE_DMABUF_RENDERER=1` so WebKitGTK renders inside the sandbox. |

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
        tag: v2.2.1
        commit: <full-40-char-sha-of-the-v2.2.1-tag>
      - cargo-sources.json
```

Everything else stays identical.

## Submission steps

1. **Tag a release** on GitHub (e.g. `v2.2.1`) and note the commit SHA.
2. **Fork** https://github.com/flathub/flathub and create a branch named exactly
   `io.github.SnowTimSwiss.TimENC` (new-app submissions use a branch, not `master`).
3. Copy into the fork root:
   - `io.github.SnowTimSwiss.TimENC.yml` (with the git source from above)
   - `cargo-sources.json`
   - `io.github.SnowTimSwiss.TimENC.metainfo.xml`
   - `io.github.SnowTimSwiss.TimENC.desktop`
   - `timenc-wrapper.sh`
   - Adjust the manifest's relative install paths (`flatpak/...`, `src-tauri/...`)
     if needed — with a git source the repo is checked out under the build dir, so
     `src-tauri/...` and `flatpak/...` paths still resolve. Keep them as-is.
4. **Open a PR** against `flathub/flathub`. The Flathub buildbot will build it.
5. Address reviewer comments (see below), then it gets merged and published.

## Regenerating cargo-sources.json

Any time `src-tauri/Cargo.lock` changes (new/updated dependency):

```sh
pip install aiohttp toml tomlkit
python flatpak-cargo-generator.py src-tauri/Cargo.lock -o flatpak/cargo-sources.json
```

Get the generator from
https://github.com/flatpak/flatpak-builder-tools/tree/master/cargo .

## Likely reviewer questions

- **`--filesystem=home`**: justified because encryption reads the input, writes
  the `.timenc` output beside it, and securely deletes the original — sibling-file
  operations the file-chooser portal does not cover. Be ready to explain this; if
  reviewers insist, the fallback is `--filesystem=home` → document the rationale in
  the PR description.
- **Network**: the app needs none at runtime, and the build is offline. Good.
- **Runtime version**: `org.gnome.Platform//48` provides WebKitGTK 4.1 + libsoup3
  that Tauri needs. Bump the runtime version as GNOME releases; old runtimes get
  end-of-lifed.

## Local test on a Linux box (before submitting)

```sh
flatpak install -y flathub org.gnome.Platform//48 org.gnome.Sdk//48 \
  org.freedesktop.Sdk.Extension.rust-stable//24.08
flatpak-builder --user --force-clean --install build-dir \
  flatpak/io.github.SnowTimSwiss.TimENC.yml
flatpak run io.github.SnowTimSwiss.TimENC
```
