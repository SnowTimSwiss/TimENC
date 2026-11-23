#!/usr/bin/env bash
# Builds TimENC_<version>_amd64.AppImage from an already built GUI binary.
#
# Usage: packaging/linux/build-appimage.sh <version> [output dir]
# Expects gui/target/release/timenc-gui. Nothing is bundled besides the
# binary: OpenGL, X11, Wayland and xkbcommon come from the host, as every
# desktop has them and they have to match its graphics driver anyway.
set -euo pipefail

version="$1"
out="${2:-.}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Pinned, and checked, so a changed download cannot slip into a release.
tool_url="https://github.com/AppImage/appimagetool/releases/download/1.9.0/appimagetool-x86_64.AppImage"
tool_sha256="46fdd785094c7f6e545b61afcfb0f3d98d8eab243f644b4b17698c01d06083d1"

app="$work/TimENC.AppDir"
id="io.github.SnowTimSwiss.TimENC"
install -Dm755 "$root/gui/target/release/timenc-gui" "$app/usr/bin/timenc-gui"
install -Dm644 "$root/packaging/linux/$id.desktop" "$app/usr/share/applications/$id.desktop"
install -Dm644 "$root/packaging/linux/$id.metainfo.xml" "$app/usr/share/metainfo/$id.appdata.xml"
install -Dm644 "$root/packaging/icons/128x128@2x.png" "$app/usr/share/icons/hicolor/256x256/apps/$id.png"
ln -s "usr/share/applications/$id.desktop" "$app/$id.desktop"
ln -s "usr/share/icons/hicolor/256x256/apps/$id.png" "$app/$id.png"
ln -s "$id.png" "$app/.DirIcon"
ln -s usr/bin/timenc-gui "$app/AppRun"

curl -fsSL -o "$work/appimagetool" "$tool_url"
echo "$tool_sha256  $work/appimagetool" | sha256sum -c --quiet
chmod +x "$work/appimagetool"

mkdir -p "$out"
# --appimage-extract-and-run: works without FUSE (CI runners, containers).
ARCH=x86_64 "$work/appimagetool" --appimage-extract-and-run --no-appstream \
    "$app" "$out/TimENC_${version}_amd64.AppImage"
