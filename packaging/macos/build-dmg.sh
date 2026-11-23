#!/usr/bin/env bash
# Builds TimENC.app and TimENC_<version>_<arch>.dmg from an already built GUI
# binary (gui/target/release/timenc-gui). Run on macOS.
#
# Usage: packaging/macos/build-dmg.sh <version> [output dir]
set -euo pipefail

version="$1"
out="${2:-.}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
arch="$(uname -m)"
[ "$arch" = arm64 ] && arch=aarch64  # the name earlier releases used
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

app="$work/dmg/TimENC.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$root/gui/target/release/timenc-gui" "$app/Contents/MacOS/TimENC"
cp "$root/packaging/icons/icon.icns" "$app/Contents/Resources/icon.icns"
sed "s/@VERSION@/$version/g" "$root/packaging/macos/Info.plist" > "$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist"
# Ad-hoc signature: Apple Silicon refuses to run unsigned code at all.
codesign --force --deep --sign - "$app"

ln -s /Applications "$work/dmg/Applications"
mkdir -p "$out"
hdiutil create -volname TimENC -srcfolder "$work/dmg" -ov -format UDZO \
    "$out/TimENC_${version}_${arch}.dmg"
