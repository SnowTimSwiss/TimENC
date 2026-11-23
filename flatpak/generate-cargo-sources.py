#!/usr/bin/env python3
"""Generates flatpak/cargo-sources.json from gui/Cargo.lock.

Usage: generate-cargo-sources.py <Cargo.lock> <existing cargo-sources.json>

Writes the new file to stdout. Every crates.io package in the lockfile becomes
an archive source plus the .cargo-checksum.json that cargo expects in a vendored
directory; the final `cargo/config` entry (which points cargo at the vendor
directory) is carried over from the existing file unchanged.

This replaces flatpak-cargo-generator.py for the registry-only dependency set
this project has. It refuses to run if the lockfile contains git dependencies,
which would need the full generator.
"""
import json
import sys
import tomllib


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2

    with open(sys.argv[1], "rb") as handle:
        lock = tomllib.load(handle)

    sources = []
    for package in lock["package"]:
        source = package.get("source")
        if source is None:  # workspace member / path dependency
            continue
        if not source.startswith("registry+"):
            sys.exit(f"{package['name']}: unsupported source {source!r}; use flatpak-cargo-generator.py")

        name, version, checksum = package["name"], package["version"], package["checksum"]
        dest = f"cargo/vendor/{name}-{version}"
        sources.append({
            "type": "archive",
            "archive-type": "tar-gzip",
            "url": f"https://static.crates.io/crates/{name}/{name}-{version}.crate",
            "sha256": checksum,
            "dest": dest,
        })
        sources.append({
            "type": "inline",
            "contents": json.dumps({"package": checksum, "files": {}}),
            "dest": dest,
            "dest-filename": ".cargo-checksum.json",
        })

    with open(sys.argv[2]) as handle:
        config_entry = json.load(handle)[-1]
    if config_entry.get("dest") != "cargo" or config_entry.get("type") != "inline":
        sys.exit("the last entry of the existing file is not the cargo config; refusing to guess")
    sources.append(config_entry)

    sys.stdout.write(json.dumps(sources, indent=4))
    return 0


if __name__ == "__main__":
    sys.exit(main())
