#!/usr/bin/env bash
# Updates GitHub releases from the notes files in this folder.
# First line of a file = title, second line empty, rest = release body.
# Usage: apply.sh [tag ...]   (no arguments = every file)
set -euo pipefail
cd "$(dirname "$0")"

tags=("$@")
if [ ${#tags[@]} -eq 0 ]; then
  for f in *.md; do tags+=("${f%.md}"); done
fi

for tag in "${tags[@]}"; do
  file="$tag.md"
  [ -f "$file" ] || { echo "no notes file for $tag" >&2; exit 1; }
  title="$(head -n 1 "$file")"
  echo "Updating $tag: $title"
  gh release edit "$tag" --title "$title" --notes-file <(tail -n +3 "$file")
done
