#!/bin/sh
# WebKitGTK often renders a blank window inside the Flatpak sandbox unless the
# DMABUF renderer is disabled. Remove this if rendering works without it.
export WEBKIT_DISABLE_DMABUF_RENDERER=1
exec /app/bin/timenc-bin "$@"
