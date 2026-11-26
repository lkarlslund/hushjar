#!/usr/bin/env bash
# Regenerates the Windows .ico and the macOS .icns from the Linux SVG icon.
# The results are committed, so builds do not need this; run it after the
# SVG changes. Needs rsvg-convert and ImageMagick.
set -euo pipefail
cd "$(dirname "$0")/.."
svg=packaging/linux/io.github.lkarlslund.Hushjar.svg
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for size in 16 24 32 48 64 128 256 512; do
    rsvg-convert -w "$size" -h "$size" "$svg" -o "$tmp/$size.png"
done

# Windows: the sizes Explorer, the taskbar and the title bar ask for.
magick "$tmp/16.png" "$tmp/24.png" "$tmp/32.png" "$tmp/48.png" "$tmp/256.png" \
    packaging/windows/hushjar.ico

# macOS: an .icns is a header followed by PNG entries (type, length, data).
# Written here so that no Mac is needed; `iconutil` would do the same.
python3 - "$tmp" packaging/macos/Hushjar.icns <<'PY'
import struct, sys
tmp, out = sys.argv[1:]
entries = [("icp4", 16), ("icp5", 32), ("icp6", 64), ("ic07", 128), ("ic08", 256), ("ic09", 512)]
body = b""
for kind, size in entries:
    data = open(f"{tmp}/{size}.png", "rb").read()
    body += kind.encode() + struct.pack(">I", len(data) + 8) + data
open(out, "wb").write(b"icns" + struct.pack(">I", len(body) + 8) + body)
PY
echo "Wrote packaging/windows/hushjar.ico and packaging/macos/Hushjar.icns"
