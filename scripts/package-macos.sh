#!/usr/bin/env bash
# Builds a release and packs it as dist/Hushjar-<version>-macos-<arch>.zip
# containing Hushjar.app. Run on a Mac (or a macOS CI runner). The app is
# signed ad hoc, so Gatekeeper asks for confirmation on first launch; real
# distribution needs a Developer ID signature and notarisation.
# Pass --no-build to pack an existing target/release build.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
arch=$(uname -m)
app=dist/Hushjar.app

[[ ${1:-} == --no-build ]] || cargo build --release --locked -p hushjar
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
install -m 0755 target/release/hushjar "$app/Contents/MacOS/hushjar"
install -m 0644 packaging/macos/Hushjar.icns "$app/Contents/Resources/Hushjar.icns"
sed "s/@VERSION@/$version/g" packaging/macos/Info.plist > "$app/Contents/Info.plist"
codesign --force --sign - "$app"

zip=dist/Hushjar-$version-macos-$arch.zip
rm -f "$zip"
# ditto keeps the bundle's metadata, which plain zip may not.
ditto -c -k --keepParent "$app" "$zip"
echo "$zip"
