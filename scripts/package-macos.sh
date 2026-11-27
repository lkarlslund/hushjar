#!/usr/bin/env bash
# Builds a release and packs it as dist/hushjar-<version>-macos-<arch>.zip
# containing Hushjar.app. Run on a Mac (or a macOS CI runner). The app is
# signed ad hoc, so Gatekeeper asks for confirmation on first launch; real
# distribution needs a Developer ID signature and notarisation.
# Pass --no-build to pack an existing target/release build.
set -euo pipefail
cd "$(dirname "$0")/.."
# The release identity, r<commit count> (scripts/build-number); the release
# workflow sets it, local builds are marked -local.
export HUSHJAR_VERSION="${HUSHJAR_VERSION:-$(scripts/build-number local)}"
version=$HUSHJAR_VERSION
case $(uname -m) in
    x86_64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) arch=$(uname -m) ;;
esac
# Bundle versions must be numbers: 66 for r0066.
number=$(sed -n 's/^r0*\([0-9][0-9]*\).*/\1/p' <<<"$version")
app=dist/Hushjar.app

[[ ${1:-} == --no-build ]] || cargo build --release --locked -p hushjar
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
install -m 0755 target/release/hushjar "$app/Contents/MacOS/hushjar"
install -m 0644 packaging/macos/Hushjar.icns "$app/Contents/Resources/Hushjar.icns"
sed "s/@VERSION@/${number:-0}/g" packaging/macos/Info.plist > "$app/Contents/Info.plist"
codesign --force --sign - "$app"

zip=dist/hushjar-$version-macos-$arch.zip
rm -f "$zip"
# ditto keeps the bundle's metadata, which plain zip may not.
ditto -c -k --keepParent "$app" "$zip"
echo "$zip"
