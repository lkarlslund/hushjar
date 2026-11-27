#!/usr/bin/env bash
# Builds a release and packs it as dist/hushjar-<version>-linux-<arch>.tar.gz (amd64 or arm64),
# laid out like a prefix so it installs with
#   tar -xzf <file> --strip-components=1 -C /usr/local
# or into ~/.local. Pass --no-build to pack an existing target/release build.
set -euo pipefail
cd "$(dirname "$0")/.."
id=io.github.lkarlslund.Hushjar
# The release identity, r<commit count> (scripts/build-number); the release
# workflow sets it, local builds are marked -local.
export HUSHJAR_VERSION="${HUSHJAR_VERSION:-$(scripts/build-number local)}"
version=$HUSHJAR_VERSION
case $(uname -m) in
    x86_64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) arch=$(uname -m) ;;
esac
name=hushjar-$version-linux-$arch

[[ ${1:-} == --no-build ]] || cargo build --release --locked -p hushjar
stage=dist/$name
rm -rf "$stage"
install -Dm0755 target/release/hushjar "$stage/bin/hushjar"
install -Dm0644 "packaging/linux/$id.desktop" "$stage/share/applications/$id.desktop"
install -Dm0644 "packaging/linux/$id.svg" "$stage/share/icons/hicolor/scalable/apps/$id.svg"
install -Dm0644 README.md "$stage/share/doc/hushjar/README.md"
tar -C dist -czf "dist/$name.tar.gz" "$name"
rm -rf "$stage"
echo "dist/$name.tar.gz"
