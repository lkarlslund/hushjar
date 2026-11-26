#!/usr/bin/env bash
# Builds a release and packs it as dist/hushjar-<version>-linux-<arch>.tar.gz,
# laid out like a prefix so it installs with
#   tar -xzf <file> --strip-components=1 -C /usr/local
# or into ~/.local. Pass --no-build to pack an existing target/release build.
set -euo pipefail
cd "$(dirname "$0")/.."
id=io.github.lkarlslund.Hushjar
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
arch=$(uname -m)
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
