#!/usr/bin/env bash
# Builds an Ubuntu package with cargo-deb, for the Ubuntu release it runs on:
#   dist/hushjar_<version>-1~ubuntu<release>_<arch>.deb
# Run it on (or in a container of) each release you want a package for; the
# release workflow does 24.04 and 26.04 on amd64 and arm64. Needs cargo-deb
# (cargo install cargo-deb) and the build libraries listed in
# .github/workflows/ci.yml.
set -euo pipefail
cd "$(dirname "$0")/.."
. /etc/os-release
[[ ${ID:-} == ubuntu ]] || { echo "Run this on Ubuntu (found ${ID:-unknown})" >&2; exit 1; }
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
deb_version="$version-1~ubuntu$VERSION_ID"
arch=$(dpkg --print-architecture)
mkdir -p dist
out="dist/hushjar_${deb_version}_$arch.deb"
cargo deb --locked -p hushjar --deb-version "$deb_version" --output "$out"
echo "$out"
