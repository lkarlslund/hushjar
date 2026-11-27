#!/usr/bin/env bash
# Builds an Ubuntu package with cargo-deb, for the Ubuntu release it runs on:
#   dist/hushjar-<version>-ubuntu<release>-<arch>.deb
# whose package version is the number in <version> (66 for r0066).
# Run it on (or in a container of) each release you want a package for; the
# release workflow does 24.04 and 26.04 on amd64 and arm64. Needs cargo-deb
# (cargo install cargo-deb) and the build libraries listed in
# .github/workflows/ci.yml.
set -euo pipefail
cd "$(dirname "$0")/.."
. /etc/os-release
[[ ${ID:-} == ubuntu ]] || { echo "Run this on Ubuntu (found ${ID:-unknown})" >&2; exit 1; }
# The release identity, r<commit count> (scripts/build-number); the release
# workflow sets it, local builds are marked -local.
export HUSHJAR_VERSION="${HUSHJAR_VERSION:-$(scripts/build-number local)}"
version=$HUSHJAR_VERSION
# Debian versions must start with a digit: 66 for r0066.
number=$(sed -n 's/^r0*\([0-9][0-9]*\).*/\1/p' <<<"$version")
deb_version="${number:-0}-1~ubuntu$VERSION_ID"
arch=$(dpkg --print-architecture)
mkdir -p dist
out="dist/hushjar-$version-ubuntu$VERSION_ID-$arch.deb"
cargo deb --locked -p hushjar --deb-version "$deb_version" --output "$out"
echo "$out"
