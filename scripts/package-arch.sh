#!/usr/bin/env bash
# Builds the Arch Linux package from the working tree's committed state:
#   dist/hushjar-<version>-1-<arch>.pkg.tar.zst
# It packs HEAD the way GitHub packs a release tag, then runs makepkg on
# packaging/arch/PKGBUILD. Run on Arch (or in an archlinux container) as a
# normal user with base-devel and cargo (rust or rustup) installed.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)
grep -q "^pkgver=$version$" packaging/arch/PKGBUILD ||
    { echo "packaging/arch/PKGBUILD pkgver does not match Cargo.toml ($version)" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp packaging/arch/PKGBUILD "$work/"
git archive --format=tar.gz --prefix="hushjar-$version/" -o "$work/hushjar-$version.tar.gz" HEAD
(cd "$work" && PKGDEST="$work/out" makepkg --noconfirm --cleanbuild)
mkdir -p dist
cp "$work"/out/*.pkg.tar.zst dist/
ls dist/*.pkg.tar.zst
