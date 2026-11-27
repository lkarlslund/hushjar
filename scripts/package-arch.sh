#!/usr/bin/env bash
# Builds the Arch Linux package from the working tree's committed state:
#   dist/hushjar-<version>-1-<arch>.pkg.tar.zst
# with <version> as pkgver (hyphens become underscores).
# It packs HEAD the way GitHub packs a release tag, then runs makepkg on
# packaging/arch/PKGBUILD. Run on Arch (or in an archlinux container) as a
# normal user with base-devel and cargo (rust or rustup) installed.
set -euo pipefail
cd "$(dirname "$0")/.."
# The release identity, r<commit count> (scripts/build-number); the release
# workflow sets it, local builds are marked -local.
export HUSHJAR_VERSION="${HUSHJAR_VERSION:-$(scripts/build-number local)}"
version=$HUSHJAR_VERSION
# pkgver may not contain hyphens.
pkgver=${version//-/_}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
sed "s/^pkgver=.*/pkgver=$pkgver/" packaging/arch/PKGBUILD >"$work/PKGBUILD"
git archive --format=tar.gz --prefix="hushjar-$pkgver/" -o "$work/hushjar-$pkgver.tar.gz" HEAD
# PKGEXT: Arch Linux ARM's makepkg.conf would make .pkg.tar.xz.
(cd "$work" && PKGDEST="$work/out" PKGEXT=.pkg.tar.zst makepkg --noconfirm --cleanbuild)
mkdir -p dist
cp "$work"/out/*.pkg.tar.zst dist/
ls dist/*.pkg.tar.zst
