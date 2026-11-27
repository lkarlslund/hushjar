#!/usr/bin/env bash
# Prepares the Docker image the Arch package is built in, for the machine's
# architecture, tagged hushjar-arch-build: the official archlinux:base-devel
# on x86_64, and on aarch64 the Arch Linux ARM root filesystem. That one is
# only served over plain HTTP, so its signature is checked against the Arch
# Linux ARM build key kept in packaging/arch/archlinuxarm.asc
# (68B3537F39A313B3E574D06777193F152BDBE6A6).
set -euo pipefail
cd "$(dirname "$0")/.."
case "$(uname -m)" in
    x86_64)
        docker pull archlinux:base-devel
        docker tag archlinux:base-devel hushjar-arch-build
        ;;
    aarch64)
        work=$(mktemp -d)
        trap 'rm -rf "$work"' EXIT
        url=http://os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz
        curl -fsSL --retry 3 -o "$work/rootfs.tar.gz" "$url"
        curl -fsSL --retry 3 -o "$work/rootfs.tar.gz.sig" "$url.sig"
        gpg --dearmor <packaging/arch/archlinuxarm.asc >"$work/key.gpg"
        gpgv --keyring "$work/key.gpg" "$work/rootfs.tar.gz.sig" "$work/rootfs.tar.gz"
        docker import "$work/rootfs.tar.gz" hushjar-arch-build
        ;;
    *)
        echo "No Arch image for $(uname -m)" >&2
        exit 1
        ;;
esac
