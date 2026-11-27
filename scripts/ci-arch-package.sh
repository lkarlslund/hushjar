#!/usr/bin/env bash
# Builds the Arch package in a fresh Arch Linux or Arch Linux ARM container
# (scripts/ci-arch-image.sh), run as root with the repository as the current
# directory: installs the build dependencies, then runs
# scripts/package-arch.sh as an ordinary user, since makepkg refuses root.
# Passes HUSHJAR_VERSION on when it is set.
set -euo pipefail
if [[ $(uname -m) == aarch64 ]]; then
    # The Arch Linux ARM root filesystem comes without an initialised
    # keyring, and with a kernel and firmware a container has no use for.
    # Docker does not allow the Landlock filesystem sandbox pacman downloads
    # in; the official archlinux image switches it off the same way.
    grep -q '^DisableSandboxFilesystem' /etc/pacman.conf ||
        sed -i '/^\[options\]/a DisableSandboxFilesystem' /etc/pacman.conf
    pacman-key --init
    pacman-key --populate archlinuxarm
    mapfile -t kernel < <(pacman -Qq | grep -E '^linux-(aarch64|firmware)' || true)
    if ((${#kernel[@]})); then
        pacman -Rdd --noconfirm "${kernel[@]}"
    fi
fi
pacman -Syu --noconfirm --needed base-devel git rust fontconfig systemd-libs \
    wayland libglvnd libxkbcommon libxkbcommon-x11 libx11 libxcb \
    libxcursor libxi libxrender dbus hicolor-icon-theme
id builder >/dev/null 2>&1 || useradd -m builder
chown -R builder: .
# su starts a clean environment, so the version is passed on.
su builder -c "git config --global --add safe.directory '$PWD' && HUSHJAR_VERSION='${HUSHJAR_VERSION:-}' scripts/package-arch.sh"
