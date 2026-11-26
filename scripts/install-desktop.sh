#!/usr/bin/env bash
# Installs Hushjar's desktop entry and icon for the current user, pointing at
# a built binary, so Linux desktops show its name and icon and match its
# window. Remove with: scripts/install-desktop.sh --uninstall
#
# Unlocking with system authentication also needs a polkit action, which only
# root can install. This script does not use sudo; it prints the command.
set -euo pipefail
cd "$(dirname "$0")/.."
id=io.github.lkarlslund.Hushjar
data=${XDG_DATA_HOME:-$HOME/.local/share}
apps=$data/applications
icons=$data/icons/hicolor/scalable/apps
polkit_actions=/usr/share/polkit-1/actions
if [[ ${1:-} == --uninstall ]]; then
    rm -f "$apps/$id.desktop" "$icons/$id.svg"
    echo "Removed $apps/$id.desktop and $icons/$id.svg"
    if [[ -e $polkit_actions/$id.policy ]]; then
        echo "To remove the polkit action for system authentication, run:"
        echo "  sudo rm $polkit_actions/$id.policy"
    fi
    exit 0
fi
binary=${1:-$PWD/target/release/hushjar}
[[ -x $binary ]] || { echo "Build first (cargo build --release) or pass the binary path" >&2; exit 1; }
mkdir -p "$apps" "$icons"
install -m 0644 "packaging/linux/$id.svg" "$icons/$id.svg"
sed "s|^Exec=hushjar$|Exec=$binary|" "packaging/linux/$id.desktop" > "$apps/$id.desktop"
chmod 0644 "$apps/$id.desktop"
command -v update-desktop-database >/dev/null && update-desktop-database "$apps" || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q "$data/icons/hicolor" 2>/dev/null || true
echo "Installed $apps/$id.desktop (runs $binary)"
if ! cmp -s "packaging/linux/$id.policy" "$polkit_actions/$id.policy"; then
    echo
    echo "To unlock with system authentication (polkit), install its action as root:"
    echo "  sudo install -m 0644 $PWD/packaging/linux/$id.policy $polkit_actions/$id.policy"
fi
