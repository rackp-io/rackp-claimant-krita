#!/bin/sh
# Installs the RACKP Claimant add-on into Krita's pykrita directory (Linux / macOS).
set -e

SRC="$(cd "$(dirname "$0")" && pwd)"

case "$(uname -s)" in
    Darwin)
        PYKRITA="$HOME/Library/Application Support/krita/pykrita"
        ;;
    *)
        PYKRITA="${XDG_DATA_HOME:-$HOME/.local/share}/krita/pykrita"
        ;;
esac

echo "Install target: $PYKRITA"

mkdir -p "$PYKRITA"

# Copy the .desktop service file
cp -f "$SRC/rackp_claimant.desktop" "$PYKRITA/rackp_claimant.desktop"

# Copy the plugin package (overwrite)
rm -rf "$PYKRITA/rackp_claimant"
cp -R "$SRC/rackp_claimant" "$PYKRITA/rackp_claimant"

echo ""
echo "Installation complete. Please restart Krita."
echo "Then enable it: Settings - Python Plugin Manager - RACKP Claimant"
