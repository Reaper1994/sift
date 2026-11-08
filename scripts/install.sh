#!/usr/bin/env bash
# Installs Sift on macOS or Linux. Run from the folder containing the sift binary:
#   bash install.sh
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/share/sift}"
HERE="$(cd "$(dirname "$0")" && pwd)"

[[ -x "$HERE/sift" ]] || { echo "sift binary not found next to this script" >&2; exit 1; }

mkdir -p "$INSTALL_DIR"
install -m 0755 "$HERE/sift" "$INSTALL_DIR/sift"

if [[ ! -f "$INSTALL_DIR/sift.env" ]]; then
  cp "$HERE/sift.env.example" "$INSTALL_DIR/sift.env"
  echo "Created $INSTALL_DIR/sift.env — fill in your settings and Jev key."
fi
chmod 600 "$INSTALL_DIR/sift.env"   # secrets: owner only

# macOS: Gatekeeper blocks unsigned downloads; clear the quarantine flag.
if [[ "$(uname)" == "Darwin" ]]; then
  xattr -d com.apple.quarantine "$INSTALL_DIR/sift" 2>/dev/null || true
fi

echo
echo "Installed to $INSTALL_DIR"
echo "Next: edit sift.env, then test with:  cd \"$INSTALL_DIR\" && ./sift"
echo "Run it in the background: see README → 'Keep it running'."
