#!/bin/bash
set -e

if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root."
   exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Mise à jour de NOVA X Tunnel (panel terminal)..."
cp "$SCRIPT_DIR/menu.sh" /usr/local/bin/menu
chmod +x /usr/local/bin/menu

# Falcon Proxy has been removed from the panel entirely - clean up any leftover files from
# a server that was updated before this removal, so nothing unused lingers on disk.
rm -rf /opt/novaxtunnel/falconproxy

echo "✅ Commande 'menu' mise à jour."
echo "(La configuration SSH existante n'est pas retouchée par une mise à jour."
echo " Pour la réappliquer, relancez install.sh à la place.)"
