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

# Safely update HAProxy config if HAProxy is active, leaving Nginx completely untouched
if command -v haproxy &>/dev/null && systemctl is-active --quiet haproxy 2>/dev/null; then
    echo "🔄 Actualisation de la configuration HAProxy (Nginx inchangé)..."
    /usr/local/bin/menu --exec update_haproxy_only || true
fi

# Falcon Proxy has been removed from the panel entirely - clean up any leftover files from
# a server that was updated before this removal, so nothing unused lingers on disk.
rm -rf "$SCRIPT_DIR/falconproxy" /opt/nova-x-tunnel/falconproxy /opt/novaxtunnel/falconproxy 2>/dev/null || true

echo "✅ Commande 'menu' et services mis à jour sans modifier la configuration Nginx."
echo "(La configuration SSH existante et vos règles Nginx personnalisées ne sont pas retouchées par la mise à jour.)"
