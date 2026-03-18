#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TheBox — Initial setup script
# Run as root (or with sudo) on the host that will act as the gateway.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "╔══════════════════════════════════════════════╗"
echo "║       TheBox — Home Network Server Setup     ║"
echo "╚══════════════════════════════════════════════╝"
echo

# ── Prerequisite checks ──────────────────────────────────────────────────────
for cmd in docker docker-compose curl; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' is required but not installed."
    exit 1
  fi
done

# ── Create .env from example if missing ─────────────────────────────────────
if [ ! -f "$REPO_DIR/.env" ]; then
  echo "Creating .env from .env.example…"
  cp "$REPO_DIR/.env.example" "$REPO_DIR/.env"
  echo "  ⚠  Edit $REPO_DIR/.env and set strong passwords before continuing."
  echo "     Press ENTER when ready, or Ctrl-C to abort."
  read -r
fi

# ── Detect primary network interface ────────────────────────────────────────
IFACE=$(ip route | awk '/default/ {print $5; exit}')
GATEWAY=$(ip route | awk '/default/ {print $3; exit}')
echo "Detected primary interface: $IFACE  (gateway: $GATEWAY)"

# ── Enable IP forwarding (required for gateway / routing features) ───────────
echo "Enabling IP forwarding…"
sysctl -w net.ipv4.ip_forward=1
if ! grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf 2>/dev/null; then
  echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

# ── Build and start containers ───────────────────────────────────────────────
cd "$REPO_DIR"
echo "Building containers…"
docker compose build --pull

echo "Starting services…"
docker compose up -d

echo
echo "╔══════════════════════════════════════════════╗"
echo "║  TheBox is running!                          ║"
echo "║                                              ║"
echo "║  Dashboard  → http://$(hostname -I | awk '{print $1}'):3000   ║"
echo "║  Pi-hole    → http://$(hostname -I | awk '{print $1}'):8080   ║"
echo "╚══════════════════════════════════════════════╝"
echo
echo "Next steps:"
echo "  1. Open the dashboard and review quarantined devices."
echo "  2. Trust known-good devices, keep new unknowns in quarantine."
echo "  3. Mark IoT devices and configure their allow-lists."
echo "  4. Point your router's DNS to this host's IP address."
