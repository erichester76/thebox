#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TheBox — Initial setup script
# Run as root (or with sudo) on the host that will act as the gateway.
# Supports Linux and macOS (Docker Desktop).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OS="$(uname -s)"

echo "╔══════════════════════════════════════════════╗"
echo "║       TheBox — Home Network Server Setup     ║"
echo "╚══════════════════════════════════════════════╝"
echo

# ── Prerequisite checks ──────────────────────────────────────────────────────
# docker compose v2 (plugin) is preferred; fall back to docker-compose v1.
if docker compose version &>/dev/null; then
  COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
  COMPOSE_CMD="docker-compose"
else
  echo "ERROR: Neither 'docker compose' (plugin) nor 'docker-compose' is available."
  exit 1
fi

for cmd in docker curl; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' is required but not installed."
    exit 1
  fi
done

# ── macOS-specific prerequisite hint ────────────────────────────────────────
if [ "$OS" = "Darwin" ]; then
  echo "  ℹ  macOS detected — using Docker Desktop networking."
  echo "     ARP-based LAN scanning requires the host to be on the same L2"
  echo "     segment as the devices.  On macOS, Docker Desktop runs inside a"
  echo "     Linux VM so network scanning will be limited to Docker-internal"
  echo "     traffic.  All other services (dashboard, Pi-hole, honeypot, etc.)"
  echo "     will work normally."
  echo
fi

# ── Create .env from example if missing ─────────────────────────────────────
if [ ! -f "$REPO_DIR/.env" ]; then
  echo "Creating .env from .env.example…"
  cp "$REPO_DIR/.env.example" "$REPO_DIR/.env"
  echo "  ⚠  Edit $REPO_DIR/.env and set strong passwords before continuing."
  echo "     Press ENTER when ready, or Ctrl-C to abort."
  read -r
fi

# ── Detect primary network interface ────────────────────────────────────────
if [ "$OS" = "Darwin" ]; then
  IFACE=$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')
  GATEWAY=$(route -n get default 2>/dev/null | awk '/gateway:/ {print $2}')
else
  IFACE=$(ip route 2>/dev/null | awk '/default/ {print $5; exit}')
  GATEWAY=$(ip route 2>/dev/null | awk '/default/ {print $3; exit}')
fi
echo "Detected primary interface: ${IFACE:-unknown}  (gateway: ${GATEWAY:-unknown})"

# ── Enable IP forwarding (required for gateway / routing features) ───────────
echo "Enabling IP forwarding…"
if [ "$OS" = "Darwin" ]; then
  sysctl -w net.inet.ip.forwarding=1
  if ! grep -q "^net.inet.ip.forwarding" /etc/sysctl.conf 2>/dev/null; then
    echo "net.inet.ip.forwarding=1" >> /etc/sysctl.conf
  fi
else
  sysctl -w net.ipv4.ip_forward=1
  if ! grep -q "^net.ipv4.ip_forward" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  fi
fi

# ── Resolve the host IP for the summary banner ──────────────────────────────
if [ "$OS" = "Darwin" ]; then
  if [ -n "${IFACE:-}" ]; then
    HOST_IP=$(ipconfig getifaddr "$IFACE" 2>/dev/null || true)
  fi
  HOST_IP="${HOST_IP:-127.0.0.1}"
else
  HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
  HOST_IP="${HOST_IP:-127.0.0.1}"
fi

# ── Select compose files ─────────────────────────────────────────────────────
# On Linux, overlay docker-compose.linux.yml which adds network_mode: host to
# discovery, guardian, and honeypot for full ARP scanning and iptables
# enforcement on the physical LAN.
# On macOS, overlay docker-compose.macos.yml which adds explicit port mappings
# for the honeypot so its listener ports are reachable from the Mac host.
if [ "$OS" = "Darwin" ] && [ -f "$REPO_DIR/docker-compose.macos.yml" ]; then
  COMPOSE_FILES="-f $REPO_DIR/docker-compose.yml -f $REPO_DIR/docker-compose.macos.yml"
elif [ "$OS" = "Linux" ] && [ -f "$REPO_DIR/docker-compose.linux.yml" ]; then
  COMPOSE_FILES="-f $REPO_DIR/docker-compose.yml -f $REPO_DIR/docker-compose.linux.yml"
else
  COMPOSE_FILES="-f $REPO_DIR/docker-compose.yml"
fi

# ── Build and start containers ───────────────────────────────────────────────
cd "$REPO_DIR"
echo "Building containers…"
# shellcheck disable=SC2086
$COMPOSE_CMD $COMPOSE_FILES build --pull

echo "Starting services…"
# shellcheck disable=SC2086
$COMPOSE_CMD $COMPOSE_FILES up -d

echo
echo "╔══════════════════════════════════════════════╗"
echo "║  TheBox is running!                          ║"
echo "║                                              ║"
echo "║  Dashboard  → http://${HOST_IP}:3000   ║"
echo "║  Pi-hole    → http://${HOST_IP}:8080   ║"
echo "╚══════════════════════════════════════════════╝"
echo
echo "Next steps:"
echo "  1. Open the dashboard and review quarantined devices."
echo "  2. Trust known-good devices, keep new unknowns in quarantine."
echo "  3. Mark IoT devices and configure their allow-lists."
echo "  4. Point your router's DNS to this host's IP address."
