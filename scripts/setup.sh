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

configure_linux_dns_stub_listener() {
  local resolved_dropin_dir="/etc/systemd/resolved.conf.d"
  local resolved_dropin="$resolved_dropin_dir/thebox.conf"
  local current_resolv=""

  if [ "$OS" != "Linux" ]; then
    return
  fi

  if ! command -v systemctl &>/dev/null; then
    return
  fi

  if ! systemctl is-active --quiet systemd-resolved; then
    return
  fi

  echo "Disabling systemd-resolved DNS stub listener so Pi-hole can bind port 53…"
  mkdir -p "$resolved_dropin_dir"
  cat > "$resolved_dropin" <<'EOF'
[Resolve]
DNSStubListener=no
EOF

  current_resolv=$(readlink -f /etc/resolv.conf 2>/dev/null || true)
  if [ "$current_resolv" = "/run/systemd/resolve/stub-resolv.conf" ] \
    && [ -e /run/systemd/resolve/resolv.conf ]; then
    ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
  fi

  systemctl restart systemd-resolved

  if command -v ss &>/dev/null \
    && ss -lntup 2>/dev/null | grep -q '127\.0\.0\.53.*:53'; then
    echo "ERROR: systemd-resolved is still binding 127.0.0.53:53."
    echo "       Review $resolved_dropin and 'systemctl status systemd-resolved'."
    exit 1
  fi
}

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
  echo "  ℹ  macOS detected — using bridge networking with port mappings."
  echo "     The macOS overlay keeps all services on Docker's bridge network"
  echo "     so that container name resolution (postgres, redis) works correctly."
  echo "     No special Docker Desktop settings are required."
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

# ── Free host DNS port 53 for Pi-hole on Ubuntu/systemd-resolved hosts ─────
# systemd-resolved commonly binds 127.0.0.53:53 on Linux. Docker treats that
# as a host port 53 conflict, so Pi-hole cannot start until the stub listener
# is disabled and /etc/resolv.conf points at the non-stub resolver file.
configure_linux_dns_stub_listener

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

# ── Generate macOS honeypot port mappings from HONEYPOT_PORTS in .env ────────
# Reads HONEYPOT_PORTS from .env, skips port 22 (bound by macOS OpenSSH),
# and writes the per-port "host:container" entries to a generated overlay file
# that is included alongside docker-compose.macos.yml at startup.
generate_macos_ports() {
  local env_file="$REPO_DIR/.env"
  local ports_file="$REPO_DIR/docker-compose.macos.ports.yml"

  # Extract the value of HONEYPOT_PORTS from .env; fall back to defaults
  # (same as the default in services/honeypot/app.py) minus port 22.
  local honeypot_ports
  honeypot_ports=$(grep -E '^HONEYPOT_PORTS=' "$env_file" 2>/dev/null \
    | cut -d'=' -f2- | tr -d " \"'")
  honeypot_ports="${honeypot_ports:-21,23,25,80,110,143,443,445,3306,3389,8080}"

  echo "Generating macOS honeypot port mappings from HONEYPOT_PORTS…"

  # Write the YAML header.
  cat > "$ports_file" <<'YAML'
# Auto-generated by scripts/setup.sh — do not edit manually.
# Re-run setup.sh to regenerate based on HONEYPOT_PORTS in .env.
services:
  honeypot:
    ports:
YAML

  # Append one port-mapping entry per port, skipping port 22.
  local skipped=()
  IFS=',' read -ra PORT_LIST <<< "$honeypot_ports"
  for port in "${PORT_LIST[@]}"; do
    if [ "$port" = "22" ]; then
      skipped+=("$port")
    else
      printf '      - "%s:%s"\n' "$port" "$port" >> "$ports_file"
    fi
  done

  if [ "${#skipped[@]}" -gt 0 ]; then
    echo "  ⚠  Skipped port(s) reserved by macOS: ${skipped[*]}"
    echo "     (Port 22 is bound by macOS's built-in OpenSSH service.)"
  fi
}

# ── Select compose files ─────────────────────────────────────────────────────
# On Linux, overlay docker-compose.linux.yml which adds network_mode: host to
# discovery, guardian, and honeypot for full ARP scanning and iptables
# enforcement on the physical LAN.
# On macOS, overlay docker-compose.macos.yml which keeps services on the
# default bridge network (so Docker DNS resolves postgres/redis correctly)
# and exposes honeypot ports via explicit port mappings generated from .env.
if [ "$OS" = "Darwin" ] && [ -f "$REPO_DIR/docker-compose.macos.yml" ]; then
  generate_macos_ports
  COMPOSE_FILES="-f $REPO_DIR/docker-compose.yml -f $REPO_DIR/docker-compose.macos.yml -f $REPO_DIR/docker-compose.macos.ports.yml"
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
