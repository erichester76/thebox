#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TheBox — Upgrade script
# Run as root (or with sudo) on the TheBox host.
# Re-applies config/postgres/init.sql against the running database so that
# any tables or indexes added since the initial install are created, then
# rebuilds and restarts all services to pick up code changes.
#
# All schema statements use CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT
# EXISTS, so existing data is never modified or lost.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OS="$(uname -s)"

echo "╔══════════════════════════════════════════════╗"
echo "║       TheBox — Upgrade                       ║"
echo "╚══════════════════════════════════════════════╝"
echo

# ── Prerequisite checks ──────────────────────────────────────────────────────
if docker compose version &>/dev/null; then
  COMPOSE_CMD="docker compose"
elif command -v docker-compose &>/dev/null; then
  COMPOSE_CMD="docker-compose"
else
  echo "ERROR: Neither 'docker compose' (plugin) nor 'docker-compose' is available."
  exit 1
fi

for cmd in docker; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' is required but not installed."
    exit 1
  fi
done

# ── Require .env ─────────────────────────────────────────────────────────────
if [ ! -f "$REPO_DIR/.env" ]; then
  echo "ERROR: $REPO_DIR/.env not found."
  echo "       Run scripts/setup.sh first, or copy .env.example and configure it."
  exit 1
fi

# Load .env so we can resolve POSTGRES_USER / POSTGRES_DB for the psql call.
# shellcheck disable=SC1091
set -a
# shellcheck source=/dev/null
source "$REPO_DIR/.env"
set +a

POSTGRES_USER="${POSTGRES_USER:-thebox}"
POSTGRES_DB="${POSTGRES_DB:-thebox}"

# ── Select compose files (same logic as setup.sh) ────────────────────────────
if [ "$OS" = "Darwin" ] && [ -f "$REPO_DIR/docker-compose.macos.yml" ]; then
  if [ ! -f "$REPO_DIR/docker-compose.macos.ports.yml" ]; then
    echo "  ⚠  docker-compose.macos.ports.yml not found — run scripts/setup.sh once to generate it."
    COMPOSE_FILES="-f $REPO_DIR/docker-compose.yml -f $REPO_DIR/docker-compose.macos.yml"
  else
    COMPOSE_FILES="-f $REPO_DIR/docker-compose.yml -f $REPO_DIR/docker-compose.macos.yml -f $REPO_DIR/docker-compose.macos.ports.yml"
  fi
elif [ "$OS" = "Linux" ] && [ -f "$REPO_DIR/docker-compose.linux.yml" ]; then
  COMPOSE_FILES="-f $REPO_DIR/docker-compose.yml -f $REPO_DIR/docker-compose.linux.yml"
else
  COMPOSE_FILES="-f $REPO_DIR/docker-compose.yml"
fi

cd "$REPO_DIR"

# ── Ensure postgres is running and ready ─────────────────────────────────────
echo "Ensuring postgres is running…"
# shellcheck disable=SC2086
$COMPOSE_CMD $COMPOSE_FILES up -d postgres
echo "  Waiting for postgres to be ready…"
for i in $(seq 1 30); do
  # shellcheck disable=SC2086
  if $COMPOSE_CMD $COMPOSE_FILES exec -T postgres \
      pg_isready -U "$POSTGRES_USER" &>/dev/null; then
    echo "  postgres is ready."
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "ERROR: postgres did not become ready in time."
    exit 1
  fi
  sleep 2
done

# ── Re-apply init.sql ─────────────────────────────────────────────────────────
echo "Applying schema migrations from config/postgres/init.sql…"
# shellcheck disable=SC2086
$COMPOSE_CMD $COMPOSE_FILES exec -T postgres \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  < "$REPO_DIR/config/postgres/init.sql"
echo "  ✔ Schema is up to date."
echo

# ── Rebuild and restart services ─────────────────────────────────────────────
echo "Pulling latest base images and rebuilding services…"
# shellcheck disable=SC2086
$COMPOSE_CMD $COMPOSE_FILES build --pull

echo "Restarting services…"
# shellcheck disable=SC2086
$COMPOSE_CMD $COMPOSE_FILES up -d

echo
echo "╔══════════════════════════════════════════════╗"
echo "║  Upgrade complete!                           ║"
echo "╚══════════════════════════════════════════════╝"
echo
echo "Check the logs with:"
echo "  docker compose logs -f"
