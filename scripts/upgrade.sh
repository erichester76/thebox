#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# TheBox — Upgrade / schema-migration script
# Run as root (or with sudo) on the TheBox host.
#
# Schema migrations
# -----------------
# Each *.sql file in config/postgres/migrations/ is a versioned, idempotent
# migration (numbered prefix: 0001_initial_schema.sql, 0002_…, …).
# A "schema_migrations" table in PostgreSQL records which versions have been
# applied; already-applied migrations are skipped so the script is safe to
# re-run at any time.
#
# To introduce a schema change:
#   1. Add a new file: config/postgres/migrations/NNNN_description.sql
#   2. Write idempotent SQL (ALTER TABLE … ADD COLUMN IF NOT EXISTS, etc.)
#   3. Re-run this script — only the new migration will be applied.
#
# Existing data is never modified or lost.
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

# ── Schema migrations ─────────────────────────────────────────────────────────
# Each *.sql file in config/postgres/migrations/ is a numbered, idempotent
# migration (e.g. 0001_initial_schema.sql, 0002_add_foo_column.sql).
# A schema_migrations table in PostgreSQL tracks which versions have already
# been applied so that each migration is only ever executed once.
# To add a new schema change, create the next numbered file and re-run this
# script; already-applied migrations are safely skipped.

echo "Running schema migrations…"

# Ensure the migration-tracking table exists (safe on both fresh and
# pre-migration installs; init.sql also creates it on new deployments).
# shellcheck disable=SC2086
$COMPOSE_CMD $COMPOSE_FILES exec -T postgres \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c \
  "CREATE TABLE IF NOT EXISTS schema_migrations (
       version    VARCHAR(16) NOT NULL PRIMARY KEY,
       applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
   );" > /dev/null

MIGRATIONS_DIR="$REPO_DIR/config/postgres/migrations"

# Collect migration files, sorted numerically.
mapfile -t MIGRATION_FILES < <(find "$MIGRATIONS_DIR" -maxdepth 1 -name '*.sql' | sort)

if [ "${#MIGRATION_FILES[@]}" -eq 0 ]; then
  echo "  No migration files found in $MIGRATIONS_DIR."
else
  for migration_file in "${MIGRATION_FILES[@]}"; do
    filename="$(basename "$migration_file")"
    # Version is the leading numeric prefix (e.g. "0001" from 0001_foo.sql).
    version="${filename%%_*}"

    # Validate version contains only digits so it can never be used to inject SQL.
    if [[ ! "$version" =~ ^[0-9]+$ ]]; then
      echo "  ⚠  Skipping $filename — version prefix '$version' must be all digits."
      continue
    fi

    # Check whether this version has already been recorded.
    # Trim whitespace from psql output before numeric comparison.
    # shellcheck disable=SC2086
    already_applied=$($COMPOSE_CMD $COMPOSE_FILES exec -T postgres \
      psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tAc \
      "SELECT COUNT(*) FROM schema_migrations WHERE version = '$version';" \
      | tr -d '[:space:]')

    if [ "$already_applied" -gt 0 ]; then
      echo "  ↷ $filename — already applied, skipping."
      continue
    fi

    echo "  ➜ Applying $filename…"
    # shellcheck disable=SC2086
    if $COMPOSE_CMD $COMPOSE_FILES exec -T postgres \
        psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
        < "$migration_file"; then
      # Record successful application.
      # shellcheck disable=SC2086
      $COMPOSE_CMD $COMPOSE_FILES exec -T postgres \
        psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c \
        "INSERT INTO schema_migrations (version) VALUES ('${version}')
             ON CONFLICT (version) DO NOTHING;" > /dev/null
      echo "    ✔ $filename applied."
    else
      echo "ERROR: Migration $filename failed — aborting."
      exit 1
    fi
  done
fi

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
echo
echo "To add a schema change in future:"
echo "  1. Create config/postgres/migrations/NNNN_description.sql"
echo "  2. Write idempotent SQL (ALTER TABLE … ADD COLUMN IF NOT EXISTS, etc.)"
echo "  3. Re-run scripts/upgrade.sh"
