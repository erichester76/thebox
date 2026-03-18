-- Migration 0002 — IoT learning methodology
-- Adds the iot_learning_sessions table to track per-device learning periods,
-- and relaxes the NOT NULL constraint on iot_allowlist.device_id so that
-- globally-shared IoT whitelist entries (device_id IS NULL) can be stored
-- alongside per-device entries.

-- IoT learning sessions: one active session per device during the 48-hour
-- observation period.  A UNIQUE constraint on device_id means a device can
-- only be in one learning session at a time; upsert logic in the discovery
-- service will reset the session if the device is re-discovered.
CREATE TABLE IF NOT EXISTS iot_learning_sessions (
    id                    SERIAL PRIMARY KEY,
    device_id             INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    pihole_group_name     VARCHAR(64) NOT NULL,
    learning_started_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    learning_completed_at TIMESTAMPTZ,
    status                VARCHAR(32) NOT NULL DEFAULT 'active',
    UNIQUE(device_id)
);

CREATE INDEX IF NOT EXISTS idx_iot_learning_status  ON iot_learning_sessions(status);
CREATE INDEX IF NOT EXISTS idx_iot_learning_started ON iot_learning_sessions(learning_started_at);

-- Allow NULL device_id in iot_allowlist for globally-shared IoT whitelist
-- entries (domains learned across all IoT devices).  Per-device entries
-- (device_id IS NOT NULL) are unchanged.
ALTER TABLE iot_allowlist ALTER COLUMN device_id DROP NOT NULL;

-- Enforce uniqueness of globally-shared FQDNs (device_id IS NULL).
-- The existing UNIQUE(device_id, fqdn) constraint does NOT prevent duplicate
-- (NULL, fqdn) rows in PostgreSQL because NULL != NULL, so we need a partial
-- unique index.
CREATE UNIQUE INDEX IF NOT EXISTS idx_iot_allowlist_global_fqdn
    ON iot_allowlist(fqdn) WHERE device_id IS NULL;

-- Record this migration as applied.
INSERT INTO schema_migrations (version) VALUES ('0002')
    ON CONFLICT (version) DO NOTHING;
