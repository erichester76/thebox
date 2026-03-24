-- Migration 0004 — Runtime configuration settings table
-- Creates a key/value store for all tuneable configuration.  On first startup
-- each service seeds its section from environment variables so that existing
-- .env-based deployments keep working without any manual database changes.
-- From that point on, values are managed through the dashboard Settings UI.

CREATE TABLE IF NOT EXISTS settings (
    key         VARCHAR(64)  NOT NULL PRIMARY KEY,
    value       TEXT         NOT NULL,
    description TEXT,
    category    VARCHAR(32)  NOT NULL DEFAULT 'general',
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_settings_category ON settings(category);

-- Record this migration as applied.
INSERT INTO schema_migrations (version) VALUES ('0004')
    ON CONFLICT (version) DO NOTHING;
