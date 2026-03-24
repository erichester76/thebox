-- Migration 0005 — additional columns for honeypot events and user auth
-- These columns were previously applied only by the service ensure_schema()
-- inline DDL.  Moving them into a numbered migration makes them part of the
-- single-source-of-truth migration chain.

-- Honeypot enrichment columns (added by the honeypot service for threat intel)
ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS interaction_level VARCHAR(16) NOT NULL DEFAULT 'none';
ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS intent           VARCHAR(32) NOT NULL DEFAULT 'scan';
ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS is_sweep         BOOLEAN     NOT NULL DEFAULT FALSE;
ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS ports_scanned    JSONB;

-- Dashboard login support
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);

-- Record this migration as applied.
INSERT INTO schema_migrations (version) VALUES ('0005')
    ON CONFLICT (version) DO NOTHING;
