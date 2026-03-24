-- Migration 0003 — add IPv6 address column to devices
-- Adds a dedicated ipv6_address column so that the discovery service can
-- record each device's globally-routable IPv6 address (sourced from the
-- kernel NDP cache) and the guardian service can enforce ip6tables policy
-- against it.

ALTER TABLE devices ADD COLUMN IF NOT EXISTS ipv6_address VARCHAR(45);

CREATE INDEX IF NOT EXISTS idx_devices_ipv6 ON devices(ipv6_address);

-- Record this migration as applied.
INSERT INTO schema_migrations (version) VALUES ('0003')
    ON CONFLICT (version) DO NOTHING;
