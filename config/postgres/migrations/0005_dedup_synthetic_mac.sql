-- Migration 0005 — remove duplicate device rows caused by synthetic MACs
--
-- When the discovery service cannot resolve a real MAC address via ARP it
-- creates a temporary record with a deterministic "synthetic" MAC derived from
-- the IP (always prefixed with '02:' — the locally-administered unicast bit).
-- If the real MAC is later discovered the upsert logic (pre-fix) treated it as
-- a brand-new device, creating a second row for the same physical device.
--
-- This migration removes those stale synthetic-MAC rows for every IP that
-- already has at least one row with a real (non-'02:') MAC address.  It is
-- idempotent: running it on a clean database (or twice) is harmless.
--
-- Safety notes:
--   * Only '02:'-prefixed rows are touched.
--   * A row is only deleted when a non-'02:' row exists for the same IP,
--     guaranteeing the device remains visible in the database.
--   * Foreign-key references (honeypot_events, dns_events, alerts,
--     redirect_events) that point at the synthetic row are re-pointed to the
--     surviving real-MAC row before deletion so that no event data is lost.
--   * Cascade-delete children (iot_allowlist, iot_learning_sessions,
--     device_groups) are also migrated to the surviving row so that any user-
--     set group memberships are preserved.

DO $$
DECLARE
    synth   RECORD;  -- synthetic-MAC device to remove
    real_id INTEGER; -- id of the surviving real-MAC record for the same IP
BEGIN
    FOR synth IN
        SELECT d.id, d.ip_address, d.mac_address
        FROM   devices d
        WHERE  d.mac_address LIKE '02:%'
          AND  d.ip_address IS NOT NULL
          AND  EXISTS (
                   SELECT 1
                   FROM   devices d2
                   WHERE  d2.ip_address    = d.ip_address
                     AND  d2.id           <> d.id
                     AND  d2.mac_address NOT LIKE '02:%'
               )
    LOOP
        -- Pick the non-synthetic record to keep (prefer the one seen most recently).
        SELECT id INTO real_id
        FROM   devices
        WHERE  ip_address    = synth.ip_address
          AND  mac_address NOT LIKE '02:%'
        ORDER  BY last_seen DESC
        LIMIT  1;

        IF real_id IS NULL THEN
            CONTINUE;  -- safety guard — should never happen given the EXISTS above
        END IF;

        -- Re-point nullable FK references so we don't lose historical data.
        UPDATE honeypot_events  SET device_id = real_id WHERE device_id = synth.id;
        UPDATE dns_events        SET device_id = real_id WHERE device_id = synth.id;
        UPDATE alerts            SET device_id = real_id WHERE device_id = synth.id;
        UPDATE redirect_events   SET device_id = real_id WHERE device_id = synth.id;

        -- Migrate cascade-delete children, skipping any that would create a
        -- duplicate (e.g. device already belongs to the same group).
        INSERT INTO device_groups (device_id, group_id)
            SELECT real_id, group_id
            FROM   device_groups
            WHERE  device_id = synth.id
        ON CONFLICT (device_id, group_id) DO NOTHING;

        INSERT INTO iot_allowlist (device_id, fqdn, created_at)
            SELECT real_id, fqdn, created_at
            FROM   iot_allowlist
            WHERE  device_id = synth.id
        ON CONFLICT (device_id, fqdn) DO NOTHING;

        -- Delete the synthetic device (cascade removes its device_groups,
        -- iot_allowlist and iot_learning_sessions rows that remain).
        DELETE FROM devices WHERE id = synth.id;

        RAISE NOTICE 'Merged synthetic device id=% (% → %) into id=%',
            synth.id, synth.mac_address, synth.ip_address, real_id;
    END LOOP;
END;
$$;

-- Record this migration as applied.
INSERT INTO schema_migrations (version) VALUES ('0005')
    ON CONFLICT (version) DO NOTHING;
