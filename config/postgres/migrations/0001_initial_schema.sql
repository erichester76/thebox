-- Migration 0001 — initial schema
-- All statements are idempotent (CREATE TABLE/INDEX IF NOT EXISTS) so this
-- migration is safe to apply against a database that was provisioned by
-- config/postgres/init.sql before the migration engine was introduced.

-- Users
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    username        VARCHAR(64) NOT NULL UNIQUE,
    display_name    VARCHAR(255),
    email           VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Devices
CREATE TABLE IF NOT EXISTS devices (
    id              SERIAL PRIMARY KEY,
    mac_address     VARCHAR(17) NOT NULL UNIQUE,
    ip_address      VARCHAR(45),
    hostname        VARCHAR(255),
    vendor          VARCHAR(255),
    device_type     VARCHAR(64) DEFAULT 'unknown',
    os_guess        VARCHAR(255),
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status          VARCHAR(32)  NOT NULL DEFAULT 'new',
    notes           TEXT,
    open_ports      JSONB DEFAULT '[]',
    extra_info      JSONB DEFAULT '{}',
    owner_id        INTEGER REFERENCES users(id) ON DELETE SET NULL
);

-- IoT allow-list
CREATE TABLE IF NOT EXISTS iot_allowlist (
    id          SERIAL PRIMARY KEY,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    fqdn        VARCHAR(255) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(device_id, fqdn)
);

-- Honeypot events
CREATE TABLE IF NOT EXISTS honeypot_events (
    id              SERIAL PRIMARY KEY,
    src_ip          VARCHAR(45) NOT NULL,
    src_port        INTEGER,
    dst_port        INTEGER NOT NULL,
    protocol        VARCHAR(10) NOT NULL DEFAULT 'tcp',
    payload_preview TEXT,
    severity        VARCHAR(16) NOT NULL DEFAULT 'low',
    device_id       INTEGER REFERENCES devices(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- DNS events
CREATE TABLE IF NOT EXISTS dns_events (
    id          SERIAL PRIMARY KEY,
    device_id   INTEGER REFERENCES devices(id),
    src_ip      VARCHAR(45) NOT NULL,
    query       VARCHAR(255) NOT NULL,
    query_type  VARCHAR(16) NOT NULL DEFAULT 'A',
    blocked     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Network scan history
CREATE TABLE IF NOT EXISTS scan_runs (
    id              SERIAL PRIMARY KEY,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ,
    network_range   VARCHAR(64) NOT NULL,
    devices_found   INTEGER NOT NULL DEFAULT 0,
    new_devices     INTEGER NOT NULL DEFAULT 0,
    status          VARCHAR(32) NOT NULL DEFAULT 'running'
);

-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
    id          SERIAL PRIMARY KEY,
    source      VARCHAR(64) NOT NULL,
    level       VARCHAR(16) NOT NULL DEFAULT 'info',
    title       VARCHAR(255) NOT NULL,
    detail      TEXT,
    device_id   INTEGER REFERENCES devices(id),
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Groups
CREATE TABLE IF NOT EXISTS groups (
    id                SERIAL PRIMARY KEY,
    name              VARCHAR(64) NOT NULL UNIQUE,
    description       TEXT,
    pihole_group_name VARCHAR(64),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- User-group memberships
CREATE TABLE IF NOT EXISTS user_groups (
    user_id   INTEGER NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    group_id  INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

-- Device-group memberships
CREATE TABLE IF NOT EXISTS device_groups (
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    group_id  INTEGER NOT NULL REFERENCES groups(id)  ON DELETE CASCADE,
    PRIMARY KEY (device_id, group_id)
);

-- Redirector events
CREATE TABLE IF NOT EXISTS redirect_events (
    id          SERIAL PRIMARY KEY,
    action      VARCHAR(64)  NOT NULL,
    target_ip   VARCHAR(45)  NOT NULL,
    target_mac  VARCHAR(17),
    mode        VARCHAR(64)  NOT NULL,
    detail      TEXT,
    device_id   INTEGER REFERENCES devices(id),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indices
CREATE INDEX IF NOT EXISTS idx_devices_mac        ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_ip         ON devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_devices_status     ON devices(status);
CREATE INDEX IF NOT EXISTS idx_devices_owner      ON devices(owner_id);
CREATE INDEX IF NOT EXISTS idx_honeypot_src_ip    ON honeypot_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_honeypot_created   ON honeypot_events(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_level       ON alerts(level);
CREATE INDEX IF NOT EXISTS idx_alerts_created     ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_user_groups_group  ON user_groups(group_id);
CREATE INDEX IF NOT EXISTS idx_device_groups_group ON device_groups(group_id);
CREATE INDEX IF NOT EXISTS idx_redirect_target_ip ON redirect_events(target_ip);
CREATE INDEX IF NOT EXISTS idx_redirect_created   ON redirect_events(created_at);
