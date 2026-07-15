-- 000_schema.sql
-- Base schema for Keepalive-MCP: the `devices` inventory (source of truth) and the
-- `audit` log. This MUST be applied BEFORE 001_devices_notify.sql — that migration
-- installs a trigger on `devices` and GRANTs on `devices_id_seq`, both of which
-- require these objects to already exist.
--
-- Apply against the keepalive database, as the role that will own the tables
-- (the same role in KA_DB_DSN — `keepalive` — so no cross-owner GRANTs are needed;
-- the owner implicitly holds all privileges, including on the `audit` table which
-- 001 does not grant):
--   psql "$KA_DB_DSN" -f deploy/migrations/000_schema.sql
--
-- Idempotent: safe to re-run.

-- ── devices ────────────────────────────────────────────────────────────────────
-- Single source of truth for the SSH pool. `id SERIAL` is deliberate: it creates
-- the sequence `devices_id_seq` that 001 grants USAGE on. `name` is the natural key
-- the app looks up / claims by, so it is UNIQUE (devices_create relies on the unique
-- violation to report "already exists"). The CHECKs mirror the app's _coerce_device /
-- _VALID_PLATFORMS validation so a direct `psql`/bulk seed can't insert a row the
-- runtime would choke on.
CREATE TABLE IF NOT EXISTS devices (
    id               SERIAL       PRIMARY KEY,
    name             TEXT         NOT NULL UNIQUE,
    host             TEXT         NOT NULL,
    port             INTEGER      NOT NULL DEFAULT 22
                                  CHECK (port BETWEEN 1 AND 65535),
    platform         TEXT         NOT NULL
                                  CHECK (platform IN (
                                      'cisco_iosxe', 'cisco_ios', 'cisco_asa', 'cisco_nxos',
                                      'cisco_iosxr', 'arista_eos', 'juniper_junos')),
    username         TEXT         NOT NULL,
    role             TEXT,
    site             TEXT,
    description      TEXT,
    max_connections  INTEGER      NOT NULL DEFAULT 2
                                  CHECK (max_connections BETWEEN 1 AND 16),
    enabled          BOOLEAN      NOT NULL DEFAULT TRUE,
    source           TEXT
);

-- _load_devices() filters `WHERE enabled = true ORDER BY name` on every warmup/find.
CREATE INDEX IF NOT EXISTS idx_devices_enabled ON devices (enabled) WHERE enabled;

-- ── audit ──────────────────────────────────────────────────────────────────────
-- One row per call (reads, config intents, pushes, pool connect/disconnect, device
-- CRUD). Command *output* is never stored — only out_chars. NOTE (see SECURITY.md):
-- `command` CAN contain secrets on write verbs (e.g. `snmp-server community …`,
-- `username … secret …`, PSKs), so this table is sensitive — keep storage-layer
-- encryption and tight access on it. The app truncates `command` to 500 chars.
CREATE TABLE IF NOT EXISTS audit (
    id               BIGSERIAL    PRIMARY KEY,
    ts               TIMESTAMPTZ  NOT NULL DEFAULT now(),
    who              TEXT,                -- principal oid (or "pool"/"app:<appid>")
    who_upn          TEXT,                -- preferred_username / upn
    mcp_session_id   TEXT,                -- MCP session id or dedicated session id (nullable)
    device           TEXT,                -- device name, or "(inventory)"
    verb             TEXT,                -- read | write | write-intent | claim | release | pool-* | device-*
    command          TEXT,
    rc               INTEGER,             -- 0 ok, 1 error, -1 intent
    status           TEXT,
    dur_ms           INTEGER,
    out_chars        INTEGER
);

CREATE INDEX IF NOT EXISTS idx_audit_ts     ON audit (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_device ON audit (device, ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_who    ON audit (who, ts DESC);
