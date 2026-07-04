-- 001_devices_notify.sql
-- Dynamic device pool: let the running keepalive-mcp reconcile its SSH pool to
-- the `devices` table WITHOUT a restart (which would bounce every live session).
--
-- The table stays the single source of truth. This trigger fires a lightweight
-- NOTIFY on every row change; the service holds a LISTEN and reconciles ONLY the
-- changed device (see Pool._listen_devices / _reconcile_from_notify in server.py).
-- Any writer converges: the REST /devices API, a direct psql edit, a bulk import,
-- and every service instance (HA-safe).
--
-- Payload is intentionally tiny ({op, name}) — well under the 8000-byte pg_notify
-- limit — so the listener re-SELECTs the authoritative row itself and never trusts
-- mutable state smuggled through the channel.
--
-- Idempotent: safe to re-run. Apply against the `keepalive` database:
--   psql "$KA_DB_DSN" -f deploy/migrations/001_devices_notify.sql

CREATE OR REPLACE FUNCTION keepalive_devices_notify() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  rec record;
BEGIN
  IF TG_OP = 'DELETE' THEN
    rec := OLD;
  ELSE
    rec := NEW;
  END IF;
  PERFORM pg_notify(
    'keepalive_devices',
    json_build_object('op', TG_OP, 'name', rec.name)::text
  );
  RETURN NULL;  -- AFTER trigger; return value ignored
END;
$$;

DROP TRIGGER IF EXISTS trg_devices_notify ON devices;
CREATE TRIGGER trg_devices_notify
  AFTER INSERT OR UPDATE OR DELETE ON devices
  FOR EACH ROW EXECUTE FUNCTION keepalive_devices_notify();

-- The app role (the user in KA_DB_DSN, `keepalive`) reads `devices` but was NOT
-- granted writes — so the REST /devices API (and any hot add/remove) fails with
-- "permission denied". Grant table writes AND usage on the identity sequence
-- (a table INSERT grant alone still fails on the serial default). Run as the
-- table owner (postgres). Adjust the role name if your KA_DB_DSN user differs.
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE devices TO keepalive;
GRANT USAGE, SELECT ON SEQUENCE devices_id_seq TO keepalive;
