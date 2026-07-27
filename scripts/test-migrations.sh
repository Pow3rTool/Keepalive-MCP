#!/usr/bin/env bash
# Validate fresh/legacy migration, NOTIFY, readiness, and graceful shutdown.
set -euo pipefail

IMAGE="${1:?usage: test-migrations.sh <candidate-image>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PODMAN="$(command -v podman || true)"
[ -n "$PODMAN" ] || { echo "podman is required" >&2; exit 1; }

suffix="$(date +%s)-$$"
network_name="keepalive-test-net-$suffix"
database_name="keepalive-test-db-$suffix"
runtime_name="keepalive-test-runtime-$suffix"

cleanup() {
  "$PODMAN" rm -f "$runtime_name" "$database_name" >/dev/null 2>&1 || true
  "$PODMAN" network rm "$network_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

"$PODMAN" network create "$network_name" >/dev/null
"$PODMAN" run -d --name "$database_name" --network "$network_name" \
  --network-alias postgres \
  -e POSTGRES_DB=keepalive \
  -e POSTGRES_USER=keepalive \
  -e POSTGRES_PASSWORD=keepalive-test \
  docker.io/library/postgres:17-alpine >/dev/null

for _attempt in $(seq 1 30); do
  if "$PODMAN" exec "$database_name" pg_isready -U keepalive -d keepalive \
      >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
"$PODMAN" exec "$database_name" pg_isready -U keepalive -d keepalive >/dev/null

dsn="postgresql://keepalive:keepalive-test@postgres:5432/keepalive"
expected_migrations="$(find "$ROOT/deploy/migrations" -maxdepth 1 \
  -type f -name '[0-9][0-9][0-9]_*.sql' | wc -l | tr -d ' ')"
run_migrations() {
  "$PODMAN" run --rm --network "$network_name" \
    -e KA_DB_DSN="$dsn" \
    --entrypoint python \
    "$IMAGE" migrate.py
}

# Fresh path and idempotent rerun.
run_migrations
run_migrations

migration_count="$("$PODMAN" exec -e PGPASSWORD=keepalive-test "$database_name" \
  psql -At -U keepalive -d keepalive \
  -c "SELECT count(*) FROM keepalive_schema_migrations")"
test "$migration_count" = "$expected_migrations"

# Seed both sides of the retention boundary before runtime starts. Startup maintenance
# must delete only expired pool telemetry and preserve permanent human attribution.
"$PODMAN" exec -e PGPASSWORD=keepalive-test "$database_name" \
  psql -v ON_ERROR_STOP=1 -U keepalive -d keepalive \
  -c "
    INSERT INTO audit (ts, who, device, verb, command, rc, status, dur_ms, out_chars)
    VALUES
      (now() - interval '31 days', 'pool', 'old-pool', 'pool-connect', NULL, 1, 'old', 0, 0),
      (now() - interval '10 years', 'operator', 'old-human', 'read', 'show clock', 0, 'ok', 1, 10),
      (now(), 'pool', 'recent-pool', 'pool-connect', NULL, 0, 'connected', 0, 0);
  " >/dev/null

# Runtime comes ready with an empty fleet; it must not wait for SSH convergence.
"$PODMAN" run -d --name "$runtime_name" --network "$network_name" \
  -e KA_DB_DSN="$dsn" \
  -e KA_TENANT_ID=00000000-0000-0000-0000-000000000000 \
  -e KA_CLIENT_ID=11111111-1111-1111-1111-111111111111 \
  -e KA_REQUIRED_SCOPE=user_impersonation \
  -e KA_ALLOWED_CLIENTS=22222222-2222-2222-2222-222222222222 \
  -e KA_REDIRECT_URI=https://ka.example.com/keepalive/auth/callback \
  -e KA_SSH_HOSTKEY_POLICY=off \
  -e KA_SSH_PASSWORD=dummy \
  -e KA_BIND=0.0.0.0 \
  "$IMAGE" >/dev/null

"$PODMAN" cp "$ROOT/scripts/check-runtime.py" \
  "$runtime_name:/tmp/check-runtime.py"
for _attempt in $(seq 1 20); do
  if "$PODMAN" exec "$runtime_name" python /tmp/check-runtime.py \
      >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
"$PODMAN" exec "$runtime_name" python /tmp/check-runtime.py

for _attempt in $(seq 1 20); do
  expired_pool="$("$PODMAN" exec -e PGPASSWORD=keepalive-test "$database_name" \
    psql -At -U keepalive -d keepalive \
    -c "SELECT count(*) FROM audit WHERE device = 'old-pool'")"
  if [ "$expired_pool" = 0 ]; then
    break
  fi
  sleep 1
done
test "$expired_pool" = 0
permanent_human="$("$PODMAN" exec -e PGPASSWORD=keepalive-test "$database_name" \
  psql -At -U keepalive -d keepalive \
  -c "SELECT count(*) FROM audit WHERE device = 'old-human'")"
recent_pool="$("$PODMAN" exec -e PGPASSWORD=keepalive-test "$database_name" \
  psql -At -U keepalive -d keepalive \
  -c "SELECT count(*) FROM audit WHERE device = 'recent-pool'")"
test "$permanent_human" = 1
test "$recent_pool" = 1

# Keep an HTTP request deliberately incomplete while stopping. Uvicorn must bound
# its drain and still let PID 1 exit cleanly inside the container stop window.
"$PODMAN" exec "$runtime_name" python -c '
import socket
import time

client = socket.create_connection(("127.0.0.1", 8784), timeout=2)
client.sendall(
    b"POST / HTTP/1.1\r\n"
    b"Host: 127.0.0.1:8784\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: 100000\r\n\r\n"
    b"{"
)
time.sleep(30)
' >/dev/null 2>&1 &
slow_client_pid=$!
sleep 1
"$PODMAN" stop --time 8 "$runtime_name" >/dev/null
wait "$slow_client_pid" >/dev/null 2>&1 || true
runtime_exit="$("$PODMAN" inspect "$runtime_name" --format "{{.State.ExitCode}}")"
test "$runtime_exit" = 0
"$PODMAN" rm "$runtime_name" >/dev/null

# Validate the real trigger and audit table from the exact runtime dependency set.
"$PODMAN" run --rm --network "$network_name" \
  -e KA_DB_DSN="$dsn" \
  -e EXPECTED_MIGRATIONS="$expected_migrations" \
  -v "$ROOT/scripts/check-database.py:/checks/check-database.py:ro" \
  --entrypoint python \
  "$IMAGE" /checks/check-database.py

# Upgrade path: an untracked legacy 000 schema must converge under the runner.
"$PODMAN" exec -e PGPASSWORD=keepalive-test "$database_name" \
  createdb -U keepalive keepalive_legacy
"$PODMAN" exec -i -e PGPASSWORD=keepalive-test "$database_name" \
  psql -v ON_ERROR_STOP=1 -U keepalive -d keepalive_legacy \
  < "$ROOT/deploy/migrations/000_schema.sql" >/dev/null
legacy_dsn="postgresql://keepalive:keepalive-test@postgres:5432/keepalive_legacy"
"$PODMAN" run --rm --network "$network_name" \
  -e KA_DB_DSN="$legacy_dsn" \
  --entrypoint python \
  "$IMAGE" migrate.py >/dev/null
legacy_count="$("$PODMAN" exec -e PGPASSWORD=keepalive-test "$database_name" \
  psql -At -U keepalive -d keepalive_legacy \
  -c "SELECT count(*) FROM keepalive_schema_migrations")"
test "$legacy_count" = "$expected_migrations"

echo "keepalive candidate migration/runtime checks passed"
