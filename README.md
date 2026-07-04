# Keepalive-MCP

An [MCP](https://modelcontextprotocol.io) server that holds **warm, persistent SSH
connections** into network gear (Cisco IOS/IOS-XE/ASA/NX-OS, IOS-XR, EOS, Junos, and
other [scrapli](https://github.com/carlmontanari/scrapli)-supported platforms) and
exposes them to agents and operators behind Entra ID authentication.

Instead of paying TCP + SSH + auth + prompt-detection latency on every command, the
server keeps one live connection per device and lets callers run reads, push config,
and hold exclusive sessions over an already-open channel — with per-verb role gating
and durable audit on every call.

> **Security model, threat model, and residual risks live in [SECURITY.md](SECURITY.md).**
> Read it before deploying. This README covers *what it is* and *how it works*.

---

## Why a warm pool

Network CLIs are slow to reach: the handshake, the enable/prompt dance, and TextFSM
priming dominate the cost of a `show` that returns in milliseconds. Keepalive-MCP
opens each connection once and keeps it alive:

- One `AsyncScrapli` connection per device, kept warm at all times.
- A background task sends a bare `\t` (tab) every `KA_KEEPALIVE_SECS` to validate the
  session **without triggering a prompt** — safe at a `--More--` pager, a
  reload-confirm, or any other device state.
- Normal calls grab a per-device `asyncio.Lock` for their duration, so concurrent
  agents never interleave on the same device.

## The verbs (MCP tools)

| Tool | Role required | What it does |
|------|---------------|--------------|
| `find_devices` | `Keepalive.Read` | Search the inventory by name glob, role, platform, or site. Paginated — never dumps the whole fleet. |
| `run` | `Keepalive.Read` | Run a **read-only** command (`show`, `ping`, `traceroute`, `dir`, `verify`). Write verbs (`configure`/`reload`/`copy`/`write`/`clear`) are refused. `parsed=true` returns structured JSON via TextFSM where supported. |
| `apply` | `Keepalive.Config` | Push config lines. **`confirm=false` (default) is a dry-run preview**; call again with `confirm=true` to apply. `save=true` writes memory only on full success. |
| `claim_session` | `Keepalive.Config` | Reserve an **exclusive** connection to a device for multi-step work; returns a `session_id` to pass to `run`/`apply`. Auto-releases after `KA_DEDICATED_TTL_SECS` of inactivity. |
| `release_session` | `Keepalive.Config` | Release a dedicated session early. |

### Config-push safety (`apply`)

`apply` is intentionally conservative — it's the verb that can break a network:

- **Dry-run by default.** Nothing is sent until you re-call with `confirm=true`.
- **Write-before-execute audit.** The intent to mutate is recorded durably *before*
  the device is touched; the push is refused if that audit write fails.
- **Halts at the first rejected line** and never `write memory` on a failed change.
- Platform-aware commit behavior:
  - **live-apply** (IOS, IOS-XE, ASA, NX-OS): `send_configs` with `stop_on_failed`.
    A failed line → `ABORTED`, partial state left live, no save. Use the returned
    diff to assess and fix.
  - **commit-capable** (IOS-XR, EOS, Junos): candidate buffer → commit on success,
    abort on any failure — **nothing lands**.

### Dedicated sessions

A `claim_session` binds an exclusive connection to **both** the MCP session id and the
authenticated principal (`oid`) — one caller cannot reuse another's claimed
connection. The pool immediately spins a replacement so the shared slot stays warm.
Per-device connection cap is `max_connections` (from the DB, default 2); at cap, a
claim returns wait info (how long the holder has been idle, when it auto-expires) so
the caller can decide whether to retry.

## Authentication & authorization

Every MCP call validates the Entra bearer token end to end — **JWKS signature (RS256),
audience, issuer, tenant (`tid`), expiry, required scope, and an allowed-client
allowlist (`azp`/`appid`)** — then gates the verb on the app **roles** claim
(`Keepalive.Read` ⊂ `Keepalive.Config`). It fails closed: any missing or failed check
returns unauthorized/forbidden.

The **status page** (`/status`, `/status.json`) is separate — it requires an
interactive Entra SSO session **and** the `KA_STATUS_ROLE` app role, because device
host/role/site topology is treated as sensitive internal detail, not public.

Every call writes an audit row (`asyncpg` → `keepalive.audit`). Command *output* is
never stored — only a character count.

## Architecture

```
        Entra ID (JWKS / SSO)
              │  bearer / session
              ▼
   agents ─▶ Keepalive-MCP ──asyncssh──▶ network devices (warm pool, 1 conn/device)
   operators     │  │
                 │  └─ LISTEN "keepalive_devices" ─┐
                 ▼                                 │ NOTIFY on row change
          Postgres (KA_DB_DSN)                     │
          ├─ devices   (source of truth) ──────────┘
          └─ audit     (every call)
```

### Dynamic device pool — no restart

The `devices` table is the single source of truth. A Postgres trigger
([`deploy/migrations/001_devices_notify.sql`](deploy/migrations/001_devices_notify.sql))
fires a lightweight `NOTIFY` on every row change; the running service holds a `LISTEN`
and reconciles **only the changed device** — so adding, updating, or draining a device
never bounces live sessions. Any writer converges: the REST API, `kadev`, a direct
`psql` edit, or a bulk import. The notify payload is tiny (`{op, name}`); the listener
re-`SELECT`s the authoritative row and never trusts state smuggled through the channel.

### Device management (REST + `kadev`)

`/devices` (`GET`/`POST`/`PATCH`/`DELETE`) manages the pool and requires the
`Keepalive.Admin` app role. [`tools/kadev.py`](tools/kadev.py) is a headless admin CLI
that mints an **app-only** token with the app's certificate (client-credentials) and
calls that API — no interactive login:

```
kadev list
kadev add --name <name> --host <addr> --platform cisco_iosxe --site <site> --role switch
kadev update <name> --enabled false      # drain out of service
kadev remove <name>
```

## Quick start

1. **Install** (Python 3.11+):
   ```
   python -m venv venv && ./venv/bin/pip install -r requirements.txt
   ```
2. **Configure.** Copy [`.env.example`](.env.example) and fill it in — Entra tenant/
   client/audience, `KA_DB_DSN`, SSH key + known_hosts. Every setting is documented
   inline in that file.
3. **Create the DB schema** and apply the notify trigger:
   ```
   psql "$KA_DB_DSN" -f deploy/migrations/001_devices_notify.sql
   ```
4. **Seed SSH host keys** (required under the default `strict` host-key policy):
   ```
   ssh-keyscan -f <device-hosts> > /etc/keepalive-mcp/ssh/known_hosts
   ```
5. **Run** — directly (`./venv/bin/python server.py`), via the provided
   [systemd unit](deploy/keepalive-mcp.service) (sandboxed, binds `127.0.0.1` behind a
   TLS-terminating reverse proxy), or the [`Dockerfile`](Dockerfile).

The server **fails closed at startup** if required config is missing (e.g. no
`KA_REDIRECT_URI`, or an empty `known_hosts` under `strict`).

## Configuration

All configuration is via environment variables — see [`.env.example`](.env.example)
for the authoritative, commented list. Notable knobs:

| Variable | Purpose |
|----------|---------|
| `KA_DB_DSN` | Postgres DSN (device inventory + audit) |
| `KA_SSH_KEY` / `KA_SSH_KNOWN_HOSTS` | SSH identity and host-key trust store |
| `KA_SSH_HOSTKEY_POLICY` | `strict` (default, verifies every device) or `off` (MITM-exposed; bootstrap/lab only) |
| `KA_TENANT_ID` / `KA_CLIENT_ID` / `KA_AUDIENCE` | Entra app identity |
| `KA_ALLOWED_CLIENTS` | appids permitted to call the API |
| `KA_REQUIRED_SCOPE` / `KA_STATUS_ROLE` | delegated scope and status-page role |
| `KA_BIND` / `KA_PORT` | listen address (default `127.0.0.1:8784`) |
| `KA_KEEPALIVE_SECS` / `KA_DEDICATED_TTL_SECS` | pool tuning |

## License

See [LICENSE](LICENSE).
