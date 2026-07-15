# Keepalive-MCP — security model & operator notes

Keepalive-MCP holds warm, privileged SSH connections into network gear and exposes
them to agents/operators behind Entra auth. This file records the threat model, the
controls, and the residual risks an operator accepts by running it.

## Access control

- **Every MCP call** validates the Entra bearer: JWKS signature, audience, issuer,
  tenant (`tid`), expiry, required scope, and allowed client id. Roles gate verbs:
  - `Keepalive.Read` → `find_devices`, `run` (read-only commands)
  - `Keepalive.Config` → additionally `apply`, `claim_session`, `release_session`
- **Status page** (`/status`, `/status.json`) requires an interactive SSO session
  **and** the `KA_STATUS_ROLE` app role (default `Keepalive.Read`). Device
  host/role/site topology is treated as sensitive internal detail, not public.
- Dedicated sessions are bound to **both** the MCP session id and the authenticated
  principal (`oid`) — one principal cannot reuse another's claimed connection.

## SSH to managed devices

- **Host-key verification** is controlled by `KA_SSH_HOSTKEY_POLICY`:
  - `strict` (default) — every device is verified against `KA_SSH_KNOWN_HOSTS`;
    unknown/changed keys are rejected. **The server refuses to start** if the
    known_hosts file is missing/empty. Seed it once at provisioning:
    ```
    ssh-keyscan -f <device-hosts> > /etc/keepalive-mcp/ssh/known_hosts
    ```
  - `off` — verification skipped (MITM-exposed). Trusted bootstrap / lab only;
    the server logs a loud warning at startup.
- **Read-command safety:** `run` refuses reads that dump raw key/credential
  material or arbitrary files (private keys, `more nvram:/flash:`, etc.), and
  **redacts** secret-bearing lines (passwords, community strings, PSKs, key
  material) from all returned output. (Read audit rows store only a char count of
  output, never the output itself.)
- **Config pushes** (`apply`) are **write-before-execute audited**: the intent to
  mutate is recorded durably *before* the device is touched, and the push is
  **refused** if that audit write fails. Pushes halt at the first rejected line and
  never `write memory` on a failed change.

### ⚠️ Residual risk — one shared device credential (accepted)

The pool authenticates to **every** device with a single shared service-account
credential — a private key (`KA_SSH_KEY`) and/or a password (`KA_SSH_PASSWORD`, e.g. a
central TACACS/RADIUS account). One compromise = SSH access to the whole fleet. Treat
it as tier-0: key files 0600 and the password only in the env file (0640, service-user
owned), on an encrypted volume, never copied off-box. Prefer scoping the account's
device privileges to the minimum the tools need. A per-device / short-lived-credential
model is the longer-term direction (see roadmap). Document custody in your runbook.

### ⚠️ Residual risk — pivoting (accepted, by design)

`run` permits `ping`/`traceroute`, which allow limited network reconnaissance from a
device's vantage point. This is inherent to the tool's purpose (reachability checks);
it is gated behind `Keepalive.Read` and audited.

## Operational notes

- `KA_SESSION_SECRET`: if unset, a random per-process secret is generated. Fine for a
  single instance; **set it explicitly** if you run more than one instance or want
  sessions to survive a restart (otherwise all status sessions invalidate on restart).
- `KA_REDIRECT_URI` is **required** — there is no baked-in host default; the server
  fails closed at startup if it is unset.
- DNS-rebinding protection is **on**; `KA_ALLOWED_HOSTS` pins the accepted `Host:`
  headers (defaults derive from the redirect host + bind address).
- The audit DB (`keepalive.audit`) stores config lines that may include secrets
  (e.g. `snmp community`, `username secret`, PSKs). Ensure storage-layer encryption
  and tight access on that database. Command *output* is not stored — only char counts.
