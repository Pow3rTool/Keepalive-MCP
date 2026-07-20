"""
Keepalive-MCP — persistent SSH connection pool into Cisco (and multi-vendor) network gear.

Pool model:
  One AsyncScrapli connection per device is kept warm at all times. A background task
  sends \\t (tab) every KEEPALIVE_INTERVAL seconds to validate the session without
  triggering any prompt (safe at reload-confirm, --More--, or any other state).

  Normal tool calls (run/apply) acquire a per-device asyncio.Lock for their duration
  and release it when done — no interleaving between concurrent agents.

  A dedicated session (claim_session) is keyed to the calling MCP session ID. The
  caller holds the lock across multiple calls. The pool immediately spins a replacement
  connection so the shared slot stays warm. Dedicated sessions expire after
  DEDICATED_TTL seconds of inactivity; release_session releases early.

  Per-device connection cap: max_connections (from DB, default 2). When at cap a
  claim request returns the caller's wait info including how long the holder has
  been idle and when it auto-expires — the LLM can decide whether to retry.

Auth:
  Every MCP call validates the Entra bearer (JWKS sig, audience, issuer, expiry,
  required scope, allowed client). Roles from the verified token gate access:
    Keepalive.Read   → find_devices, run (+ claim_session/release_session when KA_READONLY)
    Keepalive.Config → find_devices, run, apply, claim_session, release_session

  The status page (/status and /status.json) is gated behind an interactive Entra
  SSO session cookie AND the KA_STATUS_ROLE app role — device host/role/site
  topology is sensitive internal detail, not public.

Platforms:
  live-apply (IOS, IOS-XE, ASA, NX-OS): send_configs with stop_on_failed.
    Failed line → ABORTED, partial state left live, no write memory.
  commit-capable (IOS-XR, EOS, Junos): candidate buffer → commit on success,
    abort on any failure — nothing lands.

Audit: every call → asyncpg INSERT into the keepalive.audit table (KA_DB_DSN).
"""
import os, json, asyncio, time, difflib, re, fnmatch
import secrets, hashlib, base64, hmac
from html import escape
from urllib.parse import urlencode
import asyncpg
import httpx
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from scrapli import AsyncScrapli
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

os.umask(0o077)

# ── config ────────────────────────────────────────────────────────────────────
PORT              = int(os.environ.get("KA_PORT", "8784"))
BIND              = os.environ.get("KA_BIND", "127.0.0.1")
DB_DSN            = os.environ.get("KA_DB_DSN", "")
SSH_KEY           = os.environ.get("KA_SSH_KEY", "/etc/keepalive-mcp/ssh/id_keepalive")
SSH_CONFIG        = os.environ.get("KA_SSH_CONFIG", "/etc/keepalive-mcp/ssh/ssh_config")
# Device login credential(s). The pool authenticates to EVERY device with a shared
# service account (per-device username is in the DB). Provide a password (TACACS/
# RADIUS or local), a private key, or both — at least one is required (_check_config).
SSH_PASSWORD      = os.environ.get("KA_SSH_PASSWORD", "")
SSH_SECONDARY     = os.environ.get("KA_SSH_SECONDARY", "")  # enable/privilege-escalation password
# Shared service-account username for admin-onboarded devices (discover_new_device).
# Fleet-wide creds mean the per-device delta is just name/host/platform; username
# defaults to this when the caller doesn't supply one.
DEFAULT_USERNAME  = os.environ.get("KA_DEFAULT_USERNAME", "")
# Read-only mode: don't register the config-push verb (apply) at all — it never appears
# in tools/list, so the LLM can't see or call it — and tell the model up front that only
# reads work. Use when the deployment (or the SSH service account) is read-only.
READONLY          = os.environ.get("KA_READONLY", "").strip().lower() in ("1", "true", "yes", "on")
# EXPERIMENTAL per-user tool discovery: when on, tools/list returns only the tools the
# caller's Entra app roles can actually use — the roles are read from the SAME validated
# bearer the call-time gates use. This is discoverability polish, NOT a new security
# boundary: every tool still enforces its _require_* gate on call, so a client that names
# an unlisted tool still gets the normal 403. Safe to cache per user because turnstone
# pools OBO sessions per user_id — each user's filtered list is keyed under their own id,
# so there's no cross-user cache poisoning. Default off (advertise-all + call-time gate).
FILTER_TOOL_LIST  = os.environ.get("KA_FILTER_TOOL_LIST", "").strip().lower() in ("1", "true", "yes", "on")
# Host-key policy for device SSH: "strict" (verify against known_hosts, reject
# unknown/changed) or "off" (skip verification — MITM-exposed, bootstrap/lab only).
SSH_HOSTKEY_POLICY = os.environ.get("KA_SSH_HOSTKEY_POLICY", "strict").strip().lower()
SSH_KNOWN_HOSTS    = os.environ.get("KA_SSH_KNOWN_HOSTS", "/etc/keepalive-mcp/ssh/known_hosts")
# Legacy SSH algorithm allowances for reaching old gear (old IOS-XR/IOS PEs that only
# speak SHA-1). The pool's transport is asyncssh — a pure-Python client that does NOT use
# the system `ssh` binary or /etc/ssh/ssh_config, and ships with SHA-1 KEX, the ssh-rsa
# (SHA-1) host-key alg, CBC ciphers and hmac-sha1 DISABLED by default. So a device that
# only offers those is unreachable until you opt them back in HERE — re-enabling them in
# /etc/ssh/ssh_config only fixes the CLI, not this server. Each var is passed straight to
# asyncssh.connect() and takes a comma-separated list with the same OpenSSH-style +/-/^
# prefix: e.g. "+diffie-hellman-group14-sha1" APPENDS to the modern defaults, so modern
# devices still negotiate modern algs and only a device offering nothing better falls back.
# Empty = asyncssh stock defaults (modern only). Mirror, per var, whatever you re-enabled
# in /etc/ssh/ssh_config for the CLI — note ssh-rsa host keys usually need KA_SSH_HOSTKEY_ALGS
# too, not just KEX. group1-sha1 (1024-bit) is genuinely weak; prefer group14 and omit group1.
SSH_KEX_ALGS       = os.environ.get("KA_SSH_KEX_ALGS", "").strip()          # kex_algs
SSH_HOSTKEY_ALGS   = os.environ.get("KA_SSH_HOSTKEY_ALGS", "").strip()      # server_host_key_algs
SSH_ENCRYPT_ALGS   = os.environ.get("KA_SSH_ENCRYPTION_ALGS", "").strip()   # encryption_algs
SSH_MAC_ALGS       = os.environ.get("KA_SSH_MAC_ALGS", "").strip()          # mac_algs

# With host-key verification off (the norm for a large, ever-changing device fleet where
# seeding known_hosts isn't viable), scrapli logs "unable to resolve 'ssh_known_hosts' file"
# on every reconnect — expected here, not an error. Quiet scrapli below WARNING so it doesn't
# flood the logs; real events are audited to Postgres, not scrapli's logger. (Flip to strict
# and this restores scrapli's normal warnings.)
if SSH_HOSTKEY_POLICY == "off":
    import logging as _logging
    _logging.getLogger("scrapli").setLevel(_logging.ERROR)
MAX_OUT           = int(os.environ.get("KA_MAX_OUTPUT_CHARS", "60000"))
CAPTURE_TTL       = int(os.environ.get("KA_CAPTURE_TTL_SECS", "600"))   # captured-output lifetime
CAPTURE_MAX       = int(os.environ.get("KA_CAPTURE_MAX", "32"))         # max concurrent captures
KEEPALIVE_SECS    = int(os.environ.get("KA_KEEPALIVE_SECS", "30"))
DEDICATED_TTL     = int(os.environ.get("KA_DEDICATED_TTL_SECS", "300"))  # 5 min idle
RECONNECT_WAIT    = int(os.environ.get("KA_RECONNECT_WAIT_SECS", "300"))  # 5 min on DOWN
# New-connection spin-up throttle. EVERY SSH connect (cold-start, keepalive reconnect,
# hot-add) triggers a device-side TACACS/AAA transaction; a fleet-wide cold start or a
# post-flap reconnect would otherwise fire them all at once and can crater a small AAA
# cluster. Serialize connects to at most KA_CONNECT_RATE per second across the pool.
# 0 (or negative) disables the throttle. NOTE: this gate is PER-PROCESS — a future
# multi-worker/sharded deployment multiplies the aggregate rate by the worker count,
# so set it to (global_budget / workers) there, or move to a shared limiter.
CONNECT_RATE      = float(os.environ.get("KA_CONNECT_RATE", "1.0"))
# HTTP access logging is OFF by default so routine request lines don't spray into
# syslog/Ringdown (and the OAuth ?code= on /auth/callback is never logged). Set
# KA_ACCESS_LOG=true for a debugging session; the redaction filter still scrubs
# code/state/token/secret from any access line that IS emitted.
ACCESS_LOG        = os.environ.get("KA_ACCESS_LOG", "false").strip().lower() in ("1", "true", "yes")

SESSION_SECRET    = os.environ.get("KA_SESSION_SECRET", "") or secrets.token_hex(32)
KEY_PATH          = os.environ.get("KA_CERT_KEY_PATH", "/etc/keepalive-mcp/keepalive-mcp.key")
CERT_PATH         = os.environ.get("KA_CERT_PATH",     "/etc/keepalive-mcp/keepalive-mcp.crt")
REDIRECT_URI      = os.environ.get("KA_REDIRECT_URI", "").strip()   # required; no host default

TENANT            = os.environ.get("KA_TENANT_ID", "").strip()
CLIENT_ID         = os.environ.get("KA_CLIENT_ID", "").strip()
AUDIENCE          = [x for x in (CLIENT_ID,
                                  f"api://{CLIENT_ID}",
                                  os.environ.get("KA_AUDIENCE", "").strip()) if x]
REQUIRED_SCOPE    = os.environ.get("KA_REQUIRED_SCOPE", "").strip()
ALLOWED_CLIENTS   = [x.strip() for x in os.environ.get("KA_ALLOWED_CLIENTS", "").split(",") if x.strip()]
# Delegated scope the status login requests so the token endpoint returns an
# access token for THIS API. Entra emits app roles in the access token audienced
# to the API resource, not in the ID token — so roles are read from that token,
# not the id_token. Resource is the registered identifier URI (KA_AUDIENCE),
# falling back to api://{client_id}.
_API_RESOURCE     = (os.environ.get("KA_AUDIENCE", "").strip() or f"api://{CLIENT_ID}")
API_SCOPE         = f"{_API_RESOURCE}/{REQUIRED_SCOPE}" if REQUIRED_SCOPE else ""
READ_ROLES        = {"keepalive.read", "keepalive.config", "keepalive.admin"}
CONFIG_ROLES      = {"keepalive.config", "keepalive.admin"}
# Dedicated-session verbs (claim_session/release_session). A session hands out an EXCLUSIVE
# connection but no new capability — apply is Config-gated (and unregistered in read-only)
# and run refuses writes regardless — so in READ-ONLY mode these drop to the Read tier: a
# read workflow that needs connection affinity (e.g. ASA `changeto` context navigation) can
# hold a session without a Config role. Read-write keeps them Config-gated (paired with
# apply). Kept in lockstep with _require_session below.
SESSION_ROLES     = READ_ROLES if READONLY else CONFIG_ROLES
# Device-pool mutation (REST /devices add/update/remove). Admin is a superset of
# read+config: an operator who can reshape the fleet can also read and push config.
ADMIN_ROLES       = {"keepalive.admin"}
# App role required to view the status page / JSON (topology is sensitive).
STATUS_ROLE       = os.environ.get("KA_STATUS_ROLE", "Keepalive.Read").strip().lower()
# Host: headers the MCP transport accepts (DNS-rebinding guard). Empty = derive
# from REDIRECT_URI host + the bind address.
ALLOWED_HOSTS     = [x.strip() for x in os.environ.get("KA_ALLOWED_HOSTS", "").split(",") if x.strip()]

# Platforms where config lands immediately (no candidate buffer)
LIVE_APPLY = {"cisco_iosxe", "cisco_ios", "cisco_asa", "cisco_nxos"}
# Platforms with native commit/abort
COMMIT_CAP = {"cisco_iosxr", "arista_eos", "juniper_junos"}

# Platforms an admin may onboard via discover_new_device (the live Cisco fleet).
# Widen (e.g. cisco_ios, cisco_nxos) if a device outside this set needs tool onboarding.
_ONBOARD_PLATFORMS = {"cisco_iosxe", "cisco_iosxr", "cisco_asa"}

READ_OK = ("show", "ping", "traceroute", "dir", "display", "more", "get", "verify",
           "changeto")   # ASA multi-context navigation (changeto context/system) — read-safe

# Config / tech-support dumps — the dense secret source. Blocked BY DEFAULT (line-based
# redaction misses too many vendor variants on a full config — GPT #6); set
# KA_ALLOW_CONFIG_READ=true to let operators read them. Output is ALWAYS secret-redacted
# (_redact_secrets) regardless. apply's internal diff reads running-config directly on the
# connection — a separate path, also redacted before return.
ALLOW_CONFIG_READ = os.environ.get("KA_ALLOW_CONFIG_READ", "").strip().lower() in ("1", "true", "yes", "on")
_BLOCKED_CONFIG = [re.compile(p, re.I) for p in (
    r"\bshow\s+run(n|\b)",                       # show run / show running-config [...]
    r"\bshow\s+start(u|\b)",                     # show startup-config
    r"\bshow\s+config(u|\b)",                    # show config / show configuration (Junos)
    r"\bshow\s+tech(-|\s|\b)",                   # show tech-support
    r"running-config|startup-config",            # any residual (e.g. more system:running-config)
)]
# Raw key material and arbitrary file reads — ALWAYS refused (redaction can't help; these
# dump raw key bytes / arbitrary files), even when KA_ALLOW_CONFIG_READ is on.
_BLOCKED_ALWAYS = [re.compile(p, re.I) for p in (
    r"\bcrypto\s+key\b",                         # show crypto key ... (private keys)
    r"\bkey\s+(chain|zeroize|mypubkey)\b",
    r"\bmore\b.*(:|/)",                          # more nvram:/flash:/system: arbitrary file read
    r"\btype\b\s+\S",                            # type <file>
    r"\b(dir|fsck|show\s+file)\b.*(nvram|flash|bootflash|disk\d|usb)",
    r"\bshow\b.*\bkey(s)?\b",                    # show ... keys (SNMPv3, EIGRP auth, etc.)
)]

# Redaction for the output that IS returned (targeted shows, apply diffs). Each rule
# captures the directive PREFIX to keep; everything after it (the secret value) is
# masked. Over-redaction is safe; under-redaction is the bug — keep the prefix tight.
_REDACT_RULES = [re.compile(p, re.I) for p in (
    r"^(.*\b(?:password|passwd|secret)(?:\s+\d+)?)\s+\S.*$",   # enable secret / X password Y
    r"^(.*\bsnmp-server\s+community)\s+\S.*$",                 # community string
    r"^(.*\bsnmp-server\s+user)\s+\S.*$",                      # v3 user auth/priv keys
    r"^(.*\bkey-string)\s+\S.*$",                              # keychain key-string
    r"^(.*\b(?:pre-shared-key|wpa-psk|encrypted-password))\s+\S.*$",
    r"^(.*\b(?:isakmp|keyring)\s+key)\s+\S.*$",                # crypto isakmp key <psk>
    r"^(.*\b(?:md5|hmac(?:-sha\w*)?)(?:\s+\d+)?)\s+\S.*$",     # ospf/bgp message-digest
    r"^(.*\bauthentication\s+key)\s+\S.*$",
    r"^(.*\b(?:radius|tacacs)\b.*\bkey)(?:\s+\d+)?\s+\S.*$",   # shared server key
    r"^(.*\bppp\s+(?:chap|pap)\s+password)\s+\S.*$",
)]

def _blocked_read(cmd: str) -> str:
    for rx in _BLOCKED_ALWAYS:
        if rx.search(cmd):
            return ("refused: raw key material and arbitrary file reads are blocked — they dump "
                    "secrets/files that can't be safely redacted. Use a targeted 'show'.")
    if not ALLOW_CONFIG_READ:
        for rx in _BLOCKED_CONFIG:
            if rx.search(cmd):
                return ("refused: full-config/tech-support reads are disabled here. An operator can "
                        "enable them with KA_ALLOW_CONFIG_READ=true (output stays secret-redacted); "
                        "until then use a targeted 'show' for the specific state you need.")
    return ""

def _redact_secrets(text: str) -> str:
    """Mask the secret VALUE on any line that carries one, keeping the directive
    prefix so the line stays readable. Applied to all device output before return."""
    if not text:
        return text
    out = []
    for ln in text.splitlines():
        for rx in _REDACT_RULES:
            m = rx.match(ln)
            if m:
                ln = m.group(1) + " «redacted»"
                break
        out.append(ln)
    return "\n".join(out)

def _redact_result(result: dict) -> dict:
    """Redact device-sourced config text in an apply() result (config_diff,
    net-change lines, device_said, commit_output) — these come from a
    running-config diff and can carry secrets just like a raw read."""
    for k in ("config_diff", "device_said", "commit_output"):
        if isinstance(result.get(k), str):
            result[k] = _redact_secrets(result[k])
    anc = result.get("actual_net_change")
    if isinstance(anc, dict):
        for side in ("added", "removed"):
            if isinstance(anc.get(side), list):
                anc[side] = [_redact_secrets(x) if isinstance(x, str) else x for x in anc[side]]
    return result

_VOLATILE = [re.compile(p) for p in (
    r"^Building configuration", r"^Current configuration",
    r"^! Last configuration change", r"^! NVRAM config last",
    r"^ntp clock-period", r"^Cryptochecksum:", r"^: ",
    r"^!Time:", r"^\s*$")]


# ── startup validation ────────────────────────────────────────────────────────
def _check_config():
    def _bad(v):
        v = str(v).strip()
        return not v or "<" in v or ">" in v or "REPLACE" in v.upper()
    if _bad(DB_DSN):
        raise SystemExit("KA_DB_DSN is missing.")
    if _bad(TENANT) or _bad(CLIENT_ID):
        raise SystemExit("KA_TENANT_ID and KA_CLIENT_ID are required.")
    if _bad(REQUIRED_SCOPE):
        raise SystemExit("KA_REQUIRED_SCOPE is required.")
    if not ALLOWED_CLIENTS:
        raise SystemExit("KA_ALLOWED_CLIENTS is required.")
    if _bad(REDIRECT_URI):
        raise SystemExit("KA_REDIRECT_URI is required (no host default is baked in).")
    if SSH_HOSTKEY_POLICY not in ("strict", "off"):
        raise SystemExit("KA_SSH_HOSTKEY_POLICY must be strict|off.")
    if SSH_HOSTKEY_POLICY == "strict":
        try:
            seeded = os.path.getsize(SSH_KNOWN_HOSTS) > 0
        except OSError:
            seeded = False
        if not seeded:
            raise SystemExit(
                f"KA_SSH_HOSTKEY_POLICY=strict but {SSH_KNOWN_HOSTS} is missing/empty. "
                f"Seed it (e.g. `ssh-keyscan -f <device-hosts> > {SSH_KNOWN_HOSTS}`) or set "
                f"KA_SSH_HOSTKEY_POLICY=off for a trusted bootstrap only.")
    else:
        print("[keepalive-mcp] WARNING: SSH host-key verification is OFF "
              "(KA_SSH_HOSTKEY_POLICY=off) — MITM-exposed. Not for production.", flush=True)
    # Fail closed if there's no way to authenticate to devices: need a password
    # (TACACS/RADIUS/local) or a readable private key — at least one.
    if not SSH_PASSWORD and not (SSH_KEY and os.path.exists(SSH_KEY)):
        raise SystemExit(
            "No device SSH credential configured: set KA_SSH_PASSWORD (shared "
            "TACACS/RADIUS or local service account) and/or provide KA_SSH_KEY "
            "at a readable path. At least one is required.")

_check_config()


# ── database ──────────────────────────────────────────────────────────────────
_db: asyncpg.Pool | None = None

async def _db_pool() -> asyncpg.Pool:
    global _db
    if _db is None:
        _db = await asyncpg.create_pool(DB_DSN, min_size=2, max_size=10)
    return _db

async def _audit(who: str, who_upn: str, session_id: str | None,
                 device: str, verb: str, command: str | None,
                 rc: int, status: str, dur_ms: int, out_chars: int):
    try:
        pool = await _db_pool()
        await pool.execute(
            """INSERT INTO audit
               (who, who_upn, mcp_session_id, device, verb, command,
                rc, status, dur_ms, out_chars)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)""",
            who, who_upn, session_id, device, verb,
            (command or "")[:500], rc, status, dur_ms, out_chars)
    except Exception as e:
        print(f"[audit] write failed: {e}", flush=True)

async def _audit_intent(who: str, who_upn: str, session_id: str | None,
                        device: str, verb: str, command: str | None) -> bool:
    """Write-before-execute: durably record INTENT to mutate BEFORE touching the
    device (ARCHITECTURE.md mandate). Returns False if the row can't be written —
    the caller must then refuse the mutation (fail-stop), so no config push ever
    happens unaudited."""
    try:
        pool = await _db_pool()
        await pool.execute(
            """INSERT INTO audit
               (who, who_upn, mcp_session_id, device, verb, command,
                rc, status, dur_ms, out_chars)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)""",
            who, who_upn, session_id, device, verb,
            (command or "")[:500], -1, "intent", 0, 0)
        return True
    except Exception as e:
        print(f"[audit] INTENT write failed, refusing mutation: {e}", flush=True)
        return False

async def _load_devices() -> list[dict]:
    pool = await _db_pool()
    rows = await pool.fetch(
        "SELECT name, host, port, platform, username, role, site, description, "
        "       max_connections, enabled, source "
        "FROM devices WHERE enabled = true ORDER BY name")
    return [dict(r) for r in rows]


# ── JWKS / auth ───────────────────────────────────────────────────────────────
_jwks_client = None

def _jwks():
    global _jwks_client
    if _jwks_client is None:
        from jwt import PyJWKClient
        _jwks_client = PyJWKClient(
            f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys")
    return _jwks_client

def _identity(bearer: str) -> tuple[str, str, list[str]] | None:
    """Returns (oid, upn, roles) after full cryptographic validation, or None."""
    if not (bearer and TENANT and CLIENT_ID and REQUIRED_SCOPE and ALLOWED_CLIENTS):
        return None
    try:
        import jwt
        key = _jwks().get_signing_key_from_jwt(bearer).key
        claims = jwt.decode(bearer, key, algorithms=["RS256"], audience=AUDIENCE,
                            options={"require": ["exp"], "verify_aud": True})
        if claims.get("iss") not in (
                f"https://login.microsoftonline.com/{TENANT}/v2.0",
                f"https://sts.windows.net/{TENANT}/"):
            return None
        if claims.get("tid") != TENANT:
            return None
        if REQUIRED_SCOPE not in str(claims.get("scp", "")).split():
            return None
        if (claims.get("azp") or claims.get("appid")) not in ALLOWED_CLIENTS:
            return None
        oid  = claims.get("oid") or claims.get("sub") or "?"
        upn  = claims.get("preferred_username") or claims.get("upn") or oid
        roles = [str(r).lower() for r in (claims.get("roles") or [])]
        return oid, upn, roles
    except Exception:
        return None

def _bearer(ctx) -> str:
    try:
        h = ctx.request_context.request.headers.get("authorization", "") or ""
        return h[7:].strip() if h[:7].lower() == "bearer " else ""
    except Exception:
        return ""

def _session_id(ctx) -> str | None:
    try:
        return ctx.request_context.request.headers.get("mcp-session-id")
    except Exception:
        return None

def _auth(ctx):
    return _identity(_bearer(ctx))

def _require_read(ctx):
    """Returns (oid, upn, session_id) or error JSON string."""
    ident = _auth(ctx)
    if not ident:
        return json.dumps({"error": "unauthorized: valid Entra bearer required"})
    oid, upn, roles = ident
    if not (set(roles) & READ_ROLES):
        return json.dumps({"error": "forbidden: Keepalive.Read or Keepalive.Config role required"})
    return oid, upn, _session_id(ctx)

def _require_config(ctx):
    """Returns (oid, upn, session_id) or error JSON string."""
    ident = _auth(ctx)
    if not ident:
        return json.dumps({"error": "unauthorized: valid Entra bearer required"})
    oid, upn, roles = ident
    if not (set(roles) & CONFIG_ROLES):
        return json.dumps({"error": "forbidden: Keepalive.Config role required"})
    return oid, upn, _session_id(ctx)

# claim/release gate: Read tier in read-only mode (a session grants no write power),
# Config tier otherwise. Kept in lockstep with SESSION_ROLES above.
_require_session = _require_read if READONLY else _require_config

def _require_admin(ctx):
    """Returns (oid, upn, session_id) or error JSON string. Keepalive.Admin only —
    for fleet-shaping verbs (discover_new_device). The MCP tool list is advertised to
    everyone, so this call-time gate IS the boundary: non-admins see the verb but any
    call fails closed here."""
    ident = _auth(ctx)
    if not ident:
        return json.dumps({"error": "unauthorized: valid Entra bearer required"})
    oid, upn, roles = ident
    if not (set(roles) & ADMIN_ROLES):
        return json.dumps({"error": "forbidden: Keepalive.Admin role required"})
    return oid, upn, _session_id(ctx)


# ── per-user tools/list filtering (KA_FILTER_TOOL_LIST) ─────────────────────────
# The role set that makes each tool USABLE — mirrors the _require_* gate inside each
# tool EXACTLY. Consulted ONLY to decide what tools/list advertises; the gate, not this
# map, is the boundary. Keep in lockstep with each tool's _require_* call (a drift check
# in the tests asserts every registered tool appears here).
_TOOL_VISIBILITY: dict[str, set[str]] = {
    "find_devices":        READ_ROLES,
    "run":                 READ_ROLES,
    "read_output":         READ_ROLES,
    "apply":               CONFIG_ROLES,
    "claim_session":       SESSION_ROLES,
    "release_session":     SESSION_ROLES,
    "discover_new_device": ADMIN_ROLES,
}

def _filter_tools_for_roles(tools: list, roles: set[str]) -> list:
    """Keep only tools whose required-role set intersects the caller's roles. An unknown
    tool (not in _TOOL_VISIBILITY) defaults to the READ tier so a newly added read verb
    is never silently hidden — over-showing is a UX bug, the call-time gate still guards
    it. No roles (unauthenticated / role-less token) → empty list (fail closed)."""
    return [t for t in tools if roles & _TOOL_VISIBILITY.get(t.name, READ_ROLES)]


# ── device-management auth (REST /devices) ─────────────────────────────────────
def _identity_mgmt(bearer: str) -> tuple[str, str, list[str]] | None:
    """Identity for the device-management REST API. Unlike _identity (built for
    delegated user tokens and REQUIRES the user_impersonation scope), this also
    accepts an APP-ONLY (client-credentials) token so the headless admin CLI can
    authenticate with the app's certificate. Same crypto, issuer, tenant, audience
    and ALLOWED_CLIENTS gates; authorization is on the roles claim, which the caller
    checks against ADMIN_ROLES.

      • delegated token → carries a scope (scp); must include REQUIRED_SCOPE
      • app-only token  → carries no scp (client-credentials); authz rides roles

    The signature/issuer/tenant/audience/ALLOWED_CLIENTS(azp|appid) gates apply to
    both; the caller then checks roles against ADMIN_ROLES.
    NOTE: the calling app/SP appid must be in KA_ALLOWED_CLIENTS."""
    if not (bearer and TENANT and CLIENT_ID and ALLOWED_CLIENTS):
        return None
    try:
        import jwt
        key = _jwks().get_signing_key_from_jwt(bearer).key
        claims = jwt.decode(bearer, key, algorithms=["RS256"], audience=AUDIENCE,
                            options={"require": ["exp"], "verify_aud": True})
        if claims.get("iss") not in (
                f"https://login.microsoftonline.com/{TENANT}/v2.0",
                f"https://sts.windows.net/{TENANT}/"):
            return None
        if claims.get("tid") != TENANT:
            return None
        if (claims.get("azp") or claims.get("appid")) not in ALLOWED_CLIENTS:
            return None
        scp = str(claims.get("scp", "")).split()
        # Delegated tokens carry a scope (scp); app-only client-credentials tokens
        # carry none — their authz rides the roles claim (checked by the caller).
        # idtyp is optional and Entra often omits it, so absence-of-scp is the
        # reliable app-only signal; a wrong-app token is already rejected above by
        # the azp/appid ALLOWED_CLIENTS gate.
        if scp and REQUIRED_SCOPE not in scp:
            return None                          # delegated token with the wrong scope
        oid   = claims.get("oid") or claims.get("sub") or "?"
        upn   = (claims.get("preferred_username") or claims.get("upn")
                 or f"app:{claims.get('azp') or claims.get('appid')}")
        roles = [str(r).lower() for r in (claims.get("roles") or [])]
        return oid, upn, roles
    except Exception:
        return None


def _bearer_req(request) -> str:
    h = request.headers.get("authorization", "") or ""
    return h[7:].strip() if h[:7].lower() == "bearer " else ""


def _require_admin_req(request):
    """(identity, None) on success, or (None, JSONResponse) to return immediately."""
    ident = _identity_mgmt(_bearer_req(request))
    if not ident:
        return None, JSONResponse(
            {"error": "unauthorized: valid Entra bearer required"}, status_code=401)
    oid, upn, roles = ident
    if not (set(roles) & ADMIN_ROLES):
        return None, JSONResponse(
            {"error": "forbidden: Keepalive.Admin role required"}, status_code=403)
    return (oid, upn), None


# ── connection pool ───────────────────────────────────────────────────────────
class _Conn:
    """A single managed AsyncScrapli connection with state tracking."""
    __slots__ = ("device", "scrapli", "status", "since", "last_ok", "last_err")

    def __init__(self, device: str, scrapli: AsyncScrapli):
        self.device   = device
        self.scrapli  = scrapli
        self.status   = "CONNECTED"
        self.since    = time.time()
        self.last_ok  = time.time()
        self.last_err: str | None = None


class _Session:
    """A dedicated session: holds the device lock across multiple calls."""
    __slots__ = ("device", "conn", "mcp_session_id", "oid", "claimed_at", "last_active")

    def __init__(self, device: str, conn: _Conn, mcp_session_id: str, oid: str):
        self.device         = device
        self.conn           = conn
        self.mcp_session_id = mcp_session_id
        self.oid            = oid
        self.claimed_at     = time.time()
        self.last_active    = time.time()


class _ConnectRateLimiter:
    """Async token-scheduler that spaces new SSH connections to protect the
    downstream TACACS/AAA cluster. Each caller reserves the next free time slot and
    sleeps until it, so N concurrent connects drain at CONNECT_RATE/sec in arrival
    order instead of stampeding. Idle periods do not bank credit (strict spacing:
    the first connect after a quiet spell is immediate, never a saved-up burst)."""
    def __init__(self, rate_per_sec: float):
        self._interval = (1.0 / rate_per_sec) if rate_per_sec and rate_per_sec > 0 else 0.0
        self._lock     = asyncio.Lock()
        self._next     = 0.0   # monotonic time of the next free slot

    async def acquire(self):
        if self._interval <= 0:
            return
        async with self._lock:
            now  = time.monotonic()
            slot = now if now > self._next else self._next
            self._next = slot + self._interval
        delay = slot - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)

_connect_gate = _ConnectRateLimiter(CONNECT_RATE)


class Pool:
    """
    Per-device connection pool.

    _conns[device]   : list of _Conn (shared pool; 0..max_connections)
    _locks[device]   : asyncio.Lock — held for the duration of any command
    _sessions[sid]   : _Session — dedicated session holding the lock
    _device_meta[d]  : dict from DB (max_connections, platform, etc.)
    """

    def __init__(self):
        self._conns:       dict[str, list[_Conn]]   = {}
        self._locks:       dict[str, asyncio.Lock]  = {}
        self._sessions:    dict[str, _Session]       = {}
        self._meta:        dict[str, dict]            = {}
        self._tasks:       list[asyncio.Task]         = []
        self._running      = False
        # Devices whose removal/disable arrived while a dedicated session held them.
        # We refuse to yank a live session; the release path drains them (below).
        self._pending_removal: set[str]              = set()

    # ── startup / shutdown ───────────────────────────────────────────
    async def start(self):
        self._running = True
        devices = await _load_devices()
        for d in devices:
            self._meta[d["name"]] = d
            self._locks[d["name"]] = asyncio.Lock()
            self._conns[d["name"]] = []
        # Initial connects run in the BACKGROUND: with the connect throttle enabled a
        # cold start warms devices at CONNECT_RATE/sec, so blocking here would delay app
        # readiness by ~(device count / rate) seconds. Instead we become ready at once
        # and warm up in the background; a call for a not-yet-warm device gets the normal
        # "device_down" until its slot comes up (PEs/important devices warm first by list
        # order). The keepalive loop retries any that fail.
        self._tasks.append(asyncio.create_task(
            self._initial_warmup([d["name"] for d in devices])))
        self._tasks.append(asyncio.create_task(self._keepalive_loop()))
        self._tasks.append(asyncio.create_task(self._session_reaper()))
        self._tasks.append(asyncio.create_task(self._listen_devices()))

    async def stop(self):
        self._running = False
        for t in self._tasks:
            t.cancel()
        for conns in self._conns.values():
            for c in conns:
                try:
                    await c.scrapli.close()
                except Exception:
                    pass

    # ── connection lifecycle ─────────────────────────────────────────
    async def _open(self, device: str) -> _Conn | None:
        meta = self._meta.get(device)
        if not meta:
            return None
        # Pace new connects so a mass cold-start / reconnect doesn't stampede the
        # device-side TACACS/AAA cluster (see CONNECT_RATE). Covers every connect path:
        # cold-start warmup, keepalive-loop reconnect, and hot-add reconcile all land here.
        await _connect_gate.acquire()
        ssh_cfg = SSH_CONFIG if os.path.exists(SSH_CONFIG) else ""
        strict = SSH_HOSTKEY_POLICY == "strict"
        # Assemble client-auth creds: password (TACACS/RADIUS/local) and/or a private
        # key. Only pass a key if the file actually exists, so a password-only
        # deployment doesn't fail asyncssh trying to load a nonexistent key. asyncssh
        # negotiates password AND keyboard-interactive from auth_password, which covers
        # the usual TACACS prompt flows.
        auth_kwargs: dict = {"auth_username": meta["username"]}
        if SSH_PASSWORD:
            auth_kwargs["auth_password"] = SSH_PASSWORD
        if SSH_KEY and os.path.exists(SSH_KEY):
            auth_kwargs["auth_private_key"] = SSH_KEY
        if SSH_SECONDARY:
            auth_kwargs["auth_secondary"] = SSH_SECONDARY   # 'enable' after login
        # asyncssh.connect() kwargs (via scrapli transport_options). Only the SSH transport
        # keepalives are always set; the legacy-algorithm allowances are added ONLY when the
        # operator opted in via env, so the default posture stays modern-only (see above).
        asyncssh_opts: dict = {"keepalive_interval": 20, "keepalive_count_max": 3}
        if SSH_KEX_ALGS:
            asyncssh_opts["kex_algs"] = SSH_KEX_ALGS
        if SSH_HOSTKEY_ALGS:
            asyncssh_opts["server_host_key_algs"] = SSH_HOSTKEY_ALGS
        if SSH_ENCRYPT_ALGS:
            asyncssh_opts["encryption_algs"] = SSH_ENCRYPT_ALGS
        if SSH_MAC_ALGS:
            asyncssh_opts["mac_algs"] = SSH_MAC_ALGS
        try:
            sc = AsyncScrapli(
                host=meta["host"], port=meta["port"],
                auth_strict_key=strict,                       # reject unknown/changed host keys
                ssh_known_hosts_file=SSH_KNOWN_HOSTS if strict else "",
                platform=meta["platform"],
                transport="asyncssh",
                ssh_config_file=ssh_cfg,
                transport_options={"asyncssh": asyncssh_opts},
                timeout_socket=15, timeout_transport=15, timeout_ops=60,
                **auth_kwargs)
            await sc.open()
            conn = _Conn(device, sc)
            await _audit("pool", "pool", None, device, "pool-connect",
                         meta["host"], 0, "connected", 0, 0)
            return conn
        except Exception as e:
            await _audit("pool", "pool", None, device, "pool-connect",
                         meta["host"], 1, f"error: {e}", 0, 0)
            return None

    async def _init_device(self, device: str):
        conn = await self._open(device)
        if conn:
            self._conns[device].append(conn)
        # device starts as DOWN if connection failed; keepalive_loop will retry

    async def _initial_warmup(self, names: list[str]):
        """Warm the whole fleet in the background (see start()). Connects are paced by
        the shared connect throttle, so this fans out but drains at CONNECT_RATE/sec."""
        await asyncio.gather(*[self._init_device(n) for n in names],
                             return_exceptions=True)

    # ── dynamic reconcile (LISTEN/NOTIFY driven) ─────────────────────
    async def _listen_devices(self):
        """Hold a dedicated LISTEN on 'keepalive_devices' and reconcile the pool to
        the `devices` table as rows change — no restart, no bouncing other sessions.
        Reconnects on connection loss (RECONNECT_WAIT backoff)."""
        while self._running:
            conn = None
            try:
                conn = await asyncpg.connect(DB_DSN)
                await conn.add_listener("keepalive_devices", self._on_device_notify)
                print("[keepalive-mcp] device-listener active "
                      "(LISTEN keepalive_devices)", flush=True)
                while self._running:
                    await asyncio.sleep(KEEPALIVE_SECS)
                    await conn.execute("SELECT 1")   # liveness; raises on drop
            except asyncio.CancelledError:
                raise
            except Exception as e:
                print(f"[keepalive-mcp] device-listener down: {e}; "
                      f"retry in {RECONNECT_WAIT}s", flush=True)
                await asyncio.sleep(RECONNECT_WAIT)
            finally:
                if conn is not None:
                    try:
                        await conn.close()
                    except Exception:
                        pass

    def _on_device_notify(self, connection, pid, channel, payload):
        # asyncpg fires this synchronously; do the async reconcile in a task.
        asyncio.create_task(self._reconcile_from_notify(payload))

    async def _reconcile_from_notify(self, payload: str):
        try:
            msg  = json.loads(payload)
            op   = msg.get("op")
            name = msg.get("name")
        except Exception:
            return
        if not name:
            return
        if op == "DELETE":
            await self.reconcile_remove(name)
            return
        # INSERT/UPDATE: re-read the authoritative row (never trust the payload).
        try:
            db  = await _db_pool()
            row = await db.fetchrow(
                "SELECT name, host, port, platform, username, role, site, "
                "description, max_connections, enabled, source "
                "FROM devices WHERE name = $1", name)
        except Exception as e:
            print(f"[keepalive-mcp] reconcile fetch failed for {name}: {e}", flush=True)
            return
        if row is None or not row["enabled"]:
            await self.reconcile_remove(name)     # deleted or disabled → drain
        else:
            await self.reconcile_upsert(dict(row))

    async def reconcile_upsert(self, row: dict):
        """Add a new device or update an existing one, touching ONLY this device."""
        name = row["name"]
        if name not in self._meta:
            self._locks.setdefault(name, asyncio.Lock())
            self._conns.setdefault(name, [])
            self._meta[name] = row
            self._pending_removal.discard(name)
            await self._init_device(name)
            print(f"[keepalive-mcp] device added: {name} ({row['host']})", flush=True)
            return
        self._pending_removal.discard(name)   # re-enabled before it drained
        old = self._meta[name]
        self._meta[name] = row                # site/role/desc/cap changes always take
        conn_fields = ("host", "port", "platform", "username")
        if not any(old.get(f) != row.get(f) for f in conn_fields):
            return                            # nothing connection-affecting changed
        if any(s.device == name for s in self._sessions.values()):
            # Live session holds it — don't yank. New endpoint/creds take effect
            # when the session releases and the keepalive loop reconnects.
            print(f"[keepalive-mcp] device {name} changed but is claimed; "
                  f"deferring reconnect", flush=True)
            return
        lock = self._locks[name]
        async with lock:
            for c in list(self._conns.get(name, [])):
                try:
                    await c.scrapli.close()
                except Exception:
                    pass
            self._conns[name] = []
        await self._init_device(name)
        print(f"[keepalive-mcp] device reconnected: {name} ({row['host']})", flush=True)

    async def reconcile_remove(self, name: str) -> bool:
        """Drop a device from the live pool. Fail-closed if a session holds it:
        record it pending and let the release path drain it. Returns True if the
        device is now gone, False if deferred."""
        if name not in self._meta and name not in self._pending_removal:
            return True
        if any(s.device == name for s in self._sessions.values()):
            self._pending_removal.add(name)
            print(f"[keepalive-mcp] device {name} removal deferred (session active)",
                  flush=True)
            return False
        await self._drop_device(name)
        return True

    async def _drop_device(self, name: str):
        lock = self._locks.get(name)
        if lock is not None:
            async with lock:
                for c in list(self._conns.get(name, [])):
                    try:
                        await c.scrapli.close()
                    except Exception:
                        pass
        self._conns.pop(name, None)
        self._locks.pop(name, None)
        self._meta.pop(name, None)
        self._pending_removal.discard(name)
        print(f"[keepalive-mcp] device removed: {name}", flush=True)

    # ── keepalive ────────────────────────────────────────────────────
    async def _keepalive_loop(self):
        """Every KEEPALIVE_SECS: send \\t to each idle connection to validate it.
        If a device has no connection and it's not held in a session, try reconnect
        every RECONNECT_WAIT seconds."""
        _next_reconnect: dict[str, float] = {}
        while self._running:
            await asyncio.sleep(KEEPALIVE_SECS)
            for device, conns in list(self._conns.items()):
                # held by a dedicated session — don't poke it
                held = any(s.device == device for s in self._sessions.values())

                for conn in list(conns):
                    if held:
                        continue
                    try:
                        # SSH transport keepalives (asyncssh) keep the session
                        # alive at the protocol level. Here we just verify the
                        # connection object is still in an alive state.
                        if not conn.scrapli.isalive():
                            raise Exception("transport reports not alive")
                        conn.last_ok = time.time()
                        conn.status  = "CONNECTED"
                    except Exception as e:
                        conn.status   = "DOWN"
                        conn.last_err = str(e)
                        conns.remove(conn)
                        try:
                            await conn.scrapli.close()
                        except Exception:
                            pass
                        await _audit("pool", "pool", None, device,
                                     "pool-disconnect", None, 1, str(e), 0, 0)

                # no connections and none held → try reconnect on timer
                if not conns and not held:
                    now = time.time()
                    if now >= _next_reconnect.get(device, 0):
                        _next_reconnect[device] = now + RECONNECT_WAIT
                        conn = await self._open(device)
                        if conn:
                            conns.append(conn)
                            _next_reconnect.pop(device, None)

    # ── session reaper ───────────────────────────────────────────────
    async def _session_reaper(self):
        """Release dedicated sessions that have been idle past DEDICATED_TTL."""
        while self._running:
            await asyncio.sleep(30)
            now = time.time()
            for sid, sess in list(self._sessions.items()):
                if now - sess.last_active > DEDICATED_TTL:
                    await self._release_session_internal(sid, reason="ttl-expired")

    async def _release_session_internal(self, sid: str, reason: str = "released"):
        sess = self._sessions.pop(sid, None)
        if not sess:
            return
        # platform-aware teardown: abort any pending candidate config
        await self._teardown_config_state(sess.conn)
        # return connection to pool if under cap, else close it
        meta = self._meta.get(sess.device, {})
        cap  = meta.get("max_connections", 2)
        pool = self._conns.get(sess.device, [])
        if len(pool) < cap:
            sess.conn.status = "CONNECTED"
            pool.append(sess.conn)
        else:
            try:
                await sess.conn.scrapli.close()
            except Exception:
                pass
        if self._locks.get(sess.device, asyncio.Lock()).locked():
            try:
                self._locks[sess.device].release()
            except RuntimeError:
                pass
        await _audit(sess.oid, sess.oid, sid, sess.device,
                     "release", reason, 0, reason, 0, 0)
        # If this device was disabled/removed while the session held it, drain it
        # now — the session is gone and claim() is exclusive, so nothing else holds it.
        if sess.device in self._pending_removal:
            await self.reconcile_remove(sess.device)

    async def _teardown_config_state(self, conn: _Conn):
        """Ensure the connection is back at a clean exec prompt before returning it
        to the pool. On commit-capable platforms, abort any pending candidate config."""
        platform = self._meta.get(conn.device, {}).get("platform", "")
        try:
            if platform == "cisco_iosxr":
                await conn.scrapli.send_command("abort", timeout_ops=10)
            elif platform == "juniper_junos":
                await conn.scrapli.send_command("rollback 0", timeout_ops=10)
                await conn.scrapli.send_command("exit", timeout_ops=10)
            elif platform == "arista_eos":
                await conn.scrapli.send_command("abort", timeout_ops=10)
        except Exception:
            pass

    # ── borrow (for normal single commands) ─────────────────────────
    async def borrow(self, device: str) -> tuple[_Conn, asyncio.Lock] | None:
        """Return (conn, lock) with the lock ALREADY ACQUIRED. Caller must release."""
        conns = self._conns.get(device)
        if not conns:
            return None
        lock = self._locks[device]
        await lock.acquire()
        # re-check after acquiring — might have been taken by a dedicated session
        conns = self._conns.get(device)
        if not conns:
            lock.release()
            return None
        return conns[0], lock

    # ── claim (dedicated session) ────────────────────────────────────
    async def claim(self, device: str, mcp_session_id: str, oid: str) -> dict:
        """Hand the caller an exclusive connection. Returns session info or error."""
        meta = self._meta.get(device)
        if not meta:
            return {"error": f"unknown device '{device}'"}

        # already has a dedicated session for this device+mcp_session+principal?
        for sid, sess in self._sessions.items():
            if sess.device == device and sess.mcp_session_id == mcp_session_id \
                    and sess.oid == oid:
                sess.last_active = time.time()
                return {"status": "existing", "session_id": sid,
                        "claimed_at": sess.claimed_at}

        # check if already claimed by someone else
        for sid, sess in self._sessions.items():
            if sess.device == device:
                idle = time.time() - sess.last_active
                ttl_left = max(0, DEDICATED_TTL - idle)
                return {
                    "error":      "device_busy",
                    "device":     device,
                    "reason":     "dedicated session active",
                    "held_since": sess.claimed_at,
                    "idle_for_seconds":        int(idle),
                    "auto_release_in_seconds": int(ttl_left),
                }

        cap   = meta.get("max_connections", 2)
        conns = self._conns.get(device, [])
        lock  = self._locks[device]

        await lock.acquire()

        if not conns:
            lock.release()
            return {"error": "device_down", "device": device,
                    "reason": "no connection available — device may be unreachable"}

        dedicated = conns.pop(0)  # take the warm conn from the pool

        import secrets
        sid = secrets.token_hex(8)
        self._sessions[sid] = _Session(device, dedicated, mcp_session_id, oid)

        # spin a replacement connection in background (if under cap)
        if len(conns) < cap - 1:
            asyncio.create_task(self._replace_conn(device))

        lock.release()  # pool is no longer shared — dedicated session has its own conn

        return {"status": "claimed", "session_id": sid,
                "device": device, "claimed_at": time.time(),
                "note": "pass session_id to run/apply to use this dedicated connection"}

    async def _replace_conn(self, device: str):
        conn = await self._open(device)
        if conn:
            self._conns.setdefault(device, []).append(conn)

    def get_session_conn(self, session_id: str, mcp_session_id: str, oid: str) -> _Conn | None:
        sess = self._sessions.get(session_id)
        # Bind to BOTH the MCP session id AND the authenticated principal (oid),
        # so a different principal cannot reuse another's dedicated connection.
        if sess and sess.mcp_session_id == mcp_session_id and sess.oid == oid:
            sess.last_active = time.time()
            return sess.conn
        return None

    # ── status ───────────────────────────────────────────────────────
    def status_data(self) -> list[dict]:
        rows = []
        for device, meta in self._meta.items():
            conns  = self._conns.get(device, [])
            held   = {sid: s for sid, s in self._sessions.items() if s.device == device}
            if conns:
                state = "CONNECTED"
                last_ok = max((c.last_ok for c in conns), default=0)
            elif held:
                state = "CLAIMED"
                last_ok = max((s.conn.last_ok for s in held.values()), default=0)
            else:
                state = "DOWN"
                last_ok = 0
            rows.append({
                "name":     device,
                "host":     meta["host"],
                "platform": meta["platform"],
                "role":     meta.get("role"),
                "site":     meta.get("site"),
                "state":    state,
                "pool_size": len(conns),
                "sessions":  len(held),
                "last_ok":   int(last_ok),
            })
        return rows


pool = Pool()


# ── config diff helpers ───────────────────────────────────────────────────────
def _norm(cfg: str) -> list[str]:
    return [l.rstrip() for l in cfg.splitlines()
            if not any(p.search(l) for p in _VOLATILE)]

def _diff(before: str, after: str):
    b, a = _norm(before), _norm(after)
    diff = "\n".join(difflib.unified_diff(
        b, a, fromfile="running-before", tofile="running-after", lineterm=""))
    bs = {l.strip() for l in b if l.strip()}
    added   = [l.strip() for l in a if l.strip() and l.strip() not in bs]
    removed = [l.strip() for l in b if l.strip() and l.strip() not in {l.strip() for l in a if l.strip()}]
    return diff, added, removed

def _verify(intended: list[str], after: str) -> dict:
    after_set = {l.strip() for l in after.splitlines() if l.strip()}
    present = [l for l in intended if l.strip() in after_set]
    missing = [l for l in intended if l.strip() not in after_set]
    return {"expected_present": present, "expected_MISSING": missing, "match": not missing}

def _cap(s: str) -> str:
    if len(s) <= MAX_OUT:
        return s
    return s[:MAX_OUT] + f"\n\n[…truncated {len(s) - MAX_OUT} of {len(s)} chars]"


# ── large-output capture (RAM only; never persisted — output can contain config) ───────
# Output over MAX_OUT is stashed here and returned as a handle + preview instead of a lossy
# truncation, so the LLM can grep/page the whole thing via read_output. Per-principal (oid),
# TTL-expired, count-capped.
_captures: dict[str, dict] = {}

def _prune_captures() -> None:
    now = time.time()
    for cid in [c for c, v in _captures.items() if now - v["created"] > CAPTURE_TTL]:
        _captures.pop(cid, None)
    while len(_captures) > CAPTURE_MAX:
        _captures.pop(min(_captures, key=lambda c: _captures[c]["created"]), None)

def _capture_output(oid: str, device: str, command: str, text: str) -> dict:
    """Stash a large output and return a handle + preview + how to explore it."""
    _prune_captures()
    cid   = secrets.token_hex(4)
    lines = text.splitlines()
    _captures[cid] = {"oid": oid, "device": device, "command": command,
                      "lines": lines, "chars": len(text), "created": time.time()}
    return {
        "captured":    True,
        "capture_id":  cid,
        "device":      device,
        "command":     command,
        "total_lines": len(lines),
        "total_chars": len(text),
        "preview":     text[:4000] + ("\n…" if len(text) > 4000 else ""),
        "note": (f"Output is large ({len(lines)} lines) — captured server-side for "
                 f"~{CAPTURE_TTL // 60}m. read_output(capture_id='{cid}', pattern='<regex>') "
                 f"to grep, or (offset=, limit=) to page. Cheaper if you know the target: "
                 f"re-run with an on-device filter, e.g. '{command} | include <x>'."),
    }


# ── FastMCP ───────────────────────────────────────────────────────────────────
def _derive_allowed_hosts() -> list[str]:
    if ALLOWED_HOSTS:
        return ALLOWED_HOSTS
    from urllib.parse import urlparse
    hosts = {f"{BIND}:{PORT}", f"127.0.0.1:{PORT}", "127.0.0.1", "localhost"}
    h = urlparse(REDIRECT_URI).netloc
    if h:
        hosts.add(h)
    return sorted(hosts)

_ALLOWED_HOSTS = _derive_allowed_hosts()

_RO_BANNER = ("READ-ONLY MODE: this server only runs read commands "
              "(show/ping/traceroute/dir/verify) via `run`; configuration changes are "
              "disabled and the apply tool is not available — do not attempt to push config. "
              if READONLY else "")
# Role sentence for the instructions — accurate per mode. In read-only the session verbs
# are Read-tier (see SESSION_ROLES); in read-write they remain Config alongside apply.
_SESSION_ROLE_NOTE = (
    "In this read-only deployment claim_session/release_session are available to "
    "Keepalive.Read for connection affinity (e.g. ASA `changeto` context navigation). "
    if READONLY else
    "A Keepalive.Config role additionally allows apply and session management. ")

mcp = FastMCP(
    "keepalive-mcp",
    instructions=(
        _RO_BANNER +
        "Reach into Cisco (and multi-vendor) network gear over SSH. "
        "find_devices searches the inventory; run executes read-only commands "
        "(show, ping, traceroute) and returns structured JSON when parsed=true; "
        "apply pushes config — confirm=false is a dry-run, confirm=true applies. "
        "claim_session reserves an exclusive connection for multi-command work; "
        "release_session returns it. A Keepalive.Read role allows find_devices and run. " +
        _SESSION_ROLE_NOTE +
        "discover_new_device (Keepalive.Admin only) onboards a device by name + host. "
        "Large command output is auto-captured; read_output greps (pattern=) or pages "
        "(offset=/limit=) it by capture_id. For a known target, filter on the device first "
        "(e.g. `show access-list | include <x>`) — far cheaper than pulling the whole dump."),
    host=BIND, port=PORT, stateless_http=False, json_response=False,
    streamable_http_path="/",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=_ALLOWED_HOSTS,
        allowed_origins=[f"https://{h}" for h in _ALLOWED_HOSTS] + [f"http://{h}" for h in _ALLOWED_HOSTS]))


# ── tools ─────────────────────────────────────────────────────────────────────
@mcp.tool()
async def find_devices(ctx: Context, query: str = "", role: str = "",
                       platform: str = "", site: str = "",
                       limit: int = 50, cursor: int = 0) -> str:
    """SEARCH the device inventory — never dumps the whole fleet.
    query = name glob/substring ('rtr*', 'core', 'pe'). role/platform/site = exact filters.
    Returns {matched, returned, next_cursor, devices[]}. Page with cursor when matched > returned."""
    r = _require_read(ctx)
    if isinstance(r, str):
        return r
    oid, upn, sid = r
    t0 = time.monotonic()

    devices = await _load_devices()
    q = query.strip().lower()

    def _match(d):
        name = d["name"].lower()
        if q and not (q in name or fnmatch.fnmatch(name, q)):
            return False
        for field, val in (("role", role), ("platform", platform), ("site", site)):
            if val and str(d.get(field, "")).lower() != val.strip().lower():
                return False
        return True

    matched = [d for d in devices if _match(d)]
    page    = matched[cursor: cursor + max(1, limit)]
    nxt     = cursor + limit if cursor + limit < len(matched) else None

    # annotate with live pool state
    status_map = {s["name"]: s["state"] for s in pool.status_data()}
    out = {
        "matched":     len(matched),
        "returned":    len(page),
        "next_cursor": nxt,
        "devices": [{
            "name":     d["name"],
            "host":     d["host"],
            "role":     d.get("role"),
            "platform": d["platform"],
            "site":     d.get("site"),
            "state":    status_map.get(d["name"], "UNKNOWN"),
        } for d in page],
    }
    if nxt:
        out["note"] = f"showing {len(page)} of {len(matched)} — refine or page with cursor={nxt}"

    dur = int((time.monotonic() - t0) * 1000)
    asyncio.create_task(_audit(oid, upn, sid, "(inventory)",
                                "read", f"find q={query!r}", 0, "ok", dur, len(json.dumps(out))))
    return json.dumps(out, indent=2)


@mcp.tool()
async def run(ctx: Context, device: str, command: str,
              parsed: bool = False, session_id: str | None = None,
              capture: bool = False) -> str:
    """Run a READ-ONLY command on a device (show, ping, traceroute, dir, verify;
    `changeto` for ASA multi-context navigation).
    parsed=true returns structured JSON via TextFSM where supported.
    Pass session_id if you have a dedicated session from claim_session — recommended for
    ASA context work so `changeto` stays scoped to your own connection.
    LARGE OUTPUT: anything over the char cap is auto-captured server-side and returned as a
    capture_id + preview (not truncated) — use read_output to grep/page it. capture=true
    forces that even for smaller output. Cheaper for a known target: filter on the device,
    e.g. 'show access-list | include <x>' or 'show run | section <x>'.
    Write commands (configure/reload/copy/write/clear) are refused."""
    r = _require_read(ctx)
    if isinstance(r, str):
        return r
    oid, upn, mcp_sid = r
    cmd = command.strip()

    blocked = _blocked_read(cmd)
    if blocked:
        return json.dumps({"error": blocked})
    if not cmd.lower().startswith(READ_OK):
        hint = ("this server is read-only — only show/ping/traceroute/dir/verify are permitted"
                if READONLY else "use apply to push config")
        return json.dumps({"error": f"'{cmd.split()[0]}' is not a read-only command; {hint}"})

    t0 = time.monotonic()
    conn_obj: _Conn | None = None
    lock: asyncio.Lock | None = None
    dedicated = False

    if session_id:
        conn_obj = pool.get_session_conn(session_id, mcp_sid or "", oid)
        if not conn_obj:
            return json.dumps({"error": "invalid or expired session_id"})
        dedicated = True

    try:
        if not dedicated:
            borrowed = await pool.borrow(device)
            if borrowed is None:
                meta = pool._meta.get(device)
                if meta is None:
                    return json.dumps({"error": f"unknown device '{device}' — call find_devices"})
                return json.dumps({"error": "device_down", "device": device,
                                   "reason": "no connection available"})
            conn_obj, lock = borrowed

        resp = await conn_obj.scrapli.send_command(cmd)
        raw = _redact_secrets(resp.result or "")     # redact the RAW device text first
        if parsed:
            try:
                p = resp.textfsm_parse_output()
                # parse runs on the original; redact the serialized structure too
                out = _redact_secrets(json.dumps(p, indent=2)) if p else raw
            except Exception:
                out = raw
        else:
            out = raw
        conn_obj.last_ok = time.time()
        rc, status = 0, "ok"
    except Exception as e:
        out    = json.dumps({"error": str(e)})
        rc, status = 1, "error"
    finally:
        if lock and lock.locked():
            lock.release()

    dur = int((time.monotonic() - t0) * 1000)
    asyncio.create_task(_audit(oid, upn, session_id or mcp_sid, device,
                                "read", cmd, rc, status, dur, len(out)))
    # Large output: stash it and return a searchable handle instead of a lossy truncation,
    # so the LLM can grep/page the whole thing via read_output rather than lose it.
    if status == "ok" and (capture or len(out) > MAX_OUT):
        return json.dumps(_capture_output(oid, device, cmd, out), indent=2)
    return _cap(out)


@mcp.tool()
async def read_output(ctx: Context, capture_id: str, pattern: str = "",
                      offset: int = 0, limit: int = 200, context: int = 0,
                      block: bool = False) -> str:
    """Examine a large output captured by a prior run (which returned a capture_id).
    pattern = grep (case-insensitive regex): returns matching lines with line numbers.
    block=true makes each match return its whole INDENTATION STANZA instead of one line —
    the column-0 header + everything indented under it (e.g. an ASA object-group ACE plus
    its expanded host/port rules, or an IOS `interface` and its sub-lines). Combine with
    context=N to also include N lines above the header (grabs the preceding ACL `remark`).
    context alone (no block) just adds N lines around each match. No pattern = page: lines
    offset..offset+limit. Captures are per-user and expire — re-run the command if it's gone."""
    r = _require_read(ctx)
    if isinstance(r, str):
        return r
    oid, upn, sid = r
    _prune_captures()
    cap = _captures.get(capture_id)
    if not cap or cap["oid"] != oid:
        return json.dumps({"error": f"capture '{capture_id}' not found or expired "
                           f"(they last ~{CAPTURE_TTL // 60}m and are per-user) — re-run the command"})
    lines = cap["lines"]; total = len(lines)
    limit = max(1, min(limit, 2000))
    if pattern:
        try:
            rx = re.compile(pattern, re.I)
        except re.error as e:
            return json.dumps({"error": f"bad regex: {e}"})
        cn = max(0, min(context, 10))
        indent = lambda s: len(s) - len(s.lstrip())
        ranges: list[list[int]] = []; matches = 0
        for i, ln in enumerate(lines):
            if not rx.search(ln):
                continue
            matches += 1
            if block:
                h = i
                while h > 0 and indent(lines[h]) != 0:      # nearest column-0 header at/above
                    h -= 1
                e = h + 1
                while e < total and indent(lines[e]) != 0:  # span to the next column-0 line
                    e += 1
                ranges.append([max(0, h - cn), e])
            else:
                ranges.append([max(0, i - cn), min(total, i + cn + 1)])
            if matches >= limit:
                break
        ranges.sort()
        merged: list[list[int]] = []                        # coalesce overlapping stanzas
        for s, e in ranges:
            if merged and s <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], e)
            else:
                merged.append([s, e])
        sep  = "\n--\n" if block else "\n"
        body = sep.join("\n".join(f"{k+1}: {lines[k]}" for k in range(s, e)) for s, e in merged)
        meta = {"capture_id": capture_id, "device": cap["device"], "command": cap["command"],
                "pattern": pattern, "mode": "block" if block else "lines",
                "matches": matches, "blocks": len(merged), "total_lines": total,
                "note": "match limit hit — refine the pattern or raise limit" if matches >= limit else ""}
    else:
        offset = max(0, offset)
        chunk  = lines[offset: offset + limit]
        body   = "\n".join(f"{offset+k+1}: {ln}" for k, ln in enumerate(chunk))
        nxt    = offset + limit if offset + limit < total else None
        meta = {"capture_id": capture_id, "device": cap["device"], "command": cap["command"],
                "total_lines": total, "returned": len(chunk), "next_offset": nxt}
    asyncio.create_task(_audit(oid, upn, sid, cap["device"], "read",
                                f"read_output {pattern or ('@' + str(offset))}", 0, "ok", 0, len(body)))
    return json.dumps(meta, indent=2) + "\n\n" + _cap(body)


async def apply(ctx: Context, device: str, config: str,
                confirm: bool = False, save: bool = False,
                session_id: str | None = None) -> str:
    """Push config to a device. Lines are what you'd type in 'conf t', one per line.
    confirm=false (default) = DRY-RUN preview; call again with confirm=true to apply.
    save=true writes memory ONLY on full success.
    SAFETY: halts at the first rejected line, never saves a failed change.
    On live-apply platforms (IOS/XE/ASA) partial state is left live — use the returned
    diff to assess and fix. On commit-capable platforms (XR/Junos/EOS) nothing lands on failure.
    Pass session_id to use a dedicated connection from claim_session."""
    r = _require_config(ctx)
    if isinstance(r, str):
        return r
    oid, upn, mcp_sid = r

    lines = [l for l in config.splitlines() if l.strip()]
    if not lines:
        return json.dumps({"error": "no config lines provided"})

    if not confirm:
        return json.dumps({"dry_run": True, "device": device, "would_send": lines,
                           "note": "review, then call apply(..., confirm=true)"}, indent=2)

    # write-before-execute: refuse to push config we cannot audit
    if not await _audit_intent(oid, upn, session_id or mcp_sid, device,
                               "write-intent", "; ".join(lines)[:500]):
        return json.dumps({"error": "audit unavailable — refusing to apply config "
                           "(write-before-execute). Retry once auditing is healthy."})

    t0 = time.monotonic()
    conn_obj: _Conn | None = None
    lock: asyncio.Lock | None = None
    dedicated = False

    if session_id:
        conn_obj = pool.get_session_conn(session_id, mcp_sid or "", oid)
        if not conn_obj:
            return json.dumps({"error": "invalid or expired session_id"})
        dedicated = True

    try:
        if not dedicated:
            borrowed = await pool.borrow(device)
            if borrowed is None:
                meta = pool._meta.get(device)
                if meta is None:
                    return json.dumps({"error": f"unknown device '{device}'"})
                return json.dumps({"error": "device_down", "device": device})
            conn_obj, lock = borrowed

        platform = pool._meta.get(device, {}).get("platform", "cisco_iosxe")

        if platform in COMMIT_CAP:
            result = await _apply_commit(conn_obj, device, lines, save, platform)
        else:
            result = await _apply_live(conn_obj, device, lines, save)

        conn_obj.last_ok = time.time()
        rc     = 0 if result.get("status") == "applied" else 1
        status = result.get("status", "unknown")

    except Exception as e:
        result = {"error": str(e), "saved": False}
        rc, status = 1, "error"
    finally:
        if lock and lock.locked():
            lock.release()

    result = _redact_result(result)          # mask secrets in the running-config diff
    dur = int((time.monotonic() - t0) * 1000)
    diff_text = result.get("config_diff", "")
    asyncio.create_task(_audit(oid, upn, session_id or mcp_sid, device,
                                "write", "; ".join(lines)[:500],
                                rc, status, dur, len(diff_text)))
    return json.dumps(result, indent=2)


# apply is the only write verb — register it ONLY when not read-only. In read-only mode
# it is never added to the MCP tool list, so the LLM cannot see or call config-push.
if not READONLY:
    mcp.tool()(apply)


async def _apply_live(conn: _Conn, device: str, lines: list[str], save: bool) -> dict:
    """IOS / IOS-XE / ASA / NX-OS: line-live, halt on first error, no auto-revert."""
    before = (await conn.scrapli.send_command("show running-config")).result
    resp   = await conn.scrapli.send_configs(lines, stop_on_failed=True)
    after  = (await conn.scrapli.send_command("show running-config")).result
    diff_text, added, removed = _diff(before, after)

    applied = [r.channel_input for r in resp if not r.failed]
    failed  = next((r for r in resp if r.failed), None)

    result = {
        "device":          device,
        "intended":        lines,
        "actual_net_change": {"added": added, "removed": removed}
                              if (added or removed) else "NONE",
        "config_diff":     diff_text or "(no net change)",
        "saved":           False,
    }

    if failed:
        result["status"]         = "ABORTED"
        result["failed_command"] = failed.channel_input
        result["device_said"]    = (failed.result or "")[-400:]
        result["not_sent"]       = lines[len(applied) + 1:]
        result["warning"]        = (
            "Lines in actual_net_change ARE live in running-config but NOT saved. "
            "Assess and fix before retrying.")
        return result

    result["status"]       = "applied"
    result["verification"] = _verify(lines, after)
    if save:
        await conn.scrapli.send_command("write memory")
        result["saved"] = True
    return result


async def _apply_commit(conn: _Conn, device: str, lines: list[str], save: bool,
                         platform: str) -> dict:
    """IOS-XR / EOS / Junos: send to candidate buffer, commit on success, abort on any failure."""
    resp   = await conn.scrapli.send_configs(lines, stop_on_failed=True)
    applied = [r.channel_input for r in resp if not r.failed]
    failed  = next((r for r in resp if r.failed), None)

    if failed:
        # abort — nothing lands
        await pool._teardown_config_state(conn)
        return {
            "device":          device,
            "status":          "ABORTED",
            "failed_command":  failed.channel_input,
            "device_said":     (failed.result or "")[-400:],
            "not_sent":        lines[len(applied) + 1:],
            "note":            "candidate config discarded — nothing applied to running-config",
            "saved":           False,
        }

    # commit
    if platform == "cisco_iosxr":
        commit_resp = await conn.scrapli.send_command("commit")
    elif platform == "arista_eos":
        commit_resp = await conn.scrapli.send_command("commit")
    else:  # juniper_junos
        commit_resp = await conn.scrapli.send_command("commit")

    after     = (await conn.scrapli.send_command("show running-config")).result
    diff_text, added, removed = _diff("", after)  # no pre-snapshot for commit path

    return {
        "device":          device,
        "status":          "applied",
        "intended":        lines,
        "commit_output":   (commit_resp.result or "")[:500],
        "actual_net_change": {"added": added, "removed": removed} if (added or removed) else "NONE",
        "config_diff":     diff_text or "(no net change)",
        "saved":           True,  # commit == persisted on these platforms
    }


@mcp.tool()
async def claim_session(ctx: Context, device: str) -> str:
    """Reserve an exclusive SSH connection to a device for multi-command or config work.
    Returns a session_id to pass to run/apply. The session auto-releases after
    DEDICATED_TTL seconds of inactivity. Use release_session when done.
    If the device is already claimed, returns how long the holder has been idle
    and when it auto-expires so you can decide whether to retry."""
    r = _require_session(ctx)
    if isinstance(r, str):
        return r
    oid, upn, mcp_sid = r

    result = await pool.claim(device, mcp_sid or "", oid)

    if result.get("status") in ("claimed", "existing"):
        asyncio.create_task(_audit(oid, upn, mcp_sid, device, "claim",
                                   result.get("session_id"), 0, "ok", 0, 0))
    return json.dumps(result, indent=2)


@mcp.tool()
async def release_session(ctx: Context, session_id: str) -> str:
    """Release a dedicated session early (before the inactivity TTL). Good hygiene."""
    r = _require_session(ctx)
    if isinstance(r, str):
        return r
    oid, upn, mcp_sid = r

    sess = pool._sessions.get(session_id)
    if not sess:
        return json.dumps({"error": "session not found or already released"})
    if sess.mcp_session_id != (mcp_sid or "") or sess.oid != oid:
        return json.dumps({"error": "session belongs to a different principal/MCP session"})

    await pool._release_session_internal(session_id, reason="released")
    return json.dumps({"status": "released", "session_id": session_id})


@mcp.tool()
async def discover_new_device(ctx: Context, name: str, host: str,
                              platform: str = "cisco_iosxe",
                              site: str = "", role: str = "") -> str:
    """ADMIN-ONLY: onboard a device to the pool by name + host, then verify it.
    Fleet SSH creds are shared, so you only supply name, host (IP preferred over DNS),
    and platform — cisco_iosxe (default), cisco_iosxr, or cisco_asa. Optional site/role
    tags. Inserts the device (the pool connects it immediately) and waits briefly to
    report whether it came up CONNECTED or is still DOWN (bad host/reachability/creds).
    Requires the Keepalive.Admin role."""
    r = _require_admin(ctx)
    if isinstance(r, str):
        return r
    oid, upn, sid = r

    name = (name or "").strip()
    if not _DEVICE_NAME_RE.match(name):
        return json.dumps({"error": "name must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}"})
    host = (host or "").strip()
    if not host:
        return json.dumps({"error": "host (IP or DNS name) is required"})
    platform = (platform or "cisco_iosxe").strip().lower()
    if platform not in _ONBOARD_PLATFORMS:
        return json.dumps({"error": f"platform must be one of: {', '.join(sorted(_ONBOARD_PLATFORMS))}"})
    username = (DEFAULT_USERNAME or "").strip()
    if not username:
        return json.dumps({"error": "no service-account username configured — set KA_DEFAULT_USERNAME"})

    # Insert into the source-of-truth table; the LISTEN/NOTIFY reconcile connects it.
    try:
        db = await _db_pool()
        await db.execute(
            "INSERT INTO devices (name, host, port, platform, username, role, site, source) "
            "VALUES ($1,$2,22,$3,$4,$5,$6,'discover')",
            name, host, platform, username, (role or None), (site or None))
    except asyncpg.UniqueViolationError:
        return json.dumps({"error": f"device '{name}' already exists — use kadev/REST to update it"})
    except Exception as e:
        return json.dumps({"error": f"insert failed: {e}"})

    await _audit(oid, upn, sid, name, "device-add", f"{host} {platform}", 0, "created", 0, 0)

    # Verify: the connect happens in the background (NOTIFY → reconcile → connect, paced by
    # the connect-rate gate). Poll for CONNECTED; report the state if it hasn't come up yet.
    state = "pending"
    for _ in range(16):                       # up to ~8s
        await asyncio.sleep(0.5)
        st = {s["name"]: s["state"] for s in pool.status_data()}.get(name)
        if st == "CONNECTED":
            state = "CONNECTED"; break
        if st:
            state = st                        # DOWN while still connecting / after a failure
    ok = state == "CONNECTED"
    return json.dumps({
        "status":     "added",
        "name":       name,
        "host":       host,
        "platform":   platform,
        "username":   username,
        "connection": state,
        "reachable":  ok,
        "note": ("connected and warm — ready for run/apply" if ok else
                 "added to inventory but not CONNECTED yet; the pool keeps retrying. "
                 "Check host/reachability and that the shared creds work on this device."),
    }, indent=2)


# ── filtered tools/list (registered last, after every @mcp.tool() above) ───────
# Override FastMCP's default list handler so tools/list is scoped to the caller's app
# roles. We call FastMCP's own list_tools() to get the full, correctly-converted set,
# then drop anything the caller's roles can't use. Reads identity from the same request
# context the tools see (mcp.get_context() → _auth → validated Entra bearer). This is a
# discoverability filter only — call_tool still dispatches every registered tool through
# its _require_* gate, so an unlisted tool that's called anyway returns the usual 403.
if FILTER_TOOL_LIST:
    from mcp.types import Tool as _MCPTool

    @mcp._mcp_server.list_tools()
    async def _list_tools_filtered() -> list[_MCPTool]:
        full  = await mcp.list_tools()             # full registry, FastMCP's own conversion
        ident = _auth(mcp.get_context())           # (oid, upn, roles) after full JWT checks, or None
        roles = set(ident[2]) if ident else set()  # no valid bearer → no roles → nothing listed
        return _filter_tools_for_roles(full, roles)

    print("[keepalive-mcp] per-user tools/list filtering ENABLED (KA_FILTER_TOOL_LIST)", flush=True)


# ── status page (Starlette route) ─────────────────────────────────────────────
_STATUS_CSS = """
body{font-family:system-ui,-apple-system,sans-serif;background:#0c1117;color:#d8e4f0;
     margin:0;padding:32px}
h1{font-family:'SF Mono',Cascadia Code,monospace;font-size:20px;color:#c87533;
   letter-spacing:-.01em;margin:0 0 6px}
.sub{font-size:13px;color:#5c6e84;margin-bottom:28px;font-family:monospace}
table{width:100%;border-collapse:collapse;font-size:13px}
th{font-family:monospace;font-size:10px;text-transform:uppercase;letter-spacing:.12em;
   color:#4e6478;text-align:left;padding:6px 12px;border-bottom:1px solid #243044}
td{padding:9px 12px;border-bottom:1px solid #1c2638;vertical-align:top}
.name{font-family:monospace;color:#d8e4f0;font-weight:600}
.host{font-family:monospace;color:#5c6e84}
.plat{font-family:monospace;color:#5c6e84;font-size:11px}
.pill{display:inline-block;border-radius:3px;padding:2px 8px;font-size:11px;
      font-family:monospace;font-weight:600}
.green{background:rgba(76,175,114,.12);color:#4caf72;border:1px solid rgba(76,175,114,.25)}
.amber{background:rgba(212,160,23,.1); color:#d4a017;border:1px solid rgba(212,160,23,.2)}
.red  {background:rgba(196,80,80,.12); color:#c45050;border:1px solid rgba(196,80,80,.25)}
"""

# ── browser session (PKCE OIDC for status page) ──────────────────────────────
_oauth_states: dict[str, tuple[str, float]] = {}   # state token → (PKCE verifier, created_at)
_OAUTH_STATE_TTL = 600      # a login must complete within 10 min
_OAUTH_STATE_MAX = 512      # hard cap on pending logins

def _prune_oauth_states() -> None:
    now = time.time()
    for st in [s for s, (_, ts) in _oauth_states.items() if now - ts > _OAUTH_STATE_TTL]:
        _oauth_states.pop(st, None)
    # if still over cap (flood), drop the oldest
    while len(_oauth_states) > _OAUTH_STATE_MAX:
        oldest = min(_oauth_states, key=lambda s: _oauth_states[s][1])
        _oauth_states.pop(oldest, None)


def _cookie_sign(data: str) -> str:
    return hmac.new(SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()


def _make_session_cookie(oid: str, upn: str, name: str, roles: list[str]) -> str:
    payload = base64.urlsafe_b64encode(
        json.dumps({"oid": oid, "upn": upn, "name": name, "roles": roles,
                    "exp": int(time.time()) + 86400}).encode()
    ).decode()
    return f"{payload}.{_cookie_sign(payload)}"


def _validate_session_cookie(request: Request) -> dict | None:
    cookie = request.cookies.get("ka_session", "")
    if not cookie or "." not in cookie:
        return None
    try:
        payload, sig = cookie.rsplit(".", 1)
        if not hmac.compare_digest(sig, _cookie_sign(payload)):
            return None
        claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
        if claims.get("exp", 0) < time.time():
            return None
        return claims
    except Exception:
        return None


def _status_authorized(request: Request) -> dict | None:
    """Valid SSO session cookie AND the KA_STATUS_ROLE app role, else None."""
    claims = _validate_session_cookie(request)
    if not claims:
        return None
    roles = [str(r).lower() for r in (claims.get("roles") or [])]
    if STATUS_ROLE not in roles and not (ADMIN_ROLES & set(roles)):
        return None                                    # admin is a superset of the status role
    return claims


def _login_redirect(request: Request) -> RedirectResponse:
    state    = secrets.token_urlsafe(16)
    verifier = secrets.token_urlsafe(32)
    digest   = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    _prune_oauth_states()
    _oauth_states[state] = (verifier, time.time())
    params = urlencode({
        "client_id":             CLIENT_ID,
        "response_type":         "code",
        "redirect_uri":          REDIRECT_URI,
        # openid/profile → identity (id_token); API_SCOPE → an access token for
        # this API that carries the app-role (roles) claim used for authz.
        "scope":                 f"openid profile {API_SCOPE}".strip(),
        "state":                 state,
        "code_challenge":        digest,
        "code_challenge_method": "S256",
    })
    return RedirectResponse(
        f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/authorize?{params}",
        status_code=302,
    )


def _client_assertion() -> dict:
    """JWT signed with the cert private key for confidential-client token exchange.
    Azure AD requires the x5t (SHA-1 cert thumbprint) in the header to resolve
    which registered certificate to validate the signature against."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509 import load_pem_x509_certificate
    import jwt as _jwt
    with open(KEY_PATH, "rb") as f:
        key = load_pem_private_key(f.read(), password=None)
    with open(CERT_PATH, "rb") as f:
        cert = load_pem_x509_certificate(f.read())
    thumbprint = base64.urlsafe_b64encode(
        cert.fingerprint(hashes.SHA1())  # noqa: S303 — Azure AD requires SHA-1 here
    ).rstrip(b"=").decode()
    now = int(time.time())
    assertion = _jwt.encode(
        {"aud": f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
         "iss": CLIENT_ID, "sub": CLIENT_ID,
         "jti": secrets.token_urlsafe(16),
         "iat": now, "exp": now + 300},
        key, algorithm="RS256",
        headers={"x5t": thumbprint},
    )
    return {
        "client_assertion_type":
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": assertion,
    }


def _roles_from_access_token(access_token: str) -> list[str] | None:
    """Validate an access token minted for THIS API during the status login and
    return its app-role (roles) claim, lowercased. Returns None if the token is
    missing/invalid. Provenance is already established by the authorization-code
    + PKCE + client-assertion exchange, so the inbound ALLOWED_CLIENTS gate (which
    guards external MCP callers) is intentionally NOT applied here — but we still
    verify signature, audience, issuer, tenant, and the delegated scope."""
    if not access_token:
        return None
    try:
        import jwt as _jwt
        key    = _jwks().get_signing_key_from_jwt(access_token).key
        claims = _jwt.decode(access_token, key, algorithms=["RS256"],
                             audience=AUDIENCE, options={"verify_exp": True})
        if claims.get("iss") not in (
                f"https://login.microsoftonline.com/{TENANT}/v2.0",
                f"https://sts.windows.net/{TENANT}/"):
            return None
        if claims.get("tid") != TENANT:
            return None
        if REQUIRED_SCOPE not in str(claims.get("scp", "")).split():
            return None
        return [str(r).lower() for r in (claims.get("roles") or [])]
    except Exception:
        return None


async def auth_callback(request: Request):
    state    = request.query_params.get("state", "")
    code     = request.query_params.get("code", "")
    entry    = _oauth_states.pop(state, None)
    if not entry or not code:
        return Response("invalid state or missing code", status_code=400)
    verifier, created = entry
    if time.time() - created > _OAUTH_STATE_TTL:
        return Response("login state expired — retry", status_code=400)

    token_data: dict = {
        "client_id":     CLIENT_ID,
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  REDIRECT_URI,
        "code_verifier": verifier,
    }
    if KEY_PATH and os.path.exists(KEY_PATH):
        token_data.update(_client_assertion())

    async with httpx.AsyncClient() as hc:
        r = await hc.post(
            f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
            data=token_data,
        )
    tokens = r.json()
    id_token = tokens.get("id_token")
    if not id_token:
        err = tokens.get("error_description", json.dumps(tokens))
        return Response(f"token exchange failed: {err}", status_code=400)

    # id_token → identity (who the user is)
    try:
        import jwt as _jwt
        key    = _jwks().get_signing_key_from_jwt(id_token).key
        claims = _jwt.decode(id_token, key, algorithms=["RS256"],
                             audience=CLIENT_ID, options={"verify_exp": True})
        if claims.get("iss") not in (
                f"https://login.microsoftonline.com/{TENANT}/v2.0",
                f"https://sts.windows.net/{TENANT}/"):
            return Response("id_token issuer mismatch", status_code=400)
        if claims.get("tid") != TENANT:
            return Response("id_token tenant mismatch", status_code=400)
    except Exception as e:
        return Response(f"id_token invalid: {e}", status_code=400)

    # access_token → authorization (app roles). Entra emits the roles claim in
    # the token audienced to this API, not in the id_token.
    roles = _roles_from_access_token(tokens.get("access_token", ""))
    if roles is None:
        return Response(
            "authorization failed: no valid access token for the API was returned "
            "(check that the login requested the API scope and that the app "
            "registration exposes it).",
            status_code=400)
    if STATUS_ROLE not in roles and not (ADMIN_ROLES & set(roles)):
        return Response(
            f"forbidden: the '{STATUS_ROLE}' or Keepalive.Admin app role is required to view "
            f"status (assign it to your principal on the Keepalive app registration).",
            status_code=403)

    cookie = _make_session_cookie(
        oid=claims.get("oid", ""),
        upn=claims.get("preferred_username", claims.get("upn", "")),
        name=claims.get("name", ""),
        roles=roles,
    )
    base = REDIRECT_URI.replace("/auth/callback", "/status")
    resp = RedirectResponse(base, status_code=302)
    resp.set_cookie("ka_session", cookie, httponly=True, secure=True,
                    max_age=86400, samesite="lax")
    return resp


async def status_page(request: Request):
    if not _validate_session_cookie(request):
        return _login_redirect(request)
    if not _status_authorized(request):
        return HTMLResponse(
            f"<h1>keepalive-mcp</h1><p>Forbidden — the '{escape(STATUS_ROLE)}' "
            f"app role is required to view status.</p>", status_code=403)
    rows = pool.status_data()
    now  = int(time.time())
    trs  = ""
    for d in rows:
        state = d["state"]
        cls   = "green" if state == "CONNECTED" else ("amber" if state == "CLAIMED" else "red")
        age   = now - d["last_ok"] if d["last_ok"] else None
        age_s = f"{age}s ago" if age is not None else "—"
        trs += (f"<tr>"
                f"<td class='name'>{escape(str(d['name']))}</td>"
                f"<td class='host'>{escape(str(d['host']))}</td>"
                f"<td class='plat'>{escape(str(d['platform']))}</td>"
                f"<td>{escape(str(d.get('role') or '—'))}</td>"
                f"<td>{escape(str(d.get('site') or '—'))}</td>"
                f"<td><span class='pill {cls}'>{escape(str(state))}</span></td>"
                f"<td style='color:#5c6e84'>{d['pool_size']}+{d['sessions']}</td>"
                f"<td style='color:#5c6e84;font-family:monospace;font-size:12px'>{age_s}</td>"
                f"</tr>")

    html = (f"<style>{_STATUS_CSS}</style>"
            f"<h1>keepalive-mcp</h1>"
            f"<div class='sub'>network gear connection pool · {len(rows)} devices</div>"
            f"<table>"
            f"<thead><tr>"
            f"<th>device</th><th>host</th><th>platform</th>"
            f"<th>role</th><th>site</th><th>state</th>"
            f"<th>pool+sessions</th><th>last ok</th>"
            f"</tr></thead>"
            f"<tbody>{trs}</tbody>"
            f"</table>")
    return HTMLResponse(html)


async def status_json(request: Request):
    if not _status_authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse({"devices": pool.status_data(), "ts": int(time.time())})


# ── device management API (REST /devices) ──────────────────────────────────────
# Mutations write the `devices` table (the single source of truth); the Postgres
# NOTIFY trigger drives the live pool to reconcile (Pool._listen_devices). Handlers
# never touch the pool directly — the DB is the one write path, so this API, a psql
# edit, and a bulk import all converge the same way. Auth: Keepalive.Admin, and an
# app-only (client-credentials) token is accepted so the headless CLI works.

_VALID_PLATFORMS = LIVE_APPLY | COMMIT_CAP
_DEVICE_NAME_RE  = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def _coerce_device(body: dict, *, partial: bool, name: str | None = None) -> tuple[dict, str | None]:
    """Validate/normalize a device payload. Returns (fields, None) or ({}, error).
    partial=True (PATCH) only touches supplied keys; partial=False (POST/PUT)
    requires the full connection set. `name` is the key and is never in `fields`."""
    out: dict = {}
    nm = name if name is not None else body.get("name")
    if name is None or not partial:
        if not (isinstance(nm, str) and _DEVICE_NAME_RE.match(nm or "")):
            return {}, "name is required and must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}"
    if "host" in body or not partial:
        host = (body.get("host") or "").strip()
        if not host:
            return {}, "host is required"
        out["host"] = host
    if "port" in body or not partial:
        try:
            port = int(body.get("port", 22))
        except (TypeError, ValueError):
            return {}, "port must be an integer"
        if not (1 <= port <= 65535):
            return {}, "port must be 1..65535"
        out["port"] = port
    if "platform" in body or not partial:
        plat = (body.get("platform") or "").strip()
        if plat not in _VALID_PLATFORMS:
            return {}, f"platform must be one of: {', '.join(sorted(_VALID_PLATFORMS))}"
        out["platform"] = plat
    if "username" in body or not partial:
        user = (body.get("username") or "").strip()
        if not user:
            return {}, "username is required"
        out["username"] = user
    if "max_connections" in body or not partial:
        try:
            mc = int(body.get("max_connections", 2))
        except (TypeError, ValueError):
            return {}, "max_connections must be an integer"
        if not (1 <= mc <= 16):
            return {}, "max_connections must be 1..16"
        out["max_connections"] = mc
    if "enabled" in body or not partial:
        out["enabled"] = bool(body.get("enabled", True))
    for f in ("role", "site", "description", "source"):
        if f in body:
            v = body.get(f)
            out[f] = None if v is None else str(v)[:256]
    return out, None


async def _read_json(request):
    try:
        return await request.json()
    except Exception:
        return None


async def devices_list(request):
    _, err = _require_admin_req(request)
    if err:
        return err
    try:
        db   = await _db_pool()
        rows = await db.fetch(
            "SELECT name, host, port, platform, username, role, site, description, "
            "max_connections, enabled, source FROM devices ORDER BY name")
        return JSONResponse({"devices": [dict(r) for r in rows]})
    except Exception as e:
        return JSONResponse({"error": f"query failed: {e}"}, status_code=500)


async def devices_create(request):
    ident, err = _require_admin_req(request)
    if err:
        return err
    oid, upn = ident
    body = await _read_json(request)
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object body required"}, status_code=400)
    fields, verr = _coerce_device(body, partial=False)
    if verr:
        return JSONResponse({"error": verr}, status_code=400)
    name = body["name"]
    cols = ["name"] + list(fields.keys())
    vals = [name] + list(fields.values())
    ph   = ", ".join(f"${i+1}" for i in range(len(vals)))
    try:
        db = await _db_pool()
        await db.execute(f"INSERT INTO devices ({', '.join(cols)}) VALUES ({ph})", *vals)
    except asyncpg.UniqueViolationError:
        return JSONResponse({"error": f"device '{name}' already exists (use PATCH)"},
                            status_code=409)
    except Exception as e:
        return JSONResponse({"error": f"insert failed: {e}"}, status_code=500)
    await _audit(oid, upn, None, name, "device-add",
                 json.dumps({k: fields.get(k) for k in ("host", "platform")}),
                 0, "created", 0, 0)
    return JSONResponse({"status": "created", "name": name,
                         "enabled": fields.get("enabled", True)}, status_code=201)


async def devices_update(request):
    ident, err = _require_admin_req(request)
    if err:
        return err
    oid, upn = ident
    name    = request.path_params["name"]
    body    = await _read_json(request)
    if not isinstance(body, dict):
        return JSONResponse({"error": "JSON object body required"}, status_code=400)
    partial = request.method == "PATCH"      # PUT = full replace, PATCH = partial
    fields, verr = _coerce_device(body, partial=partial, name=name)
    if verr:
        return JSONResponse({"error": verr}, status_code=400)
    if not fields:
        return JSONResponse({"error": "no writable fields supplied"}, status_code=400)
    sets = ", ".join(f"{c} = ${i+2}" for i, c in enumerate(fields.keys()))
    try:
        db  = await _db_pool()
        res = await db.execute(f"UPDATE devices SET {sets} WHERE name = $1",
                               name, *fields.values())
    except Exception as e:
        return JSONResponse({"error": f"update failed: {e}"}, status_code=500)
    if res.endswith(" 0"):
        return JSONResponse({"error": f"device '{name}' not found"}, status_code=404)
    await _audit(oid, upn, None, name, "device-update",
                 json.dumps(sorted(fields.keys())), 0, "updated", 0, 0)
    return JSONResponse({"status": "updated", "name": name, "changed": sorted(fields.keys())})


async def devices_delete(request):
    ident, err = _require_admin_req(request)
    if err:
        return err
    oid, upn = ident
    name = request.path_params["name"]
    # Fail-closed: refuse to delete a device currently held in a session. To take a
    # busy device out of service, PATCH enabled=false (drains on release) then DELETE.
    if any(s.device == name for s in pool._sessions.values()):
        return JSONResponse(
            {"error": f"device '{name}' has an active session; PATCH enabled=false to "
             f"drain it, or wait for the session TTL, then delete"}, status_code=409)
    try:
        db  = await _db_pool()
        res = await db.execute("DELETE FROM devices WHERE name = $1", name)
    except Exception as e:
        return JSONResponse({"error": f"delete failed: {e}"}, status_code=500)
    if res.endswith(" 0"):
        return JSONResponse({"error": f"device '{name}' not found"}, status_code=404)
    await _audit(oid, upn, None, name, "device-remove", None, 0, "deleted", 0, 0)
    return JSONResponse({"status": "deleted", "name": name})


# ── app builder with lifespan ─────────────────────────────────────────────────
def _install_access_log_redaction():
    """Redact OAuth code/state/tokens/secrets from any uvicorn access-log line (only
    emitted when KA_ACCESS_LOG=true) so a debug session can't leak the /auth/callback
    ?code= into syslog/Ringdown."""
    import logging, re
    _pat = re.compile(r'((?:code|state|session_state|id_token|access_token|'
                      r'client_assertion|client_secret|refresh_token)=)[^&\s"\'>]+', re.I)
    _markers = ("code=", "state=", "token=", "secret=", "assertion=")

    class _Redact(logging.Filter):
        def filter(self, record):
            try:
                if record.args:
                    a = list(record.args)
                    for i, v in enumerate(a):
                        if isinstance(v, str) and any(m in v for m in _markers):
                            a[i] = _pat.sub(r"\1<redacted>", v)
                    record.args = tuple(a)
            except Exception:
                pass
            return True

    lg = logging.getLogger("uvicorn.access")
    if not any(f.__class__.__name__ == "_Redact" for f in lg.filters):
        lg.addFilter(_Redact())


def _build_app():
    from contextlib import asynccontextmanager
    from starlette.applications import Starlette
    from starlette.routing import Mount, Route

    @asynccontextmanager
    async def lifespan(app):
        _install_access_log_redaction()
        async with mcp.session_manager.run():
            await pool.start()
            print(f"[keepalive-mcp] pool started · {len(pool._meta)} devices · port {PORT}", flush=True)
            yield
            await pool.stop()
            if _db:
                await _db.close()

    mcp_app = mcp.streamable_http_app()

    app = Starlette(
        lifespan=lifespan,
        routes=[
            Route("/status",          status_page),
            Route("/status.json",     status_json),
            Route("/auth/callback",   auth_callback),
            Route("/devices",         devices_list,   methods=["GET"]),
            Route("/devices",         devices_create, methods=["POST"]),
            Route("/devices/{name}",  devices_update, methods=["PATCH", "PUT"]),
            Route("/devices/{name}",  devices_delete, methods=["DELETE"]),
            Mount("/",                app=mcp_app),
        ],
    )
    return app


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(_build_app(), host=BIND, port=PORT, log_level="info", access_log=ACCESS_LOG)
