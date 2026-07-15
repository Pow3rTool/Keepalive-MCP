#!/usr/bin/env python3
"""kadev — Keepalive device-pool admin CLI (lab).

Mints an APP-ONLY Entra token with the app's certificate (client-credentials
grant, signed client-assertion) and calls the Keepalive REST API (/devices).
No interactive login, no new dependencies beyond what server.py already uses
(PyJWT, cryptography, httpx) — run it from the same venv.

The service principal named by KADEV_CLIENT_ID must hold the `Keepalive.Admin`
app role, and its appid must be listed in the server's KA_ALLOWED_CLIENTS.

Config via env, or ~/.config/kadev.env (KEY=VALUE lines; env wins):
  KADEV_TENANT_ID   Entra tenant GUID
  KADEV_CLIENT_ID   client id of the SP that holds Keepalive.Admin
  KADEV_CERT        path to a PEM holding the SP private key + certificate
  KADEV_API         Keepalive API base URL, e.g. https://<host>/keepalive
  KADEV_RESOURCE    API resource/audience (default: api://<KADEV_CLIENT_ID>)
  KADEV_SCOPE       token scope    (default: <KADEV_RESOURCE>/.default)

Examples:
  kadev list
  kadev add --name switch01 --host 192.0.2.10 --platform cisco_iosxe \
            --username keepalive --site site-a --role switch
  kadev update switch01 --enabled false        # drain out of service
  kadev remove switch01
  kadev token                                  # print a bearer (debugging)
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

_TOKEN_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def _load_env() -> None:
    cfg = Path(os.environ.get("KADEV_ENV", str(Path.home() / ".config" / "kadev.env")))
    if not cfg.exists():
        return
    for line in cfg.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def _need(key: str) -> str:
    v = os.environ.get(key, "").strip()
    if not v:
        sys.exit(f"error: {key} is not set (env or ~/.config/kadev.env)")
    return v


def _token() -> str:
    tenant   = _need("KADEV_TENANT_ID")
    client   = _need("KADEV_CLIENT_ID")
    cert_pem = Path(_need("KADEV_CERT")).read_bytes()
    resource = os.environ.get("KADEV_RESOURCE", "").strip() or f"api://{client}"
    scope    = os.environ.get("KADEV_SCOPE", "").strip() or f"{resource}/.default"

    key  = serialization.load_pem_private_key(cert_pem, password=None)
    cert = x509.load_pem_x509_certificate(cert_pem)
    # Entra identifies the signing cert by x5t = base64url(SHA-1(DER cert)).
    x5t  = base64.urlsafe_b64encode(cert.fingerprint(hashes.SHA1())).decode().rstrip("=")

    now      = int(time.time())
    token_ep = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    assertion = jwt.encode(
        {"aud": token_ep, "iss": client, "sub": client,
         "jti": base64.urlsafe_b64encode(os.urandom(16)).decode().rstrip("="),
         "iat": now, "exp": now + 300},
        key, algorithm="RS256", headers={"x5t": x5t})

    r = httpx.post(token_ep, timeout=30, data={
        "grant_type": "client_credentials",
        "client_id": client,
        "scope": scope,
        "client_assertion_type": _TOKEN_ASSERTION_TYPE,
        "client_assertion": assertion,
    })
    body = r.json()
    if "access_token" not in body:
        sys.exit(f"token error: {body.get('error_description', body)}")
    return body["access_token"]


def _api(method: str, path: str, body: dict | None = None) -> None:
    base = _need("KADEV_API").rstrip("/")
    r = httpx.request(
        method, f"{base}{path}", timeout=30, json=body,
        headers={"authorization": f"Bearer {_token()}",
                 "content-type": "application/json"})
    try:
        out = r.json()
    except Exception:
        out = {"status_code": r.status_code, "raw": r.text}
    print(json.dumps(out, indent=2, default=str))
    if r.status_code >= 400:
        sys.exit(1)


def _device_body(a: argparse.Namespace) -> dict:
    b: dict = {}
    for f in ("host", "platform", "username", "role", "site", "description", "source"):
        v = getattr(a, f, None)
        if v is not None:
            b[f] = v
    if getattr(a, "port", None) is not None:
        b["port"] = a.port
    if getattr(a, "max_connections", None) is not None:
        b["max_connections"] = a.max_connections
    if getattr(a, "enabled", None) is not None:
        b["enabled"] = a.enabled.lower() in ("1", "true", "yes", "on")
    return b


def _device_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--host")
    sp.add_argument("--platform")
    sp.add_argument("--username")
    sp.add_argument("--role")
    sp.add_argument("--site")
    sp.add_argument("--description")
    sp.add_argument("--source")
    sp.add_argument("--port", type=int)
    sp.add_argument("--max-connections", dest="max_connections", type=int)
    sp.add_argument("--enabled", help="true/false — false drains the device")


def main() -> None:
    _load_env()
    p = argparse.ArgumentParser(prog="kadev", description="Keepalive device-pool admin")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("token", help="print an app-only bearer token")
    sub.add_parser("list", help="list all devices")

    a_add = sub.add_parser("add", help="create a device")
    a_add.add_argument("--name", required=True)
    _device_args(a_add)

    a_upd = sub.add_parser("update", help="modify a device (partial)")
    a_upd.add_argument("name")
    _device_args(a_upd)

    a_rm = sub.add_parser("remove", help="delete a device")
    a_rm.add_argument("name")

    a = p.parse_args()
    if a.cmd == "token":
        print(_token())
    elif a.cmd == "list":
        _api("GET", "/devices")
    elif a.cmd == "add":
        _api("POST", "/devices", {"name": a.name, **_device_body(a)})
    elif a.cmd == "update":
        _api("PATCH", f"/devices/{a.name}", _device_body(a))
    elif a.cmd == "remove":
        _api("DELETE", f"/devices/{a.name}")


if __name__ == "__main__":
    main()
