#!/usr/bin/env python3
"""Tests for KA_FILTER_TOOL_LIST — per-user tools/list filtering by Entra app role.

Runnable two ways:
  pytest test_tool_filter.py
  python test_tool_filter.py        # prints PASS/FAIL, no pytest needed

Env is seeded BEFORE importing server so _check_config() passes without a real
deployment (host-key policy off, dummy creds, filtering enabled). No network: the
DB pool and SSH pool are lazy and never started here.
"""
import asyncio
import os
import types as _types

# ── seed a minimal valid config, then import the server under test ──────────────
os.environ.update({
    "KA_DB_DSN":            "postgresql://u:p@localhost:5432/ka",
    "KA_TENANT_ID":         "00000000-0000-0000-0000-000000000000",
    "KA_CLIENT_ID":         "11111111-1111-1111-1111-111111111111",
    "KA_REQUIRED_SCOPE":    "user_impersonation",
    "KA_ALLOWED_CLIENTS":   "22222222-2222-2222-2222-222222222222",
    "KA_REDIRECT_URI":      "https://ka.example.com/auth/callback",
    "KA_SSH_HOSTKEY_POLICY": "off",
    "KA_SSH_PASSWORD":      "dummy",
    "KA_FILTER_TOOL_LIST":  "true",
})

import server  # noqa: E402

READ   = ["keepalive.read"]
CONFIG = ["keepalive.config"]
ADMIN  = ["keepalive.admin"]

READ_TOOLS   = {"find_devices", "run", "read_output"}
CONFIG_TOOLS = READ_TOOLS | {"apply", "claim_session", "release_session"}
ADMIN_TOOLS  = CONFIG_TOOLS | {"discover_new_device"}


def _full_tools():
    """The complete, FastMCP-converted tool list (what an unfiltered list would return)."""
    return asyncio.run(server.mcp.list_tools())


def _names(tools):
    return {t.name for t in tools}


def test_visibility_map_covers_every_registered_tool():
    """Drift guard: the role map must name exactly the tools that are registered, so a
    new tool can't slip in ungated (defaulting to READ) or a renamed one linger."""
    registered = _names(_full_tools())
    assert registered == set(server._TOOL_VISIBILITY), (
        f"map/registry drift: only-in-registry={registered - set(server._TOOL_VISIBILITY)}, "
        f"only-in-map={set(server._TOOL_VISIBILITY) - registered}")


def test_read_role_sees_only_read_tools():
    assert _names(server._filter_tools_for_roles(_full_tools(), set(READ))) == READ_TOOLS


def test_config_role_sees_read_plus_config_tools_but_not_admin():
    assert _names(server._filter_tools_for_roles(_full_tools(), set(CONFIG))) == CONFIG_TOOLS


def test_admin_role_sees_everything():
    assert _names(server._filter_tools_for_roles(_full_tools(), set(ADMIN))) == ADMIN_TOOLS


def test_no_roles_sees_nothing():
    assert server._filter_tools_for_roles(_full_tools(), set()) == []


def test_unknown_role_sees_nothing():
    assert server._filter_tools_for_roles(_full_tools(), {"keepalive.viewer"}) == []


def test_unknown_tool_defaults_to_read_tier():
    """A tool absent from the map is shown to readers (over-show, never silently hide)."""
    future = _types.SimpleNamespace(name="show_something_new")
    assert _names(server._filter_tools_for_roles([future], set(READ))) == {"show_something_new"}
    assert server._filter_tools_for_roles([future], set()) == []


def test_end_to_end_handler_honors_identity(monkeypatch):
    """Drive the actual registered handler; patch _auth to stand in for a validated
    bearer so we exercise the real wiring (get_context → _auth → filter), not just the
    pure helper."""
    for roles, expected in ((READ, READ_TOOLS), (CONFIG, CONFIG_TOOLS), (ADMIN, ADMIN_TOOLS)):
        monkeypatch.setattr(server, "_auth", lambda ctx, r=roles: ("oid", "upn", r))
        assert _names(asyncio.run(server._list_tools_filtered())) == expected
    # No/invalid bearer → identity None → nothing advertised.
    monkeypatch.setattr(server, "_auth", lambda ctx: None)
    assert asyncio.run(server._list_tools_filtered()) == []


if __name__ == "__main__":
    # Minimal runner so this works without pytest. Provides a tiny monkeypatch shim.
    class _MP:
        def __init__(self): self._undo = []
        def setattr(self, obj, name, val):
            self._undo.append((obj, name, getattr(obj, name)))
            setattr(obj, name, val)
        def undo(self):
            for obj, name, val in reversed(self._undo):
                setattr(obj, name, val)
            self._undo.clear()

    import inspect, traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for fn in fns:
        mp = _MP()
        try:
            fn(mp) if "monkeypatch" in inspect.signature(fn).parameters else fn()
            print(f"PASS  {fn.__name__}")
            passed += 1
        except Exception:
            print(f"FAIL  {fn.__name__}")
            traceback.print_exc()
            failed += 1
        finally:
            mp.undo()
    print(f"\n{passed} passed, {failed} failed")
    raise SystemExit(1 if failed else 0)
