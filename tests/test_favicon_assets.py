#!/usr/bin/env python3
"""Tests for browser icon assets and their public routes."""
import json
import os

os.environ.update({
    "KA_DB_DSN":             "postgresql://u:p@localhost:5432/ka",
    "KA_TENANT_ID":          "00000000-0000-0000-0000-000000000000",
    "KA_CLIENT_ID":          "11111111-1111-1111-1111-111111111111",
    "KA_REQUIRED_SCOPE":     "user_impersonation",
    "KA_ALLOWED_CLIENTS":    "22222222-2222-2222-2222-222222222222",
    "KA_REDIRECT_URI":       "https://ka.example.com/auth/callback",
    "KA_SSH_HOSTKEY_POLICY": "off",
    "KA_SSH_PASSWORD":       "dummy",
    "KA_FILTER_TOOL_LIST":   "true",
})

import server  # noqa: E402


def test_every_favicon_asset_exists_and_has_an_explicit_route():
    app = server._build_app()
    route_paths = {getattr(route, "path", None) for route in app.routes}

    assert set(server._FAVICON_ASSETS) <= route_paths
    for filename, _media_type in server._FAVICON_ASSETS.values():
        assert (server._STATIC_DIR / filename).is_file()


def test_manifest_is_named_and_uses_prefix_relative_icon_urls():
    manifest = json.loads((server._STATIC_DIR / "site.webmanifest").read_text())

    assert manifest["name"] == "Keepalive MCP"
    assert manifest["short_name"] == "Keepalive"
    assert manifest["theme_color"] == "#0c1117"
    assert manifest["background_color"] == "#0c1117"
    assert manifest["start_url"] == "."
    assert manifest["scope"] == "."
    assert all(not icon["src"].startswith("/") for icon in manifest["icons"])


def test_public_prefix_and_status_head_follow_the_callback_path():
    assert (
        server._public_prefix_from_redirect_uri(
            "https://mcp.secureobscure.com/keepalive/auth/callback"
        )
        == "/keepalive"
    )
    assert server._public_prefix_from_redirect_uri(
        "https://ka.example.com/auth/callback"
    ) == ""
    assert 'href="/favicon.ico"' in server._FAVICON_HEAD
    assert 'href="/site.webmanifest"' in server._FAVICON_HEAD
