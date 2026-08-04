"""Device-management payload validation."""
import json

import pytest

import server


def full_device(**overrides):
    device = {
        "name": "edge-1",
        "host": "192.0.2.1",
        "port": 22,
        "platform": "cisco_iosxe",
        "username": "automation",
        "max_connections": 2,
        "enabled": True,
    }
    device.update(overrides)
    return device


def test_full_device_payload_is_normalized():
    fields, error = server._coerce_device(full_device(
        host=" router.example.com ",
        role="r" * 300,
    ), partial=False)

    assert error is None
    assert fields["host"] == "router.example.com"
    assert fields["role"] == "r" * 256
    assert fields["enabled"] is True


def test_junos_is_supported_by_api_and_tool_onboarding():
    fields, error = server._coerce_device(
        full_device(platform="juniper_junos"),
        partial=False,
    )

    assert error is None
    assert fields["platform"] == "juniper_junos"
    assert "juniper_junos" in server._ONBOARD_PLATFORMS


@pytest.mark.asyncio
async def test_discover_onboards_junos(monkeypatch):
    writes = []

    class FakeDb:
        async def execute(self, query, *args):
            writes.append((query, args))

    async def fake_db_pool():
        return FakeDb()

    async def fake_audit(*_args, **_kwargs):
        return True

    async def no_sleep(_seconds):
        return None

    monkeypatch.setattr(server, "_require_admin", lambda _ctx: ("oid", "upn", "sid"))
    monkeypatch.setattr(server, "_db_pool", fake_db_pool)
    monkeypatch.setattr(server, "_audit", fake_audit)
    monkeypatch.setattr(server.asyncio, "sleep", no_sleep)
    monkeypatch.setattr(server, "DEFAULT_USERNAME", "keepalive-mcp")
    monkeypatch.setattr(
        server.pool,
        "status_data",
        lambda: [{"name": "srx-cluster", "state": "CONNECTED"}],
    )

    result = json.loads(await server.discover_new_device(
        object(),
        "srx-cluster",
        "192.0.2.10",
        platform="juniper_junos",
        site="branch-1",
        role="wan-router",
    ))

    assert result["connection"] == "CONNECTED"
    assert result["platform"] == "juniper_junos"
    assert writes[0][1][1:3] == ("192.0.2.10", "juniper_junos")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"name": "../edge"}, "name is required"),
        ({"host": 1234}, "host is required"),
        ({"host": "bad host"}, "no whitespace"),
        ({"port": 0}, "port must be 1..65535"),
        ({"platform": "linux"}, "platform must be one of"),
        ({"username": "bad\nuser"}, "control characters"),
        ({"max_connections": 17}, "max_connections must be 1..16"),
        ({"enabled": "false"}, "JSON boolean"),
        ({"typo_field": True}, "unknown field"),
    ],
)
def test_invalid_device_payloads_fail_closed(overrides, message):
    fields, error = server._coerce_device(
        full_device(**overrides),
        partial=False,
    )
    assert fields == {}
    assert message in error


def test_patch_changes_only_supplied_fields_and_refuses_rename():
    fields, error = server._coerce_device(
        {"enabled": False, "site": "dc-1"},
        partial=True,
        name="edge-1",
    )
    assert error is None
    assert fields == {"enabled": False, "site": "dc-1"}

    fields, error = server._coerce_device(
        {"name": "renamed"},
        partial=True,
        name="edge-1",
    )
    assert fields == {}
    assert "name cannot be changed" in error

    fields, error = server._coerce_device(
        {"name": "edge-1", "enabled": False},
        partial=True,
        name="edge-1",
    )
    assert error is None
    assert fields == {"enabled": False}
