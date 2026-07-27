"""Safety and platform behavior tests for configuration application."""
import json
import types

import pytest

import server


class Result:
    def __init__(self, command="", text="", failed=False):
        self.channel_input = command
        self.result = text
        self.failed = failed


class FakeScrapli:
    def __init__(self, command_results=None, config_results=None):
        self.command_results = list(command_results or [])
        self.config_results = list(config_results or [])
        self.commands = []
        self.configs = []

    async def send_command(self, command, **_kwargs):
        self.commands.append(command)
        if self.command_results:
            return self.command_results.pop(0)
        return Result(command, "")

    async def send_configs(self, lines, **_kwargs):
        self.configs.append(list(lines))
        return self.config_results


def connection(scrapli):
    return types.SimpleNamespace(scrapli=scrapli, last_ok=0)


@pytest.mark.asyncio
async def test_live_apply_saves_only_after_full_success():
    scrapli = FakeScrapli(
        command_results=[
            Result(text="interface Loopback0\n description old"),
            Result(text="interface Loopback0\n description new"),
            Result(text="Building configuration...\nOK"),
        ],
        config_results=[Result("description new")],
    )

    result = await server._apply_live(
        connection(scrapli),
        "router-1",
        ["description new"],
        save=True,
    )

    assert result["status"] == "applied"
    assert result["saved"] is True
    assert scrapli.commands == [
        "show running-config",
        "show running-config",
        "write memory",
    ]


@pytest.mark.asyncio
async def test_live_apply_aborts_and_never_saves_after_rejected_line():
    scrapli = FakeScrapli(
        command_results=[
            Result(text="interface Loopback0"),
            Result(text="interface Loopback0\n description first"),
        ],
        config_results=[
            Result("description first"),
            Result("bad command", "% Invalid input", failed=True),
        ],
    )

    result = await server._apply_live(
        connection(scrapli),
        "router-1",
        ["description first", "bad command", "description never-sent"],
        save=True,
    )

    assert result["status"] == "ABORTED"
    assert result["failed_command"] == "bad command"
    assert result["not_sent"] == ["description never-sent"]
    assert result["saved"] is False
    assert "write memory" not in scrapli.commands


@pytest.mark.asyncio
async def test_commit_platform_discards_candidate_on_failure(monkeypatch):
    scrapli = FakeScrapli(config_results=[
        Result("description first"),
        Result("bad command", "syntax error", failed=True),
    ])
    torn_down = []

    async def teardown(conn):
        torn_down.append(conn)

    monkeypatch.setattr(server.pool, "_teardown_config_state", teardown)
    conn = connection(scrapli)
    result = await server._apply_commit(
        conn,
        "router-1",
        ["description first", "bad command", "never sent"],
        save=True,
        platform="cisco_iosxr",
    )

    assert result["status"] == "ABORTED"
    assert result["saved"] is False
    assert result["not_sent"] == ["never sent"]
    assert torn_down == [conn]
    assert "commit" not in scrapli.commands


@pytest.mark.asyncio
async def test_commit_platform_commits_successful_candidate():
    scrapli = FakeScrapli(
        command_results=[
            Result(text="Commit complete"),
            Result(text="interface Loopback0\n description new"),
        ],
        config_results=[Result("description new")],
    )
    result = await server._apply_commit(
        connection(scrapli),
        "router-1",
        ["description new"],
        save=False,
        platform="cisco_iosxr",
    )

    assert result["status"] == "applied"
    assert result["saved"] is True
    assert scrapli.commands == ["commit", "show running-config"]


@pytest.mark.asyncio
async def test_apply_is_dry_run_by_default(monkeypatch):
    monkeypatch.setattr(
        server,
        "_require_config",
        lambda _ctx: ("oid", "upn", "mcp-session"),
    )
    result = json.loads(await server.apply(
        object(),
        "router-1",
        "interface Loopback0\ndescription preview",
    ))
    assert result["dry_run"] is True
    assert result["would_send"] == [
        "interface Loopback0",
        "description preview",
    ]


@pytest.mark.asyncio
async def test_apply_refuses_mutation_when_intent_audit_is_unavailable(
        monkeypatch):
    monkeypatch.setattr(
        server,
        "_require_config",
        lambda _ctx: ("oid", "upn", "mcp-session"),
    )

    async def audit_unavailable(*_args, **_kwargs):
        return False

    monkeypatch.setattr(server, "_audit_intent", audit_unavailable)
    result = json.loads(await server.apply(
        object(),
        "router-1",
        "description must-not-run",
        confirm=True,
    ))
    assert "audit unavailable" in result["error"]
