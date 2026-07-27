"""Pool readiness, ownership, and bounded shutdown tests."""
import asyncio
import json

import pytest

import server


class FakeTask:
    def __init__(self, done=False, cancelled=False):
        self._done = done
        self._cancelled = cancelled

    def done(self):
        return self._done

    def cancelled(self):
        return self._cancelled


class FakeScrapli:
    def __init__(self, delay=0):
        self.delay = delay
        self.close_calls = 0

    async def close(self):
        self.close_calls += 1
        await asyncio.sleep(self.delay)


def meta(name):
    return {
        "name": name,
        "host": "192.0.2.1",
        "platform": "cisco_iosxe",
        "role": "router",
        "site": "lab",
        "max_connections": 2,
    }


def test_readiness_never_waits_for_the_fleet_to_connect():
    pool = server.Pool()
    pool._running = True
    pool._inventory_loaded = True
    pool._tasks = {
        "keepalive": FakeTask(),
        "session_reaper": FakeTask(),
        "device_listener": FakeTask(),
    }
    for number in range(2_000):
        name = f"router-{number}"
        pool._meta[name] = meta(name)
        pool._conns[name] = []

    ready, snapshot = pool.health_snapshot()

    assert ready is True
    assert snapshot["status"] == "ready"
    assert snapshot["devices"] == {
        "total": 2_000,
        "connected": 0,
        "claimed": 0,
        "down": 2_000,
    }


def test_readiness_fails_when_a_supervisor_exits():
    pool = server.Pool()
    pool._running = True
    pool._inventory_loaded = True
    pool._tasks = {"keepalive": FakeTask(done=True)}

    ready, snapshot = pool.health_snapshot()

    assert ready is False
    assert snapshot["background_tasks_failed"] == ["keepalive"]


@pytest.mark.asyncio
async def test_shutdown_awaits_tasks_and_closes_shared_and_claimed_connections(
        monkeypatch):
    monkeypatch.setattr(server, "CONNECTION_CLOSE_SECS", 0.5)
    pool = server.Pool()
    pool._running = True
    pool._inventory_loaded = True
    shared_scrapli = FakeScrapli(delay=0.01)
    claimed_scrapli = FakeScrapli(delay=0.01)
    shared = server._Conn("router-1", shared_scrapli)
    claimed = server._Conn("router-2", claimed_scrapli)
    pool._conns = {
        "router-1": [shared, shared],
        "router-2": [],
    }
    pool._meta = {
        "router-1": meta("router-1"),
        "router-2": meta("router-2"),
    }
    pool._locks = {
        "router-1": asyncio.Lock(),
        "router-2": asyncio.Lock(),
    }
    pool._sessions["session"] = server._Session(
        "router-2",
        claimed,
        "mcp-session",
        "operator",
    )
    stopped = asyncio.Event()

    async def supervisor():
        try:
            await asyncio.Event().wait()
        finally:
            stopped.set()

    pool._tasks = {"keepalive": asyncio.create_task(supervisor())}
    await asyncio.sleep(0)
    await pool.stop()

    assert stopped.is_set()
    assert shared_scrapli.close_calls == 1
    assert claimed_scrapli.close_calls == 1
    assert pool._tasks == {}
    assert pool._sessions == {}
    assert pool._meta == {}


@pytest.mark.asyncio
async def test_claim_is_bound_to_principal_and_tracks_replacement(monkeypatch):
    pool = server.Pool()
    pool._running = True
    pool._inventory_loaded = True
    pool._meta["router-1"] = meta("router-1")
    pool._locks["router-1"] = asyncio.Lock()
    conn = server._Conn("router-1", FakeScrapli())
    pool._conns["router-1"] = [conn]
    replacement_started = asyncio.Event()

    async def replace(_device):
        replacement_started.set()

    monkeypatch.setattr(pool, "_replace_conn", replace)
    result = await pool.claim("router-1", "mcp-session", "operator")
    await asyncio.wait_for(replacement_started.wait(), timeout=1)

    session_id = result["session_id"]
    assert pool.get_session_conn(
        session_id, "mcp-session", "operator") is conn
    assert pool.get_session_conn(
        session_id, "other-session", "operator") is None
    assert pool.get_session_conn(
        session_id, "mcp-session", "other-operator") is None
    await pool.stop()


@pytest.mark.asyncio
async def test_health_handlers_are_non_sensitive(monkeypatch):
    class HealthyPool:
        def health_snapshot(self):
            return True, {
                "status": "ready",
                "inventory_loaded": True,
                "device_listener_connected": False,
                "devices": {
                    "total": 2_000,
                    "connected": 0,
                    "claimed": 0,
                    "down": 2_000,
                },
                "background_tasks_failed": [],
                "degraded": ["device_inventory_listener_reconnecting"],
            }

    monkeypatch.setattr(server, "pool", HealthyPool())
    live = await server.livez(None)
    ready = await server.readyz(None)

    assert live.status_code == 200
    assert json.loads(live.body) == {"status": "alive"}
    body = json.loads(ready.body)
    assert ready.status_code == 200
    assert body["devices"]["connected"] == 0
    assert "host" not in repr(body)
    assert "name" not in repr(body)


@pytest.mark.asyncio
async def test_background_audits_are_drained_or_bounded(monkeypatch):
    server._background_tasks.clear()
    finished = asyncio.Event()

    async def quick_audit():
        await asyncio.sleep(0)
        finished.set()

    server._spawn_background(quick_audit(), "quick-audit")
    await server._drain_background_tasks()
    assert finished.is_set()

    monkeypatch.setattr(server, "BACKGROUND_DRAIN_SECS", 0.01)
    cancelled = asyncio.Event()

    async def stuck_audit():
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    server._spawn_background(stuck_audit(), "stuck-audit")
    await asyncio.sleep(0)
    await server._drain_background_tasks()
    assert cancelled.is_set()
    assert not server._background_tasks
