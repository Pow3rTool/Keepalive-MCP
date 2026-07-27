"""Retention is narrow: transient pool telemetry expires, human audit does not."""

import asyncio

import pytest

import server


class FakeDatabase:
    def __init__(self, results):
        self.results = iter(results)
        self.calls = []

    async def execute(self, sql, *args):
        self.calls.append((sql, args))
        return next(self.results)


@pytest.mark.asyncio
async def test_pool_retention_is_batched_and_targets_only_pool_verbs(monkeypatch):
    database = FakeDatabase(["DELETE 10000", "DELETE 7"])

    async def database_pool():
        return database

    monkeypatch.setattr(server, "_db_pool", database_pool)
    monkeypatch.setattr(server, "_AUDIT_RETENTION_BATCH_SIZE", 10_000)
    monkeypatch.setattr(server, "_AUDIT_RETENTION_MAX_BATCHES", 10)
    monkeypatch.setattr(server, "POOL_AUDIT_RETENTION_DAYS", 30)

    deleted = await server._prune_pool_audit()

    assert deleted == 10_007
    assert len(database.calls) == 2
    for sql, args in database.calls:
        assert "verb LIKE 'pool-%'" in sql
        assert "make_interval(days => $1::int)" in sql
        assert args == (30, 10_000)
        assert "verb = 'read'" not in sql
        assert "verb LIKE 'device-%'" not in sql


@pytest.mark.asyncio
async def test_retention_failure_retries_without_exiting_supervisor(monkeypatch):
    attempts = 0
    retried = asyncio.Event()
    original_sleep = asyncio.sleep

    async def failing_prune():
        nonlocal attempts
        attempts += 1
        if attempts == 2:
            retried.set()
        raise RuntimeError("database unavailable")

    async def immediate_sleep(_seconds):
        await original_sleep(0)

    monkeypatch.setattr(server, "_prune_pool_audit", failing_prune)
    monkeypatch.setattr(server.asyncio, "sleep", immediate_sleep)

    task = asyncio.create_task(server._audit_retention_loop())
    await asyncio.wait_for(retried.wait(), timeout=1)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    assert attempts >= 2
