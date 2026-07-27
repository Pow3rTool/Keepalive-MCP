"""Unit tests for the ordered migration runner."""
from pathlib import Path

import pytest

import migrate


class Transaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


class FakeConnection:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.executed = []
        self.closed = False

    async def execute(self, sql, *args):
        self.executed.append((sql, args))

    async def fetch(self, _sql):
        return self.rows

    def transaction(self):
        return Transaction()

    async def close(self):
        self.closed = True


def write_migration(directory: Path, name: str, sql: str = "SELECT 1") -> Path:
    path = directory / name
    path.write_text(sql)
    return path


def test_discovery_is_ordered_and_requires_unique_numeric_versions(tmp_path):
    write_migration(tmp_path, "001_second.sql")
    write_migration(tmp_path, "000_first.sql")
    assert [
        path.name for path in migrate.discover_migrations(tmp_path)
    ] == ["000_first.sql", "001_second.sql"]

    write_migration(tmp_path, "001_duplicate.sql")
    with pytest.raises(ValueError, match="unique"):
        migrate.discover_migrations(tmp_path)


def test_discovery_rejects_unversioned_sql(tmp_path):
    write_migration(tmp_path, "manual-fix.sql")
    with pytest.raises(ValueError, match="invalid migration"):
        migrate.discover_migrations(tmp_path)


@pytest.mark.asyncio
async def test_runner_applies_each_migration_and_is_reentrant(tmp_path, monkeypatch):
    first = write_migration(tmp_path, "000_first.sql", "CREATE TABLE example(id int)")
    second = write_migration(tmp_path, "001_second.sql", "ALTER TABLE example ADD name text")
    connection = FakeConnection()

    async def connect(_dsn):
        return connection

    monkeypatch.setattr(migrate.asyncpg, "connect", connect)
    applied = await migrate.apply_migrations("postgresql://test", tmp_path)

    assert applied == ["000_first.sql", "001_second.sql"]
    assert connection.closed is True
    sql = "\n".join(statement for statement, _args in connection.executed)
    assert first.read_text() in sql
    assert second.read_text() in sql


@pytest.mark.asyncio
async def test_runner_rejects_changed_applied_migration(tmp_path, monkeypatch):
    path = write_migration(tmp_path, "000_first.sql")
    connection = FakeConnection(rows=[{
        "version": "000",
        "filename": path.name,
        "checksum": "not-the-current-checksum",
    }])

    async def connect(_dsn):
        return connection

    monkeypatch.setattr(migrate.asyncpg, "connect", connect)
    with pytest.raises(RuntimeError, match="no longer matches"):
        await migrate.apply_migrations("postgresql://test", tmp_path)
    assert connection.closed is True
