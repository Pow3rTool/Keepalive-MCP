"""Apply Keepalive-MCP's ordered PostgreSQL migrations exactly once."""
import asyncio
import hashlib
import os
import re
from pathlib import Path

import asyncpg


MIGRATIONS_DIR = Path(__file__).with_name("deploy") / "migrations"
_MIGRATION_NAME = re.compile(r"^\d{3}_[a-z0-9_]+\.sql$")
_LOCK_NAME = "keepalive-mcp-schema-migrations"


def discover_migrations(directory: Path = MIGRATIONS_DIR) -> list[Path]:
    """Return validated, deterministically ordered migration files."""
    migrations = sorted(directory.glob("*.sql"))
    invalid = [path.name for path in migrations if not _MIGRATION_NAME.fullmatch(path.name)]
    if invalid:
        raise ValueError(f"invalid migration filename(s): {', '.join(invalid)}")
    versions = [path.stem.split("_", 1)[0] for path in migrations]
    if len(versions) != len(set(versions)):
        raise ValueError("migration version numbers must be unique")
    return migrations


def migration_checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def apply_migrations(dsn: str, directory: Path = MIGRATIONS_DIR) -> list[str]:
    """Apply missing migrations and reject edits to already-applied files."""
    connection = await asyncpg.connect(dsn)
    applied_now = []
    locked = False
    try:
        await connection.execute(
            """
            CREATE TABLE IF NOT EXISTS keepalive_schema_migrations (
                version     TEXT        PRIMARY KEY,
                filename    TEXT        NOT NULL UNIQUE,
                checksum    TEXT        NOT NULL,
                applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )
        await connection.execute(
            "SELECT pg_advisory_lock(hashtext($1))",
            _LOCK_NAME,
        )
        locked = True
        rows = await connection.fetch(
            "SELECT version, filename, checksum FROM keepalive_schema_migrations"
        )
        applied = {row["version"]: dict(row) for row in rows}

        for path in discover_migrations(directory):
            version = path.stem.split("_", 1)[0]
            checksum = migration_checksum(path)
            previous = applied.get(version)
            if previous is not None:
                if (previous["filename"] != path.name
                        or previous["checksum"] != checksum):
                    raise RuntimeError(
                        f"applied migration {version} no longer matches {path.name}"
                    )
                continue

            async with connection.transaction():
                await connection.execute(path.read_text())
                await connection.execute(
                    """
                    INSERT INTO keepalive_schema_migrations
                        (version, filename, checksum)
                    VALUES ($1, $2, $3)
                    """,
                    version,
                    path.name,
                    checksum,
                )
            applied_now.append(path.name)
    finally:
        if locked:
            await connection.execute(
                "SELECT pg_advisory_unlock(hashtext($1))",
                _LOCK_NAME,
            )
        await connection.close()
    return applied_now


async def _main() -> None:
    dsn = os.environ.get("KA_DB_DSN", "").strip()
    if not dsn:
        raise SystemExit("KA_DB_DSN is required")
    applied = await apply_migrations(dsn)
    if applied:
        print(f"[keepalive-migrate] applied: {', '.join(applied)}", flush=True)
    else:
        print("[keepalive-migrate] schema already current", flush=True)


if __name__ == "__main__":
    asyncio.run(_main())
