"""Database/NOTIFY integration check executed in the candidate image."""
import asyncio
import json
import os

import asyncpg


async def main() -> None:
    dsn = os.environ["KA_DB_DSN"]
    expected_migrations = int(os.environ["EXPECTED_MIGRATIONS"])
    listener = await asyncpg.connect(dsn)
    writer = await asyncpg.connect(dsn)
    notification = asyncio.Event()
    payloads = []

    def notified(_connection, _pid, _channel, payload):
        payloads.append(json.loads(payload))
        notification.set()

    try:
        migration_count = await writer.fetchval(
            "SELECT count(*) FROM keepalive_schema_migrations"
        )
        assert migration_count == expected_migrations
        await listener.add_listener("keepalive_devices", notified)
        await writer.execute(
            """
            INSERT INTO devices
                (name, host, platform, username, source)
            VALUES
                ('migration-check', '192.0.2.10', 'cisco_iosxe', 'tester', 'test')
            """
        )
        await asyncio.wait_for(notification.wait(), timeout=5)
        assert payloads == [{"op": "INSERT", "name": "migration-check"}]
        await writer.execute(
            """
            INSERT INTO audit
                (who, device, verb, command, rc, status, dur_ms, out_chars)
            VALUES
                ('test', 'migration-check', 'read', 'show clock', 0, 'ok', 1, 10)
            """
        )
        assert await writer.fetchval(
            "SELECT count(*) FROM audit WHERE who = 'test'"
        ) == 1
    finally:
        await listener.close()
        await writer.close()


asyncio.run(main())
