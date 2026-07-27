"""Runtime health smoke check executed inside the candidate container."""
import json

import httpx


live = httpx.get("http://127.0.0.1:8784/livez", timeout=5)
assert live.status_code == 200, live.text
assert live.json() == {"status": "alive"}

ready = httpx.get("http://127.0.0.1:8784/readyz", timeout=5)
assert ready.status_code == 200, ready.text
body = ready.json()
assert body["status"] == "ready", json.dumps(body, indent=2)
assert body["inventory_loaded"] is True
# This is the production invariant: readiness never waits for fleet warm-up.
assert body["devices"] == {
    "total": 0,
    "connected": 0,
    "claimed": 0,
    "down": 0,
}
