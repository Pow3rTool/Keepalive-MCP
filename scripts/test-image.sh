#!/usr/bin/env bash
# Run static checks and the complete test suite against the exact candidate image.
set -euo pipefail

IMAGE="${1:?usage: test-image.sh <candidate-image>}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PODMAN="$(command -v podman || true)"
[ -n "$PODMAN" ] || { echo "podman is required" >&2; exit 1; }

"$PODMAN" run --rm --user 0 --tls-verify=false \
  --entrypoint /bin/sh \
  -v "$ROOT/tests:/tests:ro" \
  "$IMAGE" \
  -c '
    set -eu
    python -m pip install -q --root-user-action=ignore \
      pytest==8.4.2 pytest-asyncio==1.3.0 pytest-cov==6.2.1 ruff==0.12.5
    python -m pip check
    python -m py_compile /app/server.py /app/migrate.py
    cd /app
    ruff check --config /app/pyproject.toml /app/server.py /app/migrate.py /tests
    cd /tmp
    PYTHONPATH=/app python -m pytest -q -p no:cacheprovider \
      --cov=server --cov=migrate --cov-branch --cov-report=term \
      --cov-fail-under=35 /tests
  '
