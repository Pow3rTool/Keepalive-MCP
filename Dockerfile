# Self-contained image for keepalive-mcp. Build from the repo root:
#   podman build -t keepalive-mcp .
# Runtime needs (injected, not baked): KA_DB_DSN, an SSH key mount, and KA_REDIRECT_URI
# (the Entra reply URL) + a seeded known_hosts (or KA_SSH_HOSTKEY_POLICY=off). Single replica
# (the warm SSH pool is in-process state).
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .
RUN useradd --system --uid 10001 mcp
USER mcp

EXPOSE 8784
CMD ["python", "server.py"]
