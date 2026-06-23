# Deployment Guide

This guide covers running the IMAP MCP server in production. For a feature
overview and the full environment-variable reference, see the
[README](../README.md).

## Choosing a topology

| Topology | Transport | Auth | Best for |
|----------|-----------|------|----------|
| **Single user, local** | `stdio` | OS process isolation | Claude Desktop / Claude Code on one machine |
| **Shared service** | `streamable-http` | OIDC JWT (required) | A server reachable by one or more clients over the network |

> **Concurrency note.** Blocking IMAP operations run off the event loop in a
> worker thread pool, so a slow IMAP call no longer stalls other in-flight
> sessions. Each MCP session has its own IMAP connection, and access to that
> single socket is serialized by a per-session lock — so requests *within* one
> session still run one at a time, but separate sessions run concurrently
> ([#65](https://github.com/ivni/imap-mcp/issues/65)).

## Prerequisites

- An IMAP-enabled mailbox (and SMTP credentials if you need reply/draft tools).
- [Docker](https://docs.docker.com/get-docker/) for the HTTP deployment, or
  Python 3.13+ and [uv](https://docs.astral.sh/uv/) for `stdio`.
- For HTTP: an OIDC provider (Authentik, Keycloak, Auth0, …) and a TLS-
  terminating reverse proxy (the bundled compose file uses Traefik).

## Configuration

All settings come from environment variables (which override any YAML config).
**Passwords are accepted only from environment variables**, never from a config
file. Copy `.env.example` to `.env` and fill it in; in Docker the file is loaded
via `env_file:`.

### Production environment checklist

| Variable | Setting | Why |
|----------|---------|-----|
| `IMAP_HOST` / `IMAP_USERNAME` / `IMAP_PASSWORD` | required | Mailbox access (use an app-specific password). |
| `IMAP_USE_SSL` | `true` (default) | Encrypted IMAP. |
| `IMAP_ALLOWED_FOLDERS` | explicit whitelist | Least privilege; defaults to INBOX-only if unset. |
| `MCP_TRANSPORT` | `streamable-http` | Network service. |
| `OIDC_ISSUER_URL` | required (HTTP) | Token issuer; must be HTTPS. |
| `OIDC_AUDIENCE` | required (HTTP) | Binds tokens to this server (the `aud` claim). HTTP transport refuses to start without it; prevents tokens minted for other resource servers of the same issuer from being replayed here. |
| `OIDC_ALLOW_ANY_AUDIENCE` | unset / `false` | Opt-out of the `OIDC_AUDIENCE` requirement. Never enable in production — disables audience verification. |
| `MCP_RESOURCE_SERVER_URL` | public `https://…/mcp` | Advertised in OAuth metadata; set to the public HTTPS URL. |
| `OIDC_ALLOW_HTTP` | unset / `false` | Never enable in production. |
| `IMAP_MCP_LOAD_DOTENV` | unset | Keep `.env` auto-loading off on servers; pass env vars directly. |
| `IMAP_MCP_SKIP_CONFIRMATION` | unset | Only for trusted CI/automation — never with a user-facing AI. |
| `IMAP_TLS_CA_BUNDLE` | optional | Path to a custom CA bundle for internal CAs. |
| `IMAP_MCP_LOG_FORMAT` | `json` (recommended) | `json` emits one structured log object per line for ingestion by ELK/Datadog/Loki; defaults to plaintext `text`. |

## Docker deployment

The image is multi-stage, runs as a non-root user (`mcp`, UID 1000), and pins
its base images by digest.

### Standalone (no reverse proxy)

```bash
cp .env.example .env   # fill in credentials and OIDC settings
docker compose -f docker-compose.yml -f docker-compose.standalone.yml up --build
```

The server listens on `http://localhost:8010/mcp`. Put your own TLS-terminating
proxy in front of it before exposing it to a network.

### Behind Traefik (recommended for a public service)

```bash
docker network create proxy   # first run only
# set IMAP_MCP_DOMAIN=mcp.example.com in .env
docker compose up --build
```

TLS is terminated at Traefik (Let's Encrypt via the `letsencrypt` certresolver);
the container itself speaks plain HTTP on the internal `proxy` network. The
server is reachable at `https://<IMAP_MCP_DOMAIN>/mcp`.

### Resource sizing

The compose files cap each container at `512M` memory and `1.0` CPU, and rotate
JSON logs (`max-size: 10m`, `max-file: 3`). Adjust the `deploy.resources.limits`
block to your workload.

### Health endpoints

Two unauthenticated HTTP endpoints support container orchestration (both bypass
OIDC auth by design, so probes need no credentials):

| Endpoint  | Purpose   | Behaviour |
| --------- | --------- | --------- |
| `GET /health` | Liveness  | Returns `200 {"status": "ok"}` whenever the process is serving HTTP. |
| `GET /ready`  | Readiness | Returns `200 {"status": "ready"}` only when the IMAP server is reachable; `503 {"status": "unavailable"}` otherwise. |

The bundled `HEALTHCHECK` probes `GET /health`. Response bodies never include
connection details (host, username), so they are safe to expose.

`/ready` opens a short-lived IMAP connection to verify reachability, but the
result is cached for a few seconds and concurrent probes are coalesced, so a
burst of requests cannot force a login on every call (rate-limit / lockout
protection for the unauthenticated endpoint). It still bypasses OIDC, so keep
it — like `/metrics` — on the monitoring network rather than exposing it
publicly. Kubernetes example:

```yaml
livenessProbe:
  httpGet: { path: /health, port: 8010 }
  periodSeconds: 30
readinessProbe:
  httpGet: { path: /ready, port: 8010 }
  periodSeconds: 30
```

## Observability

**Structured logging.** Set `IMAP_MCP_LOG_FORMAT=json` to emit one JSON object
per line (fields: `timestamp`, `level`, `logger`, `message`, optional
`correlation_id`, optional `exception`). The default `text` format stays
human-readable. Email content, subjects, addresses, and credentials are never
logged in either format.

**Correlation IDs.** On HTTP transport each request is tagged with a correlation
ID — taken from an inbound `X-Request-ID` header when present (so an upstream
proxy's ID flows through end-to-end), otherwise generated. It is echoed in the
`X-Request-ID` response header and attached to every log line produced while
handling the request, including the offloaded IMAP work.

**Metrics.** A third unauthenticated endpoint, `GET /metrics`, exposes Prometheus
metrics (it bypasses OIDC like the health probes — keep it on the monitoring
network):

| Metric | Type | Meaning |
| ------ | ---- | ------- |
| `imap_mcp_http_requests_total{method,path,status}` | counter | HTTP requests handled. `path` is normalized to a known-route allowlist (others → `other`) to bound cardinality. |
| `imap_mcp_http_request_duration_seconds{method,path}` | histogram | Request latency. |
| `imap_mcp_active_sessions` | gauge | MCP sessions currently holding a live IMAP connection. |
| `imap_mcp_session_connections_total` | counter | Sessions that established an IMAP connection. |
| `imap_mcp_session_connection_errors_total` | counter | Sessions that failed to connect at startup. |

```yaml
# Prometheus scrape config
scrape_configs:
  - job_name: imap-mcp
    metrics_path: /metrics
    static_configs:
      - targets: ["imap-mcp:8010"]
```

Metrics live in the process's own registry, so run the HTTP server as a single
uvicorn worker (the default). Scaling to multiple workers would give each its
own counters and `imap_mcp_active_sessions`, and a scrape would see only the
worker that answered it — scale by running multiple containers (each scraped
separately) instead, or wire up `prometheus_client`'s multiprocess mode.

## stdio deployment (single user)

```bash
uv sync
uv run python -m imap_mcp.server
```

Register it with your MCP client (see the README for Claude Desktop /
Claude Code snippets). No authentication is applied — protection relies on OS
process isolation, so only run it on a trusted machine.

## Security checklist

- [ ] Credentials provided via environment variables (app-specific password).
- [ ] `IMAP_ALLOWED_FOLDERS` restricted to the folders actually needed.
- [ ] HTTP transport sits behind TLS; `OIDC_ISSUER_URL` and `MCP_RESOURCE_SERVER_URL` are HTTPS.
- [ ] `OIDC_AUDIENCE` set and verified.
- [ ] `OIDC_ALLOW_ANY_AUDIENCE`, `OIDC_ALLOW_HTTP`, `IMAP_MCP_SKIP_CONFIRMATION`, and `IMAP_MCP_LOAD_DOTENV` are **not** enabled.
- [ ] Image scanned (CI runs Trivy) and dependencies audited (`uv run pip-audit`).

## Upgrading

1. Pull the new revision and review [`CHANGELOG.md`](../CHANGELOG.md).
2. Rebuild: `docker compose build --pull` (re-pulls pinned base images).
3. `uv lock --check` and `uv run pip-audit` to confirm the lockfile is intact and
   free of known vulnerabilities.
4. Recreate the container: `docker compose up -d`.

There are no persisted data volumes — all state lives on the IMAP server — so a
rollback is simply redeploying the previous image tag.

## Known operational limitations

These are tracked as issues and are worth understanding before a high-traffic
production rollout:

- Per session, requests serialize on that session's single IMAP connection;
  separate sessions run concurrently (blocking work is offloaded off the event
  loop) ([#65](https://github.com/ivni/imap-mcp/issues/65)).
