# Deployment Guide

This guide covers running the IMAP MCP server in production. For a feature
overview and the full environment-variable reference, see the
[README](../README.md).

## Choosing a topology

| Topology | Transport | Auth | Best for |
|----------|-----------|------|----------|
| **Single user, local** | `stdio` | OS process isolation | Claude Desktop / Claude Code on one machine |
| **Shared service** | `streamable-http` | OIDC JWT (required) | A server reachable by one or more clients over the network |

> **Concurrency note.** IMAP operations are synchronous and block the event
> loop, so the HTTP server effectively serializes requests; a slow IMAP
> operation stalls all in-flight sessions. This is fine for single-user or
> low-concurrency use but is a throughput ceiling for many simultaneous users
> (see [#65](https://github.com/ivni/imap-mcp/issues/65)).

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
| `OIDC_AUDIENCE` | **set it** | Binds tokens to this server. Strongly recommended — without it the audience claim is not verified ([#66](https://github.com/ivni/imap-mcp/issues/66)). |
| `MCP_RESOURCE_SERVER_URL` | public `https://…/mcp` | Advertised in OAuth metadata; set to the public HTTPS URL. |
| `OIDC_ALLOW_HTTP` | unset / `false` | Never enable in production. |
| `IMAP_MCP_LOAD_DOTENV` | unset | Keep `.env` auto-loading off on servers; pass env vars directly. |
| `IMAP_MCP_SKIP_CONFIRMATION` | unset | Only for trusted CI/automation — never with a user-facing AI. |
| `IMAP_TLS_CA_BUNDLE` | optional | Path to a custom CA bundle for internal CAs. |

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

### Healthcheck caveat

The bundled `HEALTHCHECK` probes `GET /mcp`, which returns 401/405 once OIDC auth
is enabled, so orchestrators may report the container unhealthy. Until a
dedicated health endpoint exists, override or disable the healthcheck, or treat
process liveness as the signal. Tracked in
[#64](https://github.com/ivni/imap-mcp/issues/64).

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
- [ ] `OIDC_ALLOW_HTTP`, `IMAP_MCP_SKIP_CONFIRMATION`, and `IMAP_MCP_LOAD_DOTENV` are **not** enabled.
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

- No socket timeout on IMAP operations — a hung server blocks indefinitely
  ([#62](https://github.com/ivni/imap-mcp/issues/62)).
- Healthcheck / missing `/health` endpoint
  ([#64](https://github.com/ivni/imap-mcp/issues/64)).
- Requests are serialized under load (no real concurrency)
  ([#65](https://github.com/ivni/imap-mcp/issues/65)).
- OIDC audience not enforced unless `OIDC_AUDIENCE` is set
  ([#66](https://github.com/ivni/imap-mcp/issues/66)).
- Plaintext logging only; no structured logs or metrics
  ([#67](https://github.com/ivni/imap-mcp/issues/67)).
