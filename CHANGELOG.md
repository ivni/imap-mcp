# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> This project is pre-1.0 (Development Status :: Alpha). The initial release,
> `0.1.0`, collects all changes since the fork; subsequent changes accrue under
> **Unreleased** until the next tag.

## [Unreleased]

## [0.1.0] - 2026-06-23

This is a hardened, provider-agnostic fork of
[non-dirty/imap-mcp](https://github.com/non-dirty/imap-mcp). Gmail-specific code
was removed, the project was moved to `uv` and Docker, and OIDC authentication
plus extensive security hardening were added.

### Added

- Provider-agnostic IMAP MCP server (works with any IMAP/SMTP server; no
  hostname-based provider logic — uses IMAP capabilities for feature detection).
- MCP tools grouped into three safety tiers via `ToolAnnotations` (read-only,
  write non-destructive, write destructive); every tool has a title and
  annotations.
- MCP elicitation confirmation for destructive tools (delete, move, send/draft,
  meeting invite) (#1).
- OIDC JWT authentication for the `streamable-http` transport — the server acts
  as a Resource Server, validating RS256 tokens against the provider's JWKS;
  provider-agnostic via environment variables.
- `stdio` and `streamable-http` transports.
- Reply composition (MIME plain text + HTML) with proper threading headers
  (`In-Reply-To`, `References`), reply-all and CC support; drafts saved to the
  appropriate folder.
- Meeting invite parsing, mock calendar availability, and reply-generation
  workflows.
- `offset`/`limit` pagination for the `search_emails` tool (#34).
- TTL on the IMAP folder cache (#33).
- Fetch-count and attachment-size limits to bound resource usage (#17).
- Custom TLS CA bundle support (`IMAP_TLS_CA_BUNDLE`, `SMTP_TLS_CA_BUNDLE`) (#9).
- Configurable IMAP socket timeout (`IMAP_TIMEOUT` env / `imap.timeout` YAML,
  default 30s) so a hung or unresponsive server can no longer block a call
  indefinitely (#62).
- Unauthenticated `GET /health` (liveness) and `GET /ready` (readiness, verifies
  IMAP reachability) HTTP endpoints for container orchestrators; the Docker
  `HEALTHCHECK` now probes `/health` instead of the auth-gated `/mcp`, which had
  reported healthy containers as permanently unhealthy (#64). The `/ready`
  result is cached for a few seconds (concurrent probes coalesced) so the
  unauthenticated endpoint cannot be used to force an IMAP login per request.
- Production observability: opt-in JSON structured logging
  (`IMAP_MCP_LOG_FORMAT=json`), per-request correlation IDs propagated through
  handlers and worker threads (inbound `X-Request-ID` reused, else generated,
  and echoed in the response), and an unauthenticated Prometheus `GET /metrics`
  endpoint exposing request counts/latencies and IMAP session state. No email
  content, subjects, addresses, or credentials are logged or exported in any
  format (#67).
- Multi-stage Docker build with a non-root user, base images pinned by digest,
  and container resource limits (#29); standalone and Traefik compose files.
- GitHub Actions CI: lockfile hash verification, dependency audit (`pip-audit`),
  lint (`ruff`), format check, type check (`mypy` strict), SAST (`bandit`),
  unit tests with coverage ≥80%, Docker build, and Trivy image scan
  (#6, #25, #26, #27, #28, #30).
- `AGENTS.md` and `docs/COMMIT_CONVENTIONS.md`.

### Changed

- Blocking `imapclient` calls in async tool/resource handlers (and the
  per-session connect/disconnect) now run off the event loop via
  `anyio.to_thread.run_sync`, so a slow IMAP operation no longer head-of-line
  blocks other HTTP sessions. The shared per-session connection is guarded by a
  re-entrant lock (`ImapClient` is now thread-safe) so offloaded work cannot
  interleave commands on the single socket (#65).
- Migrated dependency management fully to `uv`; dependencies pinned by hash in
  `uv.lock` and installed with `--frozen` in CI and Docker.
- Replaced broad `except Exception` handlers with specific exceptions in core
  paths (#32). The remaining last-resort catch-alls in tool/resource handlers
  now append the exception type name (e.g. `(KeyError)`) to the user-facing
  error; the exception message is still withheld so an unexpected error cannot
  leak email content (#53).
- Removed dead code: `mcp_protocol.py` (#10), `TASKS_FILE`/`create_task` (#8),
  `get_smtp_client_from_context()` (#31), and the unused `imap_client`
  parameter on `register_tools`/`register_resources` (#55).

### Security

- Folder-name sanitization against IMAP injection characters, enforced across
  all tools (#3, #15); confirmation prompts sanitize folder names before
  interpolation (#49).
- Parameterized search criteria; fixed IMAP injection via email headers in
  `fetch_thread()` (#2).
- `allowed_folders` defaults to INBOX-only and is enforced in every code path,
  including `search_emails(folder=None)` and `move_email` (#4, #21, #45).
- Passwords accepted only from environment variables; YAML password field is
  ignored with a warning.
- `.env` file loading is opt-in via `IMAP_MCP_LOAD_DOTENV` (#7).
- Removed email-subject logging from workflow modules (#5).
- HTML output hardening: `html.escape()` in the SMTP client (#13), escaped
  sender name to fix reply XSS (#40), and `nh3` sanitization of quoted original
  HTML in replies (#52).
- OIDC issuer URL must be HTTPS (#18); JWKS discovery failure is fatal (no
  guessed fallback URI) (#14).
- `OIDC_AUDIENCE` is now required for the `streamable-http` transport — the
  server refuses to start without it, binding tokens to this server's `aud`
  claim so a token the issuer minted for another resource server cannot be
  replayed here (token passthrough / confused-deputy). `OIDC_ALLOW_ANY_AUDIENCE=true`
  is a documented, logged opt-out that disables audience verification (#66).
- UID validation on all tool and resource handlers (#12); email address format
  validation (#16).
- Explicit TLS context with certificate verification enabled by default (#9).
- Routine dependency/base-image upgrades to patch CVEs (cryptography, pyjwt,
  requests, `python:3.13-slim`).
- Upgraded all locked dependencies to clear 32 known CVEs reported by
  `pip-audit` (pyjwt 2.13.0, cryptography 49.0.0, starlette 1.3.1 via mcp 1.28.0,
  python-multipart 0.0.32, urllib3 2.7.0, idna 3.18, msgpack 1.2.1,
  python-dotenv 1.2.2, and dev tools); removed the no-longer-needed pygments
  `--ignore-vuln` from CI now that pip-audit is clean.

### Fixed

- Dead IMAP connections (idle timeout, server restart, transient network blip)
  now detected via a lightweight `NOOP` probe and transparently reconnected with
  bounded exponential-backoff retry, instead of leaving `connected = True` over a
  dead socket and failing every subsequent operation (#63). The probe is skipped
  when the socket was used within the last 30s, so it adds no round-trip on an
  actively used connection.
- Multi-folder search pagination dropping results (#41).
- Environment-variable config overrides silently ignored when a YAML file
  exists (#42).
- Meeting invite parser using the email send date instead of the invite date
  (#43); AM-midnight parsing and 23:xx hour-overflow crash (#35, #44).
- Silent mutation failures masking data corruption in IMAP operations (#46).
- `process_email` reporting success even when an IMAP action failed (#36).
- Draft save reporting a false failure on servers without UIDPLUS (#48).
- Drafts-folder detection on servers using a dot hierarchy delimiter (#50).
- `Email.from_message` mis-splitting recipients with commas in display names
  (#37); `decode_mime_header` crash on malformed encoded headers (#38).
- Reply using the wrong sender address (used `config.username`) (#11).
- Explicitly specified config file silently ignored when missing — now raises
  `FileNotFoundError` (#47).
- Replaced `assert`-based null checks in production paths with explicit
  `ConnectionError` (#51).

[Unreleased]: https://github.com/ivni/imap-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ivni/imap-mcp/releases/tag/v0.1.0
