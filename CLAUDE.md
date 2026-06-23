# IMAP MCP Server

Universal IMAP MCP server for AI assistants. Provider-agnostic: works with any IMAP server, not tied to any specific provider. Python 3.13+, FastMCP framework, imapclient library.

## Security Rules

- NEVER log email content, subjects, sender addresses, or credentials at any log level
- NEVER use f-strings or string formatting to build IMAP commands — use imapclient's parameterized API to prevent IMAP injection
- NEVER store secrets (passwords) in code, sample configs, or test fixtures — use environment variables only
- Passwords ONLY from environment variables (`IMAP_PASSWORD`, `SMTP_PASSWORD`) — `config.yaml` password field is ignored with a warning
- Environment variables ALWAYS override YAML config values (`IMAP_HOST`, `IMAP_PORT`, `IMAP_USERNAME`, `IMAP_USE_SSL`, `IMAP_ALLOWED_FOLDERS`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_USE_TLS`)
- NEVER commit files matching: `config.yaml*`, `.env*`
- MUST validate all MCP tool input parameters:
  - Folder names sanitized against IMAP injection characters (`_validate_folder_name`) and checked against `allowed_folders` when configured
  - UIDs must be positive integers
  - Search criteria must use the whitelist pattern (see `tools.py` search_criteria_map)
- MUST enforce `allowed_folders` in ALL code paths, including `search_emails` with `folder=None`
- When `allowed_folders` is not configured, defaults to INBOX-only access (principle of least privilege)
- Set `allowed_folders: []` in config or `IMAP_ALLOWED_FOLDERS=""` to explicitly allow all folders
- MUST keep TLS certificate verification enabled; support explicit custom CA bundle config (`IMAP_TLS_CA_BUNDLE`, `SMTP_TLS_CA_BUNDLE` env vars, or `tls_ca_bundle` in config YAML), never silently disable verification
- MUST require confirmation for destructive tools (delete, move, send) — design for prompt injection resistance
- `.env` file loading is disabled by default; `IMAP_MCP_LOAD_DOTENV=true` opts in — prevents malicious `.env` override in shared/containerized environments
- `IMAP_MCP_SKIP_CONFIRMATION=true` bypasses confirmation — ONLY for trusted CI/automation, never in production with user-facing AI

## Commands

- Install: `uv sync --extra dev`
- Run all tests: `uv run pytest`
- Run single test: `uv run pytest tests/test_file.py::TestClass::test_func -v`
- Test with coverage: `uv run pytest --cov=imap_mcp`
- Skip integration tests: `uv run pytest --skip-integration`
- Run server (HTTP): `uv run python -m imap_mcp.server --transport streamable-http`
- Docker build: `docker compose up --build`
- Docker standalone: `docker compose -f docker-compose.yml -f docker-compose.standalone.yml up --build`
- Docker dev: `docker compose --profile dev up imap-mcp-dev --build`
- Package management: ONLY `uv add <package>` — FORBIDDEN: `pip install`, `@latest` syntax
- Dependency audit: `uv run pip-audit`
- CI: GitHub Actions on push/PR to main — lockfile check, dependency audit, lint, type check, unit tests

## Architecture

- `imap_mcp/server.py` — FastMCP server entry point, lifespan connection management; `build_streamable_http_app()` wraps the app with observability middleware
- `imap_mcp/config.py` — YAML + env var config (ImapConfig, ServerConfig); passwords only from env vars; `create_ssl_context()` helper for TLS
- `imap_mcp/logging_config.py` — structured logging: `configure_logging()`, JSON/text formatters, correlation-ID `ContextVar` (`set_correlation_id`/`get_correlation_id`)
- `imap_mcp/metrics.py` — Prometheus instruments + `PrometheusMiddleware` (raw ASGI); exposed via `/metrics`
- `imap_mcp/imap_client.py` — IMAP operations (connect, search, fetch, move, delete, threading)
- `imap_mcp/tools.py` — MCP tool registrations with ToolAnnotations (3 tiers: read-only, write non-destructive, write destructive); all tools have title + annotations
- `imap_mcp/resources.py` — MCP resource registrations with title/description (folders, list, search, email content)
- `imap_mcp/models.py` — Data models: Email, EmailAddress, EmailContent, EmailAttachment
- `imap_mcp/auth.py` — JWT authentication: OIDC provider verification via JWKS (RS256)
- `imap_mcp/smtp_client.py` — Reply composition with MIME (plain text + HTML); nh3-based HTML sanitization for quoted content
- `imap_mcp/workflows/` — Meeting invite parsing, calendar mock, reply generation

## Concurrency

- Each MCP session has its own `ImapClient` / IMAP connection (created in `server_lifespan`); there is no shared server-wide connection
- `imapclient` is synchronous and blocking. Async tools/resources MUST offload blocking IMAP work off the event loop with `anyio.to_thread.run_sync(...)` — never call a socket-touching `ImapClient` method directly in an `async def` handler
- `ImapClient` is thread-safe: every socket-touching method is wrapped with `@_synchronized` (a re-entrant `RLock`) so worker threads sharing one connection cannot interleave commands. Use `RLock` (not `Lock`) because composite methods call other decorated methods. Pure validators (`_validate_folder_name`, `_validate_uid`, `_is_folder_allowed`) are intentionally NOT synchronized
- When adding a new socket-touching method, decorate it with `@_synchronized` (see `tests/test_imap_client_concurrency.py` which guards this)

## Observability

- Logging is configured once via `configure_logging()` (called in `main()`), NOT `logging.basicConfig`. `IMAP_MCP_LOG_FORMAT=json` opts into one-JSON-object-per-line output; default is plaintext
- The JSON formatter serializes ONLY a fixed field set (timestamp, level, logger, message, optional correlation_id/exception) — never arbitrary record attributes — so the "never log email content/subjects/addresses/credentials" invariant holds regardless of format. Preserve this when editing formatters
- Correlation IDs live in a `ContextVar` (`logging_config._correlation_id`); `CorrelationIdMiddleware` (HTTP only) sets it per request from a sanitized `X-Request-ID` or a generated UUID. `anyio.to_thread.run_sync` copies the context, so offloaded IMAP work keeps the ID
- HTTP transport runs via `_run_http()` (uvicorn on `build_streamable_http_app(server)`), NOT `server.run()`, so the correlation + Prometheus middleware can wrap the app. Both middlewares are raw ASGI (not `BaseHTTPMiddleware`) so the streaming `/mcp` endpoint is not buffered
- `/metrics`, `/health`, `/ready` are `custom_route`s that bypass OIDC — never put sensitive data in their responses. Metric label values are bounded (paths normalized against a known-route allowlist) to prevent cardinality blowup from unauthenticated callers
- When adding HTTP metrics, label only low-cardinality dimensions; when instrumenting IMAP session state, do it in `server_lifespan` (per-session), not by reaching into `imap_client.py`

## Authentication

- `streamable-http` transport requires OIDC JWT authentication — no unauthenticated access
- `stdio` transport has no auth (protected by OS process isolation)
- MCP server acts as **Resource Server** only — validates JWT tokens, does not serve OAuth endpoints
- Provider-agnostic: works with any OIDC provider (Authentik, Keycloak, Auth0, etc.)
- NEVER hardcode auth server URLs — all URLs come from environment variables
- `OIDC_AUDIENCE` is REQUIRED for HTTP transport — binds tokens to this server's `aud` claim to prevent token passthrough / confused-deputy (tokens minted for another resource server of the same issuer being replayed). HTTP transport fails to start if it is unset; `OIDC_ALLOW_ANY_AUDIENCE=true` is the explicit, logged opt-out (disables audience verification — never in production). Audience is verified (`verify_aud=True`) whenever an audience is configured.
- Environment variables:
  - `OIDC_ISSUER_URL` (required for HTTP) — OIDC provider issuer URL
  - `OIDC_JWKS_URI` (optional) — explicit JWKS endpoint, skips OIDC discovery
  - `OIDC_AUDIENCE` (required for HTTP) — expected JWT audience claim
  - `OIDC_ALLOW_ANY_AUDIENCE` (optional) — opt out of the audience requirement; disables `aud` verification
  - `MCP_RESOURCE_SERVER_URL` (optional) — public URL of MCP server for OAuth metadata

## Code Conventions

- Type hints required on all functions (mypy strict mode in pyproject.toml)
- Docstrings on all public classes and methods (Google style)
- Use specific exceptions with helpful messages, never bare `except:`
- TDD: write tests before implementation
- New MCP tools: register in `tools.py` via `register_tools()`, use `@mcp.tool()` decorator
- New MCP resources: register in `resources.py` via `register_resources()`
- Provider-agnostic: do not hardcode provider-specific logic; use IMAP capabilities for feature detection, not hostname checks
- When changing code, update affected documentation (README.md, this CLAUDE.md, docs/, docstrings) in the same PR to keep docs in sync with the codebase

## Git Workflow

- Branch naming: `feature/issue-[NUMBER]-[short-description]`
- Commits must reference issues: `refs #N`, `fixes #N`, or `closes #N`
- PR body must include `Closes #[NUMBER]` for auto-close
- Use `gh` (GitHub CLI) for all GitHub operations: issues, PRs, checks, releases
- Full conventions: see `docs/COMMIT_CONVENTIONS.md`

## Issue Tracking

- When you discover a bug, security issue, improvement opportunity, or technical debt during work — suggest the user create a GitHub issue for it (using `gh issue create`)
- Exception: if the finding is directly related to the current task, fix it in place instead of creating a separate issue

## Known Technical Debt

(none currently tracked)

## Testing

- Unit tests mock imapclient; fixtures in `tests/conftest.py`
- No integration tests currently exist; infrastructure (`@pytest.mark.integration`, `--skip-integration`) is retained
- Future integration tests should use env vars: `TEST_IMAP_HOST`, `TEST_SMTP_HOST`, `TEST_EMAIL`, `TEST_PASSWORD`
- Mark integration tests with `@pytest.mark.integration`; skip with `--skip-integration`
- Run `uv run pytest --cov=imap_mcp` before every PR

## CI/CD

- GitHub Actions workflow in `.github/workflows/ci.yml`
- Runs on push to `main` and pull requests targeting `main`
- Pipeline (`check` job): lockfile integrity (`uv lock --check`) → install (`uv sync --frozen`) → dependency audit (`pip-audit`) → lint (ruff + mypy) → unit tests
- Pipeline (`docker` job, parallel): Docker image build → Trivy vulnerability scan (CRITICAL/HIGH, fails on findings)
- Supply chain security: `uv sync --frozen` verifies all dependency hashes against `uv.lock`
- Production: `Dockerfile` also uses `uv sync --frozen` for hash-verified installs
