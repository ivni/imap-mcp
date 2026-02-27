# IMAP MCP Server

Universal IMAP MCP server for AI assistants. Provider-agnostic: works with any IMAP server, not tied to any specific provider. Python 3.13+, FastMCP framework, imapclient library.

## Security Rules

- NEVER log email content, subjects, sender addresses, or credentials at any log level
- NEVER use f-strings or string formatting to build IMAP commands — use imapclient's parameterized API to prevent IMAP injection
- NEVER store secrets (passwords) in code, sample configs, or test fixtures — use environment variables only
- Passwords ONLY from environment variables (`IMAP_PASSWORD`, `SMTP_PASSWORD`) — `config.yaml` password field is ignored with a warning
- NEVER commit files matching: `config.yaml*`, `.env*`
- MUST validate all MCP tool input parameters:
  - Folder names sanitized against IMAP injection characters (`_validate_folder_name`) and checked against `allowed_folders` when configured
  - UIDs must be positive integers
  - Search criteria must use the whitelist pattern (see `tools.py` search_criteria_map)
- MUST enforce `allowed_folders` in ALL code paths, including `search_emails` with `folder=None`
- When `allowed_folders` is not configured, defaults to INBOX-only access (principle of least privilege)
- Set `allowed_folders: []` in config or `IMAP_ALLOWED_FOLDERS=""` to explicitly allow all folders
- MUST keep TLS certificate verification enabled; support explicit custom CA bundle config, never silently disable verification
- MUST require confirmation for destructive tools (delete, move, send) — design for prompt injection resistance
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

## Architecture

- `imap_mcp/server.py` — FastMCP server entry point, lifespan connection management
- `imap_mcp/config.py` — YAML + env var config (ImapConfig, ServerConfig); passwords only from env vars
- `imap_mcp/imap_client.py` — IMAP operations (connect, search, fetch, move, delete, threading)
- `imap_mcp/tools.py` — MCP tool registrations (search, delete, move, flag, draft, meeting workflow)
- `imap_mcp/resources.py` — MCP resource registrations (folders, list, search, email content)
- `imap_mcp/models.py` — Data models: Email, EmailAddress, EmailContent, EmailAttachment
- `imap_mcp/auth.py` — JWT authentication: OIDC provider verification via JWKS (RS256)
- `imap_mcp/smtp_client.py` — Reply composition with MIME (plain text + HTML)
- `imap_mcp/workflows/` — Meeting invite parsing, calendar mock, reply generation

## Authentication

- `streamable-http` transport requires OIDC JWT authentication — no unauthenticated access
- `stdio` transport has no auth (protected by OS process isolation)
- MCP server acts as **Resource Server** only — validates JWT tokens, does not serve OAuth endpoints
- Provider-agnostic: works with any OIDC provider (Authentik, Keycloak, Auth0, etc.)
- NEVER hardcode auth server URLs — all URLs come from environment variables
- Environment variables:
  - `OIDC_ISSUER_URL` (required for HTTP) — OIDC provider issuer URL
  - `OIDC_JWKS_URI` (optional) — explicit JWKS endpoint, skips OIDC discovery
  - `OIDC_AUDIENCE` (optional) — expected JWT audience claim
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
- NEVER include `Co-Authored-By` lines or any AI tool mentions in commit messages
- Full conventions: see `docs/COMMIT_CONVENTIONS.md`

## Issue Tracking

- When you discover a bug, security issue, improvement opportunity, or technical debt during work — suggest the user create a GitHub issue for it (using `gh issue create`)
- Exception: if the finding is directly related to the current task, fix it in place instead of creating a separate issue

## Known Technical Debt

(none currently tracked)

## Testing

- Unit tests mock imapclient; fixtures in `tests/conftest.py`
- Integration tests require env vars: `TEST_IMAP_HOST`, `TEST_SMTP_HOST`, `TEST_EMAIL`, `TEST_PASSWORD`
- Mark integration tests with `@pytest.mark.integration`; skip with `--skip-integration`
- Run `uv run pytest --cov=imap_mcp` before every PR
