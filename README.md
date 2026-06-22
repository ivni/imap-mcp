# IMAP MCP Server

[![CI](https://github.com/ivni/imap-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/ivni/imap-mcp/actions/workflows/ci.yml)

It is a fork of original [non-dirty/imap-mcp](https://github.com/non-dirty/imap-mcp). Original project have security issues and was not updated for a year. It was also developed for Gmail, while Gmail itself have native integration with Claude now. So my idea was to update it:

* fix security issues
* make it provider agnostic
* remove Gmail specific code
* moved fully to uv
* move project to docker infrastructure

Model Context Protocol (MCP) server that enables AI assistants to check email, process messages, and learn user preferences through interaction.

## Overview

This project implements an MCP server that interfaces with IMAP email servers to provide the following capabilities:

* Email browsing and searching
* Email organization (moving, tagging, marking)
* Email composition and replies
* Interactive email processing and learning user preferences
* Automated email summarization and categorization
* Support for multiple IMAP providers

The IMAP MCP server is designed to work with Claude or any other MCP-compatible assistant, allowing them to act as intelligent email assistants that learn your preferences over time.

## Features

* **Email Authentication**: Secure access to IMAP servers with various authentication methods
* **Email Browsing**: List folders and messages with filtering options
* **Email Content**: Read message contents including text, HTML, and attachments
* **Email Actions**: Move, delete, mark as read/unread, flag messages (destructive actions require user confirmation)
* **Email Composition**: Draft and save replies to messages with proper formatting
  * Support for plain text and HTML replies
  * Reply-all functionality with CC support
  * Proper threading with In-Reply-To and References headers
  * Save drafts to appropriate folders
* **Search**: Basic search capabilities across folders
* **Interaction Patterns**: Structured patterns for processing emails and learning preferences (planned)
* **Learning Layer**: Record and analyze user decisions to predict future actions (planned)

## Available Tools

All tools carry [MCP ToolAnnotations](https://modelcontextprotocol.io/specification/2025-06-18/schema#toolannotations) so clients (Claude, ChatGPT, etc.) can group them by safety level and skip confirmation prompts for read-only operations.

### Read-only (safe — no server state changes)

| Tool | Title | Description |
|------|-------|-------------|
| `search_emails` | Search Emails | Search across folders by text, sender, subject, or status filters with pagination |
| `identify_meeting_invite_tool` | Identify Meeting Invite | Analyze an email for calendar invite data without modifying state |
| `check_calendar_availability_tool` | Check Calendar Availability | Check availability for a proposed meeting time (mock calendar) |
| `draft_meeting_reply_tool` | Generate Meeting Reply | Generate accept/decline reply text without saving to server |
| `server_status` | Server Status | Show IMAP/SMTP configuration and connection status |

### Write, non-destructive (modifies state but only additively)

| Tool | Title | Description | Confirmation |
|------|-------|-------------|-------------|
| `mark_as_read` | Mark as Read | Set the IMAP `\Seen` flag (idempotent) | No |
| `mark_as_unread` | Mark as Unread | Remove the IMAP `\Seen` flag (idempotent) | No |
| `flag_email` | Flag/Unflag Email | Set or remove `\Flagged` star/important marker (idempotent) | No |
| `draft_reply_tool` | Save Draft Reply | Compose a reply and save as draft with proper threading headers | Yes |
| `process_meeting_invite` | Process Meeting Invite | Full workflow: identify invite → check calendar → save draft reply | Yes |

### Write, destructive (permanently removes or relocates data)

| Tool | Title | Description | Confirmation |
|------|-------|-------------|-------------|
| `move_email` | Move Email | Move email between folders (removes from source) | Yes |
| `delete_email` | Delete Email | Permanently delete email (irreversible) | Yes |
| `process_email` | Process Email Action | Multi-action tool: read/unread/flag/unflag/move/delete | Yes (move/delete) |

### Resources

| URI | Title | Description |
|-----|-------|-------------|
| `email://folders` | Email Folders | List all accessible IMAP folders |
| `email://{folder}/list` | List Emails in Folder | Up to 50 most recent emails with summaries |
| `email://search/{query}` | Search Emails | Search across all folders (up to 10 per folder) |
| `email://{folder}/{uid}` | Get Email Content | Full email content including headers, body, attachments |

## Project Structure

```plaintext
.
├── imap_mcp/                       # Source code
│   ├── server.py                   # FastMCP server entry point
│   ├── config.py                   # Configuration handling
│   ├── imap_client.py              # IMAP client implementation
│   ├── auth.py                     # JWT authentication (OIDC/JWKS)
│   ├── smtp_client.py              # Reply composition (MIME)
│   ├── models.py                   # Data models
│   ├── resources.py                # MCP resources
│   ├── tools.py                    # MCP tools
│   └── workflows/                  # Meeting invite parsing, replies
├── tests/                          # Test suite
├── docs/
│   └── COMMIT_CONVENTIONS.md       # Git commit message format
├── Dockerfile                      # Multi-stage Docker build
├── docker-compose.yml              # Production (Traefik) + dev services
├── docker-compose.standalone.yml   # Standalone override (no Traefik)
├── .env.example                    # Environment variable template
├── .dockerignore                   # Docker build exclusions
├── pyproject.toml                  # Project configuration
├── uv.lock                         # Dependency lockfile (hash-pinned)
├── AGENTS.md                       # AI assistant instructions
└── README.md                       # This file
```

## Getting Started

### Prerequisites

* [Docker](https://docs.docker.com/get-docker/) for deployment
* An IMAP-enabled email account

### Quick Start (Docker)

1. Clone the repository:

   ```bash
   git clone https://github.com/ivni/imap-mcp.git
   cd imap-mcp
   ```

2. Copy the environment template and fill in your IMAP credentials:

   ```bash
   cp .env.example .env
   ```

3. Build and run:

   ```bash
   # Standalone (no reverse proxy required)
   docker compose -f docker-compose.yml -f docker-compose.standalone.yml up --build

   # With Traefik reverse proxy (production)
   docker network create proxy   # first run only
   docker compose up --build
   ```

   * **Standalone** — MCP server available at `http://localhost:8010/mcp`
   * **Traefik** — MCP server available at `https://<IMAP_MCP_DOMAIN>/mcp`

4. Connect from Claude Code:

   ```bash
   claude mcp add --transport http imap-mcp http://localhost:8010/mcp
   ```

> For a production deployment guide — environment checklist, TLS/reverse-proxy
> setup, OIDC configuration, resource sizing, and known operational limitations —
> see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

### Stdio Transport (Claude Desktop)

For local use without Docker, run the server via stdio transport (the default):

```bash
uv sync
uv run python -m imap_mcp.server
```

Add to Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "imap-mcp": {
      "command": "uv",
      "args": ["run", "python", "-m", "imap_mcp.server"],
      "cwd": "/path/to/imap-mcp",
      "env": {
        "IMAP_HOST": "imap.example.com",
        "IMAP_USERNAME": "you@example.com",
        "IMAP_PASSWORD": "your_app_password",
        "IMAP_MCP_LOAD_DOTENV": "true"
      }
    }
  }
}
```

Or connect from Claude Code:

```bash
claude mcp add imap-mcp -- uv run python -m imap_mcp.server
```

### Development with Docker

```bash
docker compose --profile dev up imap-mcp-dev --build
```

This mounts your local source code into the container. Restart the container to pick up code changes.
The dev server is accessible at `http://localhost:8010/mcp`.

### Local Development (without Docker)

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --extra dev
uv run pytest
```

## Authentication

When running over HTTP (`streamable-http` transport), the server **requires** JWT authentication via an external OIDC provider (Authentik, Keycloak, Auth0, etc.). The server acts as a Resource Server — it validates JWT tokens but does not handle the OAuth flow itself.

Configure via environment variables in `.env` — see [Environment Variables](#environment-variables) below for all authentication settings.

The `stdio` transport does not use authentication (protected by OS process isolation).

## Environment Variables

All environment variables override their YAML config equivalents. Passwords are **only** accepted from environment variables (never from config files).

### IMAP Connection

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `IMAP_HOST` | Yes | — | IMAP server hostname |
| `IMAP_PORT` | No | `993` (SSL) / `143` | IMAP server port |
| `IMAP_USERNAME` | Yes | — | IMAP login username |
| `IMAP_PASSWORD` | Yes | — | IMAP login password (env var only) |
| `IMAP_USE_SSL` | No | `true` | Enable SSL/TLS for IMAP connection |
| `IMAP_TLS_CA_BUNDLE` | No | system default | Path to custom CA bundle (PEM) for IMAP TLS |
| `IMAP_ALLOWED_FOLDERS` | No | `INBOX` | Comma-separated folder whitelist; empty string = unrestricted |

### SMTP Connection (optional — falls back to IMAP values)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SMTP_HOST` | No | `IMAP_HOST` | SMTP server hostname |
| `SMTP_PORT` | No | `587` | SMTP server port |
| `SMTP_USERNAME` | No | `IMAP_USERNAME` | SMTP login username |
| `SMTP_PASSWORD` | No | `IMAP_PASSWORD` | SMTP login password |
| `SMTP_USE_TLS` | No | `true` | Enable STARTTLS for SMTP |
| `SMTP_TLS_CA_BUNDLE` | No | `IMAP_TLS_CA_BUNDLE` | Path to custom CA bundle for SMTP TLS |

### Transport

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MCP_TRANSPORT` | No | `stdio` | Transport protocol: `stdio` or `streamable-http` |
| `MCP_HOST` | No | `127.0.0.1` | Bind address for HTTP transport |
| `MCP_PORT` | No | `8010` | Port for HTTP transport |
| `IMAP_MCP_CONFIG` | No | — | Path to YAML config file (overrides default locations) |

### Authentication (HTTP transport only)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OIDC_ISSUER_URL` | Yes (HTTP) | — | OIDC provider issuer URL |
| `OIDC_JWKS_URI` | No | auto-discovered | Explicit JWKS endpoint (skips OIDC discovery) |
| `OIDC_AUDIENCE` | No | — | Expected JWT audience claim |
| `OIDC_ALLOW_HTTP` | No | `false` | Allow HTTP OIDC issuer URL (development only) |
| `MCP_RESOURCE_SERVER_URL` | No | — | Public URL of MCP server for OAuth metadata |

### Security

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `IMAP_MCP_LOAD_DOTENV` | No | `false` | Set `true` to load `.env` file (disabled by default for security) |
| `IMAP_MCP_SKIP_CONFIRMATION` | No | `false` | Skip destructive action confirmation (CI/automation only) |

### Docker / Traefik

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `IMAP_MCP_DOMAIN` | No | — | Domain for Traefik reverse proxy routing |

## Security Considerations

This MCP server requires access to your email account, which contains sensitive personal information. Please be aware of the following security considerations:

* Store email credentials securely using environment variables or secure credential storage
* Consider using app-specific passwords instead of your main account password
* Limit folder access to only what's necessary for your use case
* **Environment variables always override YAML config** — when both a YAML file and env vars are present, env var values take precedence. This is critical for Docker/Kubernetes deployments where operators override settings via env vars
* **`.env` file loading is disabled by default** to prevent malicious `.env` files from overriding credentials in shared environments. Set `IMAP_MCP_LOAD_DOTENV=true` to opt in during local development. In Docker, use `env_file:` in docker-compose or pass env vars directly
* Review the permissions granted to the server in your email provider's settings
* **Destructive action confirmation**: delete, move, draft reply, and meeting invite tools require explicit user confirmation via MCP Elicitation API before execution. Confirmation messages contain only action, UID, and folder — never email content (prompt injection defense). Set `IMAP_MCP_SKIP_CONFIRMATION=true` to bypass in trusted CI/automation environments only
* **Supply chain security**: All dependencies are pinned by hash in `uv.lock`. CI and Docker builds use `uv sync --frozen` to verify hashes, preventing package substitution attacks
* **TLS certificate verification**: All IMAP and SMTP connections use explicit SSL contexts with certificate verification enabled by default. For environments with internal certificate authorities, set `IMAP_TLS_CA_BUNDLE` (and optionally `SMTP_TLS_CA_BUNDLE`) to a custom CA bundle path. SMTP falls back to `IMAP_TLS_CA_BUNDLE` when its own var is not set

## Project Roadmap

* [x] Project initialization and repository setup
* [x] Basic IMAP integration
* [x] Email resource implementation
* [x] Email tool implementation
* [x] Email reply and draft functionality
* [ ] User preference learning implementation
* [ ] Advanced search capabilities
* [ ] Multi-account support

## Contributing

Contributions are welcome!

## License

This project is licensed under the MIT License.

## Acknowledgments

* [Model Context Protocol](https://modelcontextprotocol.io/) for providing the framework
* [Anthropic](https://www.anthropic.com/) for developing Claude
* Various Python IMAP libraries that make this project possible
