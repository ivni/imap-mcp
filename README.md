# IMAP MCP Server

[![CI](https://github.com/ivni/imap-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/ivni/imap-mcp/actions/workflows/ci.yml)

It is a fork of original [non-dirty/imap-mcp](https://github.com/non-dirty/imap-mcp). Original project have security issues and was not updated for a year. It was also developed for Gmail, while Gmail itself have native integration with Claude now. So my idea was to update it:

* fix security issues
* make it provider agnostic
* remove Gmail specific code
* move fully to uv
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
├── Dockerfile                      # Multi-stage Docker build
├── docker-compose.yml              # Production (Traefik) + dev services
├── docker-compose.standalone.yml   # Standalone override (no Traefik)
├── .env.example                    # Environment variable template
├── .dockerignore                   # Docker build exclusions
├── pyproject.toml                  # Project configuration
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

Configure via environment variables in `.env`:

| Variable                   | Required   | Description                                    |
| -------------------------- | ---------- | ---------------------------------------------- |
| `OIDC_ISSUER_URL`          | Yes (HTTP) | OIDC provider issuer URL                       |
| `OIDC_JWKS_URI`            | No         | Explicit JWKS endpoint (skips OIDC discovery)  |
| `OIDC_AUDIENCE`            | No         | Expected JWT audience claim                    |
| `MCP_RESOURCE_SERVER_URL`  | No         | Public URL of MCP server for OAuth metadata    |

The `stdio` transport does not use authentication (protected by OS process isolation).

## Security Considerations

This MCP server requires access to your email account, which contains sensitive personal information. Please be aware of the following security considerations:

* Store email credentials securely using environment variables or secure credential storage
* Consider using app-specific passwords instead of your main account password
* Limit folder access to only what's necessary for your use case
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
* [ ] Integration with major email providers

## Contributing

Contributions are welcome!

## License

This project is licensed under the MIT License.

## Acknowledgments

* [Model Context Protocol](https://modelcontextprotocol.io/) for providing the framework
* [Anthropic](https://www.anthropic.com/) for developing Claude
* Various Python IMAP libraries that make this project possible
