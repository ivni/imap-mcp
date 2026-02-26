# === Builder ===
FROM python:3.13-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy application source and install the project
COPY imap_mcp/ ./imap_mcp/
COPY README.md ./
RUN uv sync --frozen --no-dev

# === Runtime ===
FROM python:3.13-slim AS runtime

RUN groupadd --gid 1000 mcp \
    && useradd --uid 1000 --gid mcp --shell /bin/bash --create-home mcp

WORKDIR /app

COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/imap_mcp /app/imap_mcp
COPY --from=builder /app/pyproject.toml /app/
COPY --from=builder /app/README.md /app/

ENV PATH="/app/.venv/bin:$PATH"
ENV MCP_TRANSPORT="streamable-http"
ENV MCP_HOST="0.0.0.0"
ENV MCP_PORT="8010"

EXPOSE 8010

USER mcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8010/mcp')" || exit 1

CMD ["python", "-m", "imap_mcp.server"]
