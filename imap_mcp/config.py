"""Configuration handling for IMAP MCP server."""

import logging
import os
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


def _maybe_load_dotenv() -> None:
    """Load .env file only when explicitly opted in via IMAP_MCP_LOAD_DOTENV=true.

    Unconditional .env loading is a security risk: an attacker with write
    access to the working directory can plant a malicious .env file to
    override credentials or redirect connections.
    """
    if os.environ.get("IMAP_MCP_LOAD_DOTENV", "").lower() == "true":
        from dotenv import load_dotenv

        load_dotenv()
        logger.warning(
            ".env file loaded (IMAP_MCP_LOAD_DOTENV=true) — "
            "disable in production for security"
        )


def create_ssl_context(ca_bundle: Optional[str] = None) -> ssl.SSLContext:
    """Create an SSL context with certificate verification and optional custom CA bundle.

    Always creates a context with certificate verification enabled.
    Never silently disables verification.

    Args:
        ca_bundle: Path to a custom CA bundle file (PEM format).
            If None, uses the system default certificate store.

    Returns:
        Configured SSL context with verification enabled.

    Raises:
        FileNotFoundError: If the specified CA bundle file does not exist.
        ssl.SSLError: If the CA bundle file cannot be loaded.
    """
    context = ssl.create_default_context()
    if ca_bundle:
        bundle_path = Path(ca_bundle)
        if not bundle_path.exists():
            raise FileNotFoundError(
                f"TLS CA bundle file not found: {ca_bundle}"
            )
        context.load_verify_locations(ca_bundle)
        logger.info("Loaded custom CA bundle: %s", ca_bundle)
    return context


@dataclass
class ImapConfig:
    """IMAP server configuration."""

    host: str
    port: int
    username: str
    password: str
    use_ssl: bool = True
    tls_ca_bundle: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ImapConfig":
        """Create configuration from dictionary.

        Password is resolved exclusively from the IMAP_PASSWORD environment
        variable. The 'password' key in config dict is ignored for security.
        """
        if data.get("password"):
            logger.warning(
                "Ignoring 'password' in IMAP config — "
                "use IMAP_PASSWORD environment variable instead"
            )

        password = os.environ.get("IMAP_PASSWORD")
        if not password:
            raise ValueError(
                "IMAP password must be specified via IMAP_PASSWORD environment variable"
            )

        tls_ca_bundle = (
            os.environ.get("IMAP_TLS_CA_BUNDLE") or data.get("tls_ca_bundle") or None
        )

        return cls(
            host=data["host"],
            port=data.get("port", 993 if data.get("use_ssl", True) else 143),
            username=data["username"],
            password=password,
            use_ssl=data.get("use_ssl", True),
            tls_ca_bundle=tls_ca_bundle,
        )


@dataclass
class SmtpConfig:
    """SMTP server configuration."""

    host: str
    port: int
    username: str
    password: str
    use_tls: bool = True
    tls_ca_bundle: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SmtpConfig":
        """Create configuration from dictionary.

        Password is resolved exclusively from the SMTP_PASSWORD environment
        variable. The 'password' key in config dict is ignored for security.
        """
        if data.get("password"):
            logger.warning(
                "Ignoring 'password' in SMTP config — "
                "use SMTP_PASSWORD environment variable instead"
            )

        password = os.environ.get("SMTP_PASSWORD") or os.environ.get("IMAP_PASSWORD")
        if not password:
            raise ValueError(
                "SMTP password must be specified via SMTP_PASSWORD "
                "(or IMAP_PASSWORD) environment variable"
            )

        tls_ca_bundle = (
            os.environ.get("SMTP_TLS_CA_BUNDLE")
            or os.environ.get("IMAP_TLS_CA_BUNDLE")
            or data.get("tls_ca_bundle")
            or None
        )

        return cls(
            host=data["host"],
            port=data.get("port", 587 if data.get("use_tls", True) else 465),
            username=data["username"],
            password=password,
            use_tls=data.get("use_tls", True),
            tls_ca_bundle=tls_ca_bundle,
        )


_ALLOWED_FOLDERS_UNSET = object()  # Sentinel: "allowed_folders" key absent from config


@dataclass
class ServerConfig:
    """MCP server configuration."""

    imap: ImapConfig
    allowed_folders: Optional[List[str]] = None
    smtp: Optional[SmtpConfig] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServerConfig":
        """Create configuration from dictionary.

        When ``allowed_folders`` is absent from *data*, the server defaults to
        INBOX-only access (principle of least privilege).  Set the key to an
        empty list explicitly to allow unrestricted folder access.
        """
        smtp_config = None
        if "smtp" in data:
            smtp_config = SmtpConfig.from_dict(data["smtp"])

        raw_allowed = data.get("allowed_folders", _ALLOWED_FOLDERS_UNSET)
        if raw_allowed is _ALLOWED_FOLDERS_UNSET:
            resolved_allowed: Optional[List[str]] = ["INBOX"]
            logger.warning(
                "allowed_folders not configured — defaulting to INBOX-only access. "
                "Set allowed_folders in config or IMAP_ALLOWED_FOLDERS env var. "
                "Use empty list for unrestricted access."
            )
        elif isinstance(raw_allowed, list) and len(raw_allowed) == 0:
            resolved_allowed = None
            logger.info(
                "allowed_folders set to empty list — all folders accessible"
            )
        else:
            resolved_allowed = raw_allowed

        return cls(
            imap=ImapConfig.from_dict(data.get("imap", {})),
            allowed_folders=resolved_allowed,
            smtp=smtp_config,
        )


def load_config(config_path: Optional[str] = None) -> ServerConfig:
    """Load configuration from file or environment variables.

    Args:
        config_path: Path to configuration file

    Returns:
        Server configuration

    Raises:
        FileNotFoundError: If configuration file is not found
        ValueError: If configuration is invalid
    """
    _maybe_load_dotenv()

    # Default locations to check for config file
    default_locations = [
        Path("config.yaml"),
        Path("config.yml"),
        Path("~/.config/imap-mcp/config.yaml"),
        Path("/etc/imap-mcp/config.yaml"),
    ]

    # Load from specified path or try default locations
    config_data: Dict[str, Any] = {}
    if config_path:
        try:
            with open(config_path, "r") as f:
                config_data = yaml.safe_load(f) or {}
            logger.info(f"Loaded configuration from {config_path}")
        except FileNotFoundError:
            logger.warning(f"Configuration file not found: {config_path}")
    else:
        for path in default_locations:
            expanded_path = path.expanduser()
            if expanded_path.exists():
                with open(expanded_path, "r") as f:
                    config_data = yaml.safe_load(f) or {}
                logger.info(f"Loaded configuration from {expanded_path}")
                break

    # If environment variables are set, they take precedence
    if not config_data:
        logger.info("No configuration file found, using environment variables")
        if not os.environ.get("IMAP_HOST"):
            raise ValueError(
                "No configuration file found and IMAP_HOST environment variable not set"
            )

        config_data = {
            "imap": {
                "host": os.environ.get("IMAP_HOST"),
                "port": int(os.environ.get("IMAP_PORT", "993")),
                "username": os.environ.get("IMAP_USERNAME"),
                "use_ssl": os.environ.get("IMAP_USE_SSL", "true").lower() == "true",
            }
        }

        env_allowed = os.environ.get("IMAP_ALLOWED_FOLDERS")
        if env_allowed is not None:
            if env_allowed.strip() == "":
                config_data["allowed_folders"] = []  # Explicit empty = unrestricted
            else:
                config_data["allowed_folders"] = [
                    f.strip() for f in env_allowed.split(",")
                ]

        # Build SMTP config from env vars, falling back to IMAP values
        smtp_host = os.environ.get("SMTP_HOST") or os.environ.get("IMAP_HOST")
        smtp_username = os.environ.get("SMTP_USERNAME") or os.environ.get("IMAP_USERNAME")
        # SMTP_PASSWORD is resolved in SmtpConfig.from_dict() from env var;
        # also check IMAP_PASSWORD fallback to decide whether to create SMTP config
        smtp_password = os.environ.get("SMTP_PASSWORD") or os.environ.get("IMAP_PASSWORD")
        if smtp_host and smtp_username and smtp_password:
            config_data["smtp"] = {
                "host": smtp_host,
                "port": int(os.environ.get("SMTP_PORT", "587")),
                "username": smtp_username,
                "use_tls": os.environ.get("SMTP_USE_TLS", "true").lower() == "true",
            }

    # Create config object
    try:
        return ServerConfig.from_dict(config_data)
    except KeyError as e:
        raise ValueError(f"Missing required configuration: {e}")
