"""Tests for the config module."""

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from imap_mcp.config import ImapConfig, ServerConfig, SmtpConfig, load_config


class TestImapConfig:
    """Test cases for the ImapConfig class."""

    def test_init(self):
        """Test ImapConfig initialization."""
        config = ImapConfig(
            host="imap.example.com",
            port=993,
            username="test@example.com",
            password="password"
        )

        assert config.host == "imap.example.com"
        assert config.port == 993
        assert config.username == "test@example.com"
        assert config.password == "password"
        assert config.use_ssl is True  # Default value

        # Test with custom SSL setting
        config = ImapConfig(
            host="imap.example.com",
            port=143,
            username="test@example.com",
            password="password",
            use_ssl=False
        )
        assert config.use_ssl is False

    def test_from_dict(self, monkeypatch):
        """Test creating ImapConfig from a dictionary."""
        monkeypatch.setenv("IMAP_PASSWORD", "env_password")

        data = {
            "host": "imap.example.com",
            "port": 993,
            "username": "test@example.com",
            "use_ssl": True
        }

        config = ImapConfig.from_dict(data)
        assert config.host == "imap.example.com"
        assert config.port == 993
        assert config.username == "test@example.com"
        assert config.password == "env_password"
        assert config.use_ssl is True

        # Test with minimal data and defaults
        minimal_data = {
            "host": "imap.example.com",
            "username": "test@example.com",
        }

        config = ImapConfig.from_dict(minimal_data)
        assert config.host == "imap.example.com"
        assert config.port == 993  # Default with SSL
        assert config.username == "test@example.com"
        assert config.password == "env_password"
        assert config.use_ssl is True  # Default

        # Test with non-SSL port default
        non_ssl_data = {
            "host": "imap.example.com",
            "username": "test@example.com",
            "use_ssl": False
        }

        config = ImapConfig.from_dict(non_ssl_data)
        assert config.port == 143  # Default non-SSL port

    def test_from_dict_with_env_password(self, monkeypatch):
        """Test creating ImapConfig with password from environment variable."""
        monkeypatch.setenv("IMAP_PASSWORD", "env_password")

        data = {
            "host": "imap.example.com",
            "username": "test@example.com",
        }

        config = ImapConfig.from_dict(data)
        assert config.password == "env_password"

    def test_from_dict_ignores_config_password(self, monkeypatch):
        """Test that password in config dict is ignored — env var is used."""
        monkeypatch.setenv("IMAP_PASSWORD", "env_password")

        data = {
            "host": "imap.example.com",
            "username": "test@example.com",
            "password": "dict_password"
        }

        config = ImapConfig.from_dict(data)
        assert config.password == "env_password"

    def test_from_dict_warns_on_config_password(self, monkeypatch, caplog):
        """Test that a warning is logged when config dict contains password."""
        monkeypatch.setenv("IMAP_PASSWORD", "env_password")

        data = {
            "host": "imap.example.com",
            "username": "test@example.com",
            "password": "dict_password"
        }

        import logging
        with caplog.at_level(logging.WARNING, logger="imap_mcp.config"):
            ImapConfig.from_dict(data)

        assert "Ignoring 'password' in IMAP config" in caplog.text

    def test_from_dict_missing_password(self, monkeypatch):
        """Test error when password env var is not set."""
        monkeypatch.delenv("IMAP_PASSWORD", raising=False)

        data = {
            "host": "imap.example.com",
            "username": "test@example.com",
        }

        with pytest.raises(ValueError) as excinfo:
            ImapConfig.from_dict(data)

        assert "IMAP password must be specified" in str(excinfo.value)

    def test_from_dict_missing_required_fields(self, monkeypatch):
        """Test error when required fields are missing."""
        monkeypatch.setenv("IMAP_PASSWORD", "password")

        # Missing host
        with pytest.raises(KeyError):
            ImapConfig.from_dict({"username": "test@example.com"})

        # Missing username
        with pytest.raises(KeyError):
            ImapConfig.from_dict({"host": "imap.example.com"})


class TestSmtpConfig:
    """Test cases for the SmtpConfig class."""

    def test_init(self):
        """Test SmtpConfig initialization."""
        config = SmtpConfig(
            host="smtp.example.com",
            port=587,
            username="test@example.com",
            password="password"
        )

        assert config.host == "smtp.example.com"
        assert config.port == 587
        assert config.username == "test@example.com"
        assert config.password == "password"
        assert config.use_tls is True  # Default value

        # Test with TLS disabled
        config = SmtpConfig(
            host="smtp.example.com",
            port=465,
            username="test@example.com",
            password="password",
            use_tls=False
        )
        assert config.use_tls is False

    def test_from_dict(self, monkeypatch):
        """Test creating SmtpConfig from a dictionary."""
        monkeypatch.setenv("SMTP_PASSWORD", "env_password")

        data = {
            "host": "smtp.example.com",
            "port": 587,
            "username": "test@example.com",
            "use_tls": True
        }

        config = SmtpConfig.from_dict(data)
        assert config.host == "smtp.example.com"
        assert config.port == 587
        assert config.username == "test@example.com"
        assert config.password == "env_password"
        assert config.use_tls is True

    def test_from_dict_defaults(self, monkeypatch):
        """Test default port based on use_tls setting."""
        monkeypatch.setenv("SMTP_PASSWORD", "password")

        # Default: use_tls=True -> port 587
        config = SmtpConfig.from_dict({
            "host": "smtp.example.com",
            "username": "test@example.com",
        })
        assert config.port == 587
        assert config.use_tls is True

        # use_tls=False -> port 465
        config = SmtpConfig.from_dict({
            "host": "smtp.example.com",
            "username": "test@example.com",
            "use_tls": False
        })
        assert config.port == 465

    def test_from_dict_with_env_password(self, monkeypatch):
        """Test creating SmtpConfig with password from environment variable."""
        monkeypatch.setenv("SMTP_PASSWORD", "env_smtp_password")

        data = {
            "host": "smtp.example.com",
            "username": "test@example.com",
        }

        config = SmtpConfig.from_dict(data)
        assert config.password == "env_smtp_password"

    def test_from_dict_ignores_config_password(self, monkeypatch):
        """Test that password in config dict is ignored — env var is used."""
        monkeypatch.setenv("SMTP_PASSWORD", "env_smtp_password")

        data = {
            "host": "smtp.example.com",
            "username": "test@example.com",
            "password": "dict_password"
        }

        config = SmtpConfig.from_dict(data)
        assert config.password == "env_smtp_password"

    def test_from_dict_warns_on_config_password(self, monkeypatch, caplog):
        """Test that a warning is logged when config dict contains password."""
        monkeypatch.setenv("SMTP_PASSWORD", "env_password")

        data = {
            "host": "smtp.example.com",
            "username": "test@example.com",
            "password": "dict_password"
        }

        import logging
        with caplog.at_level(logging.WARNING, logger="imap_mcp.config"):
            SmtpConfig.from_dict(data)

        assert "Ignoring 'password' in SMTP config" in caplog.text

    def test_from_dict_falls_back_to_imap_password(self, monkeypatch):
        """Test SMTP falls back to IMAP_PASSWORD when SMTP_PASSWORD is not set."""
        monkeypatch.delenv("SMTP_PASSWORD", raising=False)
        monkeypatch.setenv("IMAP_PASSWORD", "imap_fallback_password")

        data = {
            "host": "smtp.example.com",
            "username": "test@example.com",
        }

        config = SmtpConfig.from_dict(data)
        assert config.password == "imap_fallback_password"

    def test_from_dict_missing_password(self, monkeypatch):
        """Test error when no password env var is set."""
        monkeypatch.delenv("SMTP_PASSWORD", raising=False)
        monkeypatch.delenv("IMAP_PASSWORD", raising=False)

        data = {
            "host": "smtp.example.com",
            "username": "test@example.com",
        }

        with pytest.raises(ValueError) as excinfo:
            SmtpConfig.from_dict(data)

        assert "SMTP password must be specified" in str(excinfo.value)

    def test_from_dict_missing_required_fields(self, monkeypatch):
        """Test error when required fields are missing."""
        monkeypatch.setenv("SMTP_PASSWORD", "password")

        # Missing host
        with pytest.raises(KeyError):
            SmtpConfig.from_dict({"username": "test@example.com"})

        # Missing username
        with pytest.raises(KeyError):
            SmtpConfig.from_dict({"host": "smtp.example.com"})


class TestServerConfig:
    """Test cases for the ServerConfig class."""

    def test_init(self):
        """Test ServerConfig initialization."""
        imap_config = ImapConfig(
            host="imap.example.com",
            port=993,
            username="test@example.com",
            password="password"
        )

        # Test without allowed folders
        server_config = ServerConfig(imap=imap_config)
        assert server_config.imap == imap_config
        assert server_config.allowed_folders is None

        # Test with allowed folders
        allowed_folders = ["INBOX", "Sent", "Archive"]
        server_config = ServerConfig(imap=imap_config, allowed_folders=allowed_folders)
        assert server_config.imap == imap_config
        assert server_config.allowed_folders == allowed_folders

    def test_init_with_smtp(self):
        """Test ServerConfig with SMTP configuration."""
        imap_config = ImapConfig(
            host="imap.example.com", port=993,
            username="test@example.com", password="password"
        )
        smtp_config = SmtpConfig(
            host="smtp.example.com", port=587,
            username="test@example.com", password="password"
        )
        server_config = ServerConfig(imap=imap_config, smtp=smtp_config)
        assert server_config.smtp is not None
        assert server_config.smtp.host == "smtp.example.com"

    def test_init_without_smtp(self):
        """Test ServerConfig defaults to no SMTP."""
        imap_config = ImapConfig(
            host="imap.example.com", port=993,
            username="test@example.com", password="password"
        )
        server_config = ServerConfig(imap=imap_config)
        assert server_config.smtp is None

    def test_from_dict(self, monkeypatch):
        """Test creating ServerConfig from a dictionary."""
        monkeypatch.setenv("IMAP_PASSWORD", "env_password")

        data = {
            "imap": {
                "host": "imap.example.com",
                "port": 993,
                "username": "test@example.com",
            },
            "allowed_folders": ["INBOX", "Sent"]
        }

        config = ServerConfig.from_dict(data)
        assert config.imap.host == "imap.example.com"
        assert config.imap.port == 993
        assert config.imap.username == "test@example.com"
        assert config.imap.password == "env_password"
        assert config.allowed_folders == ["INBOX", "Sent"]
        assert config.smtp is None

        # Test with minimal data (no allowed_folders) — defaults to INBOX
        minimal_data = {
            "imap": {
                "host": "imap.example.com",
                "username": "test@example.com",
            }
        }

        config = ServerConfig.from_dict(minimal_data)
        assert config.imap.host == "imap.example.com"
        assert config.allowed_folders == ["INBOX"]

        # Test with empty dict — should fail because host is required
        with pytest.raises(KeyError):
            ServerConfig.from_dict({})

    def test_from_dict_default_inbox_when_not_set(self, monkeypatch):
        """Test that allowed_folders defaults to INBOX when key is absent."""
        monkeypatch.setenv("IMAP_PASSWORD", "env_password")

        data = {
            "imap": {
                "host": "imap.example.com",
                "username": "test@example.com",
            }
        }

        config = ServerConfig.from_dict(data)
        assert config.allowed_folders == ["INBOX"]

    def test_from_dict_explicit_empty_means_unrestricted(self, monkeypatch):
        """Test that allowed_folders: [] explicitly enables unrestricted access."""
        monkeypatch.setenv("IMAP_PASSWORD", "env_password")

        data = {
            "imap": {
                "host": "imap.example.com",
                "username": "test@example.com",
            },
            "allowed_folders": []
        }

        config = ServerConfig.from_dict(data)
        assert config.allowed_folders is None

    def test_from_dict_warning_when_not_configured(self, monkeypatch, caplog):
        """Test that a warning is logged when allowed_folders is not configured."""
        monkeypatch.setenv("IMAP_PASSWORD", "env_password")

        data = {
            "imap": {
                "host": "imap.example.com",
                "username": "test@example.com",
            }
        }

        import logging
        with caplog.at_level(logging.WARNING, logger="imap_mcp.config"):
            ServerConfig.from_dict(data)

        assert "allowed_folders not configured" in caplog.text
        assert "INBOX-only" in caplog.text

    def test_from_dict_info_when_explicitly_empty(self, monkeypatch, caplog):
        """Test that info is logged when allowed_folders is explicitly empty."""
        monkeypatch.setenv("IMAP_PASSWORD", "env_password")

        data = {
            "imap": {
                "host": "imap.example.com",
                "username": "test@example.com",
            },
            "allowed_folders": []
        }

        import logging
        with caplog.at_level(logging.INFO, logger="imap_mcp.config"):
            ServerConfig.from_dict(data)

        assert "all folders accessible" in caplog.text

    def test_from_dict_with_smtp(self, monkeypatch):
        """Test creating ServerConfig with SMTP section."""
        monkeypatch.setenv("IMAP_PASSWORD", "password")
        monkeypatch.setenv("SMTP_PASSWORD", "smtp_password")

        data = {
            "imap": {
                "host": "imap.example.com",
                "username": "test@example.com",
            },
            "smtp": {
                "host": "smtp.example.com",
                "port": 587,
                "username": "test@example.com",
            }
        }
        config = ServerConfig.from_dict(data)
        assert config.smtp is not None
        assert config.smtp.host == "smtp.example.com"
        assert config.smtp.port == 587


class TestLoadConfig:
    """Test cases for the load_config function."""

    def test_load_from_file(self, monkeypatch, tmp_path):
        """Test loading configuration from a file."""
        monkeypatch.setenv("IMAP_PASSWORD", "env_password")

        config_data = {
            "imap": {
                "host": "imap.example.com",
                "port": 993,
                "username": "test@example.com",
            },
            "allowed_folders": ["INBOX", "Sent"]
        }

        config_file = tmp_path / "config.yaml"
        with open(config_file, "w") as f:
            yaml.dump(config_data, f)

        config = load_config(str(config_file))

        assert config.imap.host == "imap.example.com"
        assert config.imap.port == 993
        assert config.imap.username == "test@example.com"
        assert config.imap.password == "env_password"
        assert config.allowed_folders == ["INBOX", "Sent"]

    def test_load_from_default_locations(self, monkeypatch, tmp_path):
        """Test loading configuration from default locations."""
        # Clear any environment variables that might affect the test
        for env_var in [
            "IMAP_HOST", "IMAP_PORT", "IMAP_USERNAME",
            "IMAP_USE_SSL", "IMAP_ALLOWED_FOLDERS"
        ]:
            monkeypatch.delenv(env_var, raising=False)

        monkeypatch.setenv("IMAP_PASSWORD", "env_password")

        config_data = {
            "imap": {
                "host": "imap.example.com",
                "username": "test@example.com",
            }
        }

        # Create a temporary config file in one of the default locations
        temp_dir = tmp_path / ".config" / "imap-mcp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_file = temp_dir / "config.yaml"

        with open(temp_file, "w") as f:
            yaml.dump(config_data, f)

        # Monkeypatch Path.expanduser to return our temp path
        target = Path("~/.config/imap-mcp/config.yaml")
        original_expanduser = Path.expanduser
        def mock_expanduser(self):
            if self == target:
                return temp_file
            return original_expanduser(self)

        monkeypatch.setattr(Path, "expanduser", mock_expanduser)

        # Monkeypatch to ensure no other config file is found
        def mock_exists(path):
            if path == temp_file:
                return True
            return False

        monkeypatch.setattr(Path, "exists", mock_exists)

        # Load config without specifying path (should find default)
        config = load_config()

        # Verify config data
        assert config.imap.host == "imap.example.com"
        assert config.imap.username == "test@example.com"
        assert config.imap.password == "env_password"

    def test_load_from_env_variables(self, monkeypatch):
        """Test loading configuration from environment variables."""
        # Set environment variables
        monkeypatch.setenv("IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("IMAP_PORT", "993")
        monkeypatch.setenv("IMAP_USERNAME", "test@example.com")
        monkeypatch.setenv("IMAP_PASSWORD", "env_password")
        monkeypatch.setenv("IMAP_USE_SSL", "true")
        monkeypatch.setenv("IMAP_ALLOWED_FOLDERS", "INBOX,Sent,Archive")

        # Mock open to raise FileNotFoundError
        original_open = open
        def mock_open(*args, **kwargs):
            if args[0] == "nonexistent_file.yaml":
                raise FileNotFoundError(f"No such file: {args[0]}")
            return original_open(*args, **kwargs)

        # Need to patch the built-in open function
        with patch("builtins.open", side_effect=mock_open):
            # Load config (will use env variables since file doesn't exist)
            config = load_config("nonexistent_file.yaml")

            # Verify config data
            assert config.imap.host == "imap.example.com"
            assert config.imap.port == 993
            assert config.imap.username == "test@example.com"
            assert config.imap.password == "env_password"
            assert config.imap.use_ssl is True
            assert config.allowed_folders == ["INBOX", "Sent", "Archive"]

            # Test with non-SSL setting
            monkeypatch.setenv("IMAP_USE_SSL", "false")
            config = load_config("nonexistent_file.yaml")
            assert config.imap.use_ssl is False

    def test_load_missing_required_env(self, monkeypatch):
        """Test error when required environment variables are missing."""
        # Ensure IMAP_HOST is not set
        monkeypatch.delenv("IMAP_HOST", raising=False)

        # Mock open to raise FileNotFoundError
        original_open = open
        def mock_open(*args, **kwargs):
            if args[0] == "nonexistent_file.yaml":
                raise FileNotFoundError(f"No such file: {args[0]}")
            return original_open(*args, **kwargs)

        # Need to patch the built-in open function
        with patch("builtins.open", side_effect=mock_open):
            with pytest.raises(ValueError) as excinfo:
                load_config("nonexistent_file.yaml")

            assert "IMAP_HOST environment variable not set" in str(excinfo.value)

    def test_load_smtp_from_env_variables(self, monkeypatch):
        """Test loading SMTP config from environment variables."""
        monkeypatch.setenv("IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("IMAP_USERNAME", "test@example.com")
        monkeypatch.setenv("IMAP_PASSWORD", "password")
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.setenv("SMTP_PORT", "465")
        monkeypatch.setenv("SMTP_USERNAME", "smtp_user@example.com")
        monkeypatch.setenv("SMTP_PASSWORD", "smtp_password")
        monkeypatch.setenv("SMTP_USE_TLS", "false")

        with patch("builtins.open", side_effect=FileNotFoundError):
            config = load_config("nonexistent.yaml")

        assert config.smtp is not None
        assert config.smtp.host == "smtp.example.com"
        assert config.smtp.port == 465
        assert config.smtp.username == "smtp_user@example.com"
        assert config.smtp.password == "smtp_password"
        assert config.smtp.use_tls is False

    def test_load_smtp_fallback_to_imap(self, monkeypatch):
        """Test SMTP falls back to IMAP credentials when SMTP vars not set."""
        monkeypatch.setenv("IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("IMAP_USERNAME", "test@example.com")
        monkeypatch.setenv("IMAP_PASSWORD", "password")
        monkeypatch.delenv("SMTP_HOST", raising=False)
        monkeypatch.delenv("SMTP_USERNAME", raising=False)
        monkeypatch.delenv("SMTP_PASSWORD", raising=False)
        monkeypatch.delenv("SMTP_PORT", raising=False)
        monkeypatch.delenv("SMTP_USE_TLS", raising=False)

        with patch("builtins.open", side_effect=FileNotFoundError):
            config = load_config("nonexistent.yaml")

        assert config.smtp is not None
        assert config.smtp.host == "imap.example.com"  # Fallback
        assert config.smtp.username == "test@example.com"  # Fallback
        assert config.smtp.password == "password"  # Fallback
        assert config.smtp.port == 587  # Default SMTP port

    def test_load_smtp_partial_override(self, monkeypatch):
        """Test partial SMTP override — only host, rest falls back."""
        monkeypatch.setenv("IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("IMAP_USERNAME", "test@example.com")
        monkeypatch.setenv("IMAP_PASSWORD", "password")
        monkeypatch.setenv("SMTP_HOST", "smtp.example.com")
        monkeypatch.delenv("SMTP_USERNAME", raising=False)
        monkeypatch.delenv("SMTP_PASSWORD", raising=False)

        with patch("builtins.open", side_effect=FileNotFoundError):
            config = load_config("nonexistent.yaml")

        assert config.smtp.host == "smtp.example.com"
        assert config.smtp.username == "test@example.com"  # Fallback from IMAP
        assert config.smtp.password == "password"  # Fallback from IMAP

    def test_load_from_yaml_with_smtp(self, monkeypatch, tmp_path):
        """Test loading SMTP config from YAML file."""
        monkeypatch.setenv("IMAP_PASSWORD", "imap_env_password")
        monkeypatch.setenv("SMTP_PASSWORD", "smtp_env_password")

        config_data = {
            "imap": {
                "host": "imap.example.com",
                "port": 993,
                "username": "test@example.com",
            },
            "smtp": {
                "host": "smtp.example.com",
                "port": 465,
                "username": "smtp_user@example.com",
                "use_tls": False
            }
        }

        config_file = tmp_path / "config.yaml"
        with open(config_file, "w") as f:
            yaml.dump(config_data, f)

        config = load_config(str(config_file))

        assert config.smtp is not None
        assert config.smtp.host == "smtp.example.com"
        assert config.smtp.port == 465
        assert config.smtp.username == "smtp_user@example.com"
        assert config.smtp.password == "smtp_env_password"
        assert config.smtp.use_tls is False

    def test_load_env_without_allowed_folders_defaults_to_inbox(self, monkeypatch):
        """Test that missing IMAP_ALLOWED_FOLDERS defaults to INBOX."""
        monkeypatch.setenv("IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("IMAP_PORT", "993")
        monkeypatch.setenv("IMAP_USERNAME", "test@example.com")
        monkeypatch.setenv("IMAP_PASSWORD", "env_password")
        monkeypatch.delenv("IMAP_ALLOWED_FOLDERS", raising=False)

        with patch("builtins.open", side_effect=FileNotFoundError):
            config = load_config("nonexistent.yaml")

        assert config.allowed_folders == ["INBOX"]

    def test_load_env_empty_allowed_folders_means_unrestricted(self, monkeypatch):
        """Test that IMAP_ALLOWED_FOLDERS='' enables unrestricted access."""
        monkeypatch.setenv("IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("IMAP_PORT", "993")
        monkeypatch.setenv("IMAP_USERNAME", "test@example.com")
        monkeypatch.setenv("IMAP_PASSWORD", "env_password")
        monkeypatch.setenv("IMAP_ALLOWED_FOLDERS", "")

        with patch("builtins.open", side_effect=FileNotFoundError):
            config = load_config("nonexistent.yaml")

        assert config.allowed_folders is None

    def test_load_env_allowed_folders_strips_whitespace(self, monkeypatch):
        """Test that IMAP_ALLOWED_FOLDERS values are trimmed."""
        monkeypatch.setenv("IMAP_HOST", "imap.example.com")
        monkeypatch.setenv("IMAP_USERNAME", "test@example.com")
        monkeypatch.setenv("IMAP_PASSWORD", "env_password")
        monkeypatch.setenv("IMAP_ALLOWED_FOLDERS", " INBOX , Sent , Archive ")

        with patch("builtins.open", side_effect=FileNotFoundError):
            config = load_config("nonexistent.yaml")

        assert config.allowed_folders == ["INBOX", "Sent", "Archive"]

    def test_load_yaml_without_allowed_folders_defaults_to_inbox(self, monkeypatch, tmp_path):
        """Test that YAML without allowed_folders key defaults to INBOX."""
        monkeypatch.setenv("IMAP_PASSWORD", "env_password")

        config_data = {
            "imap": {
                "host": "imap.example.com",
                "username": "test@example.com",
            }
        }

        config_file = tmp_path / "config.yaml"
        with open(config_file, "w") as f:
            yaml.dump(config_data, f)

        config = load_config(str(config_file))
        assert config.allowed_folders == ["INBOX"]

    def test_invalid_config(self, monkeypatch, tmp_path):
        """Test error when config is invalid."""
        monkeypatch.setenv("IMAP_PASSWORD", "password")

        # Create a config file with invalid data
        config_data = {
            "imap": {
                # Missing required host
                "username": "test@example.com",
            }
        }

        config_file = tmp_path / "config.yaml"
        with open(config_file, "w") as f:
            yaml.dump(config_data, f)

        with pytest.raises(ValueError) as excinfo:
            load_config(str(config_file))

        assert "Missing required configuration" in str(excinfo.value)
