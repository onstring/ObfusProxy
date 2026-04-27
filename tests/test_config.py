"""Tests for config loading, validation, and Pydantic models."""
import textwrap
from pathlib import Path

import pytest

from app.config import (
    AppConfig,
    BackendConfig,
    PrivacyConfig,
    WhitelistConfig,
    load_config,
)


# ---------------------------------------------------------------------------
# WhitelistConfig
# ---------------------------------------------------------------------------

class TestWhitelistConfig:
    def test_defaults(self):
        wl = WhitelistConfig()
        assert "localhost" in wl.loopback
        assert "127.0.0.1" in wl.loopback
        assert wl.ip_ranges == []
        assert wl.domains == []

    def test_custom_values(self):
        wl = WhitelistConfig(
            loopback=["localhost"],
            ip_ranges=["10.0.0.0/8"],
            domains=["github.com"],
        )
        assert "10.0.0.0/8" in wl.ip_ranges
        assert "github.com" in wl.domains


# ---------------------------------------------------------------------------
# BackendConfig
# ---------------------------------------------------------------------------

class TestBackendConfig:
    def test_regex_type(self):
        bc = BackendConfig(type="regex")
        assert bc.type == "regex"
        assert bc.model == "en_core_web_sm"

    def test_presidio_with_model(self):
        bc = BackendConfig(type="presidio", model="en_core_web_lg")
        assert bc.model == "en_core_web_lg"


# ---------------------------------------------------------------------------
# PrivacyConfig
# ---------------------------------------------------------------------------

class TestPrivacyConfig:
    def test_defaults(self):
        pc = PrivacyConfig()
        assert pc.enabled is True
        assert len(pc.backends) == 1
        assert pc.backends[0].type == "regex"

    def test_multiple_backends(self):
        pc = PrivacyConfig(backends=[BackendConfig(type="regex"), BackendConfig(type="presidio")])
        assert len(pc.backends) == 2


# ---------------------------------------------------------------------------
# AppConfig
# ---------------------------------------------------------------------------

class TestAppConfig:
    def test_minimal_valid_config(self):
        cfg = AppConfig(privacy=PrivacyConfig())
        assert cfg.server.port == 8080
        assert cfg.privacy.enabled is True

    def test_server_defaults(self):
        cfg = AppConfig(privacy=PrivacyConfig())
        assert cfg.server.host == "127.0.0.1"
        assert cfg.server.port == 8080


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_loads_real_config(self):
        cfg = load_config("config.yaml")
        assert cfg.server.port == 8080
        assert any(b.type == "regex" for b in cfg.privacy.backends)

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            load_config(str(tmp_path / "nonexistent.yaml"))

    def test_round_trip_yaml(self, tmp_path: Path):
        yaml_text = textwrap.dedent("""\
            server:
              host: "127.0.0.1"
              port: 9090
            privacy:
              enabled: true
              backends:
                - type: "regex"
              entities:
                - EMAIL_ADDRESS
              whitelist:
                loopback:
                  - "localhost"
                ip_ranges: []
                domains:
                  - "github.com"
        """)
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text(yaml_text)
        cfg = load_config(str(cfg_file))
        assert cfg.server.port == 9090
        assert "EMAIL_ADDRESS" in cfg.privacy.entities
        assert "github.com" in cfg.privacy.whitelist.domains
