from pathlib import Path

import yaml
from pydantic import BaseModel


class ServerConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8080


class WhitelistConfig(BaseModel):
    loopback: list[str] = ["localhost", "127.0.0.1", "::1", "0.0.0.0"]
    ip_ranges: list[str] = []
    domains: list[str] = []


class BackendConfig(BaseModel):
    type: str
    model: str = "en_core_web_sm"


class PrivacyConfig(BaseModel):
    enabled: bool = True
    backends: list[BackendConfig] = [BackendConfig(type="regex")]
    entities: list[str] = []
    whitelist: WhitelistConfig = WhitelistConfig()


class AppConfig(BaseModel):
    server: ServerConfig = ServerConfig()
    privacy: PrivacyConfig


def load_config(path: str = "config.yaml") -> AppConfig:
    """Load and validate config from YAML file."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(config_path, "r") as f:
        data = yaml.safe_load(f)

    return AppConfig(**data)
