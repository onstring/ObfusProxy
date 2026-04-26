from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, field_validator, model_validator


class ServerConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8080


class PrivacyConfig(BaseModel):
    enabled: bool = True
    backend: Literal["regex", "presidio", "transformer", "api"] = "regex"
    entities: list[str] = []
    whitelist: list[str] = []


class ProviderConfig(BaseModel):
    alias: str
    model: str


class RouterConfig(BaseModel):
    default_alias: str
    fallback_chain: list[str]


class AppConfig(BaseModel):
    server: ServerConfig = ServerConfig()
    privacy: PrivacyConfig
    providers: list[ProviderConfig]
    router: RouterConfig

    @model_validator(mode="after")
    def validate_router_aliases(self) -> "AppConfig":
        """Verify every alias in fallback_chain exists in providers."""
        provider_aliases = {p.alias for p in self.providers}

        if self.router.default_alias not in provider_aliases:
            raise ValueError(
                f"default_alias '{self.router.default_alias}' not found in providers"
            )

        for alias in self.router.fallback_chain:
            if alias not in provider_aliases:
                raise ValueError(
                    f"fallback_chain alias '{alias}' not found in providers"
                )

        return self

    @field_validator("providers")
    @classmethod
    def validate_unique_aliases(cls, providers: list[ProviderConfig]) -> list[ProviderConfig]:
        """Ensure provider aliases are unique."""
        aliases = [p.alias for p in providers]
        if len(aliases) != len(set(aliases)):
            raise ValueError("Provider aliases must be unique")
        return providers


def load_config(path: str = "config.yaml") -> AppConfig:
    """Load and validate config from YAML file."""
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    with open(config_path, "r") as f:
        data = yaml.safe_load(f)

    return AppConfig(**data)
