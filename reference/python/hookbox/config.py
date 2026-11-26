"""Validated YAML configuration. Configuration files are trusted administrator input."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    ValidationError,
    field_validator,
    model_validator,
)


class ConfigError(ValueError):
    """Configuration cannot be loaded; messages never include secret values."""


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_PATH = re.compile(r"^/(?:[A-Za-z0-9_-][A-Za-z0-9_.-]*)(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*$")


def _path(value: object) -> Path:
    if not isinstance(value, (str, Path)) or not str(value).strip() or "\x00" in str(value):
        raise ValueError("Expected a nonempty filesystem path")
    return Path(value)


FilePath = Annotated[Path, BeforeValidator(_path)]
PositiveSeconds = Annotated[float, Field(gt=0, allow_inf_nan=False)]
PositiveBytes = Annotated[int, Field(gt=0)]


def _http_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid HTTP URL") from None
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or any(character.isspace() or ord(character) < 32 for character in value)
        or port == 0
    ):
        raise ValueError("Expected an absolute HTTP(S) URL without credentials or fragment")
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, validate_default=True, allow_inf_nan=False)


class SSLConfig(StrictModel):
    certfile: FilePath
    keyfile: FilePath


class GeneralConfig(StrictModel):
    host: str = Field(default="127.0.0.1", min_length=1)
    port: int = Field(default=8080, ge=1, le=65535)
    url: str | None = None
    ssl: SSLConfig | None = None
    log_level: Literal["critical", "error", "warning", "info", "debug"] = "info"
    max_body_bytes: PositiveBytes = 1_048_576
    body_timeout_seconds: PositiveSeconds = 30.0
    max_concurrent_requests: int = Field(default=8, gt=0)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str | None) -> str | None:
        return _http_url(value) if value is not None else None

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        if any(character.isspace() or ord(character) < 32 for character in value):
            raise ValueError("Invalid bind host")
        return value


class CommandAction(StrictModel):
    type: Literal["command"] = "command"
    command: list[str] = Field(min_length=1)
    cwd: FilePath | None = None
    env: dict[str, str] = Field(default_factory=dict)
    timeout_seconds: PositiveSeconds = 30.0
    stdin_from_payload: bool = True
    max_output_bytes: PositiveBytes = 65_536

    @field_validator("command")
    @classmethod
    def validate_command(cls, value: list[str]) -> list[str]:
        if not value[0].strip() or any("\x00" in argument for argument in value):
            raise ValueError("Command must contain a nonempty executable and no NUL bytes")
        return value

    @field_validator("env")
    @classmethod
    def validate_env(cls, value: dict[str, str]) -> dict[str, str]:
        if any(not key or "=" in key or "\x00" in key or "\x00" in item for key, item in value.items()):
            raise ValueError("Invalid environment variable")
        return value


class HttpAction(StrictModel):
    type: Literal["http"] = "http"
    url: str
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    body: JsonValue = None
    forward_payload: bool = False
    timeout_seconds: PositiveSeconds = 30.0
    max_output_bytes: PositiveBytes = 65_536

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        return _http_url(value)

    @field_validator("headers")
    @classmethod
    def validate_headers(cls, value: dict[str, str]) -> dict[str, str]:
        if any(
            not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
            or any(character in item for character in "\r\n\x00")
            or not item.isascii()
            for key, item in value.items()
        ):
            raise ValueError("Invalid HTTP header")
        return value

    @model_validator(mode="after")
    def validate_body_source(self) -> HttpAction:
        if self.forward_payload and "body" in self.model_fields_set:
            raise ValueError("body and forward_payload are mutually exclusive")
        return self


Action = Annotated[CommandAction | HttpAction, Field(discriminator="type")]


class WebhookConfig(StrictModel):
    path: str | None = None
    methods: list[Literal["POST", "PUT", "PATCH"]] = Field(default_factory=lambda: ["POST"], min_length=1)
    enabled: bool = True
    expose_output: bool = False
    actions: list[Action] = Field(min_length=1)

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str | None) -> str | None:
        if value is not None and (not _PATH.fullmatch(value) or value == "/healthz"):
            raise ValueError("Webhook path must be a static non-reserved absolute URL path")
        return value

    @field_validator("methods")
    @classmethod
    def validate_methods(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("Duplicate webhook methods")
        return value


class UserConfig(StrictModel):
    roles: list[str] = Field(default_factory=list)
    enabled: bool = True


class TokenConfig(StrictModel):
    user: str
    sha256: str = Field(pattern=r"^[0-9a-fA-F]{64}$", repr=False)
    roles: list[str] | None = None
    enabled: bool = True

    @field_validator("sha256")
    @classmethod
    def normalize_hash(cls, value: str) -> str:
        return value.lower()


class SecurityConfig(StrictModel):
    roles: dict[str, list[str]] = Field(default_factory=dict)
    users: dict[str, UserConfig] = Field(default_factory=dict)
    tokens: dict[str, TokenConfig] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_security(self) -> SecurityConfig:
        for mapping in (self.roles, self.users, self.tokens):
            if any(not _NAME.fullmatch(name) for name in mapping):
                raise ValueError("Invalid role, user or token name")
        for user in self.users.values():
            if not set(user.roles) <= self.roles.keys():
                raise ValueError("User refers to an unknown role")
        hashes: set[str] = set()
        for token in self.tokens.values():
            if token.user not in self.users:
                raise ValueError("Token refers to an unknown user")
            if token.roles is not None and not set(token.roles) <= set(self.users[token.user].roles):
                raise ValueError("Token roles must be a subset of its user's roles")
            if token.sha256 in hashes:
                raise ValueError("Token hashes must be unique")
            hashes.add(token.sha256)
        return self


class AppConfig(StrictModel):
    general: GeneralConfig = Field(default_factory=GeneralConfig)
    webhook: dict[str, WebhookConfig]
    security: SecurityConfig

    @model_validator(mode="after")
    def validate_references(self) -> AppConfig:
        paths: set[str] = set()
        for name, hook in self.webhook.items():
            if not _NAME.fullmatch(name):
                raise ValueError("Invalid webhook name")
            if hook.path is None:
                hook.path = f"/hooks/{name}"
            if hook.path in paths:
                raise ValueError("Webhook paths must be unique")
            paths.add(hook.path)
        for hooks in self.security.roles.values():
            if any(name != "*" and name not in self.webhook for name in hooks):
                raise ValueError("Role refers to an unknown webhook")
        return self


class _UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict:
        self.flatten_mapping(node)
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                if key in result:
                    raise ConfigError("Duplicate YAML mapping key")
                result[key] = self.construct_object(value_node, deep=deep)
            except TypeError:
                raise ConfigError("Invalid YAML mapping key") from None
        return result


def _expand_environment(value: object, ancestors: set[int] | None = None) -> object:
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in os.environ:
                raise ConfigError(f"Required environment variable is missing: {name}")
            return os.environ[name]

        return _ENV.sub(replace, value)
    if isinstance(value, (dict, list)):
        ancestors = set() if ancestors is None else ancestors
        if id(value) in ancestors:
            raise ConfigError("Recursive YAML aliases are not supported")
        ancestors.add(id(value))
        try:
            if isinstance(value, dict):
                return {key: _expand_environment(item, ancestors) for key, item in value.items()}
            return [_expand_environment(item, ancestors) for item in value]
        finally:
            ancestors.remove(id(value))
    return value


def load_config(path: str | Path) -> AppConfig:
    """Load YAML, expand environment values and resolve paths against its directory."""
    config_path = Path(path).resolve()
    try:
        with config_path.open(encoding="utf-8-sig") as handle:
            raw = yaml.load(handle, Loader=_UniqueKeyLoader)
    except (OSError, UnicodeError):
        raise ConfigError("Cannot read configuration file") from None
    except yaml.YAMLError:
        raise ConfigError("Invalid YAML configuration") from None
    except RecursionError:
        raise ConfigError("Configuration nesting is too deep") from None
    try:
        config = AppConfig.model_validate(_expand_environment(raw))
    except ValidationError as exc:
        # Pydantic's default str(exc) includes input values, which may be secrets.
        issues = "; ".join(
            f"{'.'.join(map(str, error['loc'])) or 'root'}: {error['type']}"
            for error in exc.errors(include_input=False, include_context=False, include_url=False)
        )
        raise ConfigError(f"Invalid configuration ({issues})") from None
    except RecursionError:
        raise ConfigError("Configuration nesting is too deep") from None
    base = config_path.parent
    if config.general.ssl is not None:
        ssl = config.general.ssl
        ssl.certfile = (base / ssl.certfile).resolve()
        ssl.keyfile = (base / ssl.keyfile).resolve()
    for webhook in config.webhook.values():
        for action in webhook.actions:
            if isinstance(action, CommandAction):
                action.cwd = (base / action.cwd).resolve() if action.cwd is not None else base
    return config
