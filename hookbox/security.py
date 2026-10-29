"""Bearer-token authentication and deny-by-default webhook role checks."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from .config import SecurityConfig


@dataclass(frozen=True)
class Principal:
    username: str
    token_name: str
    roles: tuple[str, ...]


def authenticate(config: SecurityConfig, bearer_token: str) -> Principal | None:
    if not bearer_token:
        return None
    digest = hashlib.sha256(bearer_token.encode("utf-8")).hexdigest()
    principal = None
    # Scan the whole table; compare_digest avoids character-by-character comparisons.
    for name, token in config.tokens.items():
        matches = hmac.compare_digest(digest, token.sha256)
        user = config.users[token.user]
        if matches and token.enabled and user.enabled:
            roles = user.roles if token.roles is None else token.roles
            principal = Principal(token.user, name, tuple(roles))
    return principal


def is_allowed(config: SecurityConfig, principal: Principal, webhook_id: str) -> bool:
    return any(
        "*" in config.roles.get(role, ()) or webhook_id in config.roles.get(role, ())
        for role in principal.roles
    )
