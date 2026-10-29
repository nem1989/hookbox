import hashlib

import pytest

from hookbox.config import SecurityConfig
from hookbox.security import Principal, authenticate, is_allowed


def security_data():
    return {
        "roles": {"reader": ["echo"], "writer": ["deploy"], "admin": ["*"]},
        "users": {
            "alice": {"roles": ["reader", "writer"]},
            "root": {"roles": ["admin"]},
            "unprivileged": {},
        },
        "tokens": {
            "ci": {"user": "alice", "sha256": hashlib.sha256(b"secret").hexdigest()},
            "limited": {"user": "alice", "sha256": hashlib.sha256(b"limited").hexdigest(), "roles": ["reader"]},
            "empty": {"user": "alice", "sha256": hashlib.sha256(b"empty").hexdigest(), "roles": []},
            "root": {"user": "root", "sha256": hashlib.sha256(b"root").hexdigest()},
            "guest": {"user": "unprivileged", "sha256": hashlib.sha256(b"guest").hexdigest()},
        },
    }


def test_authentication_and_inherited_user_roles():
    config = SecurityConfig.model_validate(security_data())
    principal = authenticate(config, "secret")
    assert principal == Principal("alice", "ci", ("reader", "writer"))
    assert is_allowed(config, principal, "echo")
    assert is_allowed(config, principal, "deploy")
    assert not is_allowed(config, principal, "other")


@pytest.mark.parametrize("value", ["", "incorrect", "SECRET", " secret", "secret ", "секрет"])
def test_unknown_tokens_rejected(value):
    config = SecurityConfig.model_validate(security_data())
    assert authenticate(config, value) is None


@pytest.mark.parametrize("disabled", ["user", "token"])
def test_disabled_user_or_token_rejected(disabled):
    data = security_data()
    if disabled == "user":
        data["users"]["alice"]["enabled"] = False
    else:
        data["tokens"]["ci"]["enabled"] = False
    assert authenticate(SecurityConfig.model_validate(data), "secret") is None


def test_token_can_narrow_user_roles():
    config = SecurityConfig.model_validate(security_data())
    principal = authenticate(config, "limited")
    assert principal.roles == ("reader",)
    assert is_allowed(config, principal, "echo")
    assert not is_allowed(config, principal, "deploy")


def test_explicit_empty_roles_do_not_fall_back_to_user_roles():
    config = SecurityConfig.model_validate(security_data())
    principal = authenticate(config, "empty")
    assert principal.roles == ()
    assert not is_allowed(config, principal, "echo")


def test_wildcard_role():
    config = SecurityConfig.model_validate(security_data())
    principal = authenticate(config, "root")
    assert is_allowed(config, principal, "echo")
    assert is_allowed(config, principal, "anything")


def test_no_roles_means_no_permissions():
    config = SecurityConfig.model_validate(security_data())
    principal = authenticate(config, "guest")
    assert principal is not None
    assert not is_allowed(config, principal, "echo")


def test_uppercase_hashes_normalized():
    data = security_data()
    data["tokens"]["ci"]["sha256"] = data["tokens"]["ci"]["sha256"].upper()
    assert authenticate(SecurityConfig.model_validate(data), "secret") is not None


def test_plaintext_tokens_are_never_in_principal_repr():
    principal = authenticate(SecurityConfig.model_validate(security_data()), "secret")
    assert "secret" not in repr(principal)


def test_empty_security_rejects_everything():
    config = SecurityConfig()
    assert authenticate(config, "secret") is None
    assert not is_allowed(config, Principal("nobody", "none", ("missing",)), "echo")
