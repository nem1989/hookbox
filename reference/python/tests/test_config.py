import copy
import hashlib

import pytest
import yaml
from pydantic import ValidationError

from hookbox.config import (
    AppConfig,
    CommandAction,
    ConfigError,
    HttpAction,
    load_config,
)


def config_data():
    return {
        "general": {},
        "webhook": {"echo": {"actions": [{"type": "command", "command": ["echo", "hello"]}]}},
        "security": {
            "roles": {"operator": ["echo"]},
            "users": {"alice": {"roles": ["operator"]}},
            "tokens": {"ci": {"user": "alice", "sha256": hashlib.sha256(b"secret").hexdigest()}},
        },
    }


def write_config(tmp_path, data):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_defaults_and_relative_working_directory(tmp_path):
    config = load_config(write_config(tmp_path, config_data()))
    assert config.general.host == "127.0.0.1"
    assert config.general.port == 8080
    assert config.general.max_body_bytes == 1_048_576
    assert config.general.body_timeout_seconds == 30.0
    assert config.general.max_concurrent_requests == 8
    hook = config.webhook["echo"]
    assert hook.path == "/hooks/echo"
    assert hook.methods == ["POST"]
    assert hook.enabled and not hook.expose_output
    assert hook.actions[0].cwd == tmp_path.resolve()
    assert hook.actions[0].stdin_from_payload


def test_expands_environment_in_nested_values_without_reparsing_yaml(tmp_path, monkeypatch):
    monkeypatch.setenv("HOOK_TEST_EXEC", "test executable")
    monkeypatch.setenv("HOOK_TEST_SECRET", "yes: # not YAML\nsecret")
    data = config_data()
    data["webhook"]["echo"]["actions"][0].update(
        command=["${HOOK_TEST_EXEC}", "pre-${HOOK_TEST_SECRET}"], env={"SECRET": "${HOOK_TEST_SECRET}"}
    )
    action = load_config(write_config(tmp_path, data)).webhook["echo"].actions[0]
    assert action.command == ["test executable", "pre-yes: # not YAML\nsecret"]
    assert action.env["SECRET"] == "yes: # not YAML\nsecret"


def test_missing_environment_variable_fails(tmp_path, monkeypatch):
    monkeypatch.delenv("HOOK_TEST_ABSENT", raising=False)
    data = config_data()
    data["webhook"]["echo"]["actions"][0]["command"] = ["${HOOK_TEST_ABSENT}"]
    with pytest.raises(ConfigError, match="HOOK_TEST_ABSENT"):
        load_config(write_config(tmp_path, data))


def test_paths_resolve_against_yaml_directory(tmp_path, monkeypatch):
    folder = tmp_path / "configuration"
    folder.mkdir()
    data = config_data()
    data["general"]["ssl"] = {"certfile": "certs/server.crt", "keyfile": "certs/server.key"}
    data["webhook"]["echo"]["actions"][0]["cwd"] = "scripts"
    monkeypatch.chdir(tmp_path)
    config = load_config(write_config(folder, data))
    assert config.general.ssl.certfile == folder / "certs" / "server.crt"
    assert config.general.ssl.keyfile == folder / "certs" / "server.key"
    assert config.webhook["echo"].actions[0].cwd == folder / "scripts"


@pytest.mark.parametrize("field,value", [
    ("port", 0), ("port", 65536), ("port", "8080"), ("port", True),
    ("max_body_bytes", 0), ("max_concurrent_requests", -1),
    ("body_timeout_seconds", 0), ("body_timeout_seconds", -1),
    ("body_timeout_seconds", float("nan")), ("body_timeout_seconds", float("inf")),
    ("body_timeout_seconds", "30"), ("body_timeout_seconds", True),
    ("host", "bad host"), ("host", ""), ("log_level", "TRACE"),
    ("url", "ftp://localhost"), ("url", "http://user:password@localhost"),
    ("ssl", {"certfile": "cert.pem"}), ("ssl", {"certfile": "", "keyfile": "key.pem"}),
])
def test_rejects_invalid_general_settings(tmp_path, field, value):
    data = config_data()
    data["general"][field] = value
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path, data))


@pytest.mark.parametrize("section", ["root", "general", "webhook", "action", "security", "user", "token"])
def test_unknown_fields_rejected(tmp_path, section):
    data = config_data()
    target = {
        "root": data,
        "general": data["general"],
        "webhook": data["webhook"]["echo"],
        "action": data["webhook"]["echo"]["actions"][0],
        "security": data["security"],
        "user": data["security"]["users"]["alice"],
        "token": data["security"]["tokens"]["ci"],
    }[section]
    target["typo"] = "sensitive-value"
    with pytest.raises(ConfigError) as error:
        load_config(write_config(tmp_path, data))
    assert "sensitive-value" not in str(error.value)
    assert "extra_forbidden" in str(error.value)


@pytest.mark.parametrize("text", [
    "general: {}\ngeneral: {}\n",
    "general:\n  port: 8080\n  port: 8081\n",
    "[invalid yaml",
    "!!python/object/apply:os.system ['echo forbidden']",
    "- not\n- a mapping",
    "",
    "? [unhashable]\n: key\n",
    "recursive: &recursive\n  child: *recursive\n",
])
def test_rejects_invalid_yaml(tmp_path, text):
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_missing_file_has_safe_error(tmp_path):
    with pytest.raises(ConfigError, match="Cannot read"):
        load_config(tmp_path / "missing.yaml")


def test_yaml_error_does_not_include_secret(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("password: [top-secret\n", encoding="utf-8")
    with pytest.raises(ConfigError) as error:
        load_config(path)
    assert "top-secret" not in str(error.value)


def test_validation_error_does_not_include_secret(tmp_path):
    data = config_data()
    data["security"]["tokens"]["ci"]["sha256"] = "plain-text-secret"
    with pytest.raises(ConfigError) as error:
        load_config(write_config(tmp_path, data))
    assert "plain-text-secret" not in str(error.value)


@pytest.mark.parametrize("path", ["/healthz", "relative", "/hooks/{dynamic}", "/hooks/a?b=1", "/hooks/../admin", "/hooks//a", "/hooks/a/"])
def test_rejects_invalid_or_reserved_routes(tmp_path, path):
    data = config_data()
    data["webhook"]["echo"]["path"] = path
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path, data))


def test_rejects_duplicate_routes(tmp_path):
    data = config_data()
    data["webhook"]["echo"]["path"] = "/same"
    data["webhook"]["other"] = copy.deepcopy(data["webhook"]["echo"])
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path, data))


@pytest.mark.parametrize("methods", [[], ["GET"], ["POST", "POST"], ["post"]])
def test_rejects_unsafe_or_duplicate_methods(tmp_path, methods):
    data = config_data()
    data["webhook"]["echo"]["methods"] = methods
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path, data))


@pytest.mark.parametrize("target", ["webhook", "role", "user", "token"])
def test_names_are_safe_identifiers(tmp_path, target):
    data = config_data()
    mapping = {
        "webhook": data["webhook"], "role": data["security"]["roles"],
        "user": data["security"]["users"], "token": data["security"]["tokens"],
    }[target]
    first = next(iter(mapping))
    mapping["bad/name"] = mapping.pop(first)
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path, data))


@pytest.mark.parametrize("kind", ["unknown_hook", "unknown_role", "unknown_user", "wider_token", "duplicate_hash"])
def test_security_references_rejected(tmp_path, kind):
    data = config_data()
    security = data["security"]
    if kind == "unknown_hook":
        security["roles"]["operator"] = ["missing"]
    elif kind == "unknown_role":
        security["users"]["alice"]["roles"] = ["missing"]
    elif kind == "unknown_user":
        security["tokens"]["ci"]["user"] = "missing"
    elif kind == "wider_token":
        security["roles"]["admin"] = ["*"]
        security["tokens"]["ci"]["roles"] = ["admin"]
    else:
        security["tokens"]["duplicate"] = copy.deepcopy(security["tokens"]["ci"])
        security["tokens"]["duplicate"]["sha256"] = security["tokens"]["duplicate"]["sha256"].upper()
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path, data))


def test_wildcard_and_custom_route_are_valid(tmp_path):
    data = config_data()
    data["security"]["roles"]["operator"] = ["*"]
    data["webhook"]["echo"].update(path="/integrations/echo.v1", methods=["PUT", "PATCH"])
    config = load_config(write_config(tmp_path, data))
    assert config.webhook["echo"].path == "/integrations/echo.v1"
    assert config.webhook["echo"].methods == ["PUT", "PATCH"]


@pytest.mark.parametrize("changes", [
    {"command": []}, {"command": "echo hello"}, {"command": [""]},
    {"command": ["echo", "bad\x00argument"]}, {"env": {"BAD=KEY": "value"}},
    {"env": {"KEY": 1}}, {"timeout_seconds": 0}, {"timeout_seconds": float("inf")},
    {"max_output_bytes": 0}, {"stdin_from_payload": "yes"},
])
def test_command_validation(changes):
    data = {"command": ["echo", "hello"], **changes}
    with pytest.raises(ValidationError):
        CommandAction.model_validate(data)


@pytest.mark.parametrize("url", ["file:///etc/passwd", "localhost", "https://", "http://host:99999", "http://host:0", "http://host/a b", "http://user:secret@host", "http://host/#fragment"])
def test_http_url_validation(url):
    with pytest.raises(ValidationError):
        HttpAction(url=url)


def test_http_body_and_forwarding_are_exclusive():
    with pytest.raises(ValidationError):
        HttpAction(url="https://example.org/hook", body={"a": 1}, forward_payload=True)
    with pytest.raises(ValidationError):
        HttpAction(url="https://example.org/hook", body=None, forward_payload=True)
    assert HttpAction(url="https://example.org/hook", forward_payload=True).forward_payload


@pytest.mark.parametrize("headers", [{"Bad Name": "value"}, {"Header": "value\r\nInjected: yes"}, {"": "value"}, {"Header": "non-ascii: é"}])
def test_http_header_validation(headers):
    with pytest.raises(ValidationError):
        HttpAction(url="https://example.org", headers=headers)


def test_http_action_and_json_body_load(tmp_path):
    data = config_data()
    data["webhook"]["echo"]["actions"] = [{
        "type": "http", "url": "https://example.org/hook", "method": "PUT",
        "body": {"items": [1, True, None, "text"]}, "headers": {"X-Test": "hello"},
    }]
    action = load_config(write_config(tmp_path, data)).webhook["echo"].actions[0]
    assert isinstance(action, HttpAction)
    assert action.body == {"items": [1, True, None, "text"]}


@pytest.mark.parametrize("number", [float("nan"), float("inf"), float("-inf")])
def test_http_body_requires_finite_json_numbers(number):
    with pytest.raises(ValidationError):
        HttpAction(url="https://example.org/hook", body={"value": number})


@pytest.mark.parametrize("actions", [[], [{"type": "unknown"}], [{"command": ["echo"]}]])
def test_actions_are_nonempty_and_discriminated(tmp_path, actions):
    data = config_data()
    data["webhook"]["echo"]["actions"] = actions
    with pytest.raises(ConfigError):
        load_config(write_config(tmp_path, data))


def test_model_does_not_share_mutable_defaults():
    first = CommandAction(command=["echo"])
    second = CommandAction(command=["echo"])
    first.env["TEST"] = "one"
    assert second.env == {}


def test_absolute_cwd_preserved(tmp_path):
    data = config_data()
    data["webhook"]["echo"]["actions"][0]["cwd"] = str(tmp_path.resolve())
    assert load_config(write_config(tmp_path, data)).webhook["echo"].actions[0].cwd == tmp_path.resolve()


def test_bom_yaml_is_supported(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config_data()), encoding="utf-8-sig")
    assert load_config(path).webhook["echo"].enabled


def test_missing_security_is_rejected():
    data = config_data()
    del data["security"]
    with pytest.raises(ValidationError):
        AppConfig.model_validate(data)
