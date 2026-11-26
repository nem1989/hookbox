import hashlib
import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import main

ROOT = Path(__file__).resolve().parents[1]


def test_help_identifies_hookbox_without_loading_configuration():
    result = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--config", "does-not-exist", "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "usage: hookbox" in result.stdout
    assert "Hookbox: configuration-driven webhook integration service" in result.stdout
    assert "--check-config" in result.stdout
    assert "--generate-token" in result.stdout


def test_generate_unique_tokens_without_configuration(capsys):
    tokens = []
    for _ in range(2):
        assert main.main(["--generate-token", "--config", "does-not-exist"]) == 0
        result = json.loads(capsys.readouterr().out)
        assert len(result["token"]) >= 40
        assert hashlib.sha256(result["token"].encode()).hexdigest() == result["sha256"]
        tokens.append(result["token"])
    assert tokens[0] != tokens[1]


def test_cli_missing_config_safe_error(capsys):
    assert main.main(["--config", "does-not-exist"]) == 2
    output = capsys.readouterr()
    assert "Configuration error:" in output.err
    assert not output.out


def test_check_config_executable_entry_point(tmp_path):
    path = tmp_path / "config.yaml"
    path.write_text("general: {}\nwebhook: {}\nsecurity: {}\n", encoding="utf-8")
    result = subprocess.run([sys.executable, str(ROOT / "main.py"), "--config", str(path), "--check-config"], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert "Configuration is valid" in result.stdout


@pytest.mark.parametrize("tls", [False, True])
def test_server_arguments_and_tls_paths(tmp_path, monkeypatch, tls):
    config = {"general": {"host": "0.0.0.0", "port": 9000, "log_level": "warning"}, "webhook": {}, "security": {}}
    if tls:
        config["general"]["ssl"] = {"certfile": "cert.pem", "keyfile": "key.pem"}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    seen = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kwargs: seen.append(kwargs))
    assert main.main(["--config", str(path)]) == 0
    assert seen == [{"host": "0.0.0.0", "port": 9000, "log_level": "warning", "ssl_certfile": str(tmp_path / "cert.pem") if tls else None, "ssl_keyfile": str(tmp_path / "key.pem") if tls else None, "proxy_headers": False, "access_log": False}]


def test_cli_modes_are_mutually_exclusive():
    with pytest.raises(SystemExit) as exc:
        main.main(["--check-config", "--generate-token"])
    assert exc.value.code == 2


def test_http_client_diagnostics_cannot_leak_urls_at_debug_level(tmp_path, monkeypatch, caplog):
    path = tmp_path / "config.yaml"
    path.write_text("general: {log_level: debug}\nwebhook: {}\nsecurity: {}\n", encoding="utf-8")
    for name in ("httpx", "httpcore"):
        monkeypatch.setattr(logging.getLogger(name), "level", logging.NOTSET)

    def serve(app, **kwargs):
        logging.getLogger("httpx").info("URL contains query-secret")
        logging.getLogger("httpcore").debug("Header contains header-secret")
        logging.getLogger("hookbox").info("service-audit-event")

    monkeypatch.setattr("uvicorn.run", serve)
    with caplog.at_level(logging.DEBUG):
        assert main.main(["--config", str(path)]) == 0
    assert "query-secret" not in caplog.text
    assert "header-secret" not in caplog.text
    assert "service-audit-event" in caplog.text
