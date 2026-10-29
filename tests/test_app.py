import asyncio
import hashlib
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from fastapi.testclient import TestClient

from hookbox.actions import ActionError
from hookbox.app import create_app
from hookbox.config import AppConfig

TOKEN = "test-bearer-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def configuration(**general):
    return AppConfig.model_validate({
        "general": general,
        "webhook": {
            "echo": {"actions": [{"type": "command", "command": [sys.executable, "-c", "import sys; print(sys.stdin.read())"]}]},
            "other": {"path": "/custom/other", "methods": ["PUT"], "actions": [{"type": "command", "command": [sys.executable, "-c", "print('other')"]}]},
            "disabled": {"enabled": False, "actions": [{"type": "command", "command": ["unused"]}]},
        },
        "security": {
            "roles": {"echoer": ["echo"], "operator": ["*"]},
            "users": {"alice": {"roles": ["echoer"]}},
            "tokens": {"test": {"user": "alice", "sha256": hashlib.sha256(TOKEN.encode()).hexdigest()}},
        },
    })


@pytest.fixture
def client():
    with TestClient(create_app(configuration())) as client:
        yield client


def test_health_and_no_public_schema(client):
    assert client.app.title == "Hookbox"
    assert client.get("/healthz").json() == {"status": "ok"}
    for path in ["/docs", "/openapi.json", "/hooks/disabled", "/unknown"]:
        assert client.get(path).status_code == 404
    assert client.get("/hooks/echo", headers=AUTH).status_code == 405


@pytest.mark.parametrize("header", [None, "", "Bearer", "Bearer wrong", f"Basic {TOKEN}", f"Bearer {TOKEN} extra"])
def test_authentication_precedes_body_and_execution(client, monkeypatch, header):
    def forbidden(*args):
        pytest.fail("An unauthenticated request executed an action")
    monkeypatch.setattr("hookbox.app.execute_action", forbidden)
    response = client.post("/hooks/echo", content="invalid-json", headers={} if header is None else {"Authorization": header})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_duplicate_auth_headers_rejected(client):
    assert client.post("/hooks/echo", headers=[("Authorization", f"Bearer {TOKEN}"), ("Authorization", f"Bearer {TOKEN}")]).status_code == 401


def test_role_denies_other_hook(client, monkeypatch):
    monkeypatch.setattr("hookbox.app.execute_action", lambda *args: pytest.fail("RBAC bypass"))
    assert client.put("/custom/other", headers=AUTH, json={}).status_code == 403


def test_real_command_payload_output_and_request_id():
    config = configuration()
    config.webhook["echo"].expose_output = True
    payload = {"message": "Привет", "command": "untrusted; shell text"}
    with TestClient(create_app(config)) as client:
        response = client.post("/hooks/echo", headers=AUTH, json=payload)
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["webhook"] == "echo"
    assert body["request_id"] == response.headers["x-request-id"]
    assert json.loads(body["results"][0]["stdout"]) == payload


def test_output_hidden_and_logs_do_not_contain_secrets(client, monkeypatch, caplog):
    monkeypatch.setattr("hookbox.app.execute_action", lambda *args: {"type": "command", "exit_code": 0, "stdout": "sensitive-output", "stderr": "private", "output_truncated": False})
    with caplog.at_level("INFO"):
        response = client.post("/hooks/echo", headers=AUTH, json={"secret": "sensitive-payload"})
    assert response.json()["results"] == [{"type": "command", "exit_code": 0, "output_truncated": False}]
    assert "user=alice" in caplog.text
    for secret in [TOKEN, "sensitive-payload", "sensitive-output", "private"]:
        assert secret not in caplog.text
        assert secret not in response.text


@pytest.mark.parametrize("body,content_type,status", [
    (b"{", "application/json", 400), (b"\xff", "application/json", 400),
    (b"NaN", "application/json", 400), (b"Infinity", "application/json", 400),
    (b'{"number":1e999}', "application/json", 400),
    (b'{"text":["\\ud800"]}', "application/json", 400),
    (b'{"\\udfff":null}', "application/json", 400),
    (b"{}", "text/plain", 415), (b"{}", "", 415),
])
def test_invalid_payloads_never_execute(client, monkeypatch, body, content_type, status):
    monkeypatch.setattr("hookbox.app.execute_action", lambda *args: pytest.fail("Invalid payload executed"))
    response = client.post("/hooks/echo", headers={**AUTH, "Content-Type": content_type}, content=body)
    assert response.status_code == status


@pytest.mark.parametrize("body,content_type,expected", [(b"", "", None), (b"[1,true]", "application/vnd.test+json; charset=utf-8", [1, True])])
def test_empty_and_vendor_json(client, monkeypatch, body, content_type, expected):
    seen = []
    monkeypatch.setattr("hookbox.app.execute_action", lambda action, payload: seen.append(payload) or {"type": "command", "exit_code": 0})
    assert client.post("/hooks/echo", headers={**AUTH, "Content-Type": content_type}, content=body).status_code == 200
    assert seen == [expected]


@pytest.mark.parametrize("length,status", [("invalid", 400), ("-1", 400), ("100", 413)])
def test_content_length_validation(monkeypatch, length, status):
    monkeypatch.setattr("hookbox.app.execute_action", lambda *args: pytest.fail("Invalid request executed"))
    with TestClient(create_app(configuration(max_body_bytes=8))) as client:
        assert client.post("/hooks/echo", headers={**AUTH, "Content-Length": length}, content=b"{}").status_code == status


def test_streamed_body_limit_without_content_length(monkeypatch):
    monkeypatch.setattr("hookbox.app.execute_action", lambda *args: pytest.fail("Oversized request executed"))

    async def check():
        async def chunks():
            yield b'{"message":'
            yield b'"too large"}'
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(configuration(max_body_bytes=12))), base_url="http://test") as client:
            return await client.post("/hooks/echo", headers={**AUTH, "Content-Type": "application/json"}, content=chunks())
    assert asyncio.run(check()).status_code == 413


def test_encoding_rejected_and_slot_released(client, monkeypatch):
    monkeypatch.setattr("hookbox.app.execute_action", lambda *args: {"type": "command", "exit_code": 0})
    for _ in range(10):
        assert client.post("/hooks/echo", headers={**AUTH, "Content-Encoding": "gzip"}, content=b"{}").status_code == 415
    assert client.post("/hooks/echo", headers=AUTH).status_code == 200


def test_stalled_upload_times_out_and_releases_capacity(monkeypatch):
    seen = []
    monkeypatch.setattr("hookbox.app.execute_action", lambda action, payload: seen.append(payload) or {"type": "command", "exit_code": 0})

    async def check():
        async def stalled():
            yield b'{"x":'
            await asyncio.sleep(10)
            yield b'1}'
        app = create_app(configuration(max_concurrent_requests=1, body_timeout_seconds=0.05))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            expired = await client.post("/hooks/echo", headers={**AUTH, "Content-Type": "application/json"}, content=stalled())
            following = await client.post("/hooks/echo", headers=AUTH, json={"next": True})
            return expired, following
    expired, following = asyncio.run(check())
    assert expired.status_code == 408
    assert following.status_code == 200
    assert seen == [{"next": True}]


@pytest.mark.parametrize("error,status,code", [(ActionError("command_failed", "Command failed"), 502, "command_failed"), (ActionError("timeout", "Timed out", 504), 504, "timeout"), (RuntimeError("secret-error-text"), 500, "internal_error")])
def test_chain_stops_at_failure_and_hides_exceptions(monkeypatch, caplog, error, status, code):
    config = configuration()
    config.webhook["echo"].actions *= 3
    calls = []
    def execute(action, payload):
        calls.append(payload)
        if len(calls) == 2:
            raise error
        return {"type": "command", "exit_code": 0, "stdout": "secret-output"}
    monkeypatch.setattr("hookbox.app.execute_action", execute)
    with TestClient(create_app(config)) as client:
        response = client.post("/hooks/echo", headers=AUTH, json={"x": 1})
    assert response.status_code == status
    assert len(calls) == 2
    assert response.json()["failed_action"] == 1
    assert response.json()["error"]["code"] == code
    assert response.json()["results"] == [{"type": "command", "exit_code": 0}]
    assert "secret-error-text" not in response.text + caplog.text


def test_concurrency_limit_does_not_block_health_and_releases_capacity(monkeypatch):
    entered, release = threading.Event(), threading.Event()
    def execute(*args):
        entered.set()
        assert release.wait(5)
        return {"type": "command", "exit_code": 0}
    monkeypatch.setattr("hookbox.app.execute_action", execute)
    with TestClient(create_app(configuration(max_concurrent_requests=1))) as client, ThreadPoolExecutor() as pool:
        running = pool.submit(client.post, "/hooks/echo", headers=AUTH)
        try:
            assert entered.wait(5)
            assert client.get("/healthz").status_code == 200
            busy = client.post("/hooks/echo", headers=AUTH)
            assert busy.status_code == 503
            assert busy.headers["retry-after"] == "1"
        finally:
            release.set()
        assert running.result(timeout=5).status_code == 200
        assert client.post("/hooks/echo", headers=AUTH).status_code == 200


def test_custom_method_route_and_slashes(monkeypatch):
    config = configuration()
    config.security.users["alice"].roles = ["operator"]
    seen = []
    monkeypatch.setattr("hookbox.app.execute_action", lambda action, payload: seen.append(action.command[-1]) or {"type": "command", "exit_code": 0})
    with TestClient(create_app(config)) as client:
        assert client.put("/custom/other", headers=AUTH).status_code == 200
        assert client.post("/custom/other", headers=AUTH).status_code == 405
        assert client.post("/hooks/echo/", headers=AUTH).status_code == 404
    assert seen == ["print('other')"]
