import asyncio
import json
import os
from pathlib import Path
import socket
import sys
import time

import httpx
import pytest

from hookbox import actions
from hookbox.actions import ActionError, execute_action
from hookbox.config import CommandAction, HttpAction


def command(code, **kwargs):
    return CommandAction(type="command", command=[sys.executable, "-c", code], **kwargs)


def test_command_passes_json_stdin_without_interpreting_shell_syntax(tmp_path):
    marker = tmp_path / "injected.txt"
    payload = {"value": f"hello; echo bad > {marker}", "unicode": "Привет"}
    result = execute_action(command("import sys; print(sys.stdin.read())"), payload)
    assert json.loads(result["stdout"]) == payload
    assert result["type"] == "command"
    assert result["exit_code"] == 0
    assert result["stderr"] == ""
    assert result["output_truncated"] is False
    assert not marker.exists()


def test_command_arguments_are_literal(tmp_path):
    marker = tmp_path / "marker.txt"
    argument = f"value & echo BAD > {marker}"
    action = CommandAction(type="command", command=[
        sys.executable, "-c", "import sys; print(sys.argv[1])", argument,
    ])
    assert execute_action(action, {})["stdout"].strip() == argument
    assert not marker.exists()


def test_command_cwd_and_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("REGRESSION_INHERITED", "inherited")
    result = execute_action(command(
        "import os, json; print(json.dumps([os.getcwd(), os.environ['ACTION_VALUE'], "
        "os.environ['REGRESSION_INHERITED']]))",
        cwd=tmp_path, env={"ACTION_VALUE": "configured"},
    ), {})
    cwd, configured, inherited = json.loads(result["stdout"])
    assert Path(cwd) == tmp_path
    assert (configured, inherited) == ("configured", "inherited")


def test_command_can_disable_stdin_payload():
    result = execute_action(command(
        "import sys; print(repr(sys.stdin.read()))", stdin_from_payload=False,
    ), {"secret": "payload"})
    assert result["stdout"].strip() == "''"


def test_command_captures_stderr_and_replaces_invalid_utf8():
    result = execute_action(command(
        "import sys; sys.stdout.buffer.write(b'\\xff'); sys.stderr.write('diagnostic')",
    ), {})
    assert result["stdout"] == "\ufffd"
    assert result["stderr"] == "diagnostic"


def test_command_bounds_both_output_streams_without_deadlock():
    result = execute_action(command(
        "import sys; sys.stdout.write('x'*200000); sys.stderr.write('y'*200000)",
        max_output_bytes=32,
    ), {})
    assert result["stdout"] == "x" * 32
    assert result["stderr"] == "y" * 32
    assert result["output_truncated"] is True


def test_command_exact_output_limit_is_not_truncated():
    result = execute_action(command("print('abcd', end='')", max_output_bytes=4), {})
    assert result["stdout"] == "abcd"
    assert result["output_truncated"] is False


def test_command_nonzero_is_sanitized():
    with pytest.raises(ActionError) as error:
        execute_action(command("import sys; print('secret'); sys.exit(4)"), {})
    assert error.value.code == "command_failed"
    assert error.value.status_code == 502
    assert "secret" not in str(error.value)


def test_missing_command_is_sanitized(tmp_path):
    with pytest.raises(ActionError) as error:
        execute_action(CommandAction(type="command", command=[str(tmp_path / "missing-secret")]), {})
    assert error.value.code == "command_failed"
    assert "missing-secret" not in str(error.value)


def test_invalid_working_directory_is_sanitized(tmp_path):
    with pytest.raises(ActionError) as error:
        execute_action(command("print('unused')", cwd=tmp_path / "missing"), {})
    assert error.value.code == "command_failed"


def test_command_timeout():
    start = time.monotonic()
    with pytest.raises(ActionError) as error:
        execute_action(command("import time; time.sleep(20)", timeout_seconds=0.2), {})
    assert error.value.code == "action_timeout"
    assert error.value.status_code == 504
    assert time.monotonic() - start < 5


def test_large_stdin_to_nonreader_obeys_timeout():
    with pytest.raises(ActionError, match="timeout"):
        execute_action(command("import time; time.sleep(20)", timeout_seconds=0.2), "x" * 500000)


def test_early_stdin_close_does_not_fail_action():
    assert execute_action(command("print('done')"), "x" * 500000)["stdout"].strip() == "done"


@pytest.mark.parametrize("parent_exits", [False, True])
def test_timeout_stops_descendant_even_after_parent_exits(tmp_path, parent_exits):
    marker = tmp_path / "child_survived.txt"
    child_code = f"import time,pathlib; time.sleep(1.3); pathlib.Path({str(marker)!r}).write_text('bad')"
    parent_code = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
        + ("sys.exit(0)" if parent_exits else "time.sleep(20)")
    )
    with pytest.raises(ActionError, match="timeout"):
        execute_action(command(parent_code, timeout_seconds=0.5), {})
    time.sleep(1.3)
    assert not marker.exists(), "Child process must not outlive its action deadline"


def test_successful_action_cleans_up_background_children(tmp_path):
    marker = tmp_path / "child_survived.txt"
    child_code = f"import time,pathlib; time.sleep(1); pathlib.Path({str(marker)!r}).write_text('bad')"
    parent_code = (
        "import subprocess,sys; "
        f"subprocess.Popen([sys.executable, '-c', {child_code!r}], "
        "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)"
    )
    assert execute_action(command(parent_code), {})["exit_code"] == 0
    time.sleep(1.1)
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object failure path")
def test_windows_job_assignment_failure_does_not_start_command(monkeypatch, tmp_path):
    def fail_assignment(self, process):
        raise OSError("job cannot be assigned")

    monkeypatch.setattr(actions._WindowsJob, "assign", fail_assignment)
    marker = tmp_path / "started.txt"
    start = time.monotonic()
    with pytest.raises(ActionError) as error:
        execute_action(command(f"import pathlib; pathlib.Path({str(marker)!r}).touch()"), {})
    assert error.value.code == "command_failed"
    assert time.monotonic() - start < 2
    assert not marker.exists()


def mock_http(monkeypatch, handler):
    original_client = httpx.AsyncClient
    options = []

    def make_client(**kwargs):
        options.append(kwargs)
        return original_client(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(actions.httpx, "AsyncClient", make_client)
    return options


def test_http_forwards_payload_and_configured_headers_only(monkeypatch):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(201, content=b"accepted")

    options = mock_http(monkeypatch, handler)
    action = HttpAction(type="http", url="https://example.test/hook", method="PUT",
                        headers={"X-Configured": "value"}, forward_payload=True)
    result = execute_action(action, {"a": "Привет", "Authorization": "payload-field"})
    assert requests[0].method == "PUT"
    assert json.loads(requests[0].content) == {"a": "Привет", "Authorization": "payload-field"}
    assert requests[0].headers["X-Configured"] == "value"
    assert "Authorization" not in requests[0].headers
    assert options[0]["follow_redirects"] is False
    assert options[0]["trust_env"] is False
    assert result == {"type": "http", "status_code": 201, "body": "accepted", "output_truncated": False}


def test_http_uses_static_body(monkeypatch):
    requests = []
    mock_http(monkeypatch, lambda request: requests.append(request) or httpx.Response(200))
    execute_action(HttpAction(type="http", url="https://example.test", body={"fixed": 1}), {"ignored": 2})
    assert json.loads(requests[0].content) == {"fixed": 1}


@pytest.mark.parametrize("fields", [{"forward_payload": True}, {"body": None}])
def test_http_sends_explicit_json_null(monkeypatch, fields):
    requests = []
    mock_http(monkeypatch, lambda request: requests.append(request) or httpx.Response(204))
    execute_action(HttpAction(type="http", url="https://example.test", **fields), None)
    assert requests[0].content == b"null"
    assert requests[0].headers["content-type"] == "application/json"


def test_http_preserves_configured_content_type(monkeypatch):
    requests = []
    mock_http(monkeypatch, lambda request: requests.append(request) or httpx.Response(204))
    execute_action(HttpAction(type="http", url="https://example.test", body={},
                             headers={"content-type": "application/vnd.example+json"}), {})
    assert requests[0].headers["content-type"] == "application/vnd.example+json"


def test_http_requests_identity_encoding(monkeypatch):
    requests = []
    mock_http(monkeypatch, lambda request: requests.append(request) or httpx.Response(200))
    execute_action(HttpAction(type="http", url="https://example.test"), {})
    assert requests[0].headers["accept-encoding"] == "identity"


def test_http_rejects_compression_before_reading_body(monkeypatch):
    class UnreadBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            pytest.fail("Compressed response must not be read")
            yield b""

    mock_http(monkeypatch, lambda request: httpx.Response(
        200, headers={"Content-Encoding": "gzip"}, stream=UnreadBody(),
    ))
    with pytest.raises(ActionError) as error:
        execute_action(HttpAction(type="http", url="https://example.test"), {})
    assert error.value.code == "http_encoding"


def test_http_without_body_does_not_forward_payload(monkeypatch):
    requests = []
    mock_http(monkeypatch, lambda request: requests.append(request) or httpx.Response(204))
    result = execute_action(HttpAction(type="http", url="https://example.test", method="GET"), {"secret": 1})
    assert requests[0].content == b""
    assert result["body"] == ""


@pytest.mark.parametrize("status", [301, 401, 500])
def test_http_unsuccessful_status_including_redirect_is_error(monkeypatch, status):
    requests = []
    mock_http(monkeypatch, lambda request: requests.append(request) or httpx.Response(
        status, headers={"Location": "https://elsewhere.test"}, content=b"secret-error",
    ))
    with pytest.raises(ActionError) as error:
        execute_action(HttpAction(type="http", url="https://example.test"), {})
    assert error.value.code == "http_failed"
    assert "secret-error" not in str(error.value)
    assert len(requests) == 1


def test_http_bounds_response(monkeypatch):
    mock_http(monkeypatch, lambda request: httpx.Response(200, content=b"x" * 100000))
    result = execute_action(HttpAction(type="http", url="https://example.test", max_output_bytes=10), {})
    assert result["body"] == "x" * 10
    assert result["output_truncated"] is True


def test_http_exact_limit_is_not_truncated(monkeypatch):
    mock_http(monkeypatch, lambda request: httpx.Response(200, content=b"x" * 10))
    result = execute_action(HttpAction(type="http", url="https://example.test", max_output_bytes=10), {})
    assert result["output_truncated"] is False


def test_http_connect_failure_is_sanitized(monkeypatch):
    def handler(request):
        raise httpx.ConnectError("secret endpoint details")

    mock_http(monkeypatch, handler)
    with pytest.raises(ActionError) as error:
        execute_action(HttpAction(type="http", url="https://example.test"), {})
    assert error.value.code == "http_failed"
    assert "secret" not in str(error.value)


def test_http_network_timeout(monkeypatch):
    def handler(request):
        raise httpx.ReadTimeout("secret endpoint details")

    mock_http(monkeypatch, handler)
    with pytest.raises(ActionError) as error:
        execute_action(HttpAction(type="http", url="https://example.test"), {})
    assert error.value.status_code == 504
    assert error.value.code == "action_timeout"


def test_http_total_deadline_cancels_slow_response(monkeypatch):
    async def handler(request):
        await asyncio.sleep(20)
        return httpx.Response(200)

    mock_http(monkeypatch, handler)
    start = time.monotonic()
    with pytest.raises(ActionError) as error:
        execute_action(HttpAction(type="http", url="https://example.test", timeout_seconds=0.05), {})
    assert error.value.status_code == 504
    assert time.monotonic() - start < 2


def test_http_deadline_covers_body_stream(monkeypatch):
    class SlowBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            while True:
                await asyncio.sleep(0.02)
                yield b"x"

    mock_http(monkeypatch, lambda request: httpx.Response(200, stream=SlowBody()))
    with pytest.raises(ActionError) as error:
        execute_action(HttpAction(type="http", url="https://example.test", timeout_seconds=0.08), {})
    assert error.value.status_code == 504


def test_http_dns_timeout_does_not_connect_after_resolution(monkeypatch):
    original_getaddrinfo = socket.getaddrinfo
    dns_started = False

    def delayed_dns(host, port, *args, **kwargs):
        nonlocal dns_started
        dns_started = True
        time.sleep(0.3)
        return original_getaddrinfo("127.0.0.1", port, *args, **kwargs)

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.setblocking(False)
        port = listener.getsockname()[1]
        monkeypatch.setattr(socket, "getaddrinfo", delayed_dns)
        with pytest.raises(ActionError) as error:
            execute_action(HttpAction(type="http", url=f"http://deadline.test:{port}", timeout_seconds=0.1), {})
        assert error.value.status_code == 504
        assert dns_started
        # asyncio.run waits for the blocking resolver to exit, but cancellation
        # must prevent a late connection (and any HTTP side effect).
        with pytest.raises(BlockingIOError):
            listener.accept()
