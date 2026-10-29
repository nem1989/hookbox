"""Real TCP regression for the service entry point and execution lifecycle."""

import hashlib
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_server_over_tcp_and_graceful_stop(tmp_path):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    token = "integration-test-token"
    config = {
        "general": {"port": port},
        "webhook": {"echo": {"expose_output": True, "actions": [{
            "type": "command", "command": [sys.executable, "-c", "import sys; print(sys.stdin.read())"],
        }]}},
        "security": {
            "roles": {"caller": ["echo"]}, "users": {"test": {"roles": ["caller"]}},
            "tokens": {"test": {"user": "test", "sha256": hashlib.sha256(token.encode()).hexdigest()}},
        },
    }
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {}
    # File output avoids blocked pipes and keeps diagnostics on a failed startup.
    with (tmp_path / "server.log").open("w+", encoding="utf-8") as log:
        process = subprocess.Popen([sys.executable, str(ROOT / "main.py"), "--config", str(config_path)], cwd=tmp_path, stdout=log, stderr=log, **options)
        try:
            with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=2, trust_env=False) as client:
                deadline = time.monotonic() + 15
                while True:
                    try:
                        response = client.get("/healthz")
                        if response.status_code == 200:
                            break
                    except httpx.TransportError:
                        pass
                    if process.poll() is not None or time.monotonic() >= deadline:
                        log.seek(0)
                        raise AssertionError(f"Server did not start: {log.read()}")
                    time.sleep(0.05)
                assert response.json() == {"status": "ok"}
                assert client.post("/hooks/echo", json={}).status_code == 401
                response = client.post("/hooks/echo", headers={"Authorization": f"Bearer {token}"}, json={"real_tcp": True})
                assert response.status_code == 200, response.text
                assert json.loads(response.json()["results"][0]["stdout"]) == {"real_tcp": True}
            process.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)
            # Uvicorn re-raises the signal after completing graceful shutdown.
            expected_exit = 3 if os.name == "nt" else -signal.SIGTERM
            assert process.wait(timeout=15) == expected_exit
            log.seek(0)
            shutdown_log = log.read()
            assert "Application shutdown complete." in shutdown_log
            assert "Finished server process" in shutdown_log
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
