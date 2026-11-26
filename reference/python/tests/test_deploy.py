"""Executable checks for the shipped configuration and deployment helpers."""

import configparser
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

from hookbox.app import create_app
from hookbox.config import load_config


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def example_config(monkeypatch):
    monkeypatch.setenv("PYTHON_EXECUTABLE", sys.executable)
    monkeypatch.setenv("WEBHOOK_TOKEN_SHA256", hashlib.sha256(b"example-test-token").hexdigest())
    return load_config(ROOT / "config.example.yaml")


def test_shipped_example_runs_real_echo_from_another_directory(example_config, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    payload = {"message": "Привет", "arguments": ["; echo injected", "$(whoami)"], "value": None}
    with TestClient(create_app(example_config)) as client:
        response = client.post(
            "/hooks/echo",
            headers={"Authorization": "Bearer example-test-token"},
            json=payload,
        )
    assert response.status_code == 200
    result = response.json()["results"][0]
    assert result["exit_code"] == 0
    assert json.loads(result["stdout"]) == {"received": payload}


def test_example_requires_authentication_and_forward_is_disabled(example_config):
    with TestClient(create_app(example_config)) as client:
        assert client.post("/hooks/echo", json={}).status_code == 401
        assert client.post(
            "/hooks/forward",
            headers={"Authorization": "Bearer example-test-token"},
            json={},
        ).status_code == 404


def test_example_token_remains_restricted_after_enabling_forward(example_config):
    example_config.webhook["forward"].enabled = True
    with TestClient(create_app(example_config)) as client:
        response = client.post(
            "/hooks/forward",
            headers={"Authorization": "Bearer example-test-token"},
            json={},
        )
    assert response.status_code == 403


def _powershell():
    executable = shutil.which("powershell.exe") or shutil.which("pwsh")
    if executable is None:
        pytest.skip("PowerShell is not installed")
    return executable


def test_nssm_installer_parses_without_running_it():
    command = r"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:INSTALLER_PATH, [ref]$tokens, [ref]$errors)
if ($errors.Count -gt 0) { throw ($errors | Out-String) }
$serviceParameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'ServiceName' }
if ($serviceParameter.DefaultValue.SafeGetValue() -ne 'hookbox') { throw 'Unexpected default service name' }
"""
    result = subprocess.run(
        [_powershell(), "-NoProfile", "-NonInteractive", "-Command", command],
        env={**os.environ, "INSTALLER_PATH": str(ROOT / "deploy" / "install-nssm.ps1")},
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")


def test_linux_unit_uses_consistent_hookbox_installation_paths():
    unit = configparser.ConfigParser(interpolation=None)
    unit.read(ROOT / "deploy" / "hookbox.service", encoding="utf-8")
    service = unit["Service"]
    assert service["User"] == service["Group"] == "hookbox"
    assert service["WorkingDirectory"] == "/opt/hookbox"
    assert service["EnvironmentFile"] == "/etc/hookbox.env"
    command = service["ExecStart"].split()
    assert command == [
        "/opt/hookbox/.venv/bin/python", "/opt/hookbox/main.py",
        "--config", "/opt/hookbox/config.yaml",
    ]


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native argument escaping")
def test_nssm_native_argument_escaping_round_trips_through_real_process(tmp_path):
    values = ["plain", "space separated", 'embedded"quote', "C:\\Program Files\\path\\", "", "\\\\", 'slash\\"quote']
    argument_file = tmp_path / "arguments.json"
    argument_file.write_text(json.dumps(values), encoding="utf-8")
    # Evaluate just the pure quoting function, never the installer body or NSSM.
    command = r"""
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($env:INSTALLER_PATH, [ref]$tokens, [ref]$errors)
$function = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'ConvertTo-NativeArgument'
}, $true)
. ([scriptblock]::Create($function.Extent.Text))
$values = Get-Content -LiteralPath $env:ARGUMENT_FILE -Raw -Encoding UTF8 | ConvertFrom-Json
$nativeArguments = @('-c', 'import json,sys; print(json.dumps(sys.argv[1:]))') + @($values)
$start = New-Object System.Diagnostics.ProcessStartInfo
$start.FileName = $env:TEST_PYTHON
$start.Arguments = ($nativeArguments | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' '
$start.UseShellExecute = $false
$start.CreateNoWindow = $true
$start.RedirectStandardOutput = $true
$process = [System.Diagnostics.Process]::Start($start)
$output = $process.StandardOutput.ReadToEnd()
$process.WaitForExit()
if ($process.ExitCode -ne 0) { throw 'Child process failed' }
$process.Dispose()
Write-Output $output
"""
    result = subprocess.run(
        [_powershell(), "-NoProfile", "-NonInteractive", "-Command", command],
        env={
            **os.environ,
            "INSTALLER_PATH": str(ROOT / "deploy" / "install-nssm.ps1"),
            "ARGUMENT_FILE": str(argument_file),
            "TEST_PYTHON": sys.executable,
        },
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert json.loads(result.stdout) == values
