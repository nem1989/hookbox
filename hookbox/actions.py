"""Execute administrator-defined actions with bounded output and deadlines."""

from __future__ import annotations

import asyncio
import ctypes
import json
import os
import signal
import subprocess
import sys
import threading
import time
from typing import Any, BinaryIO

import httpx

from hookbox.config import CommandAction, HttpAction


class ActionError(Exception):
    """Public error details, deliberately excluding commands, URLs and secrets."""

    def __init__(self, code: str, message: str, status_code: int = 502):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


class _Capture:
    def __init__(self, limit: int):
        self.limit = limit
        self.data = bytearray()
        self.truncated = False

    def drain(self, stream: BinaryIO) -> None:
        try:
            while chunk := stream.read(65536):
                remaining = self.limit - len(self.data)
                self.data.extend(chunk[:remaining])
                self.truncated |= len(chunk) > remaining
        finally:
            stream.close()

    def text(self) -> str:
        return self.data.decode("utf-8", errors="replace")


class _WindowsJob:
    """Windows 8+ nested job; its entire process tree dies when closed."""

    def __init__(self) -> None:
        from ctypes import wintypes

        class BasicLimits(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [(name, ctypes.c_ulonglong) for name in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
            )]

        class ExtendedLimits(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimits), ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.api.CreateJobObjectW.restype = wintypes.HANDLE
        self.api.SetInformationJobObject.argtypes = [
            wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ]
        self.api.SetInformationJobObject.restype = wintypes.BOOL
        self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.api.AssignProcessToJobObject.restype = wintypes.BOOL
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.CloseHandle.restype = wintypes.BOOL
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedLimits()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE
        if not self.api.SetInformationJobObject(
            self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            self.close()
            raise error

    def assign(self, process: subprocess.Popen) -> None:
        if not self.api.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        if self.handle:
            self.api.CloseHandle(self.handle)
            self.handle = None


# The gate prevents the target from spawning children before job assignment.
# It uses an unbuffered read so the target receives the complete JSON stdin.
_WINDOWS_LAUNCHER = (
    "import os, subprocess, sys\n"
    "if os.read(0, 1) != b'G': sys.exit(127)\n"
    "try:\n"
    "    child = subprocess.Popen(sys.argv[1:], shell=False)\n"
    "except OSError:\n"
    "    sys.exit(127)\n"
    "sys.exit(child.wait())\n"
)


def _write_input(stream: BinaryIO, data: bytes) -> None:
    try:
        stream.write(data)
        stream.flush()
    except (BrokenPipeError, OSError):
        # Closing stdin early is valid behavior for a command.
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _stop_process_tree(process: subprocess.Popen, job: _WindowsJob | None) -> None:
    if job is not None:
        job.close()
    elif os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        # This path only occurs if Windows job setup failed before the gate.
        process.kill()
    # Assignment can fail before the Windows launcher is inside the job. It is
    # still blocked at the gate, so terminate it directly rather than waiting.
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _execute_command(action: CommandAction, payload: Any) -> dict[str, Any]:
    deadline = time.monotonic() + action.timeout_seconds
    data = (json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
            if action.stdin_from_payload else b"")
    process = None
    job = None
    workers: list[threading.Thread] = []
    stdout = _Capture(action.max_output_bytes)
    stderr = _Capture(action.max_output_bytes)
    try:
        command = action.command
        options: dict[str, Any] = {"start_new_session": True} if os.name == "posix" else {}
        if os.name == "nt":
            job = _WindowsJob()
            command = [sys.executable, "-I", "-c", _WINDOWS_LAUNCHER, *command]
            options["creationflags"] = subprocess.CREATE_NO_WINDOW
            data = b"G" + data
        process = subprocess.Popen(
            command, cwd=action.cwd, env={**os.environ, **action.env},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False, **options,
        )
        if job is not None:
            job.assign(process)
        for target, args in (
            (stdout.drain, (process.stdout,)),
            (stderr.drain, (process.stderr,)),
            (_write_input, (process.stdin, data)),
        ):
            worker = threading.Thread(target=target, args=args, daemon=True)
            worker.start()
            workers.append(worker)
        process.wait(timeout=max(0, deadline - time.monotonic()))
        for worker in workers:
            worker.join(timeout=max(0, deadline - time.monotonic()))
            if worker.is_alive():
                raise subprocess.TimeoutExpired(action.command, action.timeout_seconds)
        if process.returncode:
            raise ActionError("command_failed", "Command returned a nonzero exit code.")
        return {
            "type": "command", "exit_code": 0,
            "stdout": stdout.text(), "stderr": stderr.text(),
            "output_truncated": stdout.truncated or stderr.truncated,
        }
    except subprocess.TimeoutExpired:
        raise ActionError("action_timeout", "Action exceeded its timeout.", 504) from None
    except OSError:
        raise ActionError("command_failed", "Command could not be started.") from None
    finally:
        if process is not None:
            _stop_process_tree(process, job)
            for worker in workers:
                worker.join(timeout=1)
            # No drain threads were started if job assignment failed.
            if not workers:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()
        elif job is not None:
            job.close()


async def _http_request(action: HttpAction, payload: Any) -> dict[str, Any]:
    options: dict[str, Any] = {}
    headers = httpx.Headers(action.headers)
    # Keep the response cap meaningful: a small compressed chunk can expand to
    # an arbitrarily large allocation inside an HTTP client's decoder.
    headers.setdefault("Accept-Encoding", "identity")
    if action.forward_payload:
        options["content"] = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode("utf-8")
    elif "body" in action.model_fields_set:
        options["content"] = json.dumps(action.body, ensure_ascii=True, allow_nan=False).encode("utf-8")
    if "content" in options:
        headers.setdefault("Content-Type", "application/json")
    async with httpx.AsyncClient(
        timeout=action.timeout_seconds, follow_redirects=False, trust_env=False,
    ) as client:
        async with client.stream(
            action.method, str(action.url), headers=headers, **options,
        ) as response:
            if not 200 <= response.status_code < 300:
                raise ActionError("http_failed", "HTTP action returned an unsuccessful status.")
            if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
                raise ActionError("http_encoding", "HTTP action returned an unsupported content encoding.")
            output = bytearray()
            truncated = False
            # Identity encoding was checked before iteration; no decompression
            # occurs here and the network chunks remain bounded by HTTPX.
            async for chunk in response.aiter_bytes():
                remaining = action.max_output_bytes - len(output)
                output.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    break
            return {
                "type": "http", "status_code": response.status_code,
                "body": output.decode("utf-8", errors="replace"),
                "output_truncated": truncated,
            }


async def _execute_http(action: HttpAction, payload: Any) -> dict[str, Any]:
    try:
        return await asyncio.wait_for(_http_request(action, payload), action.timeout_seconds)
    except (TimeoutError, httpx.TimeoutException):
        raise ActionError("action_timeout", "Action exceeded its timeout.", 504) from None
    except httpx.HTTPError:
        raise ActionError("http_failed", "HTTP action could not be completed.") from None


def execute_action(action: CommandAction | HttpAction, payload: Any) -> dict[str, Any]:
    """Run from a worker thread; payload never becomes a command or destination."""
    if isinstance(action, CommandAction):
        return _execute_command(action, payload)
    if isinstance(action, HttpAction):
        return asyncio.run(_execute_http(action, payload))
    raise TypeError("Unsupported action type")
