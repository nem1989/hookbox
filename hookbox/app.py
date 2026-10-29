"""Authenticated webhook routes and bounded, sequential action execution."""

import asyncio
import json
import logging
import math
import threading
import time
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from .actions import ActionError, execute_action
from .config import AppConfig, WebhookConfig
from .security import authenticate, is_allowed

logger = logging.getLogger("hookbox")


async def _payload(request: Request, limit: int) -> Any:
    length = request.headers.get("content-length")
    if length is not None:
        try:
            size = int(length)
        except ValueError:
            raise HTTPException(400, "Invalid Content-Length") from None
        if size < 0:
            raise HTTPException(400, "Invalid Content-Length")
        if size > limit:
            raise HTTPException(413, "Request body is too large")
    if request.headers.get("content-encoding", "identity").lower() != "identity":
        raise HTTPException(415, "Content-Encoding is not supported")
    body = bytearray()
    try:
        async for chunk in request.stream():
            if len(body) + len(chunk) > limit:
                raise HTTPException(413, "Request body is too large")
            body.extend(chunk)
    except ClientDisconnect:
        raise HTTPException(400, "Client disconnected") from None
    if not body:
        return None
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if not (content_type == "application/json" or (content_type.startswith("application/") and content_type.endswith("+json"))):
        raise HTTPException(415, "Expected application/json")

    def invalid_constant(value: str) -> None:
        raise ValueError("Non-finite JSON number")

    def finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("Non-finite JSON number")
        return number

    def validate_unicode(value: Any) -> None:
        if isinstance(value, str):
            value.encode("utf-8")
        elif isinstance(value, list):
            for item in value:
                validate_unicode(item)
        elif isinstance(value, dict):
            for key, item in value.items():
                key.encode("utf-8")
                validate_unicode(item)

    try:
        payload = json.loads(body.decode("utf-8"), parse_constant=invalid_constant, parse_float=finite_float)
        validate_unicode(payload)
        return payload
    except (ValueError, RecursionError):
        raise HTTPException(400, "Invalid UTF-8 JSON body") from None


def _public_result(result: dict, expose_output: bool) -> dict:
    if expose_output:
        return result
    return {key: value for key, value in result.items() if key in {"type", "exit_code", "status_code", "output_truncated"}}


def create_app(config: AppConfig) -> FastAPI:
    app = FastAPI(title="Hookbox", docs_url=None, redoc_url=None, openapi_url=None)
    app.router.redirect_slashes = False
    slots = threading.BoundedSemaphore(config.general.max_concurrent_requests)

    @app.get("/healthz")
    async def health() -> dict:
        return {"status": "ok"}

    def endpoint_for(webhook_id: str, hook: WebhookConfig):
        async def endpoint(request: Request) -> JSONResponse:
            request_id = uuid.uuid4().hex
            headers = request.headers.getlist("authorization")
            parts = headers[0].split() if len(headers) == 1 else []
            principal = authenticate(config.security, parts[1]) if len(parts) == 2 and parts[0].lower() == "bearer" else None
            if principal is None:
                logger.warning("request=%s webhook=%s authentication_failed", request_id, webhook_id)
                raise HTTPException(401, "Invalid or missing bearer token", headers={"WWW-Authenticate": "Bearer"})
            if not is_allowed(config.security, principal, webhook_id):
                logger.warning("request=%s webhook=%s user=%s access_denied", request_id, webhook_id, principal.username)
                raise HTTPException(403, "Access denied")
            if not slots.acquire(blocking=False):
                raise HTTPException(503, "Execution capacity exhausted", headers={"Retry-After": "1"})
            started = time.monotonic()
            try:
                try:
                    payload = await asyncio.wait_for(
                        _payload(request, config.general.max_body_bytes),
                        timeout=config.general.body_timeout_seconds,
                    )
                except TimeoutError:
                    raise HTTPException(408, "Request body timed out") from None

                def execute_chain() -> tuple[dict, int]:
                    results = []
                    for index, action in enumerate(hook.actions):
                        try:
                            results.append(_public_result(execute_action(action, payload), hook.expose_output))
                        except ActionError as exc:
                            logger.warning("request=%s webhook=%s user=%s action=%s error=%s", request_id, webhook_id, principal.username, index, exc.code)
                            return {"status": "error", "failed_action": index, "error": {"code": exc.code, "message": exc.message}, "results": results}, exc.status_code
                        except Exception:
                            logger.error("request=%s webhook=%s user=%s action=%s unexpected_error", request_id, webhook_id, principal.username, index)
                            return {"status": "error", "failed_action": index, "error": {"code": "internal_error", "message": "Action execution failed"}, "results": results}, 500
                    return {"status": "ok", "results": results}, 200

                result, status_code = await run_in_threadpool(execute_chain)
                result.update(request_id=request_id, webhook=webhook_id)
                logger.info("request=%s webhook=%s user=%s token=%s status=%s duration_ms=%d", request_id, webhook_id, principal.username, principal.token_name, status_code, (time.monotonic() - started) * 1000)
                return JSONResponse(result, status_code=status_code, headers={"X-Request-ID": request_id})
            finally:
                slots.release()

        return endpoint

    for webhook_id, hook in config.webhook.items():
        if hook.enabled:
            app.add_api_route(hook.path, endpoint_for(webhook_id, hook), methods=hook.methods, name=webhook_id)
    return app
