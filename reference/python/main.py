"""Command-line entry point for both interactive and service execution."""

import argparse
import hashlib
import json
import logging
import secrets
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hookbox", description="Hookbox: configuration-driven webhook integration service")
    parser.add_argument("--config", type=Path, default=Path("config.yaml"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check-config", action="store_true", help="Validate configuration and exit")
    mode.add_argument("--generate-token", action="store_true", help="Generate a token and its SHA-256 hash")
    args = parser.parse_args(argv)
    if args.generate_token:
        token = secrets.token_urlsafe(32)
        print(json.dumps({"token": token, "sha256": hashlib.sha256(token.encode()).hexdigest()}, indent=2))
        return 0

    from hookbox.config import ConfigError, load_config

    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    if args.check_config:
        print("Configuration is valid")
        return 0

    import uvicorn
    from hookbox.app import create_app

    logging.basicConfig(
        level=config.general.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # HTTP client diagnostics include complete URLs, possibly with query secrets.
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)
    ssl = config.general.ssl
    uvicorn.run(
        create_app(config),
        host=config.general.host,
        port=config.general.port,
        log_level=config.general.log_level,
        ssl_certfile=str(ssl.certfile) if ssl else None,
        ssl_keyfile=str(ssl.keyfile) if ssl else None,
        proxy_headers=False,
        access_log=False,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
