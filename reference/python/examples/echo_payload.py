"""Example action: read one JSON value from stdin and echo it as UTF-8."""

import json
import sys


def main() -> None:
    payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
    output = json.dumps({"received": payload}, ensure_ascii=False) + "\n"
    sys.stdout.buffer.write(output.encode("utf-8"))


if __name__ == "__main__":
    main()
