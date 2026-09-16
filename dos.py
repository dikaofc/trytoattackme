"""Bounded live smoke test for the TRYTOATTACKME request recorder.

This intentionally does not generate a DoS load:
- only the project Vercel hostname is accepted;
- requests are sequential;
- at most 20 requests can be sent;
- a live run requires an explicit confirmation flag.

Example:
    python dos.py --confirm-live --count 5 --delay 1
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


DEFAULT_BASE_URL = "https://trytoattackme.vercel.app"
ALLOWED_HOST = "trytoattackme.vercel.app"
MAX_REQUESTS = 20
MIN_DELAY_SECONDS = 0.2


def get_json(url: str, timeout: float) -> tuple[int, dict | None]:
    request = Request(url, headers={"User-Agent": "trytoattackme-smoke-test/1.0"})
    try:
        with urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")
            try:
                return response.status, json.loads(body)
            except json.JSONDecodeError:
                return response.status, None
    except HTTPError as error:
        return error.code, None


def validate_base_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.hostname != ALLOWED_HOST or parsed.path not in ("", "/"):
        raise argparse.ArgumentTypeError(
            f"URL must be https://{ALLOWED_HOST}"
        )
    return value.rstrip("/")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send a small, bounded request-recording smoke test."
    )
    parser.add_argument(
        "--base-url",
        type=validate_base_url,
        default=DEFAULT_BASE_URL,
        help=f"Live project URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=3,
        help=f"Sequential requests to send (1-{MAX_REQUESTS}, default: 3)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help=f"Seconds between requests (minimum: {MIN_DELAY_SECONDS})",
    )
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument(
        "--confirm-live",
        action="store_true",
        help="Required acknowledgement that this contacts the live deployment.",
    )
    args = parser.parse_args()

    if not args.confirm_live:
        parser.error("add --confirm-live to contact the live deployment")
    if not 1 <= args.count <= MAX_REQUESTS:
        parser.error(f"--count must be between 1 and {MAX_REQUESTS}")
    if args.delay < MIN_DELAY_SECONDS:
        parser.error(f"--delay must be at least {MIN_DELAY_SECONDS} seconds")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    stats_url = f"{args.base_url}/api/stats"
    hit_url = f"{args.base_url}/api/hit?source=smoke-test"

    before_status, before = get_json(stats_url, args.timeout)
    print(f"stats before: HTTP {before_status}")
    if before is not None and "total" in before:
        print(f"recorded total before: {before['total']}")
    if before_status != 200:
        print("The stats endpoint is unavailable; hit requests may still be sent, but recording cannot be verified.")

    results: list[tuple[int, str]] = []
    for index in range(1, args.count + 1):
        try:
            status, body = get_json(hit_url, args.timeout)
            outcome = "allowed" if status == 200 else "blocked/error"
            results.append((status, outcome))
            detail = body.get("path") if isinstance(body, dict) else ""
            print(f"hit {index}/{args.count}: HTTP {status} ({outcome}){f' path={detail}' if detail else ''}")
        except URLError as error:
            print(f"hit {index}/{args.count}: network error: {error.reason}", file=sys.stderr)
            return 1
        if index < args.count:
            time.sleep(args.delay)

    after_status, after = get_json(stats_url, args.timeout)
    print(f"stats after: HTTP {after_status}")
    if after is not None and "total" in after:
        print(f"recorded total after: {after['total']}")
        if before is not None and "total" in before:
            print(f"observed increase: {after['total'] - before['total']}")
    else:
        print("Could not verify the recorded total. On serverless deployments, in-memory counters may be instance-local.")

    failures = sum(status >= 500 for status, _ in results)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
