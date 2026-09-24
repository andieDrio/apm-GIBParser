"""Safe runtime probe for the verified Group-IB API contract.

This script intentionally reports response structure, not response values.
It reads credentials only from the local environment and never prints them.

Required environment variables:
  GROUP_IB_USERNAME     Group-IB web-interface login email
  GROUP_IB_API_TOKEN    Personal API token

For compatibility with the historical local prototype, GROUP_IB_API_KEY is
accepted as a fallback token variable. It is never printed or transmitted as
a bearer credential.

Optional:
  GROUP_IB_API_BASE_URL  Defaults to https://tap.group-ib.com/api/v2/
  GROUP_IB_PROBE_LIMIT   Defaults to 1

The probe makes one bounded request to:
  compromised/account_group/updated
"""

from __future__ import annotations

import os
import sys
from collections import Counter
from typing import Any

import httpx

DEFAULT_BASE_URL = "https://tap.group-ib.com/api/v2/"
COLLECTION_PATH = "compromised/account_group/updated"


def _type_name(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int) and not isinstance(value, bool):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return type(value).__name__


def _schema_paths(value: Any, path: str = "$", depth: int = 0) -> list[tuple[str, str]]:
    if depth > 8:
        return [(path, _type_name(value) + " (depth-limit)")]

    rows: list[tuple[str, str]] = []

    if isinstance(value, dict):
        rows.append((path, "object"))
        for key in sorted(value):
            child = f"{path}.{key}"
            rows.extend(_schema_paths(value[key], child, depth + 1))
        return rows

    if isinstance(value, list):
        rows.append((path, "array"))
        if value:
            rows.extend(_schema_paths(value[0], f"{path}[]", depth + 1))
        return rows

    rows.append((path, _type_name(value)))
    return rows


def _require_environment() -> tuple[str, str, str, int]:
    username = os.getenv("GROUP_IB_USERNAME", "").strip()
    token = (
        os.getenv("GROUP_IB_API_TOKEN", "").strip()
        or os.getenv("GROUP_IB_API_KEY", "").strip()
    )
    base_url = os.getenv("GROUP_IB_API_BASE_URL", DEFAULT_BASE_URL).strip()
    raw_limit = os.getenv("GROUP_IB_PROBE_LIMIT", "1").strip()

    if not username:
        raise RuntimeError(
            "GROUP_IB_USERNAME is required. Set it to the email used for the "
            "Group-IB TI web interface. The token is not printed."
        )
    if not token:
        raise RuntimeError(
            "GROUP_IB_API_TOKEN is required (GROUP_IB_API_KEY is accepted as "
            "a local fallback). The token is not printed."
        )

    try:
        limit = int(raw_limit)
    except ValueError as exc:
        raise RuntimeError("GROUP_IB_PROBE_LIMIT must be an integer.") from exc

    if not 1 <= limit <= 5:
        raise RuntimeError("GROUP_IB_PROBE_LIMIT must be between 1 and 5.")

    return username, token, base_url.rstrip("/") + "/", limit


def main() -> int:
    try:
        username, token, base_url, limit = _require_environment()
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    url = f"{base_url}{COLLECTION_PATH}"
    params = {"limit": limit}

    print("Group-IB API contract probe")
    print(f"Endpoint: {url}")
    print(f"Bounded limit: {limit}")
    print("Credentials: loaded from environment; values are not displayed")

    try:
        with httpx.Client(
            timeout=httpx.Timeout(30.0),
            auth=(username, token),
            headers={"Accept": "application/json"},
            follow_redirects=False,
        ) as client:
            response = client.get(url, params=params)
    except httpx.TimeoutException:
        print("ERROR: request timed out.", file=sys.stderr)
        return 3
    except httpx.HTTPError as exc:
        print(f"ERROR: HTTP request failed: {exc}", file=sys.stderr)
        return 3

    print(f"HTTP status: {response.status_code}")

    if response.status_code in (401, 403):
        print(
            "Authentication/authorization was rejected. Verify the Group-IB "
            "username/token and API allow-list without printing credentials.",
            file=sys.stderr,
        )
        return 4

    if response.status_code == 429:
        print("Rate limit reached; do not retry repeatedly.", file=sys.stderr)
        return 5

    if response.is_error:
        print(
            f"ERROR: Group-IB returned HTTP {response.status_code}.",
            file=sys.stderr,
        )
        return 6

    try:
        payload = response.json()
    except ValueError:
        print("ERROR: response was not valid JSON.", file=sys.stderr)
        return 7

    print(f"Top-level response type: {_type_name(payload)}")

    if isinstance(payload, dict):
        items = payload.get("items")
        if isinstance(items, list):
            print(f"Items returned: {len(items)}")
        if "count" in payload:
            print(f"Provider count field type: {_type_name(payload['count'])}")
        if "seqUpdate" in payload:
            print(f"Provider seqUpdate field type: {_type_name(payload['seqUpdate'])}")

    print()
    print("Observed response schema (field names + types only):")

    rows = _schema_paths(payload)
    type_counts = Counter(kind for _, kind in rows)
    for path, kind in rows:
        print(f"{kind:28} {path}")

    print()
    print("Schema node counts:")
    for kind, count in sorted(type_counts.items()):
        print(f"  {kind}: {count}")

    print()
    print("No response values were printed or written to disk.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
