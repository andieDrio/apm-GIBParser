"""Group-IB TI&A API boundary.

The client owns HTTP concerns only. GUI and PDF code must not perform API
requests directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx


class GroupIBClientError(Exception):
    """Base exception for Group-IB client failures."""


class GroupIBAuthenticationError(GroupIBClientError):
    """Authentication/authorization failure."""


class GroupIBRateLimitError(GroupIBClientError):
    """API rate-limit response."""


class GroupIBRequestError(GroupIBClientError):
    """Network, timeout, or unexpected HTTP failure."""


@dataclass(frozen=True, slots=True)
class APIResponse:
    endpoint: str
    status_code: int
    data: Any


class GroupIBClient:
    """Synchronous, thread-safe-per-instance HTTP client boundary."""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://tap.group-ib.com/api/v2/",
        timeout_seconds: float = 30.0,
    ) -> None:
        if not api_key.strip():
            raise ValueError("Group-IB API key is required.")

        self._api_key = api_key
        self._base_url = base_url.rstrip("/") + "/"
        self._timeout = httpx.Timeout(timeout_seconds)
        self._client = httpx.Client(
            timeout=self._timeout,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {api_key}",
            },
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GroupIBClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _get(self, endpoint: str, params: dict[str, Any] | None = None) -> APIResponse:
        normalized = endpoint.strip("/")
        try:
            response = self._client.get(f"{self._base_url}{normalized}", params=params)
        except httpx.TimeoutException as exc:
            raise GroupIBRequestError("Group-IB request timed out.") from exc
        except httpx.HTTPError as exc:
            raise GroupIBRequestError("Group-IB request failed.") from exc

        if response.status_code in (401, 403):
            raise GroupIBAuthenticationError("Group-IB authentication was rejected.")
        if response.status_code == 429:
            raise GroupIBRateLimitError("Group-IB API rate limit was reached.")
        if response.is_error:
            raise GroupIBRequestError(
                f"Group-IB API returned HTTP {response.status_code}."
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise GroupIBRequestError("Group-IB returned invalid JSON.") from exc

        return APIResponse(normalized, response.status_code, data)

    def get_compromised_accounts(
        self, params: dict[str, Any] | None = None
    ) -> APIResponse:
        return self._get("compromised/accounts", params)

    def get_compromised_stealers(
        self, params: dict[str, Any] | None = None
    ) -> APIResponse:
        return self._get("compromised/stealers", params)
