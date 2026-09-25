"""Verified Group-IB TI provider client.

Implements only the runtime contract verified by the bounded probe:
- Basic authentication with the TI web-interface email and Personal API token.
- GET /compromised/account_group/updated
- limit parameter
- object response with count, seqUpdate and items.

Pagination/incremental parameters are intentionally not guessed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

import httpx

DEFAULT_BASE_URL = "https://tap.group-ib.com/api/v2/"
COMPROMISED_ACCOUNT_UPDATED_PATH = "compromised/account_group/updated"


class GroupIBClientError(Exception):
    """Base exception for Group-IB provider failures."""


class GroupIBConfigurationError(GroupIBClientError):
    """Local Group-IB configuration is missing or invalid."""


class GroupIBAuthenticationError(GroupIBClientError):
    """Group-IB rejected authentication or authorization."""


class GroupIBRateLimitError(GroupIBClientError):
    """Group-IB rate-limited the request."""


class GroupIBSchemaError(GroupIBClientError):
    """The provider response does not match the verified contract."""


class GroupIBRequestError(GroupIBClientError):
    """Network or unexpected HTTP failure."""


@dataclass(frozen=True, slots=True)
class GroupIBResponse:
    """Validated response from compromised/account_group/updated."""

    count: int
    seq_update: int
    items: tuple[Mapping[str, Any], ...]


class GroupIBClient:
    """Synchronous HTTP boundary for the verified Group-IB contract."""

    def __init__(
        self,
        username: str,
        api_token: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout_seconds: float = 30.0,
    ) -> None:
        username = username.strip()
        api_token = api_token.strip()
        if not username:
            raise GroupIBConfigurationError("Group-IB username is required.")
        if not api_token:
            raise GroupIBConfigurationError("Group-IB Personal API token is required.")
        if timeout_seconds <= 0:
            raise GroupIBConfigurationError("Group-IB timeout must be greater than zero.")

        self._base_url = base_url.strip().rstrip("/") + "/"
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout_seconds),
            auth=(username, api_token),
            headers={"Accept": "application/json"},
            follow_redirects=False,
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GroupIBClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def get_compromised_account_updates(self, *, limit: int = 100) -> GroupIBResponse:
        """Retrieve a bounded batch from the verified updated-account feed."""
        if not 1 <= limit <= 500:
            raise ValueError("Group-IB retrieval limit must be between 1 and 500.")

        url = f"{self._base_url}{COMPROMISED_ACCOUNT_UPDATED_PATH}"
        try:
            response = self._client.get(url, params={"limit": limit})
        except httpx.TimeoutException as exc:
            raise GroupIBRequestError("Group-IB request timed out.") from exc
        except httpx.HTTPError as exc:
            raise GroupIBRequestError("Group-IB request failed.") from exc

        if response.status_code in (401, 403):
            raise GroupIBAuthenticationError(
                "Group-IB authentication or authorization was rejected."
            )
        if response.status_code == 429:
            raise GroupIBRateLimitError("Group-IB API rate limit was reached.")
        if response.is_error:
            raise GroupIBRequestError(
                f"Group-IB API returned HTTP {response.status_code}."
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise GroupIBSchemaError("Group-IB returned invalid JSON.") from exc

        return self._parse_response(payload)

    @staticmethod
    def _parse_response(payload: Any) -> GroupIBResponse:
        if not isinstance(payload, dict):
            raise GroupIBSchemaError("Group-IB response must be a JSON object.")

        count = payload.get("count")
        seq_update = payload.get("seqUpdate")
        items = payload.get("items")

        if not isinstance(count, int) or isinstance(count, bool):
            raise GroupIBSchemaError("Group-IB response field 'count' must be an integer.")
        if not isinstance(seq_update, int) or isinstance(seq_update, bool):
            raise GroupIBSchemaError(
                "Group-IB response field 'seqUpdate' must be an integer."
            )
        if not isinstance(items, list):
            raise GroupIBSchemaError("Group-IB response field 'items' must be an array.")
        if not all(isinstance(item, dict) for item in items):
            raise GroupIBSchemaError("Group-IB response 'items' must contain objects.")

        return GroupIBResponse(
            count=count,
            seq_update=seq_update,
            items=tuple(items),
        )
