"""Verified Group-IB TI provider client.

Implements only the runtime contract verified by the bounded probe:
- Basic authentication with the TI web-interface email and Personal API token.
- GET /compromised/account_group/updated
- limit parameter
- sequence cursor from /sequence_list
- seqUpdate pagination on /compromised/account_group/updated
- object response with count, seqUpdate and items.

The daily path starts from a verified sequence cursor and walks forward through the updated feed so the first 500 records returned by an un-cursored request cannot hide newer records.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

import httpx

DEFAULT_BASE_URL = "https://tap.group-ib.com/api/v2/"
COMPROMISED_ACCOUNT_UPDATED_PATH = "compromised/account_group/updated"
SEQUENCE_LIST_PATH = "sequence_list"


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

    def get_compromised_account_updates(
        self,
        *,
        limit: int = 100,
        sequence_date: str | None = None,
    ) -> GroupIBResponse:
        """Retrieve the latest updated-account records from a sequence cursor."""
        if not 1 <= limit <= 500:
            raise ValueError("Group-IB retrieval limit must be between 1 and 500.")
        if sequence_date is None:
            raise ValueError("sequence_date is required for latest-data retrieval.")
        if len(sequence_date) != 10:
            raise ValueError("sequence_date must use YYYY-MM-DD format.")

        sequence_url = f"{self._base_url}{SEQUENCE_LIST_PATH}"
        try:
            sequence_response = self._client.get(
                sequence_url,
                params={
                    "date": sequence_date,
                    "collection": "compromised/account_group",
                },
            )
        except httpx.TimeoutException as exc:
            raise GroupIBRequestError("Group-IB sequence request timed out.") from exc
        except httpx.HTTPError as exc:
            raise GroupIBRequestError("Group-IB sequence request failed.") from exc

        self._raise_for_status(sequence_response)
        try:
            sequence_payload = sequence_response.json()
        except ValueError as exc:
            raise GroupIBSchemaError("Group-IB sequence response was invalid JSON.") from exc
        sequence_update = self._parse_sequence_update(sequence_payload)

        all_items: list[Mapping[str, Any]] = []
        last_sequence_update = sequence_update
        while True:
            page = self._get_updated_page(
                limit=limit,
                seq_update=last_sequence_update,
            )
            all_items.extend(page.items)
            if not page.items or page.count <= 0:
                break
            if page.seq_update <= last_sequence_update:
                raise GroupIBSchemaError("Group-IB sequence cursor did not advance.")
            last_sequence_update = page.seq_update

        return GroupIBResponse(
            count=len(all_items),
            seq_update=last_sequence_update,
            items=tuple(all_items),
        )

    def _get_updated_page(self, *, limit: int, seq_update: int) -> GroupIBResponse:
        url = f"{self._base_url}{COMPROMISED_ACCOUNT_UPDATED_PATH}"
        try:
            response = self._client.get(
                url,
                params={"limit": limit, "seqUpdate": seq_update},
            )
        except httpx.TimeoutException as exc:
            raise GroupIBRequestError("Group-IB request timed out.") from exc
        except httpx.HTTPError as exc:
            raise GroupIBRequestError("Group-IB request failed.") from exc

        self._raise_for_status(response)
        try:
            payload = response.json()
        except ValueError as exc:
            raise GroupIBSchemaError("Group-IB returned invalid JSON.") from exc
        return self._parse_response(payload)

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
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

    @staticmethod
    def _parse_sequence_update(payload: Any) -> int:
        if isinstance(payload, dict):
            value = payload.get("seqUpdate")
            if isinstance(value, int) and not isinstance(value, bool):
                return value
        if isinstance(payload, list) and payload:
            value = payload[0].get("seqUpdate") if isinstance(payload[0], dict) else None
            if isinstance(value, int) and not isinstance(value, bool):
                return value
        raise GroupIBSchemaError("Group-IB sequence response has no valid seqUpdate.")

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
