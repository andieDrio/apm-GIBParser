"""Application configuration and secret handling.

Secrets are never written to source-controlled files or emitted by this module.
The current baseline keeps configuration in memory; persistent secure settings
can be added behind this boundary without coupling the UI to storage.
"""

from __future__ import annotations

from dataclasses import dataclass
import os

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True, slots=True)
class AppConfig:
    api_key: str = ""
    target_domain: str = ""
    api_base_url: str = "https://tap.group-ib.com/api/v2/"
    request_timeout_seconds: float = 30.0

    @classmethod
    def from_environment(cls) -> "AppConfig":
        return cls(
            api_key=os.getenv("GROUP_IB_API_KEY", ""),
            target_domain=os.getenv("GROUP_IB_TARGET_DOMAIN", ""),
            api_base_url=os.getenv(
                "GROUP_IB_API_BASE_URL",
                "https://tap.group-ib.com/api/v2/",
            ),
        )

    def masked_api_key(self) -> str:
        if not self.api_key:
            return ""
        if len(self.api_key) <= 8:
            return "*" * len(self.api_key)
        return f"{self.api_key[:4]}{'*' * (len(self.api_key) - 8)}{self.api_key[-4:]}"
