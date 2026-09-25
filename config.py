"""Application configuration and secret handling."""

from __future__ import annotations

from dataclasses import dataclass
import os

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True, slots=True)
class AppConfig:
    username: str = ""
    api_token: str = ""
    target_domain: str = ""
    api_base_url: str = "https://tap.group-ib.com/api/v2/"
    request_timeout_seconds: float = 30.0

    @classmethod
    def from_environment(cls) -> "AppConfig":
        return cls(
            username=os.getenv("GROUP_IB_USERNAME", "").strip(),
            api_token=(
                os.getenv("GROUP_IB_API_TOKEN", "").strip()
                or os.getenv("GROUP_IB_API_KEY", "").strip()
            ),
            target_domain=os.getenv("GROUP_IB_TARGET_DOMAIN", "").strip(),
            api_base_url=os.getenv(
                "GROUP_IB_API_BASE_URL",
                "https://tap.group-ib.com/api/v2/",
            ).strip(),
        )

    def has_credentials(self) -> bool:
        return bool(self.username and self.api_token)

    def masked_api_token(self) -> str:
        if not self.api_token:
            return ""
        if len(self.api_token) <= 8:
            return "*" * len(self.api_token)
        return f"{self.api_token[:4]}{'*' * (len(self.api_token) - 8)}{self.api_token[-4:]}"
