"""
Configuration loading for the steelman SOC agent.

Reads from environment variables (or a .env file if python-dotenv is
available). Provides a single typed Settings object the rest of the
codebase consumes.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv_if_present() -> None:
    """Best-effort .env loader. Skips silently if python-dotenv is missing."""
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    for candidate in (Path.cwd() / ".env", Path(__file__).parent.parent.parent / ".env"):
        if candidate.exists():
            load_dotenv(candidate, override=False)
            return


def _get_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _get_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # Mode
    mock_mode: bool
    """If True, use the mock Splunk client with built-in sample data."""

    # Splunk connection (only needed when mock_mode is False)
    splunk_host: str
    splunk_port: int
    splunk_scheme: str
    splunk_username: str | None
    splunk_password: str | None
    splunk_token: str | None
    splunk_verify_ssl: bool
    splunk_app: str

    # Agent behaviour
    search_result_limit: int
    """Maximum number of result rows returned from any SPL search."""

    memory_db_path: Path
    """Where to store the SQLite verdict memory."""

    log_level: str

    @property
    def has_splunk_credentials(self) -> bool:
        return bool(self.splunk_token) or bool(self.splunk_username and self.splunk_password)


def load_settings() -> Settings:
    _load_dotenv_if_present()

    mock_mode = _get_bool("DEEPERSPLUNK_MOCK_MODE", default=False)

    splunk_host = os.environ.get("SPLUNK_HOST", "localhost")
    splunk_port = _get_int("SPLUNK_PORT", 8089)
    splunk_scheme = os.environ.get("SPLUNK_SCHEME", "https")
    splunk_username = os.environ.get("SPLUNK_USERNAME") or None
    splunk_password = os.environ.get("SPLUNK_PASSWORD") or None
    splunk_token = os.environ.get("SPLUNK_TOKEN") or None
    splunk_verify_ssl = _get_bool("SPLUNK_VERIFY_SSL", default=True)
    splunk_app = os.environ.get("SPLUNK_APP", "search")

    search_result_limit = _get_int("DEEPERSPLUNK_SEARCH_LIMIT", 100)

    memory_db_path_raw = os.environ.get(
        "DEEPERSPLUNK_MEMORY_DB",
        str(Path.home() / ".deepersplunk" / "memory.sqlite3"),
    )
    memory_db_path = Path(memory_db_path_raw)

    log_level = os.environ.get("DEEPERSPLUNK_LOG_LEVEL", "INFO").upper()

    # If no credentials are provided and mock mode wasn't explicitly set,
    # fall back to mock mode so the server is immediately usable.
    settings = Settings(
        mock_mode=mock_mode,
        splunk_host=splunk_host,
        splunk_port=splunk_port,
        splunk_scheme=splunk_scheme,
        splunk_username=splunk_username,
        splunk_password=splunk_password,
        splunk_token=splunk_token,
        splunk_verify_ssl=splunk_verify_ssl,
        splunk_app=splunk_app,
        search_result_limit=search_result_limit,
        memory_db_path=memory_db_path,
        log_level=log_level,
    )

    if not settings.mock_mode and not settings.has_splunk_credentials:
        # No real creds provided; auto-enable mock mode.
        return Settings(
            **{**settings.__dict__, "mock_mode": True}
        )

    return settings
