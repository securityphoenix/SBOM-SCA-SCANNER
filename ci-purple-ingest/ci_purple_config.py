"""
Optional `config.ini` support for the CI-PURPLE ingest CLI.

The sibling `sbom-single-repo/` tool has carried a `config.ini` since it shipped; this module
gives `ci_purple_sbom_to_phoenix.py` the same affordance without changing its existing
flag/environment behaviour.

**Precedence, highest first** — a later source never overrides an earlier one:

1. an explicit CLI flag (`--api-base-url`, `--api-key`, ...)
2. the environment (`PHOENIX_API_BASE_URL`, `PHOENIX_API_KEY`, ...)
3. `config.ini`  (this module)
4. the built-in default (`https://api.securityphoenix.cloud`)

Config sits BELOW the environment deliberately: a CI runner injects credentials as environment
variables, and a stale `config.ini` left in a working copy must never silently take precedence
over what the pipeline supplied.

Security (`.agent/rules/05-security.md` #4): `config.ini` may hold a real API key, so it is
gitignored and only `config.ini.template` is committed. This module never logs a value it reads
from the `[auth]` section — `describe_source` reports WHICH file supplied a setting, never what
the setting was.
"""

from __future__ import annotations

import configparser
import os
from typing import Dict, Optional

DEFAULT_CONFIG_FILENAME = "config.ini"

# Every key this module will read, by section. A key outside this map is ignored rather than
# silently trusted, so a typo in a hand-edited config.ini cannot quietly become a live setting.
KNOWN_KEYS: Dict[str, tuple] = {
    "phoenix": ("api_base_url", "allow_insecure_http", "verify_tls", "ca_bundle"),
    "auth": ("api_key",),
    "ingest": ("asset_kind", "build_file_path", "workspace_id", "wait", "poll_interval_seconds"),
}

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


class CiPurpleConfigFileError(ValueError):
    """Raised when an explicitly-requested config file is missing or unparseable."""


def default_config_path() -> str:
    """`config.ini` beside this module — the sibling tool's own convention."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), DEFAULT_CONFIG_FILENAME)


def load_config(path: Optional[str] = None, *, required: bool = False) -> "CiPurpleFileConfig":
    """
    Read `path` (default: `config.ini` beside this module).

    `required=True` (the caller passed `--config`) turns a missing file into an error; the
    implicit default path is allowed to be absent, which is the normal case in CI.
    """
    resolved = os.path.abspath(path or default_config_path())
    if not os.path.isfile(resolved):
        if required:
            raise CiPurpleConfigFileError("config file not found: {}".format(resolved))
        return CiPurpleFileConfig(path=None, values={})

    parser = configparser.ConfigParser()
    try:
        with open(resolved, encoding="utf-8") as handle:
            parser.read_file(handle)
    except (configparser.Error, OSError) as exc:
        raise CiPurpleConfigFileError("could not parse {}: {}".format(resolved, exc))

    values: Dict[str, str] = {}
    for section, keys in KNOWN_KEYS.items():
        if not parser.has_section(section):
            continue
        for key in keys:
            if parser.has_option(section, key):
                raw = parser.get(section, key).strip()
                if raw:
                    values[key] = raw
    return CiPurpleFileConfig(path=resolved, values=values)


class CiPurpleFileConfig:
    """Parsed `config.ini` values. Absent file == empty mapping, never an error."""

    def __init__(self, path: Optional[str], values: Dict[str, str]) -> None:
        self.path = path
        self._values = values

    def get(self, key: str) -> Optional[str]:
        return self._values.get(key)

    def get_bool(self, key: str) -> Optional[bool]:
        """`None` when unset; raises on a value that is neither truthy nor falsy."""
        raw = self._values.get(key)
        if raw is None:
            return None
        lowered = raw.strip().lower()
        if lowered in _TRUE:
            return True
        if lowered in _FALSE:
            return False
        raise CiPurpleConfigFileError(
            "config key {!r} must be one of {} / {}, got {!r}".format(
                key, "/".join(sorted(_TRUE)), "/".join(sorted(_FALSE)), raw
            )
        )

    def get_int(self, key: str) -> Optional[int]:
        raw = self._values.get(key)
        if raw is None:
            return None
        try:
            return int(raw)
        except ValueError:
            raise CiPurpleConfigFileError("config key {!r} must be an integer, got {!r}".format(key, raw))

    def describe_source(self) -> str:
        """Where settings came from. Names the FILE only — never a value (rule 05 #3)."""
        if self.path is None:
            return "no config.ini (flags/environment only)"
        return "config.ini: {} ({} key(s))".format(self.path, len(self._values))

    def __len__(self) -> int:
        return len(self._values)
