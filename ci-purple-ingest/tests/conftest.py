"""
Shared pytest fixtures for the CI-PURPLE ingest client's contract tests.

Adds the package directory to `sys.path` so the four sibling modules under test
(`ci_context.py`, `ci_purple_sbom.py`, `ci_purple_client.py`,
`ci_purple_sbom_to_phoenix.py`) import the same way they do when deployed together in CI, per
this tool's own "deploy these files together" convention (matching sbom-single-repo's).

`FakeResponse`/`make_client_config`/`_future_iso8601`/the `_no_real_sleep` autouse fixture below
were moved here from `test_ci_purple_client.py` when that file was split into
`test_ci_purple_client_token.py`/`_transport.py`/`_endpoints.py` (Copilot review finding - the
single file was 571 LOC, over `.agent/rules/02-modularity.md`'s 500-LOC file limit) - they are
shared by all three of the split files.
"""

import datetime
import json
import os
import sys

_PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACKAGE_DIR not in sys.path:
    sys.path.insert(0, _PACKAGE_DIR)

import pytest

import ci_purple_client

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def load_fixture(name: str):
    """Load one of the frozen server-contract fixtures copied verbatim from
    `code-analyzer-service/docs/openapi/ci-ingest-examples/` in the agent-code-analyzer-r2 repo
    (design Sec 3.1 / Task 1 fixtures) - see task-8-report.md for the re-verification note."""
    with open(os.path.join(FIXTURES_DIR, name), "r", encoding="utf-8") as handle:
        return json.load(handle)


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


def make_client_config(**overrides):
    defaults = dict(
        api_base_url="https://api.securityphoenix.cloud",
        api_key="phx_live_test_secret_should_never_appear_in_output",
        verify_tls=True,
        allow_insecure_http=False,
        timeout_seconds=5,
        max_retry_attempts=3,
        retry_base_delay_seconds=0.001,  # keep the suite fast; see also the sleep monkeypatch below
        retry_max_delay_seconds=0.002,
    )
    defaults.update(overrides)
    return ci_purple_client.CiPurpleConfig(**defaults)


class FakeResponse:
    def __init__(self, status_code, json_body=None, headers=None, text=None):
        self.status_code = status_code
        self._json_body = json_body
        self.headers = headers or {}
        self.text = text if text is not None else ("" if json_body is None else "{}")
        self.content = self.text.encode("utf-8")  # real `requests.Response.content` is bytes
        self.reason = "status {}".format(status_code)

    def json(self):
        if self._json_body is None:
            raise ValueError("no json body")
        return self._json_body


@pytest.fixture(autouse=True)
def _no_real_sleep(monkeypatch):
    """Every retry-path test using `ci_purple_client` in this suite uses a base delay of ~0ms, but
    patch `time.sleep` anyway so a real Retry-After value (e.g. "1") in a fixture cannot make the
    suite slow. Autouse and global (not just in the `ci_purple_client_*` files) is harmless: for
    test files that never call into `ci_purple_client`, this patches a module they never touch."""
    monkeypatch.setattr(ci_purple_client.time, "sleep", lambda seconds: None)


def _future_iso8601(seconds_from_now):
    dt = datetime.datetime.utcnow() + datetime.timedelta(seconds=seconds_from_now)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
