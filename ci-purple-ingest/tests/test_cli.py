"""
End-to-end CLI tests for `ci_purple_sbom_to_phoenix.py`, exercising exit codes (brief item 4/5)
and the full submit(+wait) flow with the HTTP layer mocked at the `requests.Session.request` level
- no live Phoenix instance is contacted.
"""

import json
import sys

import pytest

import ci_context
import ci_purple_client
import ci_purple_sbom_to_phoenix as cli
from conftest import load_fixture


class FakeResponse:
    def __init__(self, status_code, json_body=None, headers=None, text=None):
        self.status_code = status_code
        self._json_body = json_body
        self.headers = headers or {}
        self.text = text if text is not None else ("" if json_body is None else "{}")
        self.reason = "status {}".format(status_code)

    def json(self):
        if self._json_body is None:
            raise ValueError("no json body")
        return self._json_body


@pytest.fixture(autouse=True)
def _clean_ci_env(monkeypatch):
    for var in (
        "GITHUB_ACTIONS", "GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID",
        "GITHUB_HEAD_REF", "GITHUB_REF_NAME", "GITHUB_SHA", "RUNNER_NAME",
        "TF_BUILD", "BITBUCKET_BUILD_NUMBER", "JENKINS_URL", "BUILD_TAG",
        "PHOENIX_API_KEY", "PHOENIX_API_BASE_URL", "PHOENIX_CA_BUNDLE",
    ):
        monkeypatch.delenv(var, raising=False)
    # These CLI tests run inside this repo's OWN git checkout, which has a real `origin` remote -
    # `resolve_git_remote_url`/`resolve_commit_sha` prefer `git remote get-url origin`/
    # `git rev-parse HEAD` over the env vars this fixture sets (see ci_context.py's own docstring
    # on that precedence), so without this the test environment's real remote URL would leak into
    # the resolved context instead of the GITHUB_* values a test sets. Force the git fallback path
    # off so these tests exercise the env-var resolution deterministically.
    monkeypatch.setattr(ci_context, "_run_git", lambda *a, **k: None)
    yield


def _repo_sbom_path(tmp_path):
    fixture = load_fixture("request-repo-valid.json")
    path = tmp_path / "sbom.cdx.json"
    path.write_text(json.dumps(fixture["sbom"]), encoding="utf-8")
    return str(path), fixture


def test_cli_exits_2_on_bitbucket(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("BITBUCKET_BUILD_NUMBER", "1")
    sbom_path, _ = _repo_sbom_path(tmp_path)
    monkeypatch.setattr(sys, "argv", ["prog", "--sbom-file", sbom_path])
    rc = cli.main()
    assert rc == 2
    captured = capsys.readouterr()
    assert "sbom-single-repo" in captured.err
    assert "not supported" in captured.err.lower() or "not a supported" in captured.err.lower()


def test_cli_dry_run_succeeds_without_credentials(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "555")  # I-3: pipelineId is server-required
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    sbom_path, fixture = _repo_sbom_path(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "--sbom-file", sbom_path, "--build-file-path", fixture["asset"]["buildFilePath"], "--dry-run"],
    )
    rc = cli.main()
    assert rc == 0
    assert "Dry-run enabled" in capsys.readouterr().out


def test_cli_dry_run_with_payload_out(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "555")  # I-3: pipelineId is server-required
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    sbom_path, fixture = _repo_sbom_path(tmp_path)
    payload_out = tmp_path / "payload.json"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prog", "--sbom-file", sbom_path,
            "--build-file-path", fixture["asset"]["buildFilePath"],
            "--dry-run", "--payload-out", str(payload_out),
        ],
    )
    rc = cli.main()
    assert rc == 0
    written = json.loads(payload_out.read_text(encoding="utf-8"))
    assert written["gitRemoteUrl"].endswith("acme/app.git")
    assert written["asset"]["buildFilePath"] == fixture["asset"]["buildFilePath"]


def test_cli_missing_api_key_exits_1(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "555")  # I-3: pipelineId is server-required
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    sbom_path, fixture = _repo_sbom_path(tmp_path)
    monkeypatch.setattr(
        sys, "argv", ["prog", "--sbom-file", sbom_path, "--build-file-path", fixture["asset"]["buildFilePath"]]
    )
    rc = cli.main()
    assert rc == 1
    assert "PHOENIX_API_KEY" in capsys.readouterr().err


def test_cli_http_api_base_url_prints_clean_error_not_traceback(monkeypatch, tmp_path, capsys):
    """M-1 regression guard: an http:// --api-base-url without --allow-insecure-http must produce
    THIS tool's own "Error: ..." line (rc=1), never an unhandled traceback. No
    requests.Session.request mock is installed on purpose, so this also proves the rejection fires
    before any socket would be opened - a real network attempt here would hang or fail in an
    unrelated way, not match this test's assertions."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "555")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("PHOENIX_API_KEY", "phx_live_x")
    sbom_path, fixture = _repo_sbom_path(tmp_path)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prog", "--sbom-file", sbom_path,
            "--build-file-path", fixture["asset"]["buildFilePath"],
            "--api-base-url", "http://insecure.example.com",
        ],
    )
    rc = cli.main()  # must not raise - a raised ValueError here is exactly the M-1 defect
    assert rc == 1
    assert "plaintext HTTP" in capsys.readouterr().err


def test_cli_locally_invalid_sbom_exits_1_without_network(monkeypatch, tmp_path):
    """A GHSA-only vulnerability id must be caught by local pre-flight and never reach the
    network - patch session.request to explode if it is ever called."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "555")  # I-3: pipelineId is server-required
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("PHOENIX_API_KEY", "phx_live_should_never_be_used")

    fixture = load_fixture("request-repo-valid.json")
    sbom = dict(fixture["sbom"])
    sbom["vulnerabilities"] = [{"id": "GHSA-xxxx-yyyy-zzzz", "affects": [{"ref": sbom["components"][0]["bom-ref"]}]}]
    sbom_path = tmp_path / "sbom.cdx.json"
    sbom_path.write_text(json.dumps(sbom), encoding="utf-8")

    def _explode(*args, **kwargs):
        raise AssertionError("no network call should happen when local pre-flight fails")

    monkeypatch.setattr("requests.Session.request", _explode)
    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "--sbom-file", str(sbom_path), "--build-file-path", fixture["asset"]["buildFilePath"]],
    )
    rc = cli.main()
    assert rc == 1


def test_cli_full_submit_and_wait_pass(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "555")  # I-3: pipelineId is server-required
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("PHOENIX_API_KEY", "phx_live_should_never_be_printed")
    sbom_path, fixture = _repo_sbom_path(tmp_path)

    accepted = load_fixture("response-202-new.json")
    succeeded = load_fixture("status-succeeded.json")
    token_body = {"token": "phx_at_should_never_be_printed", "expiresAt": "2099-01-01T00:00:00Z", "purpose": "CI_INGEST"}

    def fake_request(self, method, url, **kwargs):
        if url.endswith(ci_purple_client.TOKEN_MINT_PATH):
            return FakeResponse(200, token_body)
        if url.endswith("/result"):
            return FakeResponse(200, succeeded["result"])
        if url.endswith("/" + accepted["jobId"]):
            return FakeResponse(200, succeeded)
        if url.endswith(ci_purple_client.INGEST_PATH):
            return FakeResponse(202, accepted)
        raise AssertionError("unexpected URL {}".format(url))

    monkeypatch.setattr("requests.Session.request", fake_request)
    monkeypatch.setattr(ci_purple_client.time, "sleep", lambda s: None)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "prog", "--sbom-file", sbom_path,
            "--build-file-path", fixture["asset"]["buildFilePath"],
            "--wait", "--poll-interval-seconds", "0",
        ],
    )
    rc = cli.main()
    assert rc == 0
    out = capsys.readouterr().out
    assert "verdict=PASS" in out


def test_cli_full_submit_and_wait_block_exits_3(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "555")  # I-3: pipelineId is server-required
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("PHOENIX_API_KEY", "phx_live_x")
    sbom_path, fixture = _repo_sbom_path(tmp_path)

    accepted = load_fixture("response-202-new.json")
    degraded = load_fixture("status-degraded.json")
    blocked_result = dict(degraded["result"])
    blocked_result["verdict"] = "BLOCK"
    token_body = {"token": "phx_at_x", "expiresAt": "2099-01-01T00:00:00Z", "purpose": "CI_INGEST"}

    def fake_request(self, method, url, **kwargs):
        if url.endswith(ci_purple_client.TOKEN_MINT_PATH):
            return FakeResponse(200, token_body)
        if url.endswith("/result"):
            return FakeResponse(200, blocked_result)
        if url.endswith("/" + accepted["jobId"]):
            return FakeResponse(200, degraded)
        if url.endswith(ci_purple_client.INGEST_PATH):
            return FakeResponse(202, accepted)
        raise AssertionError("unexpected URL {}".format(url))

    monkeypatch.setattr("requests.Session.request", fake_request)
    monkeypatch.setattr(ci_purple_client.time, "sleep", lambda s: None)
    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "--sbom-file", sbom_path, "--build-file-path", fixture["asset"]["buildFilePath"], "--wait", "--poll-interval-seconds", "0"],
    )
    rc = cli.main()
    assert rc == 3


def test_cli_submit_without_wait_exits_0(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "555")  # I-3: pipelineId is server-required
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("PHOENIX_API_KEY", "phx_live_x")
    sbom_path, fixture = _repo_sbom_path(tmp_path)

    accepted = load_fixture("response-202-new.json")
    token_body = {"token": "phx_at_x", "expiresAt": "2099-01-01T00:00:00Z", "purpose": "CI_INGEST"}

    def fake_request(self, method, url, **kwargs):
        if url.endswith(ci_purple_client.TOKEN_MINT_PATH):
            return FakeResponse(200, token_body)
        if url.endswith(ci_purple_client.INGEST_PATH):
            return FakeResponse(202, accepted)
        raise AssertionError("unexpected URL {} - --wait was not requested, nothing else should be called".format(url))

    monkeypatch.setattr("requests.Session.request", fake_request)
    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "--sbom-file", sbom_path, "--build-file-path", fixture["asset"]["buildFilePath"]],
    )
    rc = cli.main()
    assert rc == 0
    assert "jobId={}".format(accepted["jobId"]) in capsys.readouterr().out


def test_cli_never_prints_api_key_or_token(monkeypatch, tmp_path, capsys):
    """Secret-safety self-check (item 7): run a full submit+wait+FAILED(non-retryable) flow -
    the path most likely to interpolate error detail into a message - and assert neither the raw
    API key nor the minted token substring ever appears on stdout or stderr."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "555")  # I-3: pipelineId is server-required
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    raw_api_key = "phx_live_super_secret_value_12345"
    minted_token = "phx_at_super_secret_minted_67890"
    monkeypatch.setenv("PHOENIX_API_KEY", raw_api_key)
    sbom_path, fixture = _repo_sbom_path(tmp_path)

    accepted = load_fixture("response-202-new.json")
    failed_terminal = load_fixture("status-failed-terminal.json")
    token_body = {"token": minted_token, "expiresAt": "2099-01-01T00:00:00Z", "purpose": "CI_INGEST"}

    def fake_request(self, method, url, **kwargs):
        assert kwargs.get("headers", {}).get("Authorization") in (
            None, "Bearer {}".format(raw_api_key), "Bearer {}".format(minted_token)
        )
        if url.endswith(ci_purple_client.TOKEN_MINT_PATH):
            return FakeResponse(200, token_body)
        if url.endswith("/" + accepted["jobId"]):
            return FakeResponse(200, failed_terminal)
        if url.endswith(ci_purple_client.INGEST_PATH):
            return FakeResponse(202, accepted)
        raise AssertionError("unexpected URL {}".format(url))

    monkeypatch.setattr("requests.Session.request", fake_request)
    monkeypatch.setattr(ci_purple_client.time, "sleep", lambda s: None)
    monkeypatch.setattr(
        sys,
        "argv",
        ["prog", "--sbom-file", sbom_path, "--build-file-path", fixture["asset"]["buildFilePath"], "--wait", "--poll-interval-seconds", "0"],
    )
    rc = cli.main()
    assert rc == 1
    captured = capsys.readouterr()
    assert raw_api_key not in captured.out
    assert raw_api_key not in captured.err
    assert minted_token not in captured.out
    assert minted_token not in captured.err
