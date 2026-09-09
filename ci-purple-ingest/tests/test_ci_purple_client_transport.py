"""
Contract tests for `ci_purple_client.request_with_retry`: transport-level retry (backoff,
`Retry-After` honoured exactly, non-retryable statuses not retried, network-error exhaustion).
Split out of `test_ci_purple_client.py` (Copilot review finding - that file was 571 LOC, over
`.agent/rules/02-modularity.md`'s 500-LOC file limit); shared `FakeResponse`/`make_client_config`
now live in `conftest.py`. The HTTP layer is mocked throughout (`unittest.mock`, stdlib) - no live
Phoenix instance is required or contacted.
"""

import pytest
import requests

import ci_purple_client
from conftest import FakeResponse, make_client_config


def test_request_with_retry_succeeds_after_transient_500(monkeypatch):
    cfg = make_client_config(max_retry_attempts=3)
    session = ci_purple_client.build_session(cfg)
    responses = [FakeResponse(500, text="upstream hiccup"), FakeResponse(200, {"ok": True})]

    def fake_request(method, url, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(session, "request", fake_request)
    response = ci_purple_client.request_with_retry(session, cfg, "GET", "https://example.com")
    assert response.status_code == 200


def test_request_with_retry_honors_retry_after_header(monkeypatch):
    # retry_max_delay_seconds raised above the honoured value (1s) so M-2's clamp does not fire -
    # this test is specifically about "exact value, not a computed backoff", not about clamping;
    # see test_request_with_retry_clamps_oversized_retry_after below for the clamp itself.
    cfg = make_client_config(max_retry_attempts=2, retry_max_delay_seconds=30.0)
    session = ci_purple_client.build_session(cfg)
    responses = [FakeResponse(429, headers={"Retry-After": "1"}), FakeResponse(200, {"ok": True})]
    sleep_calls = []

    def fake_request(method, url, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(session, "request", fake_request)
    monkeypatch.setattr(ci_purple_client.time, "sleep", lambda seconds: sleep_calls.append(seconds))
    response = ci_purple_client.request_with_retry(session, cfg, "GET", "https://example.com")
    assert response.status_code == 200
    # Retry-After was honoured EXACTLY (1 second), not replaced with a computed exponential value.
    assert sleep_calls == [1.0]


def test_request_with_retry_clamps_oversized_retry_after(monkeypatch, capsys):
    """M-2 regression guard: a Retry-After far larger than retry_max_delay_seconds (an intermediary
    proxy/WAF value, not one Phoenix itself would send) must be CLAMPED, with a Warning logged -
    otherwise it sleeps outside wait_for_terminal's own deadline check and --wait-timeout-seconds
    stops actually bounding the run."""
    cfg = make_client_config(max_retry_attempts=2, retry_max_delay_seconds=5.0)
    session = ci_purple_client.build_session(cfg)
    responses = [FakeResponse(429, headers={"Retry-After": "3600"}), FakeResponse(200, {"ok": True})]
    sleep_calls = []

    def fake_request(method, url, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(session, "request", fake_request)
    monkeypatch.setattr(ci_purple_client.time, "sleep", lambda seconds: sleep_calls.append(seconds))
    response = ci_purple_client.request_with_retry(session, cfg, "GET", "https://example.com")
    assert response.status_code == 200
    assert sleep_calls == [5.0]  # clamped to retry_max_delay_seconds, not the raw 3600
    assert "clamped" in capsys.readouterr().err


def test_request_with_retry_does_not_retry_422(monkeypatch):
    cfg = make_client_config(max_retry_attempts=3)
    session = ci_purple_client.build_session(cfg)
    call_count = {"n": 0}

    def fake_request(method, url, **kwargs):
        call_count["n"] += 1
        return FakeResponse(422, {"code": "invalid_input", "message": "bad", "retryable": False})

    monkeypatch.setattr(session, "request", fake_request)
    response = ci_purple_client.request_with_retry(session, cfg, "POST", "https://example.com")
    assert response.status_code == 422
    assert call_count["n"] == 1  # no retry spent on a non-retryable status


def test_request_with_retry_exhausts_on_network_error(monkeypatch):
    cfg = make_client_config(max_retry_attempts=2)
    session = ci_purple_client.build_session(cfg)

    def fake_request(method, url, **kwargs):
        raise requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr(session, "request", fake_request)
    with pytest.raises(ci_purple_client.CiPurpleApiError) as excinfo:
        ci_purple_client.request_with_retry(session, cfg, "GET", "https://example.com")
    assert excinfo.value.code == "transport_error"
    assert "2 attempt" in str(excinfo.value)
