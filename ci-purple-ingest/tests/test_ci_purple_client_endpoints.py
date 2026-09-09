"""
Contract tests for `ci_purple_client.py`'s authenticated endpoints (ingest submit/status/result/
retry against the frozen fixtures) and `wait_for_terminal`'s polling/auto-retry/timeout
orchestration. Split out of `test_ci_purple_client.py` (Copilot review finding - that file was 571
LOC, over `.agent/rules/02-modularity.md`'s 500-LOC file limit); shared
`FakeResponse`/`make_client_config` now live in `conftest.py`. The HTTP layer is mocked throughout
(`unittest.mock`, stdlib) - no live Phoenix instance is required or contacted.
"""

import time

import pytest

import ci_purple_client
from conftest import FakeResponse, load_fixture, make_client_config

# ── ingest submit / status / result / retry (frozen fixtures) ──────────────────────────────


def _manager_with_fixed_token(cfg, session):
    manager = ci_purple_client.CiPurpleTokenManager(cfg, session)
    manager._token = "phx_at_fixed_test_token"
    manager._expires_at_epoch = time.time() + 3600
    return manager


def test_submit_ingest_new(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    fixture = load_fixture("response-202-new.json")
    monkeypatch.setattr(session, "request", lambda method, url, **kw: FakeResponse(202, fixture))
    manager = _manager_with_fixed_token(cfg, session)
    result = ci_purple_client.submit_ingest(cfg, session, manager, {"gitRemoteUrl": "x"})
    assert result == fixture
    assert result["duplicate"] is False


def test_submit_ingest_duplicate(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    fixture = load_fixture("response-202-duplicate.json")
    monkeypatch.setattr(session, "request", lambda method, url, **kw: FakeResponse(202, fixture))
    manager = _manager_with_fixed_token(cfg, session)
    result = ci_purple_client.submit_ingest(cfg, session, manager, {"gitRemoteUrl": "x"})
    assert result["duplicate"] is True
    assert result["status"] == "QUEUED"


def test_submit_ingest_remints_on_401(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    calls = {"n": 0}

    def fake_request(method, url, **kwargs):
        calls["n"] += 1
        if url.endswith(ci_purple_client.TOKEN_MINT_PATH):
            return FakeResponse(200, {"token": "phx_at_new", "expiresAt": "2099-01-01T00:00:00Z", "purpose": "CI_INGEST"})
        if calls["n"] == 1:
            return FakeResponse(401, {"code": "unauthorized", "message": "expired", "retryable": False})
        return FakeResponse(202, load_fixture("response-202-new.json"))

    monkeypatch.setattr(session, "request", fake_request)
    manager = _manager_with_fixed_token(cfg, session)
    result = ci_purple_client.submit_ingest(cfg, session, manager, {"gitRemoteUrl": "x"})
    assert result["jobId"] == load_fixture("response-202-new.json")["jobId"]


def test_submit_ingest_error_never_contains_secret(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    fixture = load_fixture("response-422-conditional-field.json")
    monkeypatch.setattr(session, "request", lambda method, url, **kw: FakeResponse(422, fixture))
    manager = _manager_with_fixed_token(cfg, session)
    with pytest.raises(ci_purple_client.CiPurpleApiError) as excinfo:
        ci_purple_client.submit_ingest(cfg, session, manager, {"gitRemoteUrl": "x"})
    assert excinfo.value.code == "invalid_input"
    message = str(excinfo.value)
    assert cfg.api_key not in message
    assert manager._token not in message


@pytest.mark.parametrize(
    "fixture_name",
    [
        "status-queued.json",
        "status-running.json",
        "status-succeeded.json",
        "status-degraded.json",
        "status-failed-retryable.json",
        "status-failed-terminal.json",
    ],
)
def test_get_status_all_frozen_shapes(monkeypatch, fixture_name):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    fixture = load_fixture(fixture_name)
    monkeypatch.setattr(session, "request", lambda method, url, **kw: FakeResponse(200, fixture))
    manager = _manager_with_fixed_token(cfg, session)
    result = ci_purple_client.get_status(cfg, session, manager, fixture["jobId"])
    assert result == fixture


def test_get_status_not_found(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    fixture = load_fixture("response-404-foreign-workspace.json")
    monkeypatch.setattr(session, "request", lambda method, url, **kw: FakeResponse(404, fixture))
    manager = _manager_with_fixed_token(cfg, session)
    with pytest.raises(ci_purple_client.CiPurpleApiError) as excinfo:
        ci_purple_client.get_status(cfg, session, manager, "unknown-job")
    assert excinfo.value.status_code == 404
    assert excinfo.value.code == "workspace_not_found"


def test_get_result_succeeded(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    status = load_fixture("status-succeeded.json")
    monkeypatch.setattr(session, "request", lambda method, url, **kw: FakeResponse(200, status["result"]))
    manager = _manager_with_fixed_token(cfg, session)
    result = ci_purple_client.get_result(cfg, session, manager, status["jobId"])
    assert result == status["result"]
    assert result["verdict"] == "PASS"


def test_get_result_not_ready_409(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    body = {"code": "result_not_ready", "message": "not terminal yet", "field": None, "retryable": False}
    monkeypatch.setattr(session, "request", lambda method, url, **kw: FakeResponse(409, body))
    manager = _manager_with_fixed_token(cfg, session)
    with pytest.raises(ci_purple_client.CiPurpleApiError) as excinfo:
        ci_purple_client.get_result(cfg, session, manager, "job-1")
    assert excinfo.value.status_code == 409
    assert excinfo.value.code == "result_not_ready"


def test_retry_job_accepted(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    status_after_retry = load_fixture("status-queued.json")
    monkeypatch.setattr(session, "request", lambda method, url, **kw: FakeResponse(202, status_after_retry))
    manager = _manager_with_fixed_token(cfg, session)
    result = ci_purple_client.retry_job(cfg, session, manager, "job-1")
    assert result["status"] == "QUEUED"


def test_retry_job_rejected_409(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    body = {"code": "retry_not_eligible", "message": "not FAILED", "field": None, "retryable": False}
    monkeypatch.setattr(session, "request", lambda method, url, **kw: FakeResponse(409, body))
    manager = _manager_with_fixed_token(cfg, session)
    with pytest.raises(ci_purple_client.CiPurpleApiError) as excinfo:
        ci_purple_client.retry_job(cfg, session, manager, "job-1")
    assert excinfo.value.code == "retry_not_eligible"


# ── wait_for_terminal orchestration ─────────────────────────────────────────────────────────


def test_wait_for_terminal_success(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    sequence = [load_fixture("status-queued.json"), load_fixture("status-running.json"), load_fixture("status-succeeded.json")]

    def fake_request(method, url, **kwargs):
        if url.endswith("/result"):
            raise AssertionError("get_result should not be called by wait_for_terminal itself")
        return FakeResponse(200, sequence.pop(0))

    monkeypatch.setattr(session, "request", fake_request)
    monkeypatch.setattr(ci_purple_client.time, "sleep", lambda s: None)
    manager = _manager_with_fixed_token(cfg, session)
    observed = []
    result = ci_purple_client.wait_for_terminal(
        cfg, session, manager, "job-1", poll_interval_seconds=0, wait_timeout_seconds=10, on_status=observed.append
    )
    assert result["status"] == "SUCCEEDED"
    assert [o["status"] for o in observed] == ["QUEUED", "RUNNING", "SUCCEEDED"]


def test_wait_for_terminal_auto_retries_retryable_failure_then_succeeds(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    failed = load_fixture("status-failed-retryable.json")
    queued_after_retry = load_fixture("status-queued.json")
    succeeded = load_fixture("status-succeeded.json")
    status_sequence = [failed, queued_after_retry, succeeded]
    retry_calls = {"n": 0}

    def fake_request(method, url, **kwargs):
        if url.endswith("/retry"):
            retry_calls["n"] += 1
            return FakeResponse(202, queued_after_retry)
        return FakeResponse(200, status_sequence.pop(0))

    monkeypatch.setattr(session, "request", fake_request)
    monkeypatch.setattr(ci_purple_client.time, "sleep", lambda s: None)
    manager = _manager_with_fixed_token(cfg, session)
    result = ci_purple_client.wait_for_terminal(
        cfg, session, manager, failed["jobId"], poll_interval_seconds=0, wait_timeout_seconds=10
    )
    assert result["status"] == "SUCCEEDED"
    assert retry_calls["n"] == 1


def test_wait_for_terminal_does_not_retry_non_retryable_failure(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    failed = load_fixture("status-failed-terminal.json")
    monkeypatch.setattr(session, "request", lambda method, url, **kw: FakeResponse(200, failed))
    manager = _manager_with_fixed_token(cfg, session)
    result = ci_purple_client.wait_for_terminal(cfg, session, manager, failed["jobId"], poll_interval_seconds=0, wait_timeout_seconds=10)
    assert result["status"] == "FAILED"
    assert result["failureCategory"] == "INVALID_INPUT"


def test_wait_for_terminal_stops_job_retries_at_ceiling(monkeypatch):
    """Never exceeds MAX_JOB_RETRY_ATTEMPTS (4) job-level retries. This is ONE LESS than the
    server's own cumulative SbomJobQueueRepository.MAX_ATTEMPTS (5) - I-1 fix round: the initial
    submit already spent attempt 1 server-side, so a client ceiling of 5 retry CALLS would bring
    attempts to 5 after the 4th retry (AT the fence) and issue a 5th call the server evaluates as
    `attempts(5) < maxAttempts(5)` (false) and rejects 409 retry_attempts_exhausted. See
    ci_purple_client.MAX_JOB_RETRY_ATTEMPTS's own comment."""
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    failed = load_fixture("status-failed-retryable.json")
    retry_calls = {"n": 0}

    def fake_request(method, url, **kwargs):
        if url.endswith("/retry"):
            retry_calls["n"] += 1
            return FakeResponse(202, failed)
        return FakeResponse(200, failed)  # always comes back FAILED+retryable

    monkeypatch.setattr(session, "request", fake_request)
    monkeypatch.setattr(ci_purple_client.time, "sleep", lambda s: None)
    manager = _manager_with_fixed_token(cfg, session)
    result = ci_purple_client.wait_for_terminal(cfg, session, manager, failed["jobId"], poll_interval_seconds=0, wait_timeout_seconds=10)
    # The loop STOPS after exhausting its own budget and RETURNS the FAILED status payload - it
    # does not raise, and it never asked the server whether attempt 5 would have been accepted.
    assert result["status"] == "FAILED"
    assert retry_calls["n"] == 4
    assert retry_calls["n"] == ci_purple_client.MAX_JOB_RETRY_ATTEMPTS


def test_wait_for_terminal_never_issues_the_call_the_server_would_409(monkeypatch):
    """I-1 regression guard: simulates the SERVER's own cumulative-attempts fence
    (SbomJobQueueRepository.MAX_ATTEMPTS = 5, retryIfFencedFailed's `attempts < maxAttempts`) and
    asserts the client's job-retry loop never reaches the call that fence would reject. If
    MAX_JOB_RETRY_ATTEMPTS ever regresses back to 5 (or higher), this test fails with a 409 raised
    from wait_for_terminal instead of a clean FAILED return."""
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    failed = load_fixture("status-failed-retryable.json")
    # Attempt 1 was already spent by the (unmodelled) initial submit, per the server's own
    # accounting - see MAX_JOB_RETRY_ATTEMPTS's comment.
    server_attempts = {"n": 1}
    SERVER_MAX_ATTEMPTS = 5

    def fake_request(method, url, **kwargs):
        if url.endswith("/retry"):
            if server_attempts["n"] >= SERVER_MAX_ATTEMPTS:
                return FakeResponse(
                    409,
                    {"code": "retry_attempts_exhausted", "message": "exhausted", "field": None, "retryable": False},
                )
            server_attempts["n"] += 1
            return FakeResponse(202, failed)
        return FakeResponse(200, failed)

    monkeypatch.setattr(session, "request", fake_request)
    monkeypatch.setattr(ci_purple_client.time, "sleep", lambda s: None)
    manager = _manager_with_fixed_token(cfg, session)
    # Must NOT raise CiPurpleApiError(409, "retry_attempts_exhausted", ...) - the client's own
    # ceiling must stop it one call before the server's fence would fire.
    result = ci_purple_client.wait_for_terminal(cfg, session, manager, failed["jobId"], poll_interval_seconds=0, wait_timeout_seconds=10)
    assert result["status"] == "FAILED"
    assert server_attempts["n"] == SERVER_MAX_ATTEMPTS  # exactly at the fence, never past it


def test_wait_for_terminal_timeout(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    running = load_fixture("status-running.json")
    monkeypatch.setattr(session, "request", lambda method, url, **kw: FakeResponse(200, running))

    clock = {"t": 0.0}
    monkeypatch.setattr(ci_purple_client.time, "time", lambda: clock["t"])

    def fake_sleep(seconds):
        clock["t"] += seconds + 1  # advance past the deadline quickly

    monkeypatch.setattr(ci_purple_client.time, "sleep", fake_sleep)
    manager = _manager_with_fixed_token(cfg, session)
    with pytest.raises(TimeoutError):
        ci_purple_client.wait_for_terminal(cfg, session, manager, running["jobId"], poll_interval_seconds=1, wait_timeout_seconds=2)


# ── non-JSON success body (proxy/WAF interception) ───────────────────────────────────────────


def test_submit_ingest_non_json_202_raises_handled_api_error(monkeypatch):
    """Regression: a `202` whose body is not JSON (a proxy, WAF or SSO portal answering in place
    of Phoenix - a supported deployment shape, since this client honours HTTPS_PROXY/--ca-bundle)
    used to let `requests`' `json.JSONDecodeError` escape as a `ValueError`. The CLI catches only
    `CiPurpleApiError`/`TimeoutError` and has no top-level `except Exception`, so that produced a
    raw traceback instead of the documented exit code."""
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    monkeypatch.setattr(session, "request", lambda method, url, **kw: FakeResponse(202, None, text="<html>407 proxy</html>"))
    manager = _manager_with_fixed_token(cfg, session)

    with pytest.raises(ci_purple_client.CiPurpleApiError) as excinfo:
        ci_purple_client.submit_ingest(cfg, session, manager, {"gitRemoteUrl": "x"})

    assert excinfo.value.code == "invalid_response_body"
    assert not isinstance(excinfo.value, ValueError)


def test_get_status_non_json_200_raises_handled_api_error(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    monkeypatch.setattr(session, "request", lambda method, url, **kw: FakeResponse(200, None, text="not json"))
    manager = _manager_with_fixed_token(cfg, session)

    with pytest.raises(ci_purple_client.CiPurpleApiError) as excinfo:
        ci_purple_client.get_status(cfg, session, manager, "job-1")
    assert excinfo.value.code == "invalid_response_body"


# ── --wait-timeout-seconds actually bounds the run ───────────────────────────────────────────


def test_poll_budget_leaves_a_generous_deadline_untouched():
    """Normal retry behaviour must be preserved when there is plenty of time left."""
    cfg = make_client_config(timeout_seconds=60, max_retry_attempts=5, retry_max_delay_seconds=30.0)
    budget = ci_purple_client._poll_budget(cfg, 3600.0)
    assert (budget.timeout_seconds, budget.max_retry_attempts, budget.retry_max_delay_seconds) == (60, 5, 30.0)


def test_poll_budget_still_allows_exactly_one_short_attempt_when_expired():
    """An already-expired deadline must not yield a zero/negative request timeout (which `requests`
    rejects) nor zero attempts - one short attempt runs so the caller sees a real status or error."""
    cfg = make_client_config(timeout_seconds=60, max_retry_attempts=5, retry_max_delay_seconds=30.0)
    budget = ci_purple_client._poll_budget(cfg, -5.0)
    assert budget.timeout_seconds >= 1
    assert budget.max_retry_attempts == 1


def test_wait_for_terminal_bounds_each_poll_by_the_remaining_deadline(monkeypatch):
    """Regression: `wait_for_terminal` consults its deadline only AFTER `get_status` returns, and
    `request_with_retry`'s per-attempt timeouts and backoff sleeps are invisible to that check. At
    the CLI defaults one degraded poll could burn 5x60s + 4x30s ~= 7 minutes before the deadline
    was read, so `--wait-timeout-seconds` did not bound the run."""
    cfg = make_client_config(timeout_seconds=60, max_retry_attempts=5, retry_max_delay_seconds=30.0)
    session = ci_purple_client.build_session(cfg)
    manager = _manager_with_fixed_token(cfg, session)
    seen = []

    def fake_get_status(poll_cfg, *_args, **_kwargs):
        seen.append(poll_cfg)
        return load_fixture("status-succeeded.json")

    monkeypatch.setattr(ci_purple_client, "get_status", fake_get_status)
    ci_purple_client.wait_for_terminal(cfg, session, manager, "job-1", poll_interval_seconds=0, wait_timeout_seconds=3)

    assert len(seen) == 1
    budget = seen[0]
    assert budget.timeout_seconds <= 3
    assert budget.retry_max_delay_seconds <= 3
    worst_case = budget.max_retry_attempts * (budget.timeout_seconds + budget.retry_max_delay_seconds)
    assert worst_case < 60, "one poll may still cost {}s against a 3s wait window".format(worst_case)
    assert budget.api_key == cfg.api_key and budget.api_base_url == cfg.api_base_url

