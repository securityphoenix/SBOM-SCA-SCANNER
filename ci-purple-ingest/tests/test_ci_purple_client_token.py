"""
Contract tests for `ci_purple_client.py`: token exchange, the M-4 nanosecond-precision-instant
parsing guard, and config/TLS. Split out of `test_ci_purple_client.py` (Copilot review finding -
that file was 571 LOC, over `.agent/rules/02-modularity.md`'s 500-LOC file limit); shared
`FakeResponse`/`make_client_config`/`_future_iso8601`/the sleep-patch fixture now live in
`conftest.py`. The HTTP layer is mocked throughout (`unittest.mock`, stdlib) - no live Phoenix
instance is required or contacted.
"""

import pytest

import ci_purple_client
from conftest import FakeResponse, _future_iso8601, make_client_config

# ── token exchange ──────────────────────────────────────────────────────────────────────────


def test_mint_token_success(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    response = FakeResponse(200, {"token": "phx_at_secret", "expiresAt": _future_iso8601(3600), "purpose": "CI_INGEST"})
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return response

    monkeypatch.setattr(session, "request", fake_request)
    manager = ci_purple_client.CiPurpleTokenManager(cfg, session)
    token = manager.get_token()
    assert token == "phx_at_secret"
    assert calls[0][0] == "POST"
    assert calls[0][1].endswith(ci_purple_client.TOKEN_MINT_PATH)
    assert calls[0][2]["headers"]["Authorization"] == "Bearer {}".format(cfg.api_key)


# ── M-4: _parse_iso8601_to_epoch nanosecond-precision-instant guard ─────────────────────────────


def test_parse_iso8601_to_epoch_accepts_nanosecond_precision():
    """The server's expiresAt is Instant.toString(), which can emit 9 fractional digits - Python
    3.7's fromisoformat only accepts 0/3/6 and would otherwise raise ValueError here."""
    epoch = ci_purple_client._parse_iso8601_to_epoch("2026-08-28T12:00:00.123456789+00:00")
    # Truncated (not rounded) to 6 digits: .123456, never .123457.
    expected = ci_purple_client._parse_iso8601_to_epoch("2026-08-28T12:00:00.123456+00:00")
    assert epoch == expected


def test_parse_iso8601_to_epoch_accepts_z_suffix_nanosecond_precision():
    epoch = ci_purple_client._parse_iso8601_to_epoch("2026-08-28T12:00:00.987654321Z")
    expected = ci_purple_client._parse_iso8601_to_epoch("2026-08-28T12:00:00.987654Z")
    assert epoch == expected


def test_parse_iso8601_to_epoch_accepts_no_fractional_seconds():
    ci_purple_client._parse_iso8601_to_epoch("2026-08-28T12:00:00Z")  # must not raise


def test_parse_iso8601_to_epoch_raises_ci_purple_api_error_on_genuine_garbage():
    with pytest.raises(ci_purple_client.CiPurpleApiError) as excinfo:
        ci_purple_client._parse_iso8601_to_epoch("not-a-timestamp-at-all")
    assert excinfo.value.code == "invalid_token_response"


def test_mint_token_succeeds_with_nanosecond_precision_expires_at(monkeypatch):
    """End-to-end: a token whose expiresAt has 9 fractional digits must mint successfully, not
    raise an unhandled traceback from inside CiPurpleTokenManager._mint."""
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    response = FakeResponse(
        200, {"token": "phx_at_ns", "expiresAt": "2099-01-01T00:00:00.123456789+00:00", "purpose": "CI_INGEST"}
    )
    monkeypatch.setattr(session, "request", lambda method, url, **kw: response)
    manager = ci_purple_client.CiPurpleTokenManager(cfg, session)
    assert manager.get_token() == "phx_at_ns"


def test_mint_token_scope_rejected_403(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    response = FakeResponse(
        403,
        {"code": "ci_ingest_scope_required", "message": "This API key is not scoped for CI ingest.", "retryable": False},
    )
    monkeypatch.setattr(session, "request", lambda method, url, **kw: response)
    manager = ci_purple_client.CiPurpleTokenManager(cfg, session)
    with pytest.raises(ci_purple_client.CiPurpleApiError) as excinfo:
        manager.get_token()
    assert excinfo.value.code == "ci_ingest_scope_required"
    assert excinfo.value.status_code == 403
    # Secret safety (item 7): the raw API key must never appear in the raised error's message.
    assert cfg.api_key not in str(excinfo.value)


def test_token_manager_reuses_valid_token(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    call_count = {"n": 0}

    def fake_request(method, url, **kwargs):
        call_count["n"] += 1
        return FakeResponse(200, {"token": "phx_at_token_{}".format(call_count["n"]), "expiresAt": _future_iso8601(3600), "purpose": "CI_INGEST"})

    monkeypatch.setattr(session, "request", fake_request)
    manager = ci_purple_client.CiPurpleTokenManager(cfg, session)
    first = manager.get_token()
    second = manager.get_token()
    assert first == second == "phx_at_token_1"
    assert call_count["n"] == 1


def test_token_manager_remints_near_expiry(monkeypatch):
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    call_count = {"n": 0}

    def fake_request(method, url, **kwargs):
        call_count["n"] += 1
        # Expires almost immediately - well within the manager's expiry margin.
        return FakeResponse(200, {"token": "phx_at_token_{}".format(call_count["n"]), "expiresAt": _future_iso8601(1), "purpose": "CI_INGEST"})

    monkeypatch.setattr(session, "request", fake_request)
    manager = ci_purple_client.CiPurpleTokenManager(cfg, session)
    first = manager.get_token()
    second = manager.get_token()
    assert first == "phx_at_token_1"
    assert second == "phx_at_token_2"
    assert call_count["n"] == 2


# ── config / TLS ─────────────────────────────────────────────────────────────────────────────


def test_validate_api_base_url_rejects_http_by_default():
    cfg = make_client_config(api_base_url="http://insecure.example.com")
    with pytest.raises(ValueError, match="plaintext HTTP"):
        ci_purple_client.validate_api_base_url(cfg)


def test_validate_api_base_url_allows_http_when_explicitly_enabled():
    cfg = make_client_config(api_base_url="http://insecure.example.com", allow_insecure_http=True)
    ci_purple_client.validate_api_base_url(cfg)  # must not raise


def test_build_session_applies_ca_bundle_path():
    cfg = make_client_config(verify_tls="/etc/ssl/custom-ca.pem")
    session = ci_purple_client.build_session(cfg)
    assert session.verify == "/etc/ssl/custom-ca.pem"


def test_ci_purple_config_repr_excludes_api_key():
    """M-6 regression guard: CiPurpleConfig's api_key must never appear in its own repr/str -
    field(repr=False) converts the secret-safety convention into a structural guarantee that
    survives a future `print(cfg)`/logged-exception-with-cfg-as-context mistake."""
    cfg = make_client_config(api_key="phx_live_should_never_appear_in_repr")
    rendered = repr(cfg)
    assert "phx_live_should_never_appear_in_repr" not in rendered
    assert str(cfg) == rendered  # dataclass __str__ falls back to __repr__ - both must exclude it


def test_token_mint_non_json_200_raises_handled_api_error(monkeypatch):
    """The mint path shares the JSON-decode guard: a non-JSON `200` must surface as a handled
    `CiPurpleApiError`, not a bare `ValueError` traceback out of `CiPurpleTokenManager._mint`."""
    cfg = make_client_config()
    session = ci_purple_client.build_session(cfg)
    monkeypatch.setattr(session, "request", lambda method, url, **kw: FakeResponse(200, None, text="<html>sso</html>"))
    manager = ci_purple_client.CiPurpleTokenManager(cfg, session)

    with pytest.raises(ci_purple_client.CiPurpleApiError) as excinfo:
        manager.get_token()
    assert excinfo.value.code == "invalid_response_body"

