"""
Phoenix HTTP transport for the CI-PURPLE SBOM ingest client.

Talks to the CI-PURPLE contract (design `docs/plans/2026-08-28-ci-purple-sbom-ingest-design.md`
Sec 3.1, Sec 8.2) - a DIFFERENT API surface from sbom-single-repo's `phoenix_client.py`:

  - Auth is a single long-lived API key (`phx_live_*` / `phx_dev_*`) exchanged for a short-lived,
    purpose-scoped `phx_at_*` token (`POST /api/v1/external/auth/ci-ingest-token`), not an
    `client_id`/`client_secret` HTTP-Basic pair minting a general access token.
  - `POST /api/v1/external/sca/ingest` is asynchronous (`202` + job id, poll for a terminal
    state) and IDEMPOTENT (org/workspace/repo/branch/commit/asset/content hash key - a duplicate
    submission returns the SAME job, per `response-202-duplicate.json`), unlike
    sbom-single-repo's synchronous, explicitly non-idempotent `/v1/import/assets` POST. This is why
    this module's transport retry (see `request_with_retry`) is safe to apply to POSTs here, where
    `phoenix_client.py`'s own comment explains why it deliberately does NOT retry POSTs.

Two DISTINCT retry concepts live in this file and must not be conflated (brief item 2):
  - `request_with_retry` - TRANSPORT-level: a network error, `429` (honouring `Retry-After`
    exactly), or `503` on ANY call, bounded exponential backoff with jitter.
  - `retry_job` - JOB-level: `POST /ingest/{jobId}/retry`, a semantically different action
    (re-running a failed ingest job server-side) gated by the SERVER's own retry-eligibility rules
    (`retryable: true` and total attempts below five - `CiIngestRetryService.kt`), not a transport
    concern at all.

Secret handling (`.claude/rules/env-secret-handling.md`, brief item 7): the raw API key and the
minted `phx_at_*` token are held ONLY in memory (`CiPurpleTokenManager`), are never written to
disk, never appear in a `print`/log call, and are excluded from every error message this module
raises - `_error_message_from_response` builds messages from status code + response body text only,
never from request headers or `str(exc)` on an exception that could carry a `PreparedRequest`.

Transport primitives (`CiPurpleConfig`, `CiPurpleApiError`, `request_with_retry`, backoff) live in
`ci_purple_transport.py` since that split; they are re-exported below so `ci_purple_client` stays
the single import surface for this package's callers and tests.
"""

import datetime
import json
import re
import time
from dataclasses import replace
from typing import Any, Dict, Optional

import requests

from ci_purple_transport import (  # noqa: F401  (re-exported for callers/tests)
    DEFAULT_API_BASE_URL,
    DEFAULT_BASE_DELAY_SECONDS,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_MAX_DELAY_SECONDS,
    GATEWAY_LIMIT_BYTES,
    RETRYABLE_STATUS_CODES,
    CiPurpleApiError,
    CiPurpleConfig,
    _decode_json_body,
    _error_message_from_response,
    build_session,
    request_with_retry,
    validate_api_base_url,
)

TOKEN_MINT_PATH = "/api/v1/external/auth/ci-ingest-token"
INGEST_PATH = "/api/v1/external/sca/ingest"

# Job-level retry ceiling (brief item 1): the server's `SbomJobQueueRepository.MAX_ATTEMPTS = 5`
# (`code-analyzer-service/.../sbom/queue/SbomJobQueueRepository.kt:576-577,598`) is a CUMULATIVE
# ceiling across every attempt, not a per-retry allowance - it counts the INITIAL submit's own
# claim as attempt 1, fenced by `retryIfFencedFailed`'s `attempts < maxAttempts`. This client's own
# loop counts RETRY CALLS, a different quantity: initial submit -> attempts=1; retry #1 ->
# attempts=2; retry #2 -> attempts=3; retry #3 -> attempts=4; retry #4 -> attempts=5, which is
# AT the server's fence - attempts is now equal to MAX_ATTEMPTS, so a FIFTH retry call would
# evaluate `attempts(5) < maxAttempts(5)` as false server-side and fail with 409
# `retry_attempts_exhausted`. So the client's own retry-call budget is MAX_ATTEMPTS - 1 = 4,
# matching the server's cumulative ceiling minus the initial attempt the first submit already
# spent. A looser client ceiling (5) would issue the retry call the server is guaranteed to
# reject, per the brief's own "should match or be more conservative, never looser."
MAX_JOB_RETRY_ATTEMPTS = 4

TERMINAL_STATUSES = frozenset({"SUCCEEDED", "DEGRADED", "FAILED"})


class CiPurpleTokenManager:
    """
    Mints and holds ONE `phx_at_*` CI-ingest token per process, re-minting before/on its 1-hour
    TTL (design Sec 8.2 / `ExternalAuthController.ciIngestToken`) - never across separate pipeline
    runs, and never to disk or a CI cache (brief item 1). A fresh process (a fresh `--wait` run, a
    fresh pipeline invocation) always mints its own token from the raw API key; nothing here
    persists that token anywhere it could outlive this process.
    """

    # Re-mint this many seconds before the stated expiry, rather than waiting for a request to
    # fail with 401 mid-run - the token has a 1-hour TTL, and 60s of margin covers ordinary clock
    # skew and the time a large SBOM upload itself takes.
    EXPIRY_MARGIN_SECONDS = 60

    def __init__(self, cfg: CiPurpleConfig, session: requests.Session):
        self._cfg = cfg
        self._session = session
        self._token: Optional[str] = None
        self._expires_at_epoch: float = 0.0

    def _mint(self) -> None:
        validate_api_base_url(self._cfg)
        url = self._cfg.api_base_url.rstrip("/") + TOKEN_MINT_PATH
        response = request_with_retry(
            self._session,
            self._cfg,
            "POST",
            url,
            headers={"Authorization": "Bearer {}".format(self._cfg.api_key)},
        )
        if response.status_code != 200:
            raise _error_message_from_response(response)
        payload = _decode_json_body(response)
        token = payload.get("token")
        expires_at = payload.get("expiresAt")
        if not token or not expires_at:
            raise CiPurpleApiError(response.status_code, "invalid_token_response", "Token response missing token/expiresAt.")
        self._token = token
        self._expires_at_epoch = _parse_iso8601_to_epoch(expires_at)

    def get_token(self) -> str:
        """Return a currently-valid token, minting or re-minting one as needed."""
        if self._token is None or time.time() >= (self._expires_at_epoch - self.EXPIRY_MARGIN_SECONDS):
            self._mint()
        assert self._token is not None
        return self._token

    def force_remint(self) -> str:
        """Discard the held token and mint a fresh one (used after an unexpected 401 mid-run)."""
        self._token = None
        return self.get_token()


_FRACTIONAL_SECONDS_PATTERN = re.compile(r"^(.*?)(\.(\d+))?([+-]\d{2}:\d{2})$")


def _parse_iso8601_to_epoch(value: str) -> float:
    """
    Parse an ISO-8601 instant (`...Z` or an explicit offset) to a Unix epoch float.

    M-4 fix: the server's `expiresAt` is `java.time.Instant.toString()`, which emits 0, 3, 6 OR 9
    fractional-second digits - and Python's `datetime.fromisoformat` (this runtime: 3.7) accepts
    only 0/3/6 digits, raising `ValueError` on 9 (nanosecond-precision instants - rare on most JDK
    clocks, but real). Truncated (never rounded, so a token's computed expiry is never
    OVER-estimated) to at most 6 fractional digits before parsing. A value that still fails to
    parse after that raises `CiPurpleApiError` rather than an unhandled traceback escaping the
    token-mint path (the same failure shape M-1 fixed for `validate_api_base_url`).
    """
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    match = _FRACTIONAL_SECONDS_PATTERN.match(text)
    if match and match.group(3) and len(match.group(3)) > 6:
        text = "{}.{}{}".format(match.group(1), match.group(3)[:6], match.group(4))
    try:
        return datetime.datetime.fromisoformat(text).timestamp()
    except ValueError as exc:
        # `from exc` (Copilot review nitpick): unlike above, safe/useful context - explicit chain.
        raise CiPurpleApiError(
            0,
            "invalid_token_response",
            "Could not parse token expiresAt {!r}: {}".format(value, exc),
        ) from exc


def _auth_headers(token: str) -> Dict[str, str]:
    return {"Authorization": "Bearer {}".format(token), "Content-Type": "application/json"}


def _call_with_token_retry(
    cfg: CiPurpleConfig,
    session: requests.Session,
    token_manager: CiPurpleTokenManager,
    method: str,
    url: str,
    expected_status: int,
    **kwargs: Any,
) -> Dict:
    """
    Shared request flow for every authenticated CI-PURPLE endpoint (Copilot review nitpick - this
    was duplicated per-function, and only `submit_ingest` re-minted-and-retried on a stray 401;
    `get_status`/`get_result`/`retry_job` did not, so a token invalidated mid-poll aborted the run
    instead of the same one-shot re-mint `submit_ingest` already had). Retries EXACTLY ONCE on 401.
    """
    token = token_manager.get_token()
    response = request_with_retry(session, cfg, method, url, headers=_auth_headers(token), **kwargs)
    if response.status_code == 401:
        # A token minted just before its margin, or invalidated server-side mid-run - one
        # re-mint-and-retry, never a silent loop.
        token = token_manager.force_remint()
        response = request_with_retry(session, cfg, method, url, headers=_auth_headers(token), **kwargs)
    if response.status_code != expected_status:
        raise _error_message_from_response(response)
    return _decode_json_body(response)


def submit_ingest(
    cfg: CiPurpleConfig,
    session: requests.Session,
    token_manager: CiPurpleTokenManager,
    body: Dict,
) -> Dict:
    """
    `POST /ingest`. Returns the parsed `202` body on success; raises `CiPurpleApiError` otherwise.

    Copilot review fix: serialized EXACTLY ONCE with the same compact separators
    `ci_purple_sbom.check_gateway_budget`'s pre-send size check measures, sent via `data=` (raw
    bytes) rather than `json=` - `requests`' own `json=` re-serializes with non-compact separators,
    silently sending more bytes than the budget check measured.
    """
    url = cfg.api_base_url.rstrip("/") + INGEST_PATH
    body_bytes = json.dumps(body, separators=(",", ":")).encode("utf-8")
    return _call_with_token_retry(cfg, session, token_manager, "POST", url, 202, data=body_bytes)


def get_status(cfg: CiPurpleConfig, session: requests.Session, token_manager: CiPurpleTokenManager, job_id: str) -> Dict:
    """`GET /ingest/{jobId}`."""
    url = "{}{}/{}".format(cfg.api_base_url.rstrip("/"), INGEST_PATH, job_id)
    return _call_with_token_retry(cfg, session, token_manager, "GET", url, 200)


def get_result(cfg: CiPurpleConfig, session: requests.Session, token_manager: CiPurpleTokenManager, job_id: str) -> Dict:
    """`GET /ingest/{jobId}/result`. Raises `CiPurpleApiError(status_code=409, ...)` before terminal."""
    url = "{}{}/{}/result".format(cfg.api_base_url.rstrip("/"), INGEST_PATH, job_id)
    return _call_with_token_retry(cfg, session, token_manager, "GET", url, 200)


def retry_job(cfg: CiPurpleConfig, session: requests.Session, token_manager: CiPurpleTokenManager, job_id: str) -> Dict:
    """
    `POST /ingest/{jobId}/retry` - the JOB-level retry (see module docstring), distinct from
    `request_with_retry`'s transport-level retry. This call itself still goes through
    `request_with_retry` for transport resilience (a network blip retrying the retry call is still
    a transport concern), but the decision to CALL this function at all belongs to the caller
    (`wait_for_terminal` below), gated on the server's own `retryable: true` + attempt-count rules.
    """
    url = "{}{}/{}/retry".format(cfg.api_base_url.rstrip("/"), INGEST_PATH, job_id)
    return _call_with_token_retry(cfg, session, token_manager, "POST", url, 202)


def _poll_budget(cfg: CiPurpleConfig, remaining_seconds: float) -> CiPurpleConfig:
    """
    Return `cfg` with its TRANSPORT budget shrunk to fit `remaining_seconds`.

    `wait_for_terminal` checks its deadline only AFTER `get_status` returns, and every sleep and
    per-request timeout inside `request_with_retry` is invisible to that check. With the defaults
    (`timeout_seconds=60`, `max_retry_attempts=5`, `retry_max_delay_seconds=30`) one degraded poll
    could therefore burn 5x60s of timeouts plus 4x30s of backoff - about 7 minutes - before the
    deadline was consulted at all, so `--wait-timeout-seconds` did not actually bound the run. The
    `Retry-After` clamp added earlier removed the UNBOUNDED case; this removes the bounded overshoot.

    Bounding the config rather than threading a deadline parameter through
    `get_status`/`_call_with_token_retry`/`request_with_retry` keeps every signature inside
    `.agent/rules/02-modularity.md`'s 6-parameter limit and leaves `ci_purple_transport` untouched:
    both of `_sleep_for_retry`'s branches already clamp to `retry_max_delay_seconds`, so capping
    that value caps the sleeps, including an honoured `Retry-After`.

    Residual, deliberately not engineered away: a stray `401` mid-poll makes
    `_call_with_token_retry` issue a second `request_with_retry` after the re-mint, so that one
    iteration can cost up to twice the remaining budget. That is a rare path, and the overshoot is
    then bounded by the remaining budget rather than by the full 7-minute worst case above.
    """
    remaining = remaining_seconds if remaining_seconds > 0 else 1.0
    timeout = max(1, int(min(float(cfg.timeout_seconds), remaining)))
    max_delay = max(0.0, min(cfg.retry_max_delay_seconds, remaining))
    # An attempt costs at most one timeout plus one backoff sleep; never budget more than fit.
    affordable = int(remaining // (timeout + max_delay)) if (timeout + max_delay) > 0 else 1
    attempts = max(1, min(cfg.max_retry_attempts, affordable))
    return replace(cfg, timeout_seconds=timeout, max_retry_attempts=attempts, retry_max_delay_seconds=max_delay)


def wait_for_terminal(
    cfg: CiPurpleConfig,
    session: requests.Session,
    token_manager: CiPurpleTokenManager,
    job_id: str,
    poll_interval_seconds: int,
    wait_timeout_seconds: int,
    on_status: Optional[Any] = None,
) -> Dict:
    """
    Poll `GET /ingest/{jobId}` until a terminal state, auto-retrying a server-classified-retryable
    `FAILED` job via `POST /ingest/{jobId}/retry` (brief item 1) up to `MAX_JOB_RETRY_ATTEMPTS`
    (4) total job-level retries - one less than the server's cumulative
    `SbomJobQueueRepository.MAX_ATTEMPTS` (5), because the initial submit already spent attempt 1
    (see the constant's own comment) - so this loop never issues the retry call the server is
    guaranteed to 409 `retry_attempts_exhausted`, and never needs to rely on that 409 to stop it.

    Raises `CiPurpleApiError` (job-retry rejected, e.g. blob expired), `TimeoutError` (deadline
    reached with the job still non-terminal), or returns the final status payload (whose `status`
    is one of `TERMINAL_STATUSES`) otherwise. `on_status`, when given, is called with each status
    payload as it is observed (for CLI progress printing) - it must not print the job's bearer
    token, which it never receives in the first place.
    """
    deadline = time.time() + wait_timeout_seconds
    job_retry_attempts = 0

    while True:
        poll_cfg = _poll_budget(cfg, deadline - time.time())
        status_payload = get_status(poll_cfg, session, token_manager, job_id)
        if on_status:
            on_status(status_payload)

        status = status_payload.get("status")
        if status in TERMINAL_STATUSES:
            if status == "FAILED" and status_payload.get("retryable") and job_retry_attempts < MAX_JOB_RETRY_ATTEMPTS:
                job_retry_attempts += 1
                retry_job(_poll_budget(cfg, deadline - time.time()), session, token_manager, job_id)
                # Re-poll immediately after a successful retry acceptance rather than waiting a
                # full interval - the job was just reset to QUEUED, so an immediate poll shows
                # forward progress instead of an idle wait.
                continue
            return status_payload

        if time.time() >= deadline:
            raise TimeoutError(
                "Timed out after {}s waiting for job {} (last status: {}). The ingest was accepted "
                "and Phoenix may still be processing it - poll GET {}/{} directly; do not assume it "
                "failed.".format(wait_timeout_seconds, job_id, status, INGEST_PATH, job_id)
            )
        # Never sleep past the deadline either - it would only delay the timeout message.
        time.sleep(max(0.0, min(float(poll_interval_seconds), deadline - time.time())))
