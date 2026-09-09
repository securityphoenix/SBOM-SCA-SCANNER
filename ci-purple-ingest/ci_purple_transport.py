"""
HTTP transport primitives for the CI-PURPLE SBOM ingest client.

Split out of `ci_purple_client.py` (`.agent/rules/02-modularity.md`: 500-LOC file limit - that
module reached 498 LOC, leaving no room for the deadline-aware retry and JSON-decode guard this
file now carries). The rule permits a new file when a module is being split.

The division of labour is deliberate:

  - THIS module knows how to make one HTTP call survive a flaky network. It is auth-agnostic and
    endpoint-agnostic: it never mints a token, never knows a job id, and never decides that a
    server-side job should be re-run.
  - `ci_purple_client.py` knows the CI-PURPLE contract: token exchange, the four `/ingest` routes,
    and the JOB-level retry (`POST /ingest/{jobId}/retry`), which is a semantically different
    action from anything here.

Conflating those two retry concepts is the specific mistake this boundary exists to prevent
(brief item 2):
  - `request_with_retry` (here) - TRANSPORT-level: a network error, `429` (honouring `Retry-After`
    exactly), or `503` on ANY call, bounded exponential backoff with jitter.
  - `retry_job` (there) - JOB-level, gated by the SERVER's own retry-eligibility rules
    (`retryable: true` and total attempts below five - `CiIngestRetryService.kt`).

Secret handling (`.claude/rules/env-secret-handling.md`, brief item 7): `CiPurpleConfig.api_key` is
excluded from the dataclass `__repr__`, and `_error_message_from_response` builds messages from
status code + response body text ONLY - never request headers, never `str(exc)` on an exception
that could carry a `PreparedRequest`.
"""

import random
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests

DEFAULT_API_BASE_URL = "https://api.securityphoenix.cloud"
# AWS API Gateway HTTP API caps a request payload around 10MiB at the edge - same constraint the
# validator enforces server-side (`CiIngestRequestValidator.MAX_BODY_BYTES`). See
# `ci_purple_sbom.check_gateway_budget` for the pre-send check that uses this figure.
GATEWAY_LIMIT_BYTES = 10 * 1024 * 1024

# Transport-retry defaults (brief item 2). Deliberately conservative: five attempts total mirrors
# the server's own job-retry ceiling (`SbomJobQueueRepository.MAX_ATTEMPTS = 5`) so a client that
# exhausts transport retries has spent no more attempts than the server would tolerate at the job
# level - "should match or be more conservative, never looser" (brief item 1), applied here too,
# by analogy, to keep both ceilings mentally aligned even though they gate different things.
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_BASE_DELAY_SECONDS = 1.0
DEFAULT_MAX_DELAY_SECONDS = 30.0
RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})

class CiPurpleApiError(RuntimeError):
    """
    A non-2xx response carrying the frozen `{code, message, field, retryable}` error envelope (or,
    for a transport-only failure with no envelope, a synthesised one).

    `str(error)` is safe to print: it never includes the raw API key, the minted token, or request
    headers - only the HTTP status, the server's own `code`/`message`/`field`, and (only when the
    server actually returned one) the `Retry-After` value.
    """

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        field: Optional[str] = None,
        retryable: bool = False,
        retry_after: Optional[str] = None,
    ):
        self.status_code = status_code
        self.code = code
        self.message = message
        self.field = field
        self.retryable = retryable
        self.retry_after = retry_after
        parts = ["HTTP {} {}: {}".format(status_code, code, message)]
        if field:
            parts.append("(field: {})".format(field))
        if retry_after:
            parts.append("(Retry-After: {}s)".format(retry_after))
        super().__init__(" ".join(parts))


@dataclass
class CiPurpleConfig:
    """
    `api_key` is excluded from the auto-generated `__repr__`/`__str__` (`field(repr=False)`, M-6
    fix) - a plain dataclass would otherwise render it in full on any future `print(cfg)`/
    `f"{cfg}"`/logged exception carrying `cfg` as context. Nothing in this branch does that today
    (see the secret-safety self-check in task-8-report.md), but this converts "nothing currently
    does it" from a convention into a structural guarantee that survives a careless future edit.
    """

    api_base_url: str
    api_key: str = field(repr=False)
    verify_tls: Any  # True/False, or a CA-bundle path string (requests' own `verify=` contract)
    allow_insecure_http: bool
    timeout_seconds: int
    max_retry_attempts: int
    retry_base_delay_seconds: float
    retry_max_delay_seconds: float


def validate_api_base_url(cfg: CiPurpleConfig) -> None:
    """
    Refuse to send the API key / minted token over plaintext HTTP.

    Adapted from sbom-single-repo's `phoenix_client.validate_api_base_url` - identical reasoning
    applies to a Bearer credential as it does to HTTP Basic: `http://` is readable by anything on
    the path.
    """
    parsed = urlparse(cfg.api_base_url)
    if parsed.scheme == "https":
        return
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(
            "api_base_url must be an absolute URL such as https://api.example.com, got {!r}".format(
                cfg.api_base_url
            )
        )
    if parsed.scheme == "http":
        if cfg.allow_insecure_http:
            return
        raise ValueError(
            "Refusing to send credentials over plaintext HTTP to {}. Use https://, or pass "
            "--allow-insecure-http if this is a local mock or lab endpoint.".format(cfg.api_base_url)
        )
    raise ValueError("Unsupported scheme {!r} in api_base_url {!r}".format(parsed.scheme, cfg.api_base_url))


def build_session(cfg: CiPurpleConfig) -> requests.Session:
    """
    Plain `requests.Session` with no built-in urllib3 `Retry` mounted - all retry logic here is the
    explicit `request_with_retry` loop below (transport retries need to honour `Retry-After`
    exactly and apply to POSTs, which urllib3's own `Retry` does not do the way this module needs).

    `session.trust_env` is left at its default (`True`), which is what makes `requests` honour the
    standard `HTTPS_PROXY`/`HTTP_PROXY`/`NO_PROXY` environment variables and `REQUESTS_CA_BUNDLE`/
    `CURL_CA_BUNDLE` automatically (brief item 6) - no proxy-specific code is needed here. An
    explicit `--ca-bundle` (mapped to `cfg.verify_tls` as a path string) always takes precedence
    over `REQUESTS_CA_BUNDLE` because it is passed directly as this session's `verify=`.
    """
    session = requests.Session()
    session.verify = cfg.verify_tls
    return session


def _error_message_from_response(response: requests.Response) -> CiPurpleApiError:
    """
    Build a `CiPurpleApiError` from a non-2xx response, using ONLY the status code and the
    response body text - never headers (Authorization is a request header, never echoed back by
    this API, but this function does not even look) and never `str(exc)` on a raised exception.
    """
    retry_after = response.headers.get("Retry-After")
    try:
        payload = response.json()
    except ValueError:
        payload = None
    if isinstance(payload, dict) and "code" in payload and "message" in payload:
        return CiPurpleApiError(
            response.status_code,
            str(payload.get("code")),
            str(payload.get("message")),
            payload.get("field"),
            bool(payload.get("retryable", False)),
            retry_after,
        )
    # No parseable error envelope (a gateway/proxy error page, an empty 5xx body, ...). Bound the
    # body text so an oversized/binary gateway page cannot flood the CI log.
    body_preview = (response.text or "")[:500]
    return CiPurpleApiError(response.status_code, "unmapped_error", body_preview or response.reason, retry_after=retry_after)


def _sleep_for_retry(attempt: int, response: Optional[requests.Response], cfg: CiPurpleConfig) -> None:
    """
    Honour `Retry-After` EXACTLY when the server supplied one (429/503 per design Sec 3.1/8.2);
    otherwise bounded exponential backoff with full jitter. Never computes its own backoff for a
    response that already told it how long to wait (brief item 2).

    M-2 fix: an honoured `Retry-After` is clamped to `cfg.retry_max_delay_seconds` (default 30s).
    Phoenix itself always sends `Retry-After: 1` (`CiIngestController.kt`/
    `CiIngestStatusController.kt`), but an intermediary proxy or WAF sitting in front of it could
    send an arbitrarily large value, and this sleep happens INSIDE `request_with_retry`, outside
    `wait_for_terminal`'s own deadline check - an unclamped multi-hour `Retry-After` would make
    `--wait-timeout-seconds` not actually bound the run. Clamping is logged so a genuinely
    surprising server-supplied value is visible in the CI log, not silently shortened.
    """
    if response is not None:
        raw = response.headers.get("Retry-After")
        if raw is not None:
            try:
                seconds = max(float(raw), 0.0)
            except ValueError:
                seconds = None  # Retry-After is occasionally an HTTP-date rather than delta-seconds.
            if seconds is not None:
                if seconds > cfg.retry_max_delay_seconds:
                    print(
                        "Warning: server Retry-After was {:.1f}s, clamped to the configured "
                        "retry-max-delay-seconds of {:.1f}s.".format(seconds, cfg.retry_max_delay_seconds),
                        file=sys.stderr,
                        flush=True,
                    )
                    seconds = cfg.retry_max_delay_seconds
                time.sleep(seconds)
                return
    delay = min(cfg.retry_max_delay_seconds, cfg.retry_base_delay_seconds * (2 ** attempt))
    time.sleep(random.uniform(0, delay))


def request_with_retry(
    session: requests.Session,
    cfg: CiPurpleConfig,
    method: str,
    url: str,
    **kwargs: Any,
) -> requests.Response:
    """
    Issue one HTTP call with bounded exponential-backoff-with-jitter transport retry (brief item
    2), applied uniformly to token exchange, ingest submit, status poll and result fetch - every
    call site in this module routes through this function rather than calling `session.request`
    directly, so the retry policy cannot silently diverge between call sites.

    Retries on: a network-level exception (connection reset, timeout, DNS failure, ...), or a
    response whose status is in `RETRYABLE_STATUS_CODES` (429/500/502/503/504). Anything else
    (2xx, or a non-retryable 4xx such as 401/403/404/409/413/422) is returned immediately on the
    first attempt with no retry - retrying those cannot help and would only waste the attempt
    budget and delay a real failure being reported.
    """
    kwargs.setdefault("timeout", cfg.timeout_seconds)
    last_exc: Optional[Exception] = None
    max_attempts = max(1, cfg.max_retry_attempts)
    for attempt in range(max_attempts):
        try:
            response = session.request(method, url, **kwargs)
        except requests.exceptions.RequestException as exc:
            last_exc = exc
            if attempt == max_attempts - 1:
                # `from None` (Copilot review nitpick): suppresses the original RequestException
                # from the chain - it can embed a full PreparedRequest (headers) in its str()/repr().
                raise CiPurpleApiError(
                    0,
                    "transport_error",
                    "{} {} failed after {} attempt(s): network error ({}).".format(
                        method, url, max_attempts, type(exc).__name__
                    ),
                ) from None
            _sleep_for_retry(attempt, None, cfg)
            continue

        if response.status_code in RETRYABLE_STATUS_CODES and attempt < max_attempts - 1:
            _sleep_for_retry(attempt, response, cfg)
            continue
        return response

    # Unreachable in practice (the loop always returns or raises), but keeps type-checkers and a
    # defensive reader happy about every path having an explicit outcome.
    if last_exc is not None:
        raise CiPurpleApiError(0, "transport_error", "Request failed with no response: {}".format(type(last_exc).__name__))
    raise AssertionError("request_with_retry: unreachable")

def _decode_json_body(response: requests.Response) -> Dict:
    """
    Decode a SUCCESSFUL response body, converting a non-JSON payload into a `CiPurpleApiError`
    rather than letting `requests`' `json.JSONDecodeError` (a `ValueError`) escape as a raw
    traceback.

    Reachable in a supported deployment: this client explicitly supports corporate proxies and
    custom CAs (`session.trust_env`, `--ca-bundle`), and an interposing proxy, WAF or SSO portal
    can answer `200`/`202` with an HTML page. The CLI's handlers catch `CiPurpleApiError` and
    `TimeoutError` only - there is no top-level `except Exception` - so without this the process
    would die with a traceback instead of the documented exit code.

    The message deliberately carries NO body text: `_error_message_from_response` already bounds a
    body preview on the ERROR path, whereas an unexpected 2xx body has no error envelope to bound
    and no established reason to be echoed. Content-Type plus byte length is enough to tell a
    proxy-interception page apart from a genuine contract change.
    """
    try:
        return response.json()
    except ValueError:
        raise CiPurpleApiError(
            response.status_code,
            "invalid_response_body",
            "Expected a JSON body but could not decode one ({} bytes, Content-Type {!r}). This is "
            "usually a proxy, WAF or SSO portal answering in place of Phoenix.".format(
                len(response.content or b""), response.headers.get("Content-Type")
            ),
        ) from None
