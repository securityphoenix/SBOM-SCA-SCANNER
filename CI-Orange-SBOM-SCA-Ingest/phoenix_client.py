"""
Phoenix API transport for the single-repo SBOM importer.

Holds the resolved configuration and every HTTP call: token exchange, the JSON asset import
(/v1/import/assets) used by the vulnerability method, the stateful SBOM import plus status
polling (/v1/import/sboms) used by the sbom method by default, and the legacy multipart
translate upload (/v1/import/assets/file/translate) kept only for --scan-type, which the
stateful endpoint does not support.
"""

import gzip
import json
import re
import os
import sys
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth

try:  # urllib3 >= 2 moved Retry, but both paths ship with requests
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover - very old urllib3
    from requests.packages.urllib3.util.retry import Retry  # type: ignore


RETRY_STATUS_CODES = (429, 500, 502, 503, 504)
# AWS API Gateway HTTP API caps a request payload at 10MB; warn before getting close.
GATEWAY_LIMIT_BYTES = 10 * 1024 * 1024
GATEWAY_WARN_BYTES = 8 * 1024 * 1024
# The gateway limit applies to the whole request; leave room for form fields and multipart framing.
UPLOAD_PART_LIMIT_BYTES = GATEWAY_LIMIT_BYTES - 64 * 1024
# sbom method: files above this are gzip-compressed before upload. Needs a Phoenix backend with gzip upload support.
COMPRESS_ABOVE_BYTES = UPLOAD_PART_LIMIT_BYTES
RETRY_TOTAL = 4
RETRY_BACKOFF_FACTOR = 1.5


@dataclass
class PhoenixConfig:
    client_id: str
    client_secret: str
    api_base_url: str
    import_type: str
    assessment_name: str
    verify_tls: bool
    timeout_seconds: int
    method: str
    project_type: str
    wait_for_completion: bool
    poll_interval_seconds: int
    poll_timeout_seconds: int
    allow_insecure_http: bool = False
    # Overrides the derived "PhxSbomSca:<project_type>" scan type. Left unset, the sbom method
    # behaves exactly as before. Set, it names one of the report formats Phoenix's translate
    # endpoint accepts ("CycloneDX Scan", "Trivy Scan", ...) so a report that already carries
    # vulnerabilities is translated rather than re-analysed by dep-scan.
    scan_type: Optional[str] = None


def build_session() -> requests.Session:
    """
    HTTP session with bounded retries on transient failures.

    CI networks drop connections and Phoenix can return 502/503 while a node recycles.
    Retrying those transparently keeps a build from failing on a blip, while 4xx responses
    other than 429 still fail immediately because retrying them cannot help.
    """
    kwargs = dict(
        total=RETRY_TOTAL,
        connect=RETRY_TOTAL,
        read=RETRY_TOTAL,
        status=RETRY_TOTAL,
        backoff_factor=RETRY_BACKOFF_FACTOR,
        status_forcelist=RETRY_STATUS_CODES,
        raise_on_status=False,
    )
    # GET only. Both POSTs here are non-idempotent: replaying /import/assets duplicates the
    # findings, and replaying the multipart upload creates a second translate request. A
    # response can also be lost after the server accepted it, so a "failed" POST may well have
    # landed - retrying it transparently is how you get two imports from one build.
    try:
        retry = Retry(allowed_methods=frozenset(["GET"]), **kwargs)
    except TypeError:  # urllib3 < 1.26 spelled it method_whitelist
        retry = Retry(method_whitelist=frozenset(["GET"]), **kwargs)
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def validate_api_base_url(cfg: PhoenixConfig) -> None:
    """
    Refuse to send credentials over plaintext HTTP.

    get_access_token sends client_id/client_secret as HTTP Basic, which is base64, not
    encryption - over http:// they are readable by anything on the path. Callers that really
    need it (a local mock, a lab tenant) opt in explicitly rather than getting it by typo.
    """
    parsed = urlparse(cfg.api_base_url)
    if parsed.scheme == "https":
        return
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(
            f"api_base_url must be an absolute URL such as https://api.example.com, got "
            f"{cfg.api_base_url!r}"
        )
    if parsed.scheme == "http":
        if cfg.allow_insecure_http:
            print(
                f"WARNING: sending credentials to {cfg.api_base_url} over plaintext HTTP "
                f"because insecure HTTP was explicitly enabled.",
                file=sys.stderr,
                flush=True,
            )
            return
        raise ValueError(
            f"Refusing to send credentials over plaintext HTTP to {cfg.api_base_url}. "
            f"Use https://, or pass --allow-insecure-http (or set allow_insecure_http = true "
            f"under [options]) if this is a local mock or lab endpoint."
        )
    raise ValueError(f"Unsupported scheme {parsed.scheme!r} in api_base_url {cfg.api_base_url!r}")


def get_access_token(cfg: PhoenixConfig, session: requests.Session) -> str:
    validate_api_base_url(cfg)
    url = f"{cfg.api_base_url}/v1/auth/access_token"
    response = session.get(
        url,
        auth=HTTPBasicAuth(cfg.client_id, cfg.client_secret),
        timeout=cfg.timeout_seconds,
        verify=cfg.verify_tls,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Token request failed: HTTP {response.status_code} - {response.text[:300]}")
    token = response.json().get("token")
    if not token:
        raise RuntimeError("Token request succeeded but no token returned")
    return token


def import_assets(cfg: PhoenixConfig, session: requests.Session, token: str, payload: Dict) -> Dict:
    """
    Post findings as JSON.

    The size check is not a Phoenix limit. The API sits behind an AWS API Gateway HTTP API
    (identifiable by the apigw-requestid response header), which caps a request payload at
    10MB and rejects anything larger at the edge - the caller sees a gateway error page rather
    than anything recognisably from Phoenix. Findings run to roughly 2.5KB each, so a large
    monorepo scan can reach it. Warning here means the cause is legible when it happens.
    """
    url = f"{cfg.api_base_url}/v1/import/assets"
    body = json.dumps(payload).encode("utf-8")
    if len(body) > GATEWAY_WARN_BYTES:
        finding_count = len(payload.get("assets", [{}])[0].get("findings", [])) if payload.get("assets") else 0
        print(
            f"Warning: payload is {len(body) / 1_048_576:.1f}MB across {finding_count} findings. "
            f"The API gateway rejects requests over ~{GATEWAY_LIMIT_BYTES // 1_048_576}MB, and does so "
            f"with a gateway error rather than a Phoenix one. Split the scan by manifest or "
            f"sub-project if this fails.",
            file=sys.stderr,
            flush=True,
        )
    response = session.post(
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload,
        timeout=cfg.timeout_seconds,
        verify=cfg.verify_tls,
    )
    if response.status_code == 413:
        raise RuntimeError(
            f"Import rejected as too large (HTTP 413). The payload was "
            f"{len(body) / 1_048_576:.1f}MB and the API gateway caps requests at about "
            f"{GATEWAY_LIMIT_BYTES // 1_048_576}MB. Split the scan into smaller imports - by "
            f"manifest, or by sub-project - rather than retrying it unchanged."
        )
    if response.status_code not in (200, 201):
        raise RuntimeError(f"Import failed: HTTP {response.status_code} - {response.text[:500]}")
    return response.json() if response.text.strip() else {"status": "accepted"}


# Terminal states returned by GET /v1/import/assets/file/translate/request/{id}


TRANSLATE_DONE_STATES = {"IMPORTED"}
TRANSLATE_ERROR_STATES = {"ERROR"}
TRANSLATE_PENDING_STATES = {"TRANSLATING", "READY_FOR_IMPORT"}



# Artefact identity parameters (Phoenix "Artefact parameters"). All optional; omitting every
# one reproduces the previous BOM-inferred behaviour byte for byte. They are validated here as
# well as server-side so a malformed value fails locally with a usable message instead of after
# an upload. Note they only change the persisted import on POST /assets/file/translate with a
# PhxSbomSca: scanType against an org with in-house translation enabled - elsewhere Phoenix
# validates and discards them.
ARTEFACT_TYPES = ("BUILD_FILE", "CONTAINER")
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Base image rules. Same rules as the Phoenix backend (ArtefactSpec) so a bad value fails here
# with the backend's own message. Keep these functions small: the container lab copies them.
_BASE_NAME_MAX = 512
_BASE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*$")
_BASE_NAME_DIGEST_RE = re.compile(r"@sha256:([0-9A-Fa-f]{64})$")


def normalise_base_image(
    name: Optional[str], digest: Optional[str]
) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    """
    Apply every backend rule to a base image name and digest.

    Returns (fields, None) when both are valid, (None, "<backend 400 message>") when a rule
    fails, and (None, None) when both are blank. Blank after trim counts as absent. The digest is
    lowercased; a name that ends in @sha256:<hex> must carry the same digest and loses that part.
    """
    name = (name or "").strip()
    digest = (digest or "").strip().lower()
    if not name and not digest:
        return None, None
    if not name or not digest:
        return None, "baseImageName and baseImageDigest must be sent together"

    errors = []
    digest_ok = bool(_DIGEST_RE.match(digest))
    if not digest_ok:
        errors.append("baseImageDigest must match sha256:<64 hex chars>")
    if len(name) > _BASE_NAME_MAX:
        errors.append("baseImageName must be at most 512 characters")
    if not _BASE_NAME_RE.match(name):
        errors.append("baseImageName must be an image reference")
    embedded = _BASE_NAME_DIGEST_RE.search(name)
    if embedded:
        if digest_ok and "sha256:" + embedded.group(1).lower() != digest:
            errors.append("baseImageName digest does not match baseImageDigest")
        name = name[: embedded.start()]
    if errors:
        return None, "; ".join(errors)
    return {"baseImageName": name, "baseImageDigest": digest}, None


def _container_artefact_fields(
    container_name: Optional[str],
    container_version: Optional[str],
    container_digest: Optional[str],
    registry: Optional[str],
) -> Dict[str, str]:
    """
    Build the CONTAINER identity fields, treating whitespace-only input as absent.

    Every value is stripped before it is tested, not after. Testing first meant a value such
    as " " passed the truthiness check and was then stripped to "", so a required name could
    end up sent as an empty parameter and an optional one as an empty string.
    """
    name = (container_name or "").strip()
    if not name:
        raise ValueError("container_name is required when artefact_type is CONTAINER")
    fields: Dict[str, str] = {"containerName": name}

    version = (container_version or "").strip()
    if version:
        fields["containerVersion"] = version

    digest = (container_digest or "").strip()
    if digest:
        if not _DIGEST_RE.match(digest):
            raise ValueError(
                f"container_digest must look like sha256:<64 hex characters>, got {container_digest!r}"
            )
        fields["containerDigest"] = digest

    host = (registry or "").strip()
    if host:
        fields["registry"] = host

    return fields


def build_artefact_fields(
    artefact_type: Optional[str] = None,
    build_file: Optional[str] = None,
    container_name: Optional[str] = None,
    container_version: Optional[str] = None,
    container_digest: Optional[str] = None,
    registry: Optional[str] = None,
    base_image_name: Optional[str] = None,
    base_image_digest: Optional[str] = None,
) -> Dict[str, str]:
    """
    Validate the artefact parameters and return only those that are set.

    base_image_name and base_image_digest must already be normalised (normalise_base_image);
    they are added only for CONTAINER and only when both are set.
    """
    if not artefact_type:
        return {}

    normalised = artefact_type.strip().upper()
    if normalised not in ARTEFACT_TYPES:
        raise ValueError(
            f"artefact_type must be one of {', '.join(ARTEFACT_TYPES)} (case-insensitive), "
            f"got {artefact_type!r}"
        )

    fields: Dict[str, str] = {"artefactType": normalised}

    if normalised == "BUILD_FILE":
        candidate = (build_file or "").strip()
        if candidate:
            # Mirrors the server rule: relative only, no parent-directory segments.
            if candidate.startswith("/") or ".." in candidate.split("/"):
                raise ValueError(
                    f"build_file must be a relative path without '..' segments, got {build_file!r}"
                )
            fields["buildFile"] = candidate
    else:
        fields.update(
            _container_artefact_fields(container_name, container_version, container_digest, registry)
        )
        if base_image_name and base_image_digest:
            fields["baseImageName"] = base_image_name
            fields["baseImageDigest"] = base_image_digest

    if normalised != "CONTAINER" and (base_image_name or base_image_digest):
        raise ValueError("base image fields require artefact_type CONTAINER")

    return fields


def _prepare_upload(sbom_path: str, *, compress: bool = True):
    """
    Read sbom_path and return (filename, content, content_type) for the multipart `file` part.

    Always returns bytes; there is no file handle to manage. A file within COMPRESS_ABOVE_BYTES is
    returned unchanged - the multipart body is byte-for-byte what the previous open(...) handle
    produced. A larger file is gzip-compressed. With compress=False (the --scan-type translate
    upload) nothing is compressed, and a file over UPLOAD_PART_LIMIT_BYTES is refused before any
    request instead.

    Reads both limits as module globals rather than default arguments so tests can monkeypatch
    them per call.
    """
    basename = os.path.basename(sbom_path)
    with open(sbom_path, "rb") as handle:
        data = handle.read()

    if not compress:
        if len(data) > UPLOAD_PART_LIMIT_BYTES:
            raise RuntimeError(
                f"{basename} is {len(data) / 1_048_576:.1f}MB; --scan-type uploads go through Phoenix's "
                f"translation service, which accepts at most 10MB. Drop --scan-type to use the SBOM "
                f"import, which compresses large CycloneDX files, or split the report."
            )
        return basename, data, "application/json"

    if len(data) <= COMPRESS_ABOVE_BYTES:
        return basename, data, "application/json"

    compressed = gzip.compress(data)
    print(
        f"Compressed {basename} from {len(data) / 1_048_576:.1f}MB to "
        f"{len(compressed) / 1_048_576:.1f}MB for upload",
        flush=True,
    )
    return basename + ".gz", compressed, "application/gzip"


def upload_sbom_file(
    cfg: PhoenixConfig,
    session: requests.Session,
    token: str,
    sbom_path: str,
    repo: str,
    file_path: str,
    auto_import: bool,
    scan_target: Optional[str],
    artefact_fields: Optional[Dict[str, str]] = None,
    project_type: Optional[str] = None,
) -> Dict:
    """
    Upload a report file for server-side processing.

    Two shapes of scanType go to this endpoint, and they do opposite things:

    "PhxSbomSca:<projectType>" (the default) hands the SBOM to Phoenix's dep-scan service,
    which derives vulnerabilities from the component list. Any vulnerabilities already in the
    file are not what gets imported.

    A report-format name from Phoenix's scanType catalogue ("CycloneDX Scan", "Trivy Scan",
    ...), set via cfg.scan_type, routes the file to the matching translator instead, which
    reads the findings the scanner already produced. That is the route for a report that is
    already enriched, and the only one that lets Phoenix infer a CONTAINER asset from the
    report's own structure.
    """
    url = f"{cfg.api_base_url}/v1/import/assets/file/translate"
    # project_type is passed in rather than read from cfg: the caller resolves "auto" against
    # the BOM, and reading cfg here would send the unresolved literal while the caller printed
    # the resolved one - the log and the request would disagree.
    scan_type = cfg.scan_type or f"PhxSbomSca:{project_type or cfg.project_type}"

    data = {
        "importType": cfg.import_type,
        "scanType": scan_type,
        "assessmentName": cfg.assessment_name,
        "autoImport": "true" if auto_import else "false",
        "repository": repo,
    }
    if scan_target:
        data["scanTarget"] = scan_target
    if artefact_fields:
        data.update(artefact_fields)

    filename, content, content_type = _prepare_upload(sbom_path, compress=False)
    files = {"file": (filename, content, content_type)}
    response = session.post(
        url,
        headers={"Authorization": f"Bearer {token}"},
        data=data,
        files=files,
        timeout=cfg.timeout_seconds,
        verify=cfg.verify_tls,
    )

    if response.status_code not in (200, 201):
        raise RuntimeError(f"SBOM upload failed: HTTP {response.status_code} - {response.text[:500]}")
    return response.json() if response.text.strip() else {}


def create_sbom_import(
    cfg: PhoenixConfig,
    session: requests.Session,
    token: str,
    sbom_path: str,
    repository: Optional[str] = None,
    scan_target: Optional[str] = None,
    assessment_name: Optional[str] = None,
    import_type: Optional[str] = None,
    artefact_fields: Optional[Dict[str, str]] = None,
    idempotency_key: Optional[str] = None,
) -> Dict:
    """
    Queue an SBOM on the stateful import endpoint (POST /v1/import/sboms).

    scanType is fixed server-side to "PhxSbomSca:sbom" and cannot be set from here - Phoenix
    always treats the upload as CycloneDX. depscan only runs when the file itself carries no
    vulnerabilities (depscanPolicy=MISSING_VULNS is likewise fixed), so an SBOM the scanner
    already enriched is imported as-is instead of being re-derived. importType is a
    compatibility field the endpoint defaults to "new" itself; only send it when the caller
    asked for something explicit; a config-file default meant for the other methods should not
    leak in here.
    """
    url = f"{cfg.api_base_url}/v1/import/sboms"
    data: Dict[str, str] = {}
    if import_type:
        data["importType"] = import_type
    if assessment_name:
        data["assessmentName"] = assessment_name
    if scan_target:
        data["scanTarget"] = scan_target
    if repository:
        data["repository"] = repository
    if artefact_fields:
        data.update(artefact_fields)

    headers = {"Authorization": f"Bearer {token}"}
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key

    filename, content, content_type = _prepare_upload(sbom_path)
    files = {"file": (filename, content, content_type)}
    response = session.post(
        url,
        headers=headers,
        data=data,
        files=files,
        timeout=cfg.timeout_seconds,
        verify=cfg.verify_tls,
    )

    if response.status_code not in (200, 201):
        raise RuntimeError(f"SBOM import failed: HTTP {response.status_code} - {response.text[:500]}")
    return response.json() if response.text.strip() else {}


# Terminal states returned by GET /v1/import/sboms/{id}
SBOM_IMPORT_DONE_STATES = {"IMPORTED"}
SBOM_IMPORT_ERROR_STATES = {"ERROR"}


def get_sbom_import_status(cfg: PhoenixConfig, session: requests.Session, token: str, request_id: str) -> Dict:
    url = f"{cfg.api_base_url}/v1/import/sboms/{request_id}"
    response = session.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        timeout=cfg.timeout_seconds,
        verify=cfg.verify_tls,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Status request failed: HTTP {response.status_code} - {response.text[:300]}")
    return response.json() if response.text.strip() else {}


def wait_for_sbom_import(cfg: PhoenixConfig, session: requests.Session, token: str, request_id: str) -> Dict:
    """
    Poll a stateful SBOM import request until it settles, errors, or the poll timeout elapses.

    Unlike the legacy translate request, autoImport is always true here, so there is no
    READY_FOR_IMPORT resting state to wait for - only IMPORTED counts as done.
    """
    deadline = time.time() + cfg.poll_timeout_seconds
    last_status = ""

    while True:
        payload = get_sbom_import_status(cfg, session, token, request_id)
        status = str(payload.get("status", "")).upper()
        if status != last_status:
            print(f"Import status: {status or 'UNKNOWN'}", flush=True)
            last_status = status

        if status in SBOM_IMPORT_DONE_STATES:
            return payload
        if status in SBOM_IMPORT_ERROR_STATES:
            raise RuntimeError(f"Import failed: {payload.get('error') or 'no error detail returned'}")

        if time.time() >= deadline:
            raise RuntimeError(
                f"Timed out after {cfg.poll_timeout_seconds}s waiting for request {request_id} "
                f"(last status: {status or 'UNKNOWN'}). The upload was accepted and Phoenix is "
                f"still processing it server-side, so it may yet import - check it at "
                f"{cfg.api_base_url}/v1/import/sboms/{request_id}."
            )
        time.sleep(cfg.poll_interval_seconds)


def get_translate_status(cfg: PhoenixConfig, session: requests.Session, token: str, request_id: str) -> Dict:
    url = f"{cfg.api_base_url}/v1/import/assets/file/translate/request/{request_id}"
    response = session.get(
        url,
        headers={"Authorization": f"Bearer {token}"},
        timeout=cfg.timeout_seconds,
        verify=cfg.verify_tls,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Status request failed: HTTP {response.status_code} - {response.text[:300]}")
    return response.json() if response.text.strip() else {}


def wait_for_translate(
    cfg: PhoenixConfig,
    session: requests.Session,
    token: str,
    request_id: str,
    auto_import: bool = True,
) -> Dict:
    """
    Poll a translation request until it settles, errors, or the poll timeout elapses.

    What counts as settled depends on autoImport. With it on, Phoenix carries the translation
    through to IMPORTED. With it off the request is meant to stop at READY_FOR_IMPORT for
    review, so waiting for IMPORTED would poll until the timeout and fail a request that did
    exactly what was asked of it.
    """
    done_states = TRANSLATE_DONE_STATES if auto_import else TRANSLATE_DONE_STATES | {"READY_FOR_IMPORT"}
    deadline = time.time() + cfg.poll_timeout_seconds
    last_status = ""

    while True:
        payload = get_translate_status(cfg, session, token, request_id)
        status = str(payload.get("status", "")).upper()
        if status != last_status:
            # Flushed explicitly: CI pipes stdout, so without this the whole wait is silent.
            print(f"Import status: {status or 'UNKNOWN'}", flush=True)
            last_status = status

        if status in done_states:
            return payload
        if status in TRANSLATE_ERROR_STATES:
            raise RuntimeError(f"Import failed: {payload.get('error') or 'no error detail returned'}")

        if time.time() >= deadline:
            raise RuntimeError(
                f"Timed out after {cfg.poll_timeout_seconds}s waiting for request {request_id} "
                f"(last status: {status or 'UNKNOWN'}). The upload was accepted and Phoenix is "
                f"still processing it server-side, so it may yet import - check it at "
                f"{cfg.api_base_url}/v1/import/assets/file/translate/request/{request_id}. "
                f"Do not assume it will: a request that overlaps another upload from the same "
                f"organization has been observed to sit in TRANSLATING for about an hour and then "
                f"fail with ResourceAccessException. If this recurs, serialise the uploads or use "
                f"the vulnerability import method instead."
            )
        time.sleep(cfg.poll_interval_seconds)
