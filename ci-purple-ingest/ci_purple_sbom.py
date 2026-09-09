"""
CycloneDX reading and request-body construction for the CI-PURPLE ingest client.

The new `/api/v1/external/sca/ingest` contract (design Sec 3.1) is a genuinely different shape
from sbom-single-repo's older `/v1/import/assets*` payload: the server wants the CycloneDX document
mostly AS-IS (embedded under `sbom`), not a Phoenix-specific findings/installedSoftware payload
built by parsing it - so `cyclonedx_sbom.py`'s `build_payload`/`build_findings`/severity-mapping
logic does not apply here and is not reused.

What IS reused, nearly verbatim, is `cyclonedx_sbom.read_sbom`'s file-shape checks (exists,
non-empty, valid JSON, `bomFormat == "CycloneDX"` with the same helpful format-mismatch hints) -
those checks are format-detection, not payload construction, and apply identically to both
contracts.

`preflight_validate` below is a deliberately NON-authoritative, best-effort local check. The
server's `CiIngestRequestValidator` (Kotlin) is the single source of truth for what is accepted;
this module exists only to fail fast with a clear message for the common, cheap-to-detect mistakes
(wrong spec version, duplicate bom-ref, a GHSA/OSV-only vulnerability id, an oversized document)
BEFORE spending a network round trip and a 422 to find out. A local preflight PASS is not a
guarantee of server acceptance; a local preflight FAILURE is not guaranteed to enumerate every
server-side rejection reason either - it stops at the first class of problem it finds, matching the
server's own "reject the document" (not "collect every error") behaviour.
"""

import json
import os
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Mirrors CiIngestRequestValidator.kt's own constants (server source, re-verified against HEAD for
# this client - see task-8-report.md). Keep these two files in step if the server's budgets change.
MAX_BODY_BYTES = 10 * 1024 * 1024
MAX_JSON_DEPTH = 64
MAX_COMPONENTS = 10_000
MAX_VULNERABILITIES = 50_000
MAX_DEPENDENCY_EDGES = 100_000
MAX_LEN_URL_OR_PURL = 2048
MAX_LEN_IDENTIFIER = 512
MAX_LEN_BOM_REF = 1024
MAX_LEN_EVIDENCE = 8192

ACCEPTED_SPEC_VERSIONS = ("1.4", "1.5", "1.6")
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-fA-F]{64}$")
COMMIT_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")


class SbomReadError(ValueError):
    """The SBOM file could not be read, or is not a CycloneDX JSON document."""


def read_sbom(path: str) -> Dict:
    """
    Read and shape-check a CycloneDX JSON SBOM file.

    Adapted near-verbatim from sbom-single-repo's `cyclonedx_sbom.read_sbom` - the file-existence/
    empty-file/JSON-validity/bomFormat checks are identical needs for both contracts.
    """
    if not os.path.exists(path):
        raise SbomReadError(
            "SBOM file not found: {}. Check that the scan stage ran and wrote its output to this "
            "path.".format(path)
        )
    if os.path.getsize(path) == 0:
        raise SbomReadError(
            "SBOM file is empty: {}. The scanner exited without writing a report - check the scan "
            "stage logs.".format(path)
        )
    with open(path, "r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise SbomReadError("SBOM file is not valid JSON ({}): {}".format(path, exc))

    if not isinstance(data, dict):
        raise SbomReadError(
            "SBOM file must contain a JSON object, got {} ({})".format(type(data).__name__, path)
        )

    bom_format = data.get("bomFormat")
    if bom_format != "CycloneDX":
        hint = ""
        if "runs" in data:
            hint = " This looks like SARIF."
        elif "Results" in data or "SchemaVersion" in data:
            hint = " This looks like Trivy's native JSON - re-run with '--format cyclonedx'."
        elif "spdxVersion" in data:
            hint = " This looks like SPDX - re-generate the SBOM in CycloneDX format."
        raise SbomReadError("Input is not a CycloneDX JSON SBOM (bomFormat={!r}).{}".format(bom_format, hint))
    return data


def _max_depth(node, current: int = 0) -> int:
    """
    Mirrors `CiIngestRequestValidator.maxDepth` (server source): recursively measures the deepest
    nesting level of a parsed JSON structure. Short-circuits once past `MAX_JSON_DEPTH` (M-3 fix).

    N-2 fix (re-review round 1): the server measures depth over the WHOLE request body, where the
    `sbom` node itself already sits at depth 1 - so the caller below passes `current=1`, not this
    function's own default of 0 (kept for direct unit testing of the helper in isolation).
    """
    if current > MAX_JSON_DEPTH:
        return current
    if isinstance(node, dict):
        if not node:
            return current
        return max((_max_depth(v, current + 1) for v in node.values()), default=current)
    if isinstance(node, list):
        if not node:
            return current
        return max((_max_depth(v, current + 1) for v in node), default=current)
    return current


def _validate_components(components: object) -> Tuple[set, List[str]]:
    """Component-level checks, split out of `preflight_validate` for the 50-LOC function limit
    (`.agent/rules/02-modularity.md`). Returns `(known_bom_refs, problems)`. Copilot review fix: a
    truthy non-string `bom-ref` used to hit `len()` directly and raise `TypeError`; now guarded."""
    problems: List[str] = []
    if not isinstance(components, list):
        return set(), ["sbom.components must be an array."]
    if len(components) > MAX_COMPONENTS:
        problems.append(
            "sbom.components has {} entries, exceeding the limit of {}.".format(len(components), MAX_COMPONENTS)
        )

    seen_bom_refs = set()
    known_bom_refs = set()
    for idx, component in enumerate(components[:MAX_COMPONENTS]):
        bom_ref = component.get("bom-ref") if isinstance(component, dict) else None
        if not bom_ref:
            problems.append("sbom.components[{}] has no bom-ref.".format(idx))
            continue
        if not isinstance(bom_ref, str):
            problems.append("sbom.components[{}].bom-ref must be a string.".format(idx))
            continue
        if len(bom_ref) > MAX_LEN_BOM_REF:
            problems.append("sbom.components[{}].bom-ref exceeds {} characters.".format(idx, MAX_LEN_BOM_REF))
        if bom_ref in seen_bom_refs:
            problems.append("Duplicate bom-ref {!r} at sbom.components[{}].".format(bom_ref, idx))
        seen_bom_refs.add(bom_ref)
        known_bom_refs.add(bom_ref)

        # M-3 fix: name/version/purl/description length checks, previously declared
        # (MAX_LEN_IDENTIFIER, MAX_LEN_URL_OR_PURL, MAX_LEN_EVIDENCE) but never enforced here.
        name = component.get("name")
        if isinstance(name, str) and len(name) > MAX_LEN_IDENTIFIER:
            problems.append("sbom.components[{}].name exceeds {} characters.".format(idx, MAX_LEN_IDENTIFIER))
        version = component.get("version")
        if isinstance(version, str) and len(version) > MAX_LEN_IDENTIFIER:
            problems.append("sbom.components[{}].version exceeds {} characters.".format(idx, MAX_LEN_IDENTIFIER))
        purl = component.get("purl")
        if isinstance(purl, str) and len(purl) > MAX_LEN_URL_OR_PURL:
            problems.append("sbom.components[{}].purl exceeds {} characters.".format(idx, MAX_LEN_URL_OR_PURL))
        description = component.get("description")
        if isinstance(description, str) and len(description) > MAX_LEN_EVIDENCE:
            problems.append("sbom.components[{}].description exceeds {} characters.".format(idx, MAX_LEN_EVIDENCE))

    return known_bom_refs, problems


def _metadata_bom_ref(sbom: Dict) -> Optional[str]:
    """`sbom.metadata.component.bom-ref` also counts as a known bom-ref for `affects[].ref`."""
    metadata = sbom.get("metadata")
    if not isinstance(metadata, dict):
        return None
    component = metadata.get("component")
    if not isinstance(component, dict):
        return None
    return component.get("bom-ref")


def _validate_vulnerabilities(vulnerabilities: object, known_bom_refs: set) -> List[str]:
    """Vulnerability-level checks split out of `preflight_validate` (same 50-LOC rule as above)."""
    if not isinstance(vulnerabilities, list):
        return ["sbom.vulnerabilities must be an array."]

    problems: List[str] = []
    if len(vulnerabilities) > MAX_VULNERABILITIES:
        problems.append(
            "sbom.vulnerabilities has {} entries, exceeding the limit of {}.".format(
                len(vulnerabilities), MAX_VULNERABILITIES
            )
        )

    for idx, vuln in enumerate(vulnerabilities[:MAX_VULNERABILITIES]):
        vuln_id = vuln.get("id") if isinstance(vuln, dict) else None
        if not vuln_id:
            problems.append("sbom.vulnerabilities[{}] has no id.".format(idx))
            continue
        if not CVE_PATTERN.match(str(vuln_id).strip().upper()):
            problems.append(
                "sbom.vulnerabilities[{}].id {!r} is not a CVE-YYYY-NNNN(N...) identifier - "
                "GHSA/OSV-only identifiers are rejected by the server (422 "
                "unsupported_vulnerability_id), not silently dropped.".format(idx, vuln_id)
            )
        affects = vuln.get("affects") if isinstance(vuln, dict) else None  # non-list => was TypeError
        for aff_idx, affect in enumerate(affects if isinstance(affects, list) else []):
            ref = affect.get("ref") if isinstance(affect, dict) else None
            if not ref or (known_bom_refs and ref not in known_bom_refs):
                problems.append(
                    "sbom.vulnerabilities[{}].affects[{}].ref {!r} does not resolve to a known "
                    "component bom-ref.".format(idx, aff_idx, ref)
                )
    return problems


def _validate_dependency_edges(dependencies: object) -> List[str]:
    """Dependency-edge budget check, split out of `preflight_validate` (same 50-LOC rule). Copilot
    review fix: a scalar `dependsOn` used to hit `len()` and raise `TypeError`; only list-valued
    entries are counted now (best-effort check, so under-counting a malformed one is safe)."""
    if not isinstance(dependencies, list):
        return []
    edges = sum(
        len(dep.get("dependsOn", []))
        for dep in dependencies
        if isinstance(dep, dict) and isinstance(dep.get("dependsOn", []), list)
    )
    if edges > MAX_DEPENDENCY_EDGES:
        return ["Total dependency edges ({}) exceed the limit of {}.".format(edges, MAX_DEPENDENCY_EDGES)]
    return []


def preflight_validate(sbom: Dict) -> List[str]:
    """
    Best-effort local check against the server's structural/semantic budgets (design Sec 3.1).
    Returns a list of human-readable problem descriptions; empty means no LOCALLY DETECTABLE
    problem was found (see module docstring - not a guarantee of server acceptance).

    Split into `_validate_components`/`_validate_vulnerabilities`/`_validate_dependency_edges`
    (`.agent/rules/02-modularity.md`'s 50-LOC limit); this is now the orchestrator.
    """
    problems: List[str] = []

    # current=1, not the default 0: the server measures depth over the WHOLE request body, where
    # the `sbom` node is already one level deep (N-2 fix, re-review round 1).
    depth = _max_depth(sbom, current=1)
    if depth > MAX_JSON_DEPTH:
        problems.append("JSON nesting depth ({}) exceeds the limit of {}.".format(depth, MAX_JSON_DEPTH))

    spec_version = sbom.get("specVersion")
    if spec_version not in ACCEPTED_SPEC_VERSIONS:
        problems.append(
            "sbom.specVersion must be one of {} (got {!r}).".format(
                ", ".join(ACCEPTED_SPEC_VERSIONS), spec_version
            )
        )

    known_bom_refs, component_problems = _validate_components(sbom.get("components", []))
    problems.extend(component_problems)
    metadata_bom_ref = _metadata_bom_ref(sbom)
    if metadata_bom_ref:
        known_bom_refs.add(metadata_bom_ref)

    problems.extend(_validate_vulnerabilities(sbom.get("vulnerabilities", []), known_bom_refs))
    problems.extend(_validate_dependency_edges(sbom.get("dependencies", [])))
    return problems


def _assert_safe_relative_path(path: str, field: str) -> None:
    if not path or not path.strip():
        raise ValueError("{} must not be empty.".format(field))
    if path.startswith("/") or path.startswith("\\"):
        raise ValueError("{} must be a relative path.".format(field))
    if re.match(r"^[A-Za-z]:[\\/]", path):
        raise ValueError("{} must be a relative path.".format(field))
    segments = re.split(r"[\\/]", path)
    if any(seg in ("", ".", "..") for seg in segments):
        raise ValueError("{} must not contain an empty, '.' or '..' segment.".format(field))


def assert_no_authority_hazards(url: str, field: str) -> None:
    """
    I-4 fix: local mirror of the server's `CiIngestRequestValidator.assertNoAuthorityHazards`
    (`code-analyzer-service/.../validation/CiIngestRequestValidator.kt:294-355`), ported line-for-
    line because the scheme-aware ssh-vs-non-ssh distinction is genuinely subtle (inline comments
    below mirror the Kotlin source's own reasoning).

    Runs before the request body is assembled, not merely before it is sent: (a) a checkout cloned
    with an embedded credential (routine on hand-configured Jenkins/self-hosted runners) leaves it
    in `git remote get-url origin`, which this client reads verbatim - catching it here means it is
    never written to `--payload-out` or transmitted; (b) Azure Repos' own documented clone URL form
    is unconditionally rejected server-side regardless of whether it carries a real credential -
    failing fast locally, with a message pointing at `--git-remote-url`, beats a bare 422.
    """
    if url.lower().startswith("file:"):
        raise ValueError("{} must not be a file: URL.".format(field))

    if "://" not in url:
        # scp-style shorthand: [user[:password]@]host:path. git@github.com:org/repo (no password)
        # is legitimate; a ':' in the userinfo before '@' IS an embedded credential.
        at_idx = url.find("@")
        if at_idx > 0 and ":" in url[:at_idx]:
            raise ValueError("{} must not contain embedded credentials.".format(field))
        return

    scheme, _, after_scheme = url.partition("://")
    scheme = scheme.lower()
    authority, _, path_and_beyond = after_scheme.partition("/")

    if "@" in authority:
        # SCHEME-AWARE: ssh://git@host is a bare login user, no password - narrow to a ':' in the
        # userinfo. https://<token>@host is the common PAT-embedding pattern with NO colon either,
        # so any '@'-bearing authority on a non-ssh scheme is rejected outright.
        userinfo = authority.split("@", 1)[0]
        is_credential = (":" in userinfo) if scheme == "ssh" else True
        if is_credential:
            raise ValueError("{} must not contain embedded credentials.".format(field))

    if "?" in path_and_beyond:
        raise ValueError("{} must not contain a query string.".format(field))
    if "#" in path_and_beyond:
        raise ValueError("{} must not contain a fragment.".format(field))

    # N-4 fix: `.isascii() and .isdigit()`, not bare `.isdigit()` - Python's isdigit() accepts
    # non-ASCII digits (e.g. Arabic-Indic U+0664) that `int()` still parses; `.isascii()` ensures
    # only plain 0-9 reaches `int()`, matching Kotlin's `toIntOrNull()` behaviour exactly.
    port_part = authority.partition(":")[2] if ":" in authority else ""
    if port_part and port_part.isascii() and port_part.isdigit():
        port = int(port_part)
        default_port = {"https": 443, "http": 80}.get(scheme)
        if default_port is not None and port != default_port:
            raise ValueError("{} must not specify a non-default explicit port.".format(field))


@dataclass
class RequestContext:
    """Git identity + provenance for both asset kinds - bundled to keep `build_request_body`'s
    parameter count within `.agent/rules/02-modularity.md`'s 6-parameter limit (Copilot review)."""

    git_remote_url: str
    branch: str
    commit_sha: str
    provenance: Dict[str, Optional[str]]


@dataclass
class AssetInput:
    """`asset.kind`-specific fields for `build_request_body` (see its docstring) - the other half
    of the parameter-count fix above, replacing 11 loose parameters with one object."""

    kind: str
    build_file_path: Optional[str] = None
    registry: Optional[str] = None
    image: Optional[str] = None
    tag: Optional[str] = None
    digest: Optional[str] = None
    dockerfile_path: Optional[str] = None
    from_line: Optional[int] = None
    base_image_ref: Optional[str] = None


def _reject_if_supplied(pairs: List[Tuple[str, object]], this_kind: str, other_kind: str) -> None:
    """Raise on the first non-None field in `pairs`, naming it - used by `_build_repo_asset`/
    `_build_container_asset` to reject a field belonging to the OTHER asset kind."""
    for name, value in pairs:
        if value is not None:
            raise ValueError(
                "{} is only valid for asset.kind={}; it was supplied on a {} asset.".format(
                    name, other_kind, this_kind
                )
            )


def _build_repo_asset(asset: AssetInput, provenance: Dict[str, Optional[str]]) -> Tuple[Dict, Dict]:
    """REPO half of `build_request_body`, split out for the 50-LOC limit. Copilot review fix:
    `provenance.dockerfilePath`/`fromLine`/`baseImageRef` used to be silently ignored here; rejected
    now, alongside the pre-existing CONTAINER_IMAGE `asset.*` field rejection."""
    if not asset.build_file_path:
        raise ValueError("asset.buildFilePath is required for asset.kind=REPO.")
    _assert_safe_relative_path(asset.build_file_path, "asset.buildFilePath")
    _reject_if_supplied(
        [
            ("asset.registry", asset.registry),
            ("asset.image", asset.image),
            ("asset.tag", asset.tag),
            ("asset.digest", asset.digest),
            ("provenance.dockerfilePath", asset.dockerfile_path),
            ("provenance.fromLine", asset.from_line),
            ("provenance.baseImageRef", asset.base_image_ref),
        ],
        this_kind="REPO",
        other_kind="CONTAINER_IMAGE",
    )
    return {"kind": "REPO", "buildFilePath": asset.build_file_path}, dict(provenance)


def _build_container_asset(
    asset: AssetInput, provenance: Dict[str, Optional[str]], git_remote_url: str, commit_sha_norm: str
) -> Tuple[Dict, Dict]:
    """CONTAINER_IMAGE half of `build_request_body`, split out for the 50-LOC limit. Copilot
    review fix: `asset.buildFilePath` used to be silently ignored here; now rejected too."""
    _reject_if_supplied([("asset.buildFilePath", asset.build_file_path)], this_kind="CONTAINER_IMAGE", other_kind="REPO")

    missing = [n for n, v in (("registry", asset.registry), ("image", asset.image), ("tag", asset.tag), ("digest", asset.digest)) if not v]
    if missing:
        raise ValueError("asset.{} required for asset.kind=CONTAINER_IMAGE.".format(", asset.".join(missing)))
    if not DIGEST_PATTERN.match(asset.digest):
        raise ValueError("asset.digest must be an exact sha256:<64 hex> digest (got {!r}).".format(asset.digest))
    if not asset.dockerfile_path:
        raise ValueError("provenance.dockerfilePath is required for asset.kind=CONTAINER_IMAGE.")
    _assert_safe_relative_path(asset.dockerfile_path, "provenance.dockerfilePath")
    if asset.from_line is not None and asset.from_line <= 0:
        raise ValueError("provenance.fromLine must be a positive line number.")

    asset_out = {
        "kind": "CONTAINER_IMAGE",
        "registry": asset.registry,
        "image": asset.image,
        "tag": asset.tag,
        "digest": asset.digest.strip().lower(),
    }
    provenance_out = dict(provenance)
    provenance_out.update(
        {
            # Derived, never caller-supplied - see build_request_body's docstring.
            "builtFromRepo": git_remote_url,
            "builtFromCommit": commit_sha_norm,
            "dockerfilePath": asset.dockerfile_path,
            "fromLine": asset.from_line,
            "baseImageRef": asset.base_image_ref,
        }
    )
    return asset_out, provenance_out


def build_request_body(context: RequestContext, sbom_node: Dict, asset: AssetInput, workspace_id: Optional[str] = None) -> Dict:
    """
    Build the exact `POST /ingest` request body (design Sec 3.1; DTO field names re-verified
    against `CiIngestDtos.kt` at HEAD - see task-8-report.md). Raises `ValueError` on a locally
    detectable mistake so the caller gets a clear message instead of a round-trip 422.

    `builtFromRepo`/`builtFromCommit` (CONTAINER_IMAGE only) are derived, never caller-supplied.
    `context.git_remote_url` is checked for authority hazards (I-4) FIRST, before anything else
    runs, so a hazardous remote never reaches `--payload-out` or the network.

    `context`/`asset` replace 15 loose parameters with two dataclasses (Copilot review finding,
    `.agent/rules/02-modularity.md`'s 6-parameter limit); the two branches are split into
    `_build_repo_asset`/`_build_container_asset` (same rule's 50-LOC limit).
    """
    assert_no_authority_hazards(context.git_remote_url, "gitRemoteUrl")

    commit_sha_norm = context.commit_sha.strip().lower()
    if not COMMIT_SHA_PATTERN.match(commit_sha_norm):
        raise ValueError(
            "commitSha must be exactly 40 hexadecimal characters (got {!r}, length {}). A short "
            "SHA (e.g. `git rev-parse --short HEAD`) is not accepted - use the full SHA.".format(
                context.commit_sha, len(context.commit_sha)
            )
        )

    kind = asset.kind.strip().upper()
    if kind == "REPO":
        asset_out, provenance_out = _build_repo_asset(asset, context.provenance)
    elif kind == "CONTAINER_IMAGE":
        asset_out, provenance_out = _build_container_asset(asset, context.provenance, context.git_remote_url, commit_sha_norm)
    else:
        raise ValueError("asset.kind must be REPO or CONTAINER_IMAGE (got {!r}).".format(kind))

    body = {
        "gitRemoteUrl": context.git_remote_url,
        "branch": context.branch,
        "commitSha": commit_sha_norm,
        "asset": asset_out,
        "provenance": provenance_out,
        "sbom": sbom_node,
    }
    if workspace_id:
        body["workspaceId"] = workspace_id
    return body


def estimate_body_size(body: Dict) -> int:
    """Byte size of the body as `json.dumps` (without extra whitespace) would send it."""
    return len(json.dumps(body, separators=(",", ":")).encode("utf-8"))


def check_gateway_budget(body: Dict) -> Tuple[bool, str]:
    """
    Local pre-send size check against the server's own 10 MiB hard limit (design Sec 3.1,
    `CiIngestRequestValidator.MAX_BODY_BYTES`). Returns (ok, message) - `ok=False` means sending
    would be rejected 413 server-side. Copilot review fix: authoritative only if the caller sends
    EXACTLY these compact-separator bytes - `ci_purple_client.submit_ingest` now does.
    """
    size = estimate_body_size(body)
    if size > MAX_BODY_BYTES:
        return False, (
            "Request body is {:.1f} MiB, over the server's {} MiB ingest limit (413). Split the "
            "SBOM (per manifest/sub-project) or trim components/vulnerabilities before "
            "retrying - resending unchanged will not help.".format(
                size / 1_048_576, MAX_BODY_BYTES // 1_048_576
            )
        )
    if size > MAX_BODY_BYTES * 0.8:
        return True, "Request body is {:.1f} MiB, approaching the server's {} MiB ingest limit.".format(
            size / 1_048_576, MAX_BODY_BYTES // 1_048_576
        )
    return True, ""
