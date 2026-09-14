#!/usr/bin/env python3
"""
Single-repo CycloneDX SBOM importer for Phoenix.

Two import methods are supported, selected with --method:

vulnerability (POST /v1/import/assets)
    The SBOM must already carry vulnerabilities. This script parses them, builds one
    BUILD asset keyed as repo/file:branch, and posts the findings as JSON. Use this
    when the scanner already did the vulnerability analysis (Trivy with --scanners
    vuln, a dep-scan VDR, Grype, ...).

sbom (POST /v1/import/sboms by default; POST /v1/import/assets/file/translate with --scan-type)
    Uploads the SBOM file itself. By default Phoenix uses the vulnerabilities already in the
    file and only runs dep-scan when it has none (scanType is fixed server-side to
    "PhxSbomSca:sbom"). Pass --scan-type to route a non-CycloneDX report, or one Phoenix
    should translate through a specific format translator, through the legacy endpoint
    instead.

Supporting modules live alongside this file and must be deployed with it:
    phoenix_client.py   configuration and every HTTP call
    cyclonedx_sbom.py   CycloneDX parsing and payload construction
    ci_context.py       repository/CI metadata resolution
"""

import argparse
import configparser
import json
import os
import sys

from ci_context import resolve_repo_context
from cyclonedx_sbom import (
    build_payload,
    container_identity_from_sbom,
    read_report,
    read_sbom,
)
from upload_plan import describe_report, resolve_project_type
from phoenix_client import (
    build_artefact_fields,
    PhoenixConfig,
    build_session,
    create_sbom_import,
    get_access_token,
    import_assets,
    upload_sbom_file,
    wait_for_sbom_import,
    wait_for_translate,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import CycloneDX SBOM findings to Phoenix as a single BUILD asset"
    )
    parser.add_argument("--sbom-file", required=True, help="Path to CycloneDX JSON file")
    parser.add_argument("--repo", help="Repository name, e.g. org/service")
    parser.add_argument("--file-path", help="Manifest/file path, e.g. package-lock.json")
    parser.add_argument("--branch", help="Branch name, e.g. main")
    parser.add_argument(
        "--from-bitbucket-env",
        action="store_true",
        help="Populate repo/branch/commit/build metadata from Bitbucket Pipeline environment variables",
    )
    parser.add_argument(
        "--from-jenkins-env",
        action="store_true",
        help="Populate repo/branch/commit/build metadata from Jenkins environment variables",
    )
    parser.add_argument(
        "--from-github-env",
        action="store_true",
        help="Populate repo/branch/commit/build metadata from GitHub Actions environment variables",
    )
    parser.add_argument("--assessment-name", help="Phoenix assessment name override")
    parser.add_argument("--import-type", choices=["new", "merge", "delta"], help="Phoenix import type")
    parser.add_argument(
        "--method",
        choices=["vulnerability", "sbom"],
        help=(
            "Import method. 'vulnerability' parses vulnerabilities out of the SBOM and posts "
            "findings to /v1/import/assets. 'sbom' uploads the plain SBOM file and lets Phoenix "
            "run dep-scan over it. Default: vulnerability."
        ),
    )
    parser.add_argument(
        "--project-type",
        help=(
            "Ecosystem sent to Phoenix dep-scan as scanType 'PhxSbomSca:<projectType>' "
            "(sbom method only). Default 'auto' reads it from the BOM's package URLs; a "
            "container or OS image resolves to 'universal'. Accepts a comma-separated list "
            "for a polyglot repository, and the cdxgen spellings (js, nodejs) as well as "
            "Phoenix's (npm). Examples: auto, java, npm, java,python, universal."
        ),
    )
    parser.add_argument(
        "--scan-type",
        help=(
            "sbom method: send this literal scanType instead of the derived "
            "'PhxSbomSca:<projectType>'. Use a report-format name from Phoenix's scanType "
            "catalogue - 'CycloneDX Scan', 'Trivy Scan', 'Anchore Grype', ... - to have "
            "Phoenix translate the findings the report already contains rather than run "
            "dep-scan over its components. Required for importing an enriched report."
        ),
    )
    parser.add_argument("--scan-target", help="Scan target recorded on the import (sbom method)")
    parser.add_argument(
        "--idempotency-key",
        help=(
            "sbom method, stateful endpoint only (no --scan-type): sent as the Idempotency-Key "
            "header. Reusing the same value on a retry returns the existing import request for "
            "the organization instead of creating a new one."
        ),
    )
    parser.add_argument(
        "--artefact-type",
        choices=["BUILD_FILE", "CONTAINER"],
        help=(
            "sbom method: declare artefact identity explicitly instead of letting Phoenix infer "
            "it from the BOM. Omit to keep the previous behaviour exactly."
        ),
    )
    parser.add_argument("--build-file", help="BUILD_FILE: relative build file path, e.g. services/api/pom.xml")
    parser.add_argument("--container-name", help="CONTAINER: image name, required with --artefact-type CONTAINER")
    parser.add_argument("--container-version", help="CONTAINER: image tag")
    parser.add_argument("--container-digest", help="CONTAINER: sha256:<64 hex>; derived from the SBOM when omitted")
    parser.add_argument("--registry", help="CONTAINER: container registry host")
    parser.add_argument(
        "--no-auto-import",
        action="store_true",
        help="sbom method: stage the translation but do not import it automatically",
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="sbom method: poll until the translation/import finishes instead of returning immediately",
    )
    parser.add_argument("--config", default="config.ini", help="INI configuration file")
    parser.add_argument("--origin", default="cyclonedx-sca", help="Phoenix asset origin value")
    parser.add_argument("--api-base-url", help="Phoenix API base URL override")
    parser.add_argument("--client-id", help="Phoenix client_id override")
    parser.add_argument("--client-secret", help="Phoenix client_secret override")
    parser.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help=(
            "Permit an http:// api_base_url. Credentials are sent as HTTP Basic, so this "
            "exposes them on the wire - use it only for a local mock or lab endpoint."
        ),
    )
    # Mutually exclusive: passing both used to resolve silently to --no-verify-tls, quietly
    # turning verification off for someone who had asked for it in the same command.
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--verify-tls", action="store_true", help="Force TLS certificate verification")
    tls.add_argument("--no-verify-tls", action="store_true", help="Disable TLS verification")
    parser.add_argument("--dry-run", action="store_true", help="Build payload but do not call Phoenix")
    parser.add_argument("--payload-out", help="Write generated JSON payload to this file")
    return parser.parse_args()


def load_config(config_file: str, args: argparse.Namespace, require_credentials: bool = True) -> PhoenixConfig:
    parser = configparser.ConfigParser()
    if os.path.exists(config_file):
        parser.read(config_file)

    phoenix_section = parser["phoenix"] if "phoenix" in parser else {}
    options_section = parser["options"] if "options" in parser else {}

    client_id = args.client_id or os.getenv("PHOENIX_CLIENT_ID") or phoenix_section.get("client_id", "")
    client_secret = (
        args.client_secret or os.getenv("PHOENIX_CLIENT_SECRET") or phoenix_section.get("client_secret", "")
    )
    api_base_url = (
        args.api_base_url
        or os.getenv("PHOENIX_API_BASE_URL")
        or phoenix_section.get("api_base_url", "https://api.securityphoenix.cloud")
    ).rstrip("/")
    import_type = args.import_type or phoenix_section.get("import_type", "merge")
    assessment_name = args.assessment_name or phoenix_section.get("assessment_name", "single-repo-sca-sbom")
    method = (args.method or phoenix_section.get("method", "vulnerability")).strip().lower()
    if method not in ("vulnerability", "sbom"):
        raise ValueError(f"Unsupported method '{method}' (expected 'vulnerability' or 'sbom')")
    project_type = args.project_type or phoenix_section.get("project_type", "auto")
    scan_type = args.scan_type or phoenix_section.get("scan_type", "") or None
    if scan_type:
        scan_type = scan_type.strip() or None
    # project_type only ever reached Phoenix through the derived scan type, so an explicit
    # scan type silently retires it. Say so rather than leaving someone to wonder why
    # --project-type java changed nothing.
    if scan_type and (args.project_type or phoenix_section.get("project_type")):
        print(
            f"Warning: --scan-type {scan_type!r} replaces the derived "
            f"'PhxSbomSca:{project_type}', so project_type has no effect on this run.",
            file=sys.stderr,
            flush=True,
        )
    # Without --scan-type, sbom-method uploads now go to the stateful endpoint
    # (POST /v1/import/sboms), which fixes scanType to "PhxSbomSca:sbom" server-side -
    # project_type has no consumer left on that path.
    elif method == "sbom" and not scan_type and (args.project_type or phoenix_section.get("project_type")):
        print(
            "Warning: --project-type has no effect on the stateful sbom-method endpoint "
            "(POST /v1/import/sboms), which fixes scanType to 'PhxSbomSca:sbom' server-side. "
            "It only applies together with --scan-type, which routes to the legacy translate "
            "endpoint instead.",
            file=sys.stderr,
            flush=True,
        )

    verify_tls = True
    if options_section:
        verify_tls = options_section.get("verify_tls", "true").strip().lower() == "true"
    if args.verify_tls:
        verify_tls = True
    if args.no_verify_tls:
        verify_tls = False

    allow_insecure_http = args.allow_insecure_http
    if not allow_insecure_http and options_section:
        allow_insecure_http = options_section.get("allow_insecure_http", "false").strip().lower() == "true"

    timeout_seconds = int(options_section.get("timeout_seconds", "60")) if options_section else 60
    poll_interval_seconds = int(options_section.get("poll_interval_seconds", "10")) if options_section else 10
    poll_timeout_seconds = int(options_section.get("poll_timeout_seconds", "1800")) if options_section else 1800
    wait_for_completion = args.wait
    if not wait_for_completion and options_section:
        wait_for_completion = options_section.get("wait_for_completion", "false").strip().lower() == "true"

    for label, value in (
        ("timeout_seconds", timeout_seconds),
        ("poll_interval_seconds", poll_interval_seconds),
        ("poll_timeout_seconds", poll_timeout_seconds),
    ):
        if value <= 0:
            raise ValueError(
                f"{label} must be greater than 0, got {value}. A zero or negative value either "
                f"spins without pausing or expires before the first check."
            )

    missing = []
    if require_credentials:
        if not client_id:
            missing.append("client_id")
        if not client_secret:
            missing.append("client_secret")
    if not api_base_url:
        missing.append("api_base_url")
    if missing:
        raise ValueError(f"Missing required Phoenix configuration: {', '.join(missing)}")

    return PhoenixConfig(
        client_id=client_id,
        client_secret=client_secret,
        api_base_url=api_base_url,
        import_type=import_type,
        assessment_name=assessment_name,
        verify_tls=verify_tls,
        timeout_seconds=timeout_seconds,
        method=method,
        project_type=project_type,
        wait_for_completion=wait_for_completion,
        poll_interval_seconds=poll_interval_seconds,
        poll_timeout_seconds=poll_timeout_seconds,
        allow_insecure_http=allow_insecure_http,
        scan_type=scan_type,
    )


def resolve_artefact_fields(args: argparse.Namespace, sbom: dict) -> dict:
    """
    Build the artefact parameters, filling container details from the BOM where not given.

    A container BOM already carries image name, tag and digest in metadata.component, so a
    pipeline that knows it is scanning an image need not restate them. Explicit flags always
    win. Returns {} when --artefact-type is unset, reproducing the previous behaviour exactly.
    """
    if not args.artefact_type:
        return {}

    name = args.container_name
    version = args.container_version
    digest = args.container_digest
    registry = args.registry

    if args.artefact_type == "CONTAINER":
        derived = container_identity_from_sbom(sbom)
        name = name or derived.get("name")
        version = version or derived.get("version")
        digest = digest or derived.get("digest")
        registry = registry or derived.get("registry")

    build_file = args.build_file
    if args.artefact_type == "BUILD_FILE" and not build_file:
        build_file = args.file_path

    return build_artefact_fields(
        artefact_type=args.artefact_type,
        build_file=build_file,
        container_name=name,
        container_version=version,
        container_digest=digest,
        registry=registry,
    )


def _await_translation(cfg: PhoenixConfig, args: argparse.Namespace, session, token, request_id) -> None:
    """Poll the translate request and report where it landed."""
    if not request_id:
        raise RuntimeError("Cannot wait for completion: no request id returned by Phoenix")
    final = wait_for_translate(cfg, session, token, request_id, auto_import=not args.no_auto_import)
    print(
        "Translation staged for review." if args.no_auto_import else "Import completed.",
        flush=True,
    )
    print(json.dumps(final, indent=2)[:1000], flush=True)


def run_sbom_upload(cfg: PhoenixConfig, args: argparse.Namespace, sbom: dict, context: dict) -> int:
    """
    Upload the report file itself and let Phoenix process it server-side.

    An explicit --scan-type names a report format ("Trivy Scan", ...) other than plain
    CycloneDX, which only the legacy translate endpoint can accept - the stateful endpoint
    fixes scanType to "PhxSbomSca:sbom" and always expects CycloneDX. Everything else goes to
    the stateful endpoint, which is now the default: it uses vulnerabilities already in the
    file and only falls back to dep-scan when the file has none, so a scanner-enriched SBOM no
    longer needs a separate --method vulnerability run.
    """
    if cfg.scan_type:
        return run_sbom_upload_translate(cfg, args, sbom, context)
    return run_sbom_upload_stateful(cfg, args, sbom, context)


def run_sbom_upload_stateful(cfg: PhoenixConfig, args: argparse.Namespace, sbom: dict, context: dict) -> int:
    """Upload to POST /v1/import/sboms - the default, queue-backed sbom-method path."""
    vuln_count = len(sbom.get("vulnerabilities", []))
    if vuln_count:
        analysis = f"Phoenix will import the {vuln_count} vulnerabilities already in the file"
    else:
        analysis = "Phoenix will run dep-scan (the file has no vulnerabilities of its own)"
    print(
        f"Method: sbom upload (stateful) | components={len(sbom.get('components', []))}, "
        f"vulnerabilities-in-file={vuln_count} ({analysis})",
        flush=True,
    )
    print(f"repository={context['repo']}", flush=True)

    # Resolved before the dry-run exit: a dry run exists to catch bad input without calling
    # the API, so invalid artefact options must still fail here, and the identity derived from
    # the BOM is exactly what a dry run is meant to show.
    artefact_fields = resolve_artefact_fields(args, sbom)
    if artefact_fields:
        print("Artefact: " + ", ".join(f"{k}={v}" for k, v in sorted(artefact_fields.items())), flush=True)

    if args.no_auto_import:
        print(
            "Warning: --no-auto-import has no effect here - the stateful endpoint always sets "
            "autoImport=true. Add --scan-type to route through the translate endpoint instead "
            "if you need a staged review.",
            file=sys.stderr,
            flush=True,
        )

    if args.dry_run:
        print("Dry-run enabled: no API call was made.", flush=True)
        return 0

    session = build_session()
    token = get_access_token(cfg, session)
    result = create_sbom_import(
        cfg=cfg,
        session=session,
        token=token,
        sbom_path=args.sbom_file,
        repository=context["repo"],
        scan_target=args.scan_target or context["file_path"],
        assessment_name=cfg.assessment_name,
        import_type=cfg.import_type,
        artefact_fields=artefact_fields,
        idempotency_key=args.idempotency_key,
    )
    request_id = result.get("id")
    print(f"SBOM import request queued (status={result.get('status', 'UNKNOWN')}).", flush=True)
    print(json.dumps(result, indent=2)[:1000], flush=True)

    if cfg.wait_for_completion:
        if not request_id:
            raise RuntimeError("Cannot wait for completion: no request id returned by Phoenix")
        final = wait_for_sbom_import(cfg, session, token, request_id)
        print("Import completed.", flush=True)
        print(json.dumps(final, indent=2)[:1000], flush=True)
    return 0


def run_sbom_upload_translate(cfg: PhoenixConfig, args: argparse.Namespace, sbom: dict, context: dict) -> int:
    """
    Upload to POST /v1/import/assets/file/translate - kept only for --scan-type.

    This is the one thing the stateful endpoint cannot do: import a report in a format other
    than plain CycloneDX (a native Trivy JSON, ...) by naming its scanType explicitly so Phoenix
    translates the findings it already carries instead of running dep-scan over it.
    """
    # cfg.scan_type is set on every path that reaches this function, so project_type is never
    # spent or warned about here.
    project_type = cfg.project_type
    scan_type = cfg.scan_type
    contents, analysis = describe_report(sbom, cfg.scan_type, args.sbom_file, scan_type)

    print(f"Method: sbom upload (translate) | {contents} ({analysis})", flush=True)
    print(f"scanType={scan_type}, importType={cfg.import_type}, repository={context['repo']}", flush=True)

    # Resolved before the dry-run exit: a dry run exists to catch bad input without calling
    # the API, so invalid artefact options must still fail here, and the identity derived from
    # the BOM is exactly what a dry run is meant to show.
    artefact_fields = resolve_artefact_fields(args, sbom)
    if artefact_fields:
        print("Artefact: " + ", ".join(f"{k}={v}" for k, v in sorted(artefact_fields.items())), flush=True)

    if args.dry_run:
        print("Dry-run enabled: no API call was made.", flush=True)
        return 0

    session = build_session()
    token = get_access_token(cfg, session)
    result = upload_sbom_file(
        cfg=cfg,
        session=session,
        token=token,
        sbom_path=args.sbom_file,
        repo=context["repo"],
        file_path=context["file_path"],
        auto_import=not args.no_auto_import,
        scan_target=args.scan_target or context["file_path"],
        artefact_fields=artefact_fields,
        project_type=project_type,
    )
    request_id = result.get("id") or result.get("requestId")
    print("SBOM uploaded successfully.", flush=True)
    print(json.dumps(result, indent=2)[:1000], flush=True)

    if cfg.wait_for_completion:
        _await_translation(cfg, args, session, token, request_id)
    return 0


def run_vulnerability_import(cfg: PhoenixConfig, args: argparse.Namespace, sbom: dict, context: dict) -> int:
    """Parse vulnerabilities out of the SBOM and post them as findings on one BUILD asset."""
    payload = build_payload(
        sbom=sbom,
        assessment_name=cfg.assessment_name,
        import_type=cfg.import_type,
        repo=context["repo"],
        file_path=context["file_path"],
        branch=context["branch"],
        origin=args.origin,
        ci_meta=context,
    )

    if args.payload_out:
        with open(args.payload_out, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)

    assets_count = len(payload.get("assets", []))
    findings_count = len(payload["assets"][0].get("findings", [])) if assets_count else 0
    print(f"Prepared payload: assets={assets_count}, findings={findings_count}", flush=True)

    if findings_count == 0 and sbom.get("components"):
        print(
            "Warning: the SBOM contains components but no vulnerabilities, so no findings "
            "will be imported. Re-scan with vulnerability analysis enabled (for example "
            "'trivy --scanners vuln'), or use --method sbom to let Phoenix analyse it.",
            file=sys.stderr,
            flush=True,
        )

    if args.dry_run:
        print("Dry-run enabled: no API call was made.", flush=True)
        return 0

    session = build_session()
    token = get_access_token(cfg, session)
    result = import_assets(cfg, session, token, payload)
    print("Import submitted successfully.", flush=True)
    print(json.dumps(result, indent=2), flush=True)
    return 0


_SBOM_ONLY_FLAGS = (
    ("--scan-type", "scan_type"),
)


_ARTEFACT_FLAGS = (
    ("--artefact-type", "artefact_type"),
    ("--build-file", "build_file"),
    ("--container-name", "container_name"),
    ("--container-version", "container_version"),
    ("--container-digest", "container_digest"),
    ("--registry", "registry"),
)


def _reject_artefact_options(args: argparse.Namespace) -> None:
    """
    Artefact identity describes the uploaded SBOM file, which the vulnerability method never sends.

    run_vulnerability_import posts findings parsed out of the BOM and never calls
    resolve_artefact_fields, so these flags previously did nothing and said nothing about it -
    the same silent no-op --wait and --no-auto-import are rejected for.
    """
    used = [flag for flag, attr in _ARTEFACT_FLAGS if getattr(args, attr, None)]
    if used:
        raise ValueError(
            f"{' and '.join(used)} {'apply' if len(used) > 1 else 'applies'} only to --method sbom. "
            f"The vulnerability method posts findings parsed from the BOM and sends no artefact "
            f"identity, so these would be ignored. Drop them, or switch to --method sbom."
        )

    used = [flag for flag, attr in _SBOM_ONLY_FLAGS if getattr(args, attr, None)]
    if used:
        raise ValueError(
            f"{' and '.join(used)} names the scanType on the translate upload, which only the "
            f"sbom method performs. The vulnerability method translates the report locally and "
            f"posts findings to /v1/import/assets, where there is no scanType. Drop it, or "
            f"switch to --method sbom."
        )


def validate_method_options(cfg: PhoenixConfig, args: argparse.Namespace) -> None:
    """
    Reject options that only mean something for the sbom method.

    --wait and --no-auto-import both describe the asynchronous translate request. The
    vulnerability method is a single synchronous POST with nothing to poll or stage, so asking
    for them there previously did nothing at all and said nothing about it.

    A CLI flag is an explicit request and fails. wait_for_completion coming from config.ini is
    only a warning: one config file is commonly shared across both methods, and a vulnerability
    run should not break because the file also configures sbom runs.
    """
    if cfg.method != "vulnerability":
        return
    explicit = []
    if args.wait:
        explicit.append("--wait")
    if args.no_auto_import:
        explicit.append("--no-auto-import")
    if explicit:
        raise ValueError(
            f"{' and '.join(explicit)} "
            f"{'apply' if len(explicit) > 1 else 'applies'} only to --method sbom. The vulnerability method "
            f"posts findings synchronously, so there is no translation to wait for or stage. "
            f"Drop the flag, or switch to --method sbom."
        )
    _reject_artefact_options(args)
    if cfg.wait_for_completion:
        print(
            "Warning: wait_for_completion is set but --method vulnerability imports "
            "synchronously, so it has no effect on this run.",
            file=sys.stderr,
            flush=True,
        )


def main() -> int:
    args = parse_args()
    try:
        cfg = load_config(args.config, args, require_credentials=not args.dry_run)
        validate_method_options(cfg, args)
        # An explicit scanType names the report format, and the sbom method uploads the file
        # rather than parsing it - so a Trivy native JSON is legitimate input there. Every
        # other path reads the document and still requires CycloneDX.
        if cfg.method == "sbom" and cfg.scan_type:
            sbom = read_report(args.sbom_file)
        else:
            sbom = read_sbom(args.sbom_file)
        context = resolve_repo_context(args)

        if cfg.method == "sbom":
            return run_sbom_upload(cfg, args, sbom, context)
        return run_vulnerability_import(cfg, args, sbom, context)

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
