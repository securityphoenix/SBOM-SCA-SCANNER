#!/usr/bin/env python3
"""
CI-PURPLE SBOM ingest client for Phoenix.

Submits one CycloneDX JSON SBOM to the new `/api/v1/external/sca/ingest` contract (design
`docs/plans/2026-08-28-ci-purple-sbom-ingest-design.md`, Sec 3.1/8.2) - a DIFFERENT API surface
from the sibling `sbom-single-repo/` tool (which targets Phoenix's older `/v1/import/assets*`
routes and keeps working unchanged for teams already using it; see that tool's own README for why
it exists and how it differs).

Flow:
  1. Auto-detect the CI provider (GitHub Actions, Jenkins, Azure DevOps) and resolve
     gitRemoteUrl/branch/commitSha/provenance - see `ci_context.py`. Bitbucket exits 2 immediately
     (unsupported in v1; `sbom-single-repo` supports it and is the recommended alternative).
  2. Read and locally pre-flight-validate the CycloneDX SBOM - see `ci_purple_sbom.py`.
  3. Mint a short-lived, CI-ingest-scoped token from the long-lived API key, submit the ingest,
     and (with --wait) poll to a terminal state, auto-retrying a retryable failure and gating the
     exit code on the terminal verdict - see `ci_purple_client.py`.

Supporting modules live alongside this file and must be deployed with it:
    ci_context.py       CI-provider auto-detection and repo/provenance resolution
    ci_purple_sbom.py   CycloneDX reading, local pre-flight validation, request-body construction
    ci_purple_client.py Phoenix HTTP transport: token exchange, ingest, status/result/retry, retry

Exit codes:
    0   Ingest submitted (no --wait), or --wait completed with a terminal verdict other than BLOCK.
    1   Any handled runtime failure: bad configuration, unreadable/non-CycloneDX/locally-invalid
        SBOM, missing CI context, auth failure, non-2xx response, terminal FAILED (not retryable or
        retries exhausted), or a --wait timeout. The reason is printed to stderr.
    2   Invalid command line (argparse), OR the detected CI provider is Bitbucket (unsupported in
        v1 - use `sbom-single-repo` instead, see the printed message for the exact command).
    3   --wait completed and the terminal result's verdict is BLOCK - the CI pipeline gate should
        fail the build on this exit code specifically, distinct from a client-side error (1).

`main()`/`parse_args()` are both orchestrators over small per-stage helpers below
(`.agent/rules/02-modularity.md`'s 50-LOC function limit, Copilot review finding) - see each
helper's own docstring for the stage it covers.
"""

import argparse
import json
import os
import sys
from typing import Dict, Optional, Tuple

from ci_context import BITBUCKET, CiContextError, SUPPORTED_CI_SYSTEMS, resolve_context
from ci_purple_config import CiPurpleConfigFileError, load_config
from ci_purple_client import (
    CiPurpleApiError,
    CiPurpleConfig,
    CiPurpleTokenManager,
    build_session,
    get_result,
    submit_ingest,
    validate_api_base_url,
    wait_for_terminal,
)
from ci_purple_sbom import (
    AssetInput,
    RequestContext,
    SbomReadError,
    build_request_body,
    check_gateway_budget,
    preflight_validate,
    read_sbom,
)

BITBUCKET_ALTERNATIVE_MESSAGE = (
    "Bitbucket Pipelines is not a supported CI system for CI-PURPLE ingest in v1 (design D18) - "
    "the server rejects ciSystem=BITBUCKET with 422 unsupported_ci_system, so this client refuses "
    "locally instead of shipping a request that would be rejected anyway.\n\n"
    "Use the existing 'sbom-single-repo' tool instead, which DOES support Bitbucket Pipelines:\n\n"
    "    python3 ../sbom-single-repo/sbom_sca_single_repo_to_phoenix.py \\\n"
    "        --sbom-file <path> --file-path <manifest> --from-bitbucket-env --import-type merge\n\n"
    "See Utils/SBOM-SCA-CONTAINER-PIPELINE/sbom-single-repo/README.md 'Bitbucket Pipeline mode' "
    "for the full example."
)


def _add_sbom_and_asset_args(parser: argparse.ArgumentParser) -> None:
    """`--sbom-file` + the two asset kinds' own flags."""
    parser.add_argument("--sbom-file", required=True, help="Path to a CycloneDX JSON (1.4/1.5/1.6) SBOM")
    parser.add_argument("--asset-kind", choices=["REPO", "CONTAINER_IMAGE"], default="REPO")
    parser.add_argument("--build-file-path", help="REPO asset: manifest path, e.g. package-lock.json")
    parser.add_argument("--registry", help="CONTAINER_IMAGE asset: registry host, e.g. ghcr.io")
    parser.add_argument("--image", help="CONTAINER_IMAGE asset: image name, e.g. acme/payments-service")
    parser.add_argument("--tag", help="CONTAINER_IMAGE asset: image tag, e.g. v1.0.0")
    parser.add_argument("--digest", help="CONTAINER_IMAGE asset: exact sha256:<64 hex> digest")
    parser.add_argument("--dockerfile-path", help="CONTAINER_IMAGE: Dockerfile path relative to the repo root")
    parser.add_argument("--from-line", type=int, help="CONTAINER_IMAGE: optional FROM line number in the Dockerfile")
    parser.add_argument("--base-image-ref", help="CONTAINER_IMAGE: optional exact FROM reference")


def _add_ci_context_args(parser: argparse.ArgumentParser) -> None:
    """CI-provider auto-detection overrides."""
    parser.add_argument(
        "--ci-provider",
        choices=list(SUPPORTED_CI_SYSTEMS) + [BITBUCKET],
        help="Force the CI provider instead of auto-detecting it from the environment",
    )
    parser.add_argument("--git-remote-url", help="Override the auto-detected git remote URL")
    parser.add_argument("--branch", help="Override the auto-detected branch")
    parser.add_argument("--commit-sha", help="Override the auto-detected 40-hex commit SHA")
    parser.add_argument("--run-url", help="Override the auto-detected provenance.runUrl")
    parser.add_argument("--runner", help="Override the auto-detected provenance.runner")
    parser.add_argument("--pipeline-id", help="Override the auto-detected provenance.pipelineId")
    parser.add_argument("--workspace-id", help="Optional explicit Phoenix workspace UUID to disambiguate")


def _add_auth_and_tls_args(parser: argparse.ArgumentParser) -> None:
    """API key/base-URL and TLS verification flags."""
    parser.add_argument(
        "--api-key",
        help=(
            "Phoenix API key (phx_live_*/phx_dev_*), scoped to ci:ingest. Prefer the "
            "PHOENIX_API_KEY environment variable instead (both shipped pipeline templates use "
            "it) - a value on the command line is visible in the process list (`ps`) and shell "
            "history. This flag exists for local ad-hoc debugging only."
        ),
    )
    parser.add_argument(
        "--config",
        help="Path to a config.ini (default: config.ini beside this script, if present). "
             "Flags and environment variables both override it.",
    )
    parser.add_argument("--api-base-url", help="Phoenix API base URL override")

    tls = parser.add_mutually_exclusive_group()
    tls.add_argument("--verify-tls", action="store_true", help="Force TLS certificate verification (default)")
    tls.add_argument("--no-verify-tls", action="store_true", help="Disable TLS verification")
    parser.add_argument(
        "--ca-bundle",
        help="Path to a custom CA bundle for TLS verification (self-hosted Phoenix / TLS-inspecting proxy)",
    )
    parser.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help="Permit an http:// api-base-url. Exposes the API key/token on the wire - lab/mock use only.",
    )


def _add_retry_and_wait_args(parser: argparse.ArgumentParser) -> None:
    """Transport-retry tuning, --wait polling, and dry-run/payload-dump flags."""
    parser.add_argument("--timeout-seconds", type=int, default=60, help="Per-request HTTP timeout")
    parser.add_argument("--max-retry-attempts", type=int, default=5, help="Transport-retry ceiling per call")
    parser.add_argument("--retry-base-delay-seconds", type=float, default=1.0)
    parser.add_argument("--retry-max-delay-seconds", type=float, default=30.0)

    parser.add_argument("--wait", action="store_true", help="Poll until the ingest job reaches a terminal state")
    parser.add_argument("--poll-interval-seconds", type=int, default=10)
    parser.add_argument("--wait-timeout-seconds", type=int, default=1800)

    parser.add_argument("--dry-run", action="store_true", help="Build and pre-flight-validate the request, no API calls")
    parser.add_argument("--payload-out", help="Write the generated request body JSON to this file")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Submit a CycloneDX SBOM to Phoenix's CI-PURPLE SBOM ingest endpoint."
    )
    _add_sbom_and_asset_args(parser)
    _add_ci_context_args(parser)
    _add_auth_and_tls_args(parser)
    _add_retry_and_wait_args(parser)
    return parser.parse_args()


def _resolve_verify_tls(args: argparse.Namespace) -> object:
    if args.ca_bundle:
        if args.no_verify_tls:
            raise ValueError("--ca-bundle and --no-verify-tls are mutually exclusive.")
        return args.ca_bundle
    env_ca_bundle = os.getenv("PHOENIX_CA_BUNDLE")
    if env_ca_bundle and not args.no_verify_tls:
        return env_ca_bundle
    return not args.no_verify_tls


def _print_status_transition(previous_status: Optional[str]):
    """Returns a callback that prints only NEW statuses (never the same one twice), never touching
    the token/credential the status payload does not contain in the first place."""

    state = {"previous": previous_status}

    def _on_status(payload):
        status = payload.get("status")
        if status != state["previous"]:
            print("Ingest status: {}".format(status), flush=True)
            state["previous"] = status

    return _on_status


def _resolve_cli_context(args: argparse.Namespace) -> Tuple[Optional[Dict], Optional[int]]:
    """
    Stage 1 of `main()`: CI-context resolution. Returns `(context, None)` on success, or
    `(None, exit_code)` when the caller should return immediately - Bitbucket detection happens
    FIRST, before reading the SBOM or requiring credentials (brief item 4), so a Bitbucket user
    gets an immediate, actionable message with no other setup needed.
    """
    try:
        context = resolve_context(
            provider_override=args.ci_provider,
            git_remote_url_override=args.git_remote_url,
            branch_override=args.branch,
            commit_sha_override=args.commit_sha,
            run_url_override=args.run_url,
            runner_override=args.runner,
            pipeline_id_override=args.pipeline_id,
        )
    except CiContextError as exc:
        print("Error: {}".format(exc), file=sys.stderr, flush=True)
        return None, 1

    if context.get("provider") == BITBUCKET:
        print(BITBUCKET_ALTERNATIVE_MESSAGE, file=sys.stderr, flush=True)
        return None, 2

    return context, None


def _read_and_validate_sbom(args: argparse.Namespace) -> Tuple[Optional[Dict], Optional[int]]:
    """Read the SBOM file and locally pre-flight-validate it, split out of `_prepare_payload` for
    the 50-LOC function limit (`.agent/rules/02-modularity.md`). Returns `(sbom, None)` on success,
    or `(None, exit_code)` when the caller should return immediately."""
    try:
        sbom = read_sbom(args.sbom_file)
    except SbomReadError as exc:
        print("Error: {}".format(exc), file=sys.stderr, flush=True)
        return None, 1

    problems = preflight_validate(sbom)
    if problems:
        print(
            "Error: local pre-flight validation found {} problem(s) the server would also reject "
            "(this list is best-effort and may not be exhaustive - see ci_purple_sbom.py):".format(len(problems)),
            file=sys.stderr,
            flush=True,
        )
        for problem in problems:
            print("  - {}".format(problem), file=sys.stderr, flush=True)
        return None, 1
    return sbom, None


def _build_body_or_exit(args: argparse.Namespace, context: Dict, sbom: Dict) -> Tuple[Optional[Dict], Optional[int]]:
    """Build the request body and check it against the gateway size budget, split out of
    `_prepare_payload` for the same 50-LOC limit. Returns `(body, None)` on success, or
    `(None, exit_code)` when the caller should return immediately."""
    try:
        req_context = RequestContext(
            git_remote_url=context["gitRemoteUrl"],
            branch=context["branch"],
            commit_sha=context["commitSha"],
            provenance=context["provenance"],
        )
        asset = AssetInput(
            kind=args.asset_kind,
            build_file_path=args.build_file_path,
            registry=args.registry,
            image=args.image,
            tag=args.tag,
            digest=args.digest,
            dockerfile_path=args.dockerfile_path,
            from_line=args.from_line,
            base_image_ref=args.base_image_ref,
        )
        body = build_request_body(req_context, sbom, asset, workspace_id=args.workspace_id)
    except ValueError as exc:
        print("Error: {}".format(exc), file=sys.stderr, flush=True)
        return None, 1

    budget_ok, budget_message = check_gateway_budget(body)
    if budget_message:
        print(("Error: " if not budget_ok else "Warning: ") + budget_message, file=sys.stderr, flush=True)
    if not budget_ok:
        return None, 1
    return body, None


def _prepare_payload(args: argparse.Namespace, context: Dict) -> Tuple[Optional[Tuple[Dict, Dict]], Optional[int]]:
    """
    Stage 2 of `main()`, now itself split into `_read_and_validate_sbom`/`_build_body_or_exit`
    (`.agent/rules/02-modularity.md`'s 50-LOC function limit) - this is the orchestrator. Returns
    `((sbom, body), None)` on success, or `(None, exit_code)` when the caller should return
    immediately. Also writes `--payload-out` and prints the "Prepared request: ..." summary line on
    success - both happen regardless of `--dry-run`, which the caller checks after this returns.
    """
    sbom, exit_code = _read_and_validate_sbom(args)
    if exit_code is not None:
        return None, exit_code

    body, exit_code = _build_body_or_exit(args, context, sbom)
    if exit_code is not None:
        return None, exit_code

    if args.payload_out:
        with open(args.payload_out, "w", encoding="utf-8") as handle:
            json.dump(body, handle, indent=2)

    component_count = len(sbom.get("components", []))
    vulnerability_count = len(sbom.get("vulnerabilities", []))
    print(
        "Prepared request: ciSystem={} assetKind={} components={} vulnerabilities={}".format(
            context["provenance"]["ciSystem"], args.asset_kind, component_count, vulnerability_count
        ),
        flush=True,
    )
    return (sbom, body), None


def _resolve_client_config(
    args: argparse.Namespace, file_cfg: Optional[object] = None
) -> Tuple[Optional[CiPurpleConfig], Optional[int]]:
    """Resolve credentials, base URL, and TLS config into a `CiPurpleConfig`, split out of
    `_submit_request` for the 50-LOC function limit. Returns `(cfg, None)` on success, or
    `(None, exit_code)` when the caller should return immediately."""
    file_cfg = file_cfg if file_cfg is not None else load_config()
    api_key = args.api_key or os.getenv("PHOENIX_API_KEY") or file_cfg.get("api_key")
    if not api_key:
        print(
            "Error: missing Phoenix API key. Pass --api-key or set PHOENIX_API_KEY. The key must "
            "be scoped with exactly scopes: [\"ci:ingest\"].",
            file=sys.stderr,
            flush=True,
        )
        return None, 1
    api_base_url = (
        args.api_base_url
        or os.getenv("PHOENIX_API_BASE_URL")
        or file_cfg.get("api_base_url")
        or "https://api.securityphoenix.cloud"
    ).rstrip("/")

    try:
        verify_tls = _resolve_verify_tls(args)
    except ValueError as exc:
        print("Error: {}".format(exc), file=sys.stderr, flush=True)
        return None, 1

    cfg = CiPurpleConfig(
        api_base_url=api_base_url,
        api_key=api_key,
        verify_tls=verify_tls,
        allow_insecure_http=args.allow_insecure_http or bool(file_cfg.get_bool("allow_insecure_http")),
        timeout_seconds=args.timeout_seconds,
        max_retry_attempts=args.max_retry_attempts,
        retry_base_delay_seconds=args.retry_base_delay_seconds,
        retry_max_delay_seconds=args.retry_max_delay_seconds,
    )

    # M-1 fix: validate_api_base_url raises a plain ValueError (never a CiPurpleApiError) - called
    # explicitly here so an http:// base URL prints this tool's own "Error: ..." line instead of an
    # unhandled traceback (CiPurpleTokenManager._mint calls it again per-mint; deliberately
    # redundant so the error-reporting contract is honoured before any network work is attempted).
    try:
        validate_api_base_url(cfg)
    except ValueError as exc:
        print("Error: {}".format(exc), file=sys.stderr, flush=True)
        return None, 1
    return cfg, None


def _submit_request(
    args: argparse.Namespace, body: Dict, file_cfg: Optional[object] = None
) -> Tuple[Optional[Tuple[CiPurpleConfig, object, CiPurpleTokenManager, Dict]], Optional[int]]:
    """
    Stage 3 of `main()`, now split with `_resolve_client_config` for the 50-LOC function limit:
    build the session and submit the ingest. Returns `((cfg, session, token_manager, accepted),
    None)` on success, or `(None, exit_code)` when the caller should return immediately.
    """
    cfg, exit_code = _resolve_client_config(args, file_cfg)
    if exit_code is not None:
        return None, exit_code

    session = build_session(cfg)
    token_manager = CiPurpleTokenManager(cfg, session)

    try:
        accepted = submit_ingest(cfg, session, token_manager, body)
    except CiPurpleApiError as exc:
        print("Error: {}".format(exc), file=sys.stderr, flush=True)
        return None, 1

    print(
        "Ingest accepted: jobId={} workspaceId={} duplicate={} statusUrl={}".format(
            accepted["jobId"], accepted.get("workspaceId"), accepted.get("duplicate"), accepted.get("statusUrl")
        ),
        flush=True,
    )
    return (cfg, session, token_manager, accepted), None


def _wait_and_gate(
    args: argparse.Namespace, cfg: CiPurpleConfig, session: object, token_manager: CiPurpleTokenManager, accepted: Dict
) -> int:
    """Stage 4 of `main()`, only reached when `--wait` was passed: poll to a terminal state,
    fetch the result, and gate the exit code on its verdict (see the module docstring's exit-code
    table). Always returns an int."""
    job_id = accepted["jobId"]
    try:
        final_status = wait_for_terminal(
            cfg,
            session,
            token_manager,
            job_id,
            poll_interval_seconds=args.poll_interval_seconds,
            wait_timeout_seconds=args.wait_timeout_seconds,
            on_status=_print_status_transition(accepted.get("status")),
        )
    except (CiPurpleApiError, TimeoutError) as exc:
        print("Error: {}".format(exc), file=sys.stderr, flush=True)
        return 1

    status = final_status.get("status")
    if status == "FAILED":
        print(
            "Error: ingest job {} FAILED (category={}, retryable={}). See {} for detail.".format(
                job_id, final_status.get("failureCategory"), final_status.get("retryable"), accepted.get("statusUrl") or job_id
            ),
            file=sys.stderr,
            flush=True,
        )
        return 1

    try:
        result = get_result(cfg, session, token_manager, job_id)
    except CiPurpleApiError as exc:
        print("Error: {}".format(exc), file=sys.stderr, flush=True)
        return 1

    print(
        "Ingest {}: verdict={} components={} vulnerabilities={}".format(
            status, result.get("verdict"), result.get("componentCount"), result.get("vulnerabilityCount")
        ),
        flush=True,
    )
    if result.get("verdict") == "BLOCK":
        print("Policy verdict is BLOCK - failing the build (exit 3).", file=sys.stderr, flush=True)
        return 3
    return 0


def _load_file_config(args: argparse.Namespace) -> Tuple[Optional[object], Optional[int]]:
    """Load `config.ini` before any other stage, so an explicit `--config` that is missing or
    unparseable fails the run even under `--dry-run` (which returns before any API call is
    made). An ABSENT default `config.ini` is not an error -- that is the normal CI case."""
    requested = getattr(args, "config", None)
    try:
        file_cfg = load_config(requested, required=bool(requested))
    except CiPurpleConfigFileError as exc:
        print("Error: {}".format(exc), file=sys.stderr, flush=True)
        return None, 1
    if len(file_cfg):
        print("Config: {}".format(file_cfg.describe_source()), flush=True)
    return file_cfg, None


def main() -> int:
    """Orchestrates the four stages above (`.agent/rules/02-modularity.md`'s 50-LOC function
    limit) - see the module docstring for the full flow and exit-code contract."""
    args = parse_args()

    file_cfg, exit_code = _load_file_config(args)
    if exit_code is not None:
        return exit_code

    context, exit_code = _resolve_cli_context(args)
    if exit_code is not None:
        return exit_code

    prepared, exit_code = _prepare_payload(args, context)
    if exit_code is not None:
        return exit_code
    _sbom, body = prepared

    if args.dry_run:
        print("Dry-run enabled: no API call was made.", flush=True)
        return 0

    submission, exit_code = _submit_request(args, body, file_cfg)
    if exit_code is not None:
        return exit_code
    cfg, session, token_manager, accepted = submission

    if not args.wait:
        return 0

    return _wait_and_gate(args, cfg, session, token_manager, accepted)


if __name__ == "__main__":
    sys.exit(main())
