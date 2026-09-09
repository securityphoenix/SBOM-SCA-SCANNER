"""
CI-provider auto-detection and repository/provenance resolution for the CI-PURPLE ingest client.

Unlike sbom-single-repo's `ci_context.py` (explicit `--from-*-env` flags, `owner/repo` asset key),
the CI-PURPLE contract (design `docs/plans/2026-08-28-ci-purple-sbom-ingest-design.md` Sec 3.1)
needs a full git remote URL, a full 40-hex commit SHA, and a `provenance` block keyed by an exact
`ciSystem` enum (`GITHUB_ACTIONS | JENKINS | AZURE_DEVOPS`) - GHSA/OSV-shaped guesses are rejected,
not best-effort mapped, by the server's validator, so getting these fields right locally matters.
This module therefore AUTO-DETECTS the provider from environment markers instead of requiring an
explicit flag, and prefers asking `git` directly for the remote URL and commit SHA (the checkout
itself is the most authoritative source and works identically across providers) before falling back
to provider-specific environment variables.

Bitbucket Pipelines is detected but never given a provenance block: Design D18 / Sec 3.1 says v1
supports exactly `GITHUB_ACTIONS | JENKINS | AZURE_DEVOPS`; the server rejects `ciSystem=BITBUCKET`
with `422 unsupported_ci_system`, so this client refuses locally (exit code 2) rather than shipping
a request the server will reject.
"""

import os
import subprocess
import sys
from typing import Dict, Optional, Tuple

GITHUB_ACTIONS = "GITHUB_ACTIONS"
JENKINS = "JENKINS"
AZURE_DEVOPS = "AZURE_DEVOPS"
BITBUCKET = "BITBUCKET"  # detected only so the caller can exit(2) with a helpful message

SUPPORTED_CI_SYSTEMS = (GITHUB_ACTIONS, JENKINS, AZURE_DEVOPS)


class CiContextError(ValueError):
    """Repository/provenance context could not be resolved."""


def _run_git(args, cwd: Optional[str] = None) -> Optional[str]:
    """
    Run a `git` subcommand and return its trimmed stdout, or None on any failure.

    Best-effort by design: a shallow/detached/worktree-less checkout, a missing `git` binary, or
    running outside a repository must fall back to CI environment variables rather than raise -
    those are all ordinary CI conditions, not errors.
    """
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    text = result.stdout.decode("utf-8", errors="replace").strip()
    return text or None


def detect_ci_provider() -> Optional[str]:
    """
    Detect the running CI provider from canonical, provider-published environment markers.

    Order matters for exactly one pair: Jenkins is checked BEFORE Bitbucket (Copilot review fix -
    the previous order checked Bitbucket first, which would misclassify an environment leaking BOTH
    `BITBUCKET_BUILD_NUMBER` and a Jenkins marker as Bitbucket even though Jenkins IS supported and
    Bitbucket is not; this also contradicted `jenkins_ci_purple_ingest_pipeline.groovy`'s own
    comment, which already documented Jenkins markers as taking precedence). Every other pair is
    specific enough that evaluation order between them does not change the result:
      - GitHub Actions sets `GITHUB_ACTIONS=true` on every run.
      - Azure Pipelines sets `TF_BUILD=True` on every run - this is Microsoft's own documented
        "am I running in Azure Pipelines" marker, not an inferred value.
      - Jenkins does not have one universally-set marker across all installations; `JENKINS_URL`
        is set when the admin configured it (common), and `BUILD_TAG` (`jenkins-<job>-<build>`) is
        set unconditionally by Jenkins core, so it is the reliable fallback.
      - Bitbucket Pipelines sets `BITBUCKET_BUILD_NUMBER` on every run - checked LAST, so a
        misconfigured/leaked environment that also carries a Jenkins marker still detects as
        Jenkins (a supported provider) rather than the unsupported Bitbucket.
    """
    if os.getenv("GITHUB_ACTIONS", "").strip().lower() == "true":
        return GITHUB_ACTIONS
    if os.getenv("TF_BUILD", "").strip().lower() == "true":
        return AZURE_DEVOPS
    if os.getenv("JENKINS_URL") or os.getenv("BUILD_TAG", "").startswith("jenkins-"):
        return JENKINS
    if os.getenv("BITBUCKET_BUILD_NUMBER"):
        return BITBUCKET
    return None


def strip_ref_prefix(ref: str) -> str:
    """Turn `refs/heads/main` or `origin/main` into `main`."""
    ref = ref.strip()
    if ref.startswith("refs/heads/"):
        return ref[len("refs/heads/"):]
    if ref.startswith("refs/tags/"):
        return ref[len("refs/tags/"):]
    if "/" in ref and ref.split("/", 1)[0] in {"origin", "refs"}:
        return ref.split("/", 1)[1]
    return ref


def resolve_git_remote_url(explicit: Optional[str], provider: Optional[str]) -> Optional[str]:
    """
    Resolve the git remote URL, highest precedence first:
      1. `explicit` (a `--git-remote-url` CLI override).
      2. `git remote get-url origin` in the current checkout - the same URL every provider's own
         checkout step configured, so it is provider-agnostic and does not need per-provider logic.
      3. A provider-specific environment reconstruction, for the case `git` is unavailable or the
         checkout has no `origin` remote (e.g. a detached fetch without a full clone).
    """
    if explicit:
        return explicit
    from_git = _run_git(["remote", "get-url", "origin"])
    if from_git:
        return from_git

    if provider == GITHUB_ACTIONS:
        server = os.getenv("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
        repository = os.getenv("GITHUB_REPOSITORY", "")
        if repository:
            return "{}/{}.git".format(server, repository)
    elif provider == JENKINS:
        url = os.getenv("GIT_URL") or os.getenv("GIT_URL_1")
        if url:
            return url
    elif provider == AZURE_DEVOPS:
        uri = os.getenv("BUILD_REPOSITORY_URI")
        if uri:
            return uri
    return None


def resolve_commit_sha(explicit: Optional[str], provider: Optional[str]) -> Optional[str]:
    """
    Resolve the full 40-hex commit SHA, highest precedence first: `explicit`, `git rev-parse HEAD`
    (works even on a shallow clone - shallow only limits history depth, not the SHA of HEAD
    itself), then a provider environment variable.
    """
    if explicit:
        return explicit
    from_git = _run_git(["rev-parse", "HEAD"])
    if from_git:
        return from_git

    if provider == GITHUB_ACTIONS:
        return os.getenv("GITHUB_SHA") or None
    if provider == JENKINS:
        return os.getenv("GIT_COMMIT") or None
    if provider == AZURE_DEVOPS:
        return os.getenv("BUILD_SOURCEVERSION") or None
    return None


def resolve_branch(explicit: Optional[str], provider: Optional[str]) -> Optional[str]:
    """
    Resolve the branch name.

    Deliberately prefers the CI provider's own environment variable over asking `git` - every
    provider in scope checks out a detached `HEAD` for the commit under test (that is how they
    build a specific SHA reproducibly), so `git branch --show-current` returns an EMPTY string in
    the exact environment this function needs to work in. The environment variable, not the
    checkout state, is the reliable source here - the opposite precedence from
    `resolve_git_remote_url`/`resolve_commit_sha` above, and deliberately so.
    """
    if explicit:
        return explicit

    if provider == GITHUB_ACTIONS:
        # GITHUB_HEAD_REF is the PR's source branch; on a pull_request event GITHUB_REF_NAME is
        # "<pr-number>/merge", not a branch name, so the head ref must be preferred when present.
        return os.getenv("GITHUB_HEAD_REF") or os.getenv("GITHUB_REF_NAME") or None
    if provider == JENKINS:
        return os.getenv("BRANCH_NAME") or (
            strip_ref_prefix(os.getenv("GIT_BRANCH", "")) if os.getenv("GIT_BRANCH") else None
        )
    if provider == AZURE_DEVOPS:
        # Same PR-source-branch trap as GitHub: on a PR trigger, BUILD_SOURCEBRANCH is
        # "refs/pull/<id>/merge", not a real branch. SYSTEM_PULLREQUEST_SOURCEBRANCH carries the
        # actual PR source branch and is set only on PR triggers, so it is preferred when present.
        #
        # BUILD_SOURCEBRANCHNAME is deliberately NOT used even though Azure Pipelines exposes it as
        # a ready-made "short branch name": for a branch containing a slash (e.g. "feature/foo"),
        # Azure derives BUILD_SOURCEBRANCHNAME by taking only the LAST path segment ("foo"), which
        # silently discards the "feature/" prefix. Stripping "refs/heads/" from BUILD_SOURCEBRANCH
        # ourselves keeps the branch name intact.
        pr_source = os.getenv("SYSTEM_PULLREQUEST_SOURCEBRANCH")
        if pr_source:
            return strip_ref_prefix(pr_source)
        source_branch = os.getenv("BUILD_SOURCEBRANCH")
        if source_branch:
            return strip_ref_prefix(source_branch)
        return None
    from_git = _run_git(["rev-parse", "--abbrev-ref", "HEAD"])
    if from_git and from_git != "HEAD":
        return from_git
    return None


def _drop_non_https_run_url(provenance: Dict[str, Optional[str]]) -> Dict[str, Optional[str]]:
    """
    I-2 fix: the server (`CiIngestRequestValidator.kt:139-142`) requires `provenance.runUrl` to
    start with `https://` WHEN PRESENT, but treats it as fully optional when absent. A large share
    of self-managed Jenkins controllers (and some on-prem Azure DevOps/GitHub Enterprise setups)
    serve on plain HTTP, so `BUILD_URL`/equivalent env vars commonly resolve to an `http://` value
    that would otherwise be shipped verbatim and guaranteed-422 server-side. Dropping it here is
    lossless for acceptance (the field is optional) and is strictly better than a round trip to
    discover the same rejection - matching every other check `preflight_validate` already makes.
    """
    run_url = provenance.get("runUrl")
    if run_url and not run_url.startswith("https://"):
        print(
            "Warning: provenance.runUrl {!r} does not start with https:// and would be rejected "
            "(422 invalid_input) by the server - omitting it. provenance.runUrl is optional, so "
            "omission does not block acceptance. Pass --run-url explicitly with an https:// value "
            "if you want this field populated.".format(run_url),
            file=sys.stderr,
            flush=True,
        )
        provenance = dict(provenance)
        provenance["runUrl"] = None
    return provenance


def build_provenance(
    provider: str,
    run_url_override: Optional[str] = None,
    runner_override: Optional[str] = None,
    pipeline_id_override: Optional[str] = None,
) -> Dict[str, Optional[str]]:
    """
    Build the `provenance` block for the given (already-detected, already-validated-supported)
    provider. `pipelineId` is documented in design Sec 3.1 as "provider run/build id" - a
    per-execution identifier, not the pipeline/job DEFINITION name - so each branch below picks the
    provider's own unique-per-run identifier, not a job/workflow name that repeats across runs.

    Every branch's `runUrl` (auto-detected OR `--run-url`-overridden) is passed through
    `_drop_non_https_run_url` before returning - see I-2 in task-8-report.md.
    """
    if provider == GITHUB_ACTIONS:
        server = os.getenv("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
        repository = os.getenv("GITHUB_REPOSITORY", "")
        run_id = os.getenv("GITHUB_RUN_ID", "")
        run_url = None
        if repository and run_id:
            run_url = "{}/{}/actions/runs/{}".format(server, repository, run_id)
        return _drop_non_https_run_url({
            "ciSystem": GITHUB_ACTIONS,
            "pipelineId": pipeline_id_override or run_id or None,
            "runUrl": run_url_override or run_url,
            "runner": runner_override or os.getenv("RUNNER_NAME") or os.getenv("RUNNER_OS") or None,
        })
    if provider == JENKINS:
        # BUILD_TAG ("jenkins-<job>-<build>") is preferred over the bare BUILD_NUMBER, which is
        # only unique WITHIN one job - two different jobs can both be on build #42 concurrently.
        return _drop_non_https_run_url({
            "ciSystem": JENKINS,
            "pipelineId": pipeline_id_override or os.getenv("BUILD_TAG") or os.getenv("BUILD_NUMBER") or None,
            "runUrl": run_url_override or os.getenv("BUILD_URL") or None,
            "runner": runner_override or os.getenv("NODE_NAME") or None,
        })
    if provider == AZURE_DEVOPS:
        collection_uri = os.getenv("SYSTEM_COLLECTIONURI", "")
        team_project = os.getenv("SYSTEM_TEAMPROJECT", "")
        build_id = os.getenv("BUILD_BUILDID", "")
        run_url = None
        if collection_uri and team_project and build_id:
            run_url = "{}{}/_build/results?buildId={}".format(collection_uri, team_project, build_id)
        return _drop_non_https_run_url({
            "ciSystem": AZURE_DEVOPS,
            "pipelineId": pipeline_id_override or build_id or None,
            "runUrl": run_url_override or run_url,
            "runner": runner_override or os.getenv("AGENT_NAME") or None,
        })
    raise CiContextError("build_provenance called with unsupported provider {!r}".format(provider))


def _pipeline_id_hint(provider: str) -> str:
    """Names the env var(s) `build_provenance` reads for `pipelineId` on the given provider, for
    the I-3 fail-fast message above."""
    if provider == GITHUB_ACTIONS:
        return "Expected GITHUB_RUN_ID to be set (GitHub Actions sets it on every run)."
    if provider == JENKINS:
        return "Expected BUILD_TAG or BUILD_NUMBER to be set (only present after a real build step - a freestyle job or an agent-side script run outside one may lack them)."
    if provider == AZURE_DEVOPS:
        return "Expected BUILD_BUILDID to be set (Azure Pipelines sets it on every run)."
    return ""


def _resolve_repo_fields(
    provider: Optional[str],
    git_remote_url_override: Optional[str],
    branch_override: Optional[str],
    commit_sha_override: Optional[str],
) -> Tuple[str, str, str]:
    """`gitRemoteUrl`/`branch`/`commitSha` resolution + the top-level "could not resolve" fail-fast,
    split out of `resolve_context` for the 50-LOC function limit (`.agent/rules/02-modularity.md`)."""
    git_remote_url = resolve_git_remote_url(git_remote_url_override, provider)
    branch = resolve_branch(branch_override, provider)
    commit_sha = resolve_commit_sha(commit_sha_override, provider)

    missing = [
        name
        for name, value in (("gitRemoteUrl", git_remote_url), ("branch", branch), ("commitSha", commit_sha))
        if not value
    ]
    if missing:
        hint = ""
        if provider is None:
            hint = (
                " No CI provider was auto-detected (checked GITHUB_ACTIONS, TF_BUILD, "
                "BITBUCKET_BUILD_NUMBER, JENKINS_URL/BUILD_TAG) and `git` could not supply it "
                "either - pass --git-remote-url/--branch/--commit-sha explicitly, or "
                "--ci-provider to force detection."
            )
        raise CiContextError(
            "Could not resolve required repository context: {}.{}".format(", ".join(missing), hint)
        )
    return git_remote_url, branch, commit_sha


def _resolve_provenance(
    provider: Optional[str],
    run_url_override: Optional[str],
    runner_override: Optional[str],
    pipeline_id_override: Optional[str],
) -> Dict[str, Optional[str]]:
    """
    `provenance` construction + its two provider-related fail-fasts + the I-3 pipelineId fail-fast,
    split out of `resolve_context` for the same 50-LOC limit.

    I-3 fix: `provenance.pipelineId` is the ONE provenance field the server REQUIRES (non-null,
    non-blank - `CiIngestRequestValidator.kt:138`'s `requireLen` throws 422 `invalid_input`
    otherwise), unlike `runUrl`/`runner` which are genuinely optional. A null `pipelineId` here means
    the environment marker `detect_ci_provider` used to recognize the provider was present, but the
    specific env var(s) that supply the run/build id were not - most plausibly a Jenkins freestyle
    job or an agent-side script run outside a normal build step (detected via `JENKINS_URL` alone,
    which does not itself guarantee `BUILD_TAG`/`BUILD_NUMBER` are set), or an Azure Pipelines agent
    stripped of `BUILD_BUILDID`. Fail fast with the same diagnostic style as `_resolve_repo_fields`'s
    fields, rather than silently emitting a request the server is guaranteed to 422 on this field.
    """
    provenance = None
    if provider in SUPPORTED_CI_SYSTEMS:
        provenance = build_provenance(provider, run_url_override, runner_override, pipeline_id_override)
    elif pipeline_id_override or run_url_override or runner_override:
        # No provider was auto-detected, but the caller supplied provenance fields directly
        # (e.g. a bare-metal/self-hosted runner with no recognized marker) - CiSystem must still
        # be stated explicitly via --ci-provider in that case; there is nothing to default to.
        raise CiContextError(
            "provenance fields were supplied but no supported CI provider was detected or given "
            "via --ci-provider (must be one of GITHUB_ACTIONS, JENKINS, AZURE_DEVOPS)."
        )

    if provenance is None:
        raise CiContextError(
            "No supported CI provider was detected (checked GITHUB_ACTIONS, TF_BUILD, "
            "BITBUCKET_BUILD_NUMBER, JENKINS_URL/BUILD_TAG). Pass --ci-provider to force one of "
            "GITHUB_ACTIONS, JENKINS, AZURE_DEVOPS, or run this from within that CI system."
        )

    if not provenance.get("pipelineId"):
        raise CiContextError(
            "Could not resolve required provenance.pipelineId for detected CI provider {}. "
            "{} Pass --pipeline-id explicitly to supply it.".format(provider, _pipeline_id_hint(provider))
        )
    return provenance


def resolve_context(
    provider_override: Optional[str] = None,
    git_remote_url_override: Optional[str] = None,
    branch_override: Optional[str] = None,
    commit_sha_override: Optional[str] = None,
    run_url_override: Optional[str] = None,
    runner_override: Optional[str] = None,
    pipeline_id_override: Optional[str] = None,
) -> Dict[str, object]:
    """
    Resolve the full context needed for one ingest request: `gitRemoteUrl`, `branch`, `commitSha`,
    and the `provenance` block, plus the detected `provider` for the caller to branch on (e.g. exit
    2 for Bitbucket before doing any of the work above).

    Raises `CiContextError` naming exactly which fields could not be resolved and, when a provider
    was detected, which environment/flag would have supplied them - mirroring the diagnostic style
    of sbom-single-repo's own `_validate_context`. Split into `_resolve_repo_fields`/
    `_resolve_provenance` (`.agent/rules/02-modularity.md`'s 50-LOC function limit); this function
    is now the orchestrator.
    """
    provider = provider_override or detect_ci_provider()

    if provider == BITBUCKET:
        return {"provider": BITBUCKET}

    git_remote_url, branch, commit_sha = _resolve_repo_fields(
        provider, git_remote_url_override, branch_override, commit_sha_override
    )
    provenance = _resolve_provenance(provider, run_url_override, runner_override, pipeline_id_override)

    return {
        "provider": provider,
        "gitRemoteUrl": git_remote_url,
        "branch": branch,
        "commitSha": commit_sha,
        "provenance": provenance,
    }
