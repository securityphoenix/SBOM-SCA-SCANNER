"""
Repository context resolution.

Works out the repo, manifest path, and branch that form the Phoenix asset key, plus the commit,
build number, and run URL recorded as tags. Values come from CLI flags, or from the environment
of whichever CI system is in use.
"""

import argparse
import os
from typing import Dict


def repo_from_git_url(git_url: str) -> str:
    """
    Derive an `org/repo` identifier from a git remote URL.

    Handles both HTTP(S) remotes (https://github.com/acme/payments.git) and
    scp-style SSH remotes (git@github.com:acme/payments.git).
    """
    url = git_url.strip()
    if not url:
        return ""
    if url.endswith(".git"):
        url = url[: -len(".git")]

    if "://" in url:
        without_scheme = url.split("://", 1)[1]
        parts = without_scheme.split("/", 1)
        url = parts[1] if len(parts) > 1 else ""
    elif ":" in url:
        url = url.split(":", 1)[1]

    return url.strip("/")


# Longest first: refs/remotes/origin/ must be tried before refs/remotes/ and refs/.
_REF_PREFIXES = (
    "refs/remotes/origin/",
    "refs/remotes/",
    "refs/heads/",
    "refs/tags/",
    "origin/",
    "refs/",
)


def strip_remote_prefix(branch: str) -> str:
    """
    Turn a Jenkins GIT_BRANCH value into a bare branch or tag name.

    Each known prefix is stripped explicitly. A generic "drop the first segment" rule left
    `refs/tags/v1.0.0` as `tags/v1.0.0` and `refs/remotes/origin/dev` as `remotes/origin/dev`,
    both of which reach the asset key - so the same file built from a tag was recorded as a
    different asset from the same file built from a branch.
    """
    branch = branch.strip()
    for prefix in _REF_PREFIXES:
        if branch.startswith(prefix):
            return branch[len(prefix):]
    return branch


def _apply_bitbucket_env(context: Dict[str, str]) -> None:
    """Fill context from Bitbucket Pipelines variables. CLI values already set win."""
    context["repo"] = context["repo"] or os.getenv("BITBUCKET_REPO_FULL_NAME", "")
    context["branch"] = context["branch"] or os.getenv("BITBUCKET_BRANCH", "")
    context["commit"] = os.getenv("BITBUCKET_COMMIT", "")
    context["build_number"] = os.getenv("BITBUCKET_BUILD_NUMBER", "")

    workspace = os.getenv("BITBUCKET_WORKSPACE", "")
    repo_slug = os.getenv("BITBUCKET_REPO_SLUG", "")
    if workspace and repo_slug and context["build_number"]:
        context["pipeline_url"] = (
            f"https://bitbucket.org/{workspace}/{repo_slug}/pipelines/results/{context['build_number']}"
        )


def _apply_jenkins_env(context: Dict[str, str]) -> None:
    """Fill context from Jenkins variables, which only exist after a checkout step."""
    context["repo"] = (
        context["repo"] or repo_from_git_url(os.getenv("GIT_URL", "")) or os.getenv("JOB_NAME", "")
    )
    context["branch"] = (
        context["branch"]
        or os.getenv("BRANCH_NAME", "")
        or strip_remote_prefix(os.getenv("GIT_BRANCH", ""))
    )
    context["commit"] = os.getenv("GIT_COMMIT", "")
    context["build_number"] = os.getenv("BUILD_NUMBER", "")
    context["pipeline_url"] = os.getenv("BUILD_URL", "")


def _apply_github_env(context: Dict[str, str]) -> None:
    """Fill context from GitHub Actions variables."""
    # GITHUB_REPOSITORY is already "owner/repo", the exact shape the asset key wants.
    context["repo"] = context["repo"] or os.getenv("GITHUB_REPOSITORY", "")
    # On pull_request events GITHUB_REF_NAME is "<pr>/merge", so the head branch wins.
    context["branch"] = (
        context["branch"]
        or os.getenv("GITHUB_HEAD_REF", "")
        or os.getenv("GITHUB_REF_NAME", "")
    )
    context["commit"] = os.getenv("GITHUB_SHA", "")
    context["build_number"] = os.getenv("GITHUB_RUN_NUMBER", "")

    server = os.getenv("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    repository = os.getenv("GITHUB_REPOSITORY", "")
    run_id = os.getenv("GITHUB_RUN_ID", "")
    if repository and run_id:
        context["pipeline_url"] = f"{server}/{repository}/actions/runs/{run_id}"


def _validate_context(context: Dict[str, str], args: argparse.Namespace) -> None:
    """Raise if repo/file_path/branch could not be resolved, hinting at the likely cause."""
    missing = [k for k in ("repo", "file_path", "branch") if not context[k]]
    if not missing:
        return
    hints = (
        (args.from_bitbucket_env, " (tip: use --from-bitbucket-env in Bitbucket Pipelines)"),
        (args.from_jenkins_env, " (tip: Jenkins only exports GIT_URL/GIT_BRANCH after a checkout step)"),
        (args.from_github_env, " (tip: GITHUB_REPOSITORY/GITHUB_REF_NAME are only set inside GitHub Actions)"),
    )
    mode_hint = next((h for enabled, h in hints if enabled), "")
    raise ValueError(f"Missing required repository context: {', '.join(missing)}{mode_hint}")


def resolve_repo_context(args: argparse.Namespace) -> Dict[str, str]:
    """
    Resolve required repository context from CLI and optionally CI env vars.
    """
    selected_ci = [
        name
        for name, enabled in (
            ("--from-bitbucket-env", args.from_bitbucket_env),
            ("--from-jenkins-env", args.from_jenkins_env),
            ("--from-github-env", args.from_github_env),
        )
        if enabled
    ]
    if len(selected_ci) > 1:
        raise ValueError(f"{' and '.join(selected_ci)} are mutually exclusive")

    context = {
        "repo": args.repo or "",
        "file_path": args.file_path or "",
        "branch": args.branch or "",
        "commit": "",
        "build_number": "",
        "pipeline_url": "",
    }

    if args.from_bitbucket_env:
        _apply_bitbucket_env(context)
    if args.from_jenkins_env:
        _apply_jenkins_env(context)
    if args.from_github_env:
        _apply_github_env(context)

    _validate_context(context, args)
    return context
