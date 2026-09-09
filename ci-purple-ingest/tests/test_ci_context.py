"""
Contract tests for `ci_context.py`: CI-provider auto-detection and provenance resolution.

`git` subprocess calls are mocked out everywhere (monkeypatching `ci_context._run_git`) - these
tests must run in CI with no dependency on the actual checkout state, per the brief's "mock the
HTTP layer/do not require a live [...] instance" instruction extended here to the `git` dependency
too, so a test run never depends on whether the sandbox running it happens to be inside a real git
checkout with a configured `origin` remote.
"""

import pytest

import ci_context


@pytest.fixture(autouse=True)
def _clean_ci_env(monkeypatch):
    """Every test starts from a CI-marker-free environment - otherwise running these tests INSIDE
    a real CI system (which this very tool will eventually run under) would leak markers into the
    test itself and make results depend on where the suite executes."""
    for var in (
        "GITHUB_ACTIONS", "GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID",
        "GITHUB_HEAD_REF", "GITHUB_REF_NAME", "GITHUB_SHA", "RUNNER_NAME", "RUNNER_OS",
        "TF_BUILD", "BUILD_REPOSITORY_URI", "BUILD_SOURCEBRANCH", "BUILD_SOURCEBRANCHNAME",
        "BUILD_SOURCEVERSION", "BUILD_BUILDID", "SYSTEM_COLLECTIONURI", "SYSTEM_TEAMPROJECT",
        "AGENT_NAME", "SYSTEM_PULLREQUEST_SOURCEBRANCH",
        "BITBUCKET_BUILD_NUMBER",
        "JENKINS_URL", "BUILD_TAG", "BUILD_NUMBER", "BUILD_URL", "NODE_NAME", "GIT_URL",
        "GIT_URL_1", "GIT_BRANCH", "GIT_COMMIT", "BRANCH_NAME",
    ):
        monkeypatch.delenv(var, raising=False)
    yield


def test_detect_none_when_no_markers_present():
    assert ci_context.detect_ci_provider() is None


def test_detect_github_actions(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert ci_context.detect_ci_provider() == ci_context.GITHUB_ACTIONS


def test_detect_azure_devops(monkeypatch):
    monkeypatch.setenv("TF_BUILD", "True")
    assert ci_context.detect_ci_provider() == ci_context.AZURE_DEVOPS


def test_detect_bitbucket(monkeypatch):
    monkeypatch.setenv("BITBUCKET_BUILD_NUMBER", "42")
    assert ci_context.detect_ci_provider() == ci_context.BITBUCKET


def test_detect_jenkins_via_jenkins_url(monkeypatch):
    monkeypatch.setenv("JENKINS_URL", "https://jenkins.example.com/")
    assert ci_context.detect_ci_provider() == ci_context.JENKINS


def test_detect_jenkins_via_build_tag_fallback(monkeypatch):
    # JENKINS_URL is not guaranteed to be configured by every Jenkins admin; BUILD_TAG is set
    # unconditionally by Jenkins core and is the documented fallback marker.
    monkeypatch.setenv("BUILD_TAG", "jenkins-my-job-42")
    assert ci_context.detect_ci_provider() == ci_context.JENKINS


def test_github_actions_precedence_over_others(monkeypatch):
    # A misconfigured environment could plausibly leak multiple markers (e.g. a self-hosted
    # Jenkins agent that also sets TF_BUILD for an unrelated reason) - GitHub Actions' own
    # boolean marker is checked first and is exact, so it should win.
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("TF_BUILD", "True")
    assert ci_context.detect_ci_provider() == ci_context.GITHUB_ACTIONS


def test_strip_ref_prefix():
    assert ci_context.strip_ref_prefix("refs/heads/main") == "main"
    assert ci_context.strip_ref_prefix("refs/heads/feature/foo") == "feature/foo"
    assert ci_context.strip_ref_prefix("origin/main") == "main"
    assert ci_context.strip_ref_prefix("main") == "main"


def test_resolve_git_remote_url_explicit_wins(monkeypatch):
    monkeypatch.setattr(ci_context, "_run_git", lambda *a, **k: "https://example.com/should-not-be-used.git")
    result = ci_context.resolve_git_remote_url("https://github.com/acme/app.git", ci_context.GITHUB_ACTIONS)
    assert result == "https://github.com/acme/app.git"


def test_resolve_git_remote_url_prefers_git_over_env(monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setattr(ci_context, "_run_git", lambda *a, **k: "git@github.com:acme/app.git")
    result = ci_context.resolve_git_remote_url(None, ci_context.GITHUB_ACTIONS)
    assert result == "git@github.com:acme/app.git"


def test_resolve_git_remote_url_github_env_fallback(monkeypatch):
    monkeypatch.setattr(ci_context, "_run_git", lambda *a, **k: None)
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    result = ci_context.resolve_git_remote_url(None, ci_context.GITHUB_ACTIONS)
    assert result == "https://github.com/acme/app.git"


def test_resolve_git_remote_url_azure_env_fallback(monkeypatch):
    monkeypatch.setattr(ci_context, "_run_git", lambda *a, **k: None)
    monkeypatch.setenv("BUILD_REPOSITORY_URI", "https://dev.azure.com/acme/app/_git/app")
    result = ci_context.resolve_git_remote_url(None, ci_context.AZURE_DEVOPS)
    assert result == "https://dev.azure.com/acme/app/_git/app"


def test_resolve_commit_sha_prefers_git(monkeypatch):
    monkeypatch.setattr(ci_context, "_run_git", lambda *a, **k: "a" * 40)
    monkeypatch.setenv("GITHUB_SHA", "b" * 40)
    assert ci_context.resolve_commit_sha(None, ci_context.GITHUB_ACTIONS) == "a" * 40


def test_resolve_commit_sha_env_fallback(monkeypatch):
    monkeypatch.setattr(ci_context, "_run_git", lambda *a, **k: None)
    monkeypatch.setenv("GITHUB_SHA", "b" * 40)
    assert ci_context.resolve_commit_sha(None, ci_context.GITHUB_ACTIONS) == "b" * 40


def test_resolve_branch_github_prefers_head_ref(monkeypatch):
    monkeypatch.setenv("GITHUB_HEAD_REF", "feature/my-branch")
    monkeypatch.setenv("GITHUB_REF_NAME", "42/merge")
    assert ci_context.resolve_branch(None, ci_context.GITHUB_ACTIONS) == "feature/my-branch"


def test_resolve_branch_github_falls_back_to_ref_name(monkeypatch):
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    assert ci_context.resolve_branch(None, ci_context.GITHUB_ACTIONS) == "main"


def test_resolve_branch_jenkins_prefers_branch_name(monkeypatch):
    monkeypatch.setenv("BRANCH_NAME", "main")
    monkeypatch.setenv("GIT_BRANCH", "origin/develop")
    assert ci_context.resolve_branch(None, ci_context.JENKINS) == "main"


def test_resolve_branch_jenkins_strips_origin_prefix(monkeypatch):
    monkeypatch.setenv("GIT_BRANCH", "origin/develop")
    assert ci_context.resolve_branch(None, ci_context.JENKINS) == "develop"


def test_resolve_branch_azure_prefers_pr_source_branch(monkeypatch):
    monkeypatch.setenv("SYSTEM_PULLREQUEST_SOURCEBRANCH", "refs/heads/feature/foo")
    monkeypatch.setenv("BUILD_SOURCEBRANCH", "refs/pull/123/merge")
    assert ci_context.resolve_branch(None, ci_context.AZURE_DEVOPS) == "feature/foo"


def test_resolve_branch_azure_strips_refs_heads_not_last_segment(monkeypatch):
    # Regression guard for the documented Azure gotcha: BUILD_SOURCEBRANCHNAME would have
    # returned only "foo" for a branch named "feature/foo" (it takes the LAST path segment) -
    # stripping "refs/heads/" from BUILD_SOURCEBRANCH ourselves must keep the full name.
    monkeypatch.setenv("BUILD_SOURCEBRANCH", "refs/heads/feature/foo")
    monkeypatch.setenv("BUILD_SOURCEBRANCHNAME", "foo")  # what Azure itself would expose - unused
    assert ci_context.resolve_branch(None, ci_context.AZURE_DEVOPS) == "feature/foo"


def test_build_provenance_github_actions(monkeypatch):
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_RUN_ID", "9182736451")
    monkeypatch.setenv("RUNNER_NAME", "ubuntu-latest-runner")
    provenance = ci_context.build_provenance(ci_context.GITHUB_ACTIONS)
    assert provenance == {
        "ciSystem": "GITHUB_ACTIONS",
        "pipelineId": "9182736451",
        "runUrl": "https://github.com/acme/app/actions/runs/9182736451",
        "runner": "ubuntu-latest-runner",
    }


def test_build_provenance_jenkins_prefers_build_tag(monkeypatch):
    monkeypatch.setenv("BUILD_TAG", "jenkins-my-job-42")
    monkeypatch.setenv("BUILD_NUMBER", "42")
    monkeypatch.setenv("BUILD_URL", "https://jenkins.example.com/job/my-job/42/")
    monkeypatch.setenv("NODE_NAME", "agent-1")
    provenance = ci_context.build_provenance(ci_context.JENKINS)
    assert provenance["pipelineId"] == "jenkins-my-job-42"
    assert provenance["runUrl"] == "https://jenkins.example.com/job/my-job/42/"
    assert provenance["runner"] == "agent-1"
    assert provenance["ciSystem"] == "JENKINS"


def test_build_provenance_jenkins_drops_non_https_run_url(monkeypatch, capsys):
    """I-2 regression guard: a plain-http self-managed Jenkins BUILD_URL (routine, per the review)
    must NOT be shipped verbatim - the server would 422 it (CiIngestRequestValidator.kt:139-142).
    The field is optional, so dropping it (with a stderr Warning) is lossless for acceptance."""
    monkeypatch.setenv("BUILD_TAG", "jenkins-app-42")
    monkeypatch.setenv("BUILD_URL", "http://jenkins.internal:8080/job/app/42/")
    monkeypatch.setenv("NODE_NAME", "agent-1")
    provenance = ci_context.build_provenance(ci_context.JENKINS)
    assert provenance["runUrl"] is None
    assert provenance["pipelineId"] == "jenkins-app-42"  # unaffected - only runUrl is dropped
    captured = capsys.readouterr()
    assert "Warning:" in captured.err
    assert "http://jenkins.internal:8080/job/app/42/" in captured.err


def test_build_provenance_drops_non_https_run_url_override_too(monkeypatch, capsys):
    """The drop applies to an explicit --run-url override as well as an auto-detected value -
    build_provenance has one enforcement point for all three providers, not one per source."""
    provenance = ci_context.build_provenance(
        ci_context.GITHUB_ACTIONS, run_url_override="http://insecure.example.com/run/1"
    )
    assert provenance["runUrl"] is None
    captured = capsys.readouterr()
    assert "Warning:" in captured.err


def test_build_provenance_azure_devops(monkeypatch):
    monkeypatch.setenv("SYSTEM_COLLECTIONURI", "https://dev.azure.com/acme/")
    monkeypatch.setenv("SYSTEM_TEAMPROJECT", "app")
    monkeypatch.setenv("BUILD_BUILDID", "778")
    monkeypatch.setenv("AGENT_NAME", "Hosted Agent")
    provenance = ci_context.build_provenance(ci_context.AZURE_DEVOPS)
    assert provenance == {
        "ciSystem": "AZURE_DEVOPS",
        "pipelineId": "778",
        "runUrl": "https://dev.azure.com/acme/app/_build/results?buildId=778",
        "runner": "Hosted Agent",
    }


def test_resolve_context_bitbucket_short_circuits(monkeypatch):
    monkeypatch.setenv("BITBUCKET_BUILD_NUMBER", "7")
    context = ci_context.resolve_context()
    assert context == {"provider": ci_context.BITBUCKET}


def test_resolve_context_raises_when_nothing_resolvable(monkeypatch):
    """
    Copilot review fix: without stubbing `_run_git`, this test previously fell through to the REAL
    `git` binary against whatever repository happens to contain this checkout - which, run from
    inside this repo's own working tree, actually resolves gitRemoteUrl/branch/commitSha
    SUCCESSFULLY via `git remote get-url origin`/`git rev-parse HEAD`/`git rev-parse --abbrev-ref
    HEAD`. With `_clean_ci_env` clearing every CI marker, `provider` is then None but every field
    resolved - so the raised CiContextError was actually the DIFFERENT "no supported CI provider
    was detected" branch, not the "nothing resolvable" branch this test's name promises, and
    whether it raised at all was silently dependent on where the suite happened to run (a
    non-git-repo checkout would have hit the OTHER branch instead). Stubbing `_run_git` to always
    return None makes every git-based fallback fail deterministically, so this now genuinely
    exercises - and asserts the message names the fields for - the unresolvable-fields branch.
    """
    monkeypatch.setattr(ci_context, "_run_git", lambda *a, **k: None)
    with pytest.raises(ci_context.CiContextError, match="gitRemoteUrl"):
        ci_context.resolve_context()


def test_resolve_context_full_github_actions(monkeypatch):
    monkeypatch.setattr(ci_context, "_run_git", lambda *a, **k: None)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_RUN_ID", "1")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    context = ci_context.resolve_context()
    assert context["provider"] == ci_context.GITHUB_ACTIONS
    assert context["gitRemoteUrl"] == "https://github.com/acme/app.git"
    assert context["branch"] == "main"
    assert context["commitSha"] == "a" * 40
    assert context["provenance"]["ciSystem"] == "GITHUB_ACTIONS"


def test_resolve_context_explicit_overrides_win(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_RUN_ID", "1")  # I-3: pipelineId is server-required
    context = ci_context.resolve_context(
        git_remote_url_override="https://example.com/override.git",
        branch_override="override-branch",
        commit_sha_override="c" * 40,
    )
    assert context["gitRemoteUrl"] == "https://example.com/override.git"
    assert context["branch"] == "override-branch"
    assert context["commitSha"] == "c" * 40


def test_resolve_context_raises_when_pipeline_id_unresolvable_jenkins(monkeypatch):
    """I-3 regression guard: JENKINS_URL alone (detect_ci_provider's own Jenkins marker) does NOT
    guarantee BUILD_TAG/BUILD_NUMBER are set (a freestyle job or an agent-side script run outside
    a build step) - the server requires provenance.pipelineId non-blank
    (CiIngestRequestValidator.kt:138), so this must fail fast rather than silently emit `null`."""
    monkeypatch.setenv("JENKINS_URL", "https://jenkins.example.com/")
    monkeypatch.setenv("GIT_URL", "https://github.com/acme/app.git")
    monkeypatch.setenv("GIT_COMMIT", "a" * 40)
    monkeypatch.setenv("BRANCH_NAME", "main")
    with pytest.raises(ci_context.CiContextError, match="pipelineId"):
        ci_context.resolve_context()


def test_resolve_context_raises_when_pipeline_id_unresolvable_azure(monkeypatch):
    """I-3 regression guard: TF_BUILD=True alone does not guarantee BUILD_BUILDID is set."""
    monkeypatch.setenv("TF_BUILD", "True")
    monkeypatch.setenv("BUILD_REPOSITORY_URI", "https://dev.azure.com/acme/app/_git/app")
    monkeypatch.setenv("BUILD_SOURCEVERSION", "a" * 40)
    monkeypatch.setenv("BUILD_SOURCEBRANCH", "refs/heads/main")
    with pytest.raises(ci_context.CiContextError, match="pipelineId"):
        ci_context.resolve_context()


def test_resolve_context_raises_when_pipeline_id_unresolvable_github(monkeypatch):
    """I-3 regression guard, third provider: GITHUB_ACTIONS=true alone does not guarantee
    GITHUB_RUN_ID is set (e.g. a scrubbed/replayed environment for local testing)."""
    monkeypatch.setattr(ci_context, "_run_git", lambda *a, **k: None)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/app")
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    with pytest.raises(ci_context.CiContextError, match="pipelineId"):
        ci_context.resolve_context()


def test_resolve_context_pipeline_id_override_satisfies_the_requirement(monkeypatch):
    """--pipeline-id must be an effective escape hatch for the I-3 fail-fast check above."""
    monkeypatch.setenv("JENKINS_URL", "https://jenkins.example.com/")
    monkeypatch.setenv("GIT_URL", "https://github.com/acme/app.git")
    monkeypatch.setenv("GIT_COMMIT", "a" * 40)
    monkeypatch.setenv("BRANCH_NAME", "main")
    context = ci_context.resolve_context(pipeline_id_override="manual-42")
    assert context["provenance"]["pipelineId"] == "manual-42"


def _init_git_repo(path, remote_url):
    """Test helper: a real, minimal git repo with one commit and one `origin` remote - used only
    by the N-1 regression guard below, which needs `git remote get-url origin`/`git rev-parse
    HEAD` to answer for two DIFFERENT real repositories from two different cwds."""
    import subprocess

    path.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q"], cwd=str(path), check=True)
    subprocess.run(["git", "remote", "add", "origin", remote_url], cwd=str(path), check=True)
    subprocess.run(
        [
            "git", "-c", "user.email=test@test.com", "-c", "user.name=test",
            "commit", "--allow-empty", "-q", "-m", "init",
        ],
        cwd=str(path),
        check=True,
    )


def test_git_remote_url_resolution_reflects_cwd_not_script_location(tmp_path, monkeypatch):
    """N-1 regression guard (re-review round 1, jenkins_ci_purple_ingest_pipeline.groovy).

    `resolve_git_remote_url`/`resolve_commit_sha` resolve via `git remote get-url origin` /
    `git rev-parse HEAD` run against the CURRENT WORKING DIRECTORY - never the location of
    ci_context.py itself, never an argument. This is exactly why the Jenkins template's OLD `cd`
    into its own vendored ci-purple-ingest client checkout (nested inside `.phoenix-utils/`)
    silently resolved gitRemoteUrl/commitSha against PHOENIX's utils repository instead of the
    CUSTOMER's scanned repository - exit 0, no warning, wrong asset identity - and exactly why the
    fix (stay in $WORKSPACE, invoke the client by path, never `cd`) resolves correctly. This test
    builds the EXACT nested-repository shape the Jenkins checkout stage creates and asserts the two
    cwd choices produce two DIFFERENT, individually-correct-for-that-cwd answers - proving cwd
    alone, not anything about which files exist, drives the result.
    """
    outer_repo = tmp_path / "outer-repo"
    _init_git_repo(outer_repo, "https://github.com/customer/their-app.git")

    # The Jenkins fix's own checkout stage clones the utils repo into this exact nested path.
    nested_utils = outer_repo / ".phoenix-utils"
    _init_git_repo(nested_utils, "https://github.com/securityphoenix/autoconfig-priv-PYRUS-PRIV-NEW.git")

    # OLD (buggy) shape: cwd is the nested utils checkout (what the removed `cd` produced).
    monkeypatch.chdir(nested_utils)
    buggy_url = ci_context.resolve_git_remote_url(None, ci_context.JENKINS)
    assert buggy_url == "https://github.com/securityphoenix/autoconfig-priv-PYRUS-PRIV-NEW.git"

    # NEW (fixed) shape: cwd stays at $WORKSPACE, the outer/scanned repository.
    monkeypatch.chdir(outer_repo)
    fixed_url = ci_context.resolve_git_remote_url(None, ci_context.JENKINS)
    assert fixed_url == "https://github.com/customer/their-app.git"

    # The whole point: same code, same script location, two different cwds, two different (and
    # each individually correct-for-that-cwd) answers - the defect was purely about WHERE the
    # process's shell left cwd, never about the client's own logic.
    assert buggy_url != fixed_url
