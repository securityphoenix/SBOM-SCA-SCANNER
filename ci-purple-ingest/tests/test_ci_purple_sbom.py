"""
Contract tests for `ci_purple_sbom.py` against the frozen server fixtures (copied verbatim into
`tests/fixtures/` from `code-analyzer-service/docs/openapi/ci-ingest-examples/` in the
agent-code-analyzer-r2 repo - design Sec 3.1).
"""

import copy
import json
import re

import pytest

import ci_purple_sbom
from ci_purple_sbom import AssetInput, RequestContext
from conftest import load_fixture


def test_read_sbom_valid(tmp_path):
    fixture = load_fixture("request-repo-valid.json")
    sbom_path = tmp_path / "sbom.cdx.json"
    sbom_path.write_text(json.dumps(fixture["sbom"]), encoding="utf-8")
    result = ci_purple_sbom.read_sbom(str(sbom_path))
    assert result["bomFormat"] == "CycloneDX"


def test_read_sbom_missing_file(tmp_path):
    with pytest.raises(ci_purple_sbom.SbomReadError, match="not found"):
        ci_purple_sbom.read_sbom(str(tmp_path / "missing.json"))


def test_read_sbom_empty_file(tmp_path):
    path = tmp_path / "empty.json"
    path.write_text("", encoding="utf-8")
    with pytest.raises(ci_purple_sbom.SbomReadError, match="empty"):
        ci_purple_sbom.read_sbom(str(path))


def test_read_sbom_not_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("not json{{{", encoding="utf-8")
    with pytest.raises(ci_purple_sbom.SbomReadError, match="not valid JSON"):
        ci_purple_sbom.read_sbom(str(path))


def test_read_sbom_wrong_format_sarif_hint(tmp_path):
    path = tmp_path / "sarif.json"
    path.write_text(json.dumps({"runs": []}), encoding="utf-8")
    with pytest.raises(ci_purple_sbom.SbomReadError, match="SARIF"):
        ci_purple_sbom.read_sbom(str(path))


def test_preflight_validate_repo_fixture_clean():
    fixture = load_fixture("request-repo-valid.json")
    assert ci_purple_sbom.preflight_validate(fixture["sbom"]) == []


def test_preflight_validate_container_fixture_clean():
    fixture = load_fixture("request-container-valid.json")
    assert ci_purple_sbom.preflight_validate(fixture["sbom"]) == []


def test_preflight_validate_rejects_bad_spec_version():
    sbom = copy.deepcopy(load_fixture("request-repo-valid.json")["sbom"])
    sbom["specVersion"] = "1.2"
    problems = ci_purple_sbom.preflight_validate(sbom)
    assert any("specVersion" in p for p in problems)


def test_preflight_validate_rejects_duplicate_bom_ref():
    sbom = copy.deepcopy(load_fixture("request-repo-valid.json")["sbom"])
    sbom["components"].append(dict(sbom["components"][0]))
    problems = ci_purple_sbom.preflight_validate(sbom)
    assert any("Duplicate bom-ref" in p for p in problems)


def test_preflight_validate_rejects_ghsa_id():
    """The frozen contract's own fixture for this rejection:
    response-422-invalid-cve-id.json ("Only CVE-YYYY-NNNN(N...) identifiers ... GHSA/OSV-only
    identifiers are rejected, not dropped")."""
    fixture = load_fixture("response-422-invalid-cve-id.json")
    sbom = copy.deepcopy(load_fixture("request-repo-valid.json")["sbom"])
    sbom["vulnerabilities"] = [
        {"id": "GHSA-xxxx-yyyy-zzzz", "affects": [{"ref": sbom["components"][0]["bom-ref"]}]}
    ]
    problems = ci_purple_sbom.preflight_validate(sbom)
    assert any("CVE-YYYY-NNNN" in p for p in problems)
    # Sanity: the fixture's own message uses the identical phrase this test asserts against, so a
    # future drift in the server's wording would be caught by re-reading the fixture, not silently.
    assert "CVE-YYYY-NNNN" in fixture["message"]


def test_preflight_validate_accepts_cve_case_insensitive():
    sbom = copy.deepcopy(load_fixture("request-repo-valid.json")["sbom"])
    sbom["vulnerabilities"] = [
        {"id": "cve-2020-8203", "affects": [{"ref": sbom["components"][0]["bom-ref"]}]}
    ]
    assert ci_purple_sbom.preflight_validate(sbom) == []


def test_preflight_validate_rejects_unresolvable_affects_ref():
    sbom = copy.deepcopy(load_fixture("request-repo-valid.json")["sbom"])
    sbom["vulnerabilities"] = [{"id": "CVE-2020-8203", "affects": [{"ref": "does-not-exist"}]}]
    problems = ci_purple_sbom.preflight_validate(sbom)
    assert any("does not resolve to a known component bom-ref" in p for p in problems)


def test_preflight_validate_survives_non_list_affects():
    """Regression: a scalar `affects` reached `enumerate()` and raised an unhandled `TypeError`
    (`'int' object is not iterable`), crashing preflight instead of reporting a problem. Same bug
    class as the scalar `dependsOn` fix in `_validate_dependency_edges`. A non-list value is
    treated as no affects entries (best-effort local check); the server still rejects it."""
    for bad in (5, "a", {"ref": "a"}, True):
        sbom = copy.deepcopy(load_fixture("request-repo-valid.json")["sbom"])
        sbom["vulnerabilities"] = [{"id": "CVE-2020-8203", "affects": bad}]
        assert ci_purple_sbom.preflight_validate(sbom) == [], "non-list affects {!r}".format(bad)


def test_preflight_validate_still_checks_valid_list_affects():
    """The above fallback must not swallow a genuine unresolvable ref in a well-formed list."""
    sbom = copy.deepcopy(load_fixture("request-repo-valid.json")["sbom"])
    sbom["vulnerabilities"] = [{"id": "CVE-2020-8203", "affects": [{"ref": "nope"}]}]
    problems = ci_purple_sbom.preflight_validate(sbom)
    assert any("does not resolve to a known component bom-ref" in p for p in problems)


def test_preflight_validate_component_budget():
    sbom = {"specVersion": "1.5", "components": [{"bom-ref": "c{}".format(i)} for i in range(ci_purple_sbom.MAX_COMPONENTS + 1)]}
    problems = ci_purple_sbom.preflight_validate(sbom)
    assert any("exceeding the limit" in p for p in problems)


# ── M-3: the four previously-declared-but-unwired budget constants, now enforced ────────────────


def test_preflight_validate_rejects_oversized_component_name():
    sbom = copy.deepcopy(load_fixture("request-repo-valid.json")["sbom"])
    sbom["components"][0]["name"] = "x" * (ci_purple_sbom.MAX_LEN_IDENTIFIER + 1)
    problems = ci_purple_sbom.preflight_validate(sbom)
    assert any(".name exceeds" in p for p in problems)


def test_preflight_validate_rejects_oversized_component_version():
    sbom = copy.deepcopy(load_fixture("request-repo-valid.json")["sbom"])
    sbom["components"][0]["version"] = "x" * (ci_purple_sbom.MAX_LEN_IDENTIFIER + 1)
    problems = ci_purple_sbom.preflight_validate(sbom)
    assert any(".version exceeds" in p for p in problems)


def test_preflight_validate_rejects_oversized_purl():
    sbom = copy.deepcopy(load_fixture("request-repo-valid.json")["sbom"])
    sbom["components"][0]["purl"] = "pkg:generic/x@1?" + ("y" * ci_purple_sbom.MAX_LEN_URL_OR_PURL)
    problems = ci_purple_sbom.preflight_validate(sbom)
    assert any(".purl exceeds" in p for p in problems)


def test_preflight_validate_rejects_oversized_description():
    sbom = copy.deepcopy(load_fixture("request-repo-valid.json")["sbom"])
    sbom["components"][0]["description"] = "x" * (ci_purple_sbom.MAX_LEN_EVIDENCE + 1)
    problems = ci_purple_sbom.preflight_validate(sbom)
    assert any(".description exceeds" in p for p in problems)


def test_preflight_validate_rejects_excess_json_depth():
    # Build a JSON structure nested one level past MAX_JSON_DEPTH.
    node = {"leaf": True}
    for _ in range(ci_purple_sbom.MAX_JSON_DEPTH + 2):
        node = {"nested": node}
    sbom = copy.deepcopy(load_fixture("request-repo-valid.json")["sbom"])
    sbom["extensionsDeepNestingProbe"] = node
    problems = ci_purple_sbom.preflight_validate(sbom)
    assert any("nesting depth" in p for p in problems)


def test_preflight_validate_json_depth_matches_server_offset():
    """N-2 regression guard (re-review round 1): the server measures depth over the WHOLE request
    body, where the `sbom` node is already one level deep - so `preflight_validate` must seed its
    own walk at current=1, not the helper's own default of 0. This builds a document the OLD
    (off-by-one, current=0) code would have measured at exactly MAX_JSON_DEPTH (i.e. NOT flagged,
    since the check is strictly `>`) but the FIXED code measures one level deeper (flagged) -
    proving the offset fix actually changes the outcome, not just the internal number."""
    node = {"leaf": True}
    for _ in range(ci_purple_sbom.MAX_JSON_DEPTH - 2):
        node = {"nested": node}
    sbom = {"specVersion": "1.5", "extra": node}

    # Sanity-pin the exact boundary this test relies on before trusting the behavioural assertion.
    assert ci_purple_sbom._max_depth(sbom, current=0) == ci_purple_sbom.MAX_JSON_DEPTH
    assert ci_purple_sbom._max_depth(sbom, current=1) == ci_purple_sbom.MAX_JSON_DEPTH + 1

    problems = ci_purple_sbom.preflight_validate(sbom)
    assert any("nesting depth" in p for p in problems)


def test_preflight_validate_accepts_normal_depth():
    sbom = load_fixture("request-repo-valid.json")["sbom"]
    problems = ci_purple_sbom.preflight_validate(sbom)
    assert not any("nesting depth" in p for p in problems)


def test_build_request_body_matches_repo_fixture_shape():
    fixture = load_fixture("request-repo-valid.json")
    body = ci_purple_sbom.build_request_body(
        RequestContext(
            git_remote_url=fixture["gitRemoteUrl"],
            branch=fixture["branch"],
            commit_sha=fixture["commitSha"],
            provenance={
                "ciSystem": fixture["provenance"]["ciSystem"],
                "pipelineId": fixture["provenance"]["pipelineId"],
                "runUrl": fixture["provenance"]["runUrl"],
                "runner": fixture["provenance"]["runner"],
            },
        ),
        fixture["sbom"],
        AssetInput(kind="REPO", build_file_path=fixture["asset"]["buildFilePath"]),
    )
    assert body["gitRemoteUrl"] == fixture["gitRemoteUrl"]
    assert body["branch"] == fixture["branch"]
    assert body["commitSha"] == fixture["commitSha"]
    assert body["asset"] == {"kind": "REPO", "buildFilePath": fixture["asset"]["buildFilePath"]}
    assert body["provenance"] == fixture["provenance"]
    assert body["sbom"] == fixture["sbom"]
    assert "workspaceId" not in body  # fixture's workspaceId is null - omitted, not sent as null


def test_build_request_body_matches_container_fixture_shape():
    fixture = load_fixture("request-container-valid.json")
    prov = fixture["provenance"]
    body = ci_purple_sbom.build_request_body(
        RequestContext(
            git_remote_url=fixture["gitRemoteUrl"],
            branch=fixture["branch"],
            commit_sha=fixture["commitSha"],
            provenance={"ciSystem": prov["ciSystem"], "pipelineId": prov["pipelineId"], "runUrl": prov["runUrl"], "runner": prov["runner"]},
        ),
        fixture["sbom"],
        AssetInput(
            kind="CONTAINER_IMAGE",
            registry=fixture["asset"]["registry"],
            image=fixture["asset"]["image"],
            tag=fixture["asset"]["tag"],
            digest=fixture["asset"]["digest"],
            dockerfile_path=prov["dockerfilePath"],
            from_line=prov["fromLine"],
            base_image_ref=prov["baseImageRef"],
        ),
    )
    assert body["asset"] == fixture["asset"]
    # builtFromRepo/builtFromCommit are DERIVED (see module docstring), not caller-supplied - they
    # must equal gitRemoteUrl/commitSha exactly, matching the fixture's own values.
    assert body["provenance"]["builtFromRepo"] == fixture["provenance"]["builtFromRepo"] == fixture["gitRemoteUrl"]
    assert body["provenance"]["builtFromCommit"] == fixture["provenance"]["builtFromCommit"] == fixture["commitSha"]
    assert body["provenance"]["dockerfilePath"] == fixture["provenance"]["dockerfilePath"]
    assert body["provenance"]["fromLine"] == fixture["provenance"]["fromLine"]
    assert body["provenance"]["baseImageRef"] == fixture["provenance"]["baseImageRef"]


def _repo_context(**overrides):
    """Test helper: a minimal RequestContext for the negative-path tests below, which only care
    about asset-level validation, not a realistic git identity."""
    defaults = dict(git_remote_url="https://github.com/acme/app.git", branch="main", commit_sha="a" * 40, provenance={})
    defaults.update(overrides)
    return RequestContext(**defaults)


def test_build_request_body_rejects_short_commit_sha():
    with pytest.raises(ValueError, match="40 hexadecimal"):
        ci_purple_sbom.build_request_body(
            _repo_context(commit_sha="abc123"), {}, AssetInput(kind="REPO", build_file_path="package-lock.json")
        )


def test_build_request_body_repo_requires_build_file_path():
    with pytest.raises(ValueError, match="buildFilePath is required"):
        ci_purple_sbom.build_request_body(_repo_context(), {}, AssetInput(kind="REPO"))


def test_build_request_body_repo_rejects_container_fields():
    with pytest.raises(ValueError, match=re.escape("only valid for asset.kind=CONTAINER_IMAGE")):
        ci_purple_sbom.build_request_body(
            _repo_context(),
            {},
            AssetInput(kind="REPO", build_file_path="package-lock.json", registry="ghcr.io"),
        )


def test_build_request_body_container_rejects_bad_digest():
    with pytest.raises(ValueError, match="sha256"):
        ci_purple_sbom.build_request_body(
            _repo_context(),
            {},
            AssetInput(
                kind="CONTAINER_IMAGE",
                registry="ghcr.io",
                image="acme/app",
                tag="v1",
                digest="sha256:not-hex",
                dockerfile_path="Dockerfile",
            ),
        )


def test_build_request_body_container_rejects_build_file_path():
    """Copilot review fix regression guard: build_request_body previously silently ACCEPTED (and
    ignored) asset.buildFilePath on a CONTAINER_IMAGE asset instead of rejecting it, the mirror
    image of test_build_request_body_repo_rejects_container_fields above."""
    with pytest.raises(ValueError, match=re.escape("only valid for asset.kind=REPO")):
        ci_purple_sbom.build_request_body(
            _repo_context(),
            {},
            AssetInput(
                kind="CONTAINER_IMAGE",
                build_file_path="package-lock.json",
                registry="ghcr.io",
                image="acme/app",
                tag="v1",
                digest="sha256:" + "a" * 64,
                dockerfile_path="Dockerfile",
            ),
        )


def test_build_request_body_repo_rejects_container_provenance_fields():
    """Copilot review fix regression guard: dockerfilePath/fromLine/baseImageRef (provenance
    fields, not asset fields) were previously accepted-and-ignored on a REPO asset instead of
    rejected, unlike registry/image/tag/digest above."""
    with pytest.raises(ValueError, match=re.escape("only valid for asset.kind=CONTAINER_IMAGE")):
        ci_purple_sbom.build_request_body(
            _repo_context(),
            {},
            AssetInput(kind="REPO", build_file_path="package-lock.json", dockerfile_path="Dockerfile"),
        )


def test_build_request_body_rejects_path_traversal():
    with pytest.raises(ValueError, match="must not contain"):
        ci_purple_sbom.build_request_body(
            _repo_context(), {}, AssetInput(kind="REPO", build_file_path="../../etc/passwd")
        )


def test_build_request_body_rejects_absolute_path():
    with pytest.raises(ValueError, match="relative path"):
        ci_purple_sbom.build_request_body(_repo_context(), {}, AssetInput(kind="REPO", build_file_path="/etc/passwd"))


# ── I-4: gitRemoteUrl authority-hazard checks (mirrors CiIngestRequestValidator.assertNoAuthorityHazards) ──


def test_assert_no_authority_hazards_rejects_file_url():
    with pytest.raises(ValueError, match="file:"):
        ci_purple_sbom.assert_no_authority_hazards("file:///etc/passwd", "gitRemoteUrl")


def test_assert_no_authority_hazards_allows_credential_free_scp_shorthand():
    ci_purple_sbom.assert_no_authority_hazards("git@github.com:acme/app.git", "gitRemoteUrl")  # must not raise


def test_assert_no_authority_hazards_rejects_scp_shorthand_with_password():
    with pytest.raises(ValueError, match="embedded credentials"):
        ci_purple_sbom.assert_no_authority_hazards("user:token@github.com:acme/app.git", "gitRemoteUrl")


def test_assert_no_authority_hazards_allows_ssh_bare_user_at_host():
    ci_purple_sbom.assert_no_authority_hazards("ssh://git@github.com/acme/app.git", "gitRemoteUrl")  # must not raise


def test_assert_no_authority_hazards_rejects_https_embedded_token():
    with pytest.raises(ValueError, match="embedded credentials"):
        ci_purple_sbom.assert_no_authority_hazards("https://ghp_faketoken123@github.com/acme/app.git", "gitRemoteUrl")


def test_assert_no_authority_hazards_rejects_azure_repos_clone_url():
    """I-4's named example: Azure Repos' own documented clone URL form is unconditionally rejected
    by the server (a non-ssh @-bearing authority is ALWAYS a credential, regardless of intent)."""
    with pytest.raises(ValueError, match="embedded credentials"):
        ci_purple_sbom.assert_no_authority_hazards(
            "https://acme-org@dev.azure.com/acme-org/my-project/_git/my-repo", "gitRemoteUrl"
        )


def test_assert_no_authority_hazards_rejects_query_string():
    with pytest.raises(ValueError, match="query string"):
        ci_purple_sbom.assert_no_authority_hazards("https://github.com/acme/app.git?ref=main", "gitRemoteUrl")


def test_assert_no_authority_hazards_rejects_fragment():
    with pytest.raises(ValueError, match="fragment"):
        ci_purple_sbom.assert_no_authority_hazards("https://github.com/acme/app.git#readme", "gitRemoteUrl")


def test_assert_no_authority_hazards_rejects_non_default_port():
    with pytest.raises(ValueError, match="non-default explicit port"):
        ci_purple_sbom.assert_no_authority_hazards("https://github.internal:8443/acme/app.git", "gitRemoteUrl")


def test_assert_no_authority_hazards_allows_default_https_port():
    ci_purple_sbom.assert_no_authority_hazards("https://github.com:443/acme/app.git", "gitRemoteUrl")  # must not raise


def test_assert_no_authority_hazards_allows_plain_https():
    ci_purple_sbom.assert_no_authority_hazards("https://github.com/acme/app.git", "gitRemoteUrl")  # must not raise


def test_assert_no_authority_hazards_unicode_digit_port_does_not_raise():
    """N-4 regression guard (re-review round 1): a Unicode-digit port (e.g. Arabic-Indic U+0664
    digits) must not crash `int()` on a superscript-like non-ASCII digit character, and the
    `.isascii()` guard means this class of port string is skipped by the port check entirely
    rather than raising - a safe (non-authoritative-preflight) direction, never a false local
    rejection or an uncaught exception."""
    ci_purple_sbom.assert_no_authority_hazards("https://github.com:\u0664\u0664\u0663/acme/app.git", "gitRemoteUrl")  # must not raise


def test_build_request_body_rejects_credential_bearing_git_remote_url_before_anything_else():
    """I-4 wiring: a hazardous gitRemoteUrl must be rejected by build_request_body itself, before
    any of asset/provenance construction - proven here by passing otherwise-invalid REPO asset
    args (no build_file_path) and asserting the FIRST error raised is the authority-hazard one,
    not the asset.buildFilePath one."""
    with pytest.raises(ValueError, match="embedded credentials"):
        ci_purple_sbom.build_request_body(
            _repo_context(git_remote_url="https://user:token@github.com/acme/app.git"),
            {},
            # build_file_path deliberately omitted - if authority-hazard checking ran AFTER asset
            # validation, this would raise "buildFilePath is required" instead, masking I-4.
            AssetInput(kind="REPO"),
        )


def test_build_request_body_includes_workspace_id_when_given():
    body = ci_purple_sbom.build_request_body(
        _repo_context(),
        {},
        AssetInput(kind="REPO", build_file_path="package-lock.json"),
        workspace_id="b3e1c9a0-1f2d-4a3b-9c8e-7d6f5a4b3c2d",
    )
    assert body["workspaceId"] == "b3e1c9a0-1f2d-4a3b-9c8e-7d6f5a4b3c2d"


def test_check_gateway_budget_ok_for_small_body():
    ok, message = ci_purple_sbom.check_gateway_budget({"sbom": {"components": []}})
    assert ok is True
    assert message == ""


def test_check_gateway_budget_rejects_oversized_body():
    huge = {"components": [{"bom-ref": "x" * 1000, "name": "n"} for _ in range(15000)]}
    ok, message = ci_purple_sbom.check_gateway_budget({"sbom": huge})
    assert ok is False
    assert "413" in message or "MiB" in message
