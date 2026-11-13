"""
Container base image: read from trivy labels or flags, checked with the backend rules, sent with
the stateful SBOM upload only (ASPMAIN-9160).
"""

import argparse
import json
import sys

import pytest

import sbom_sca_single_repo_to_phoenix as cli
from cyclonedx_sbom import base_image_from_sbom
from phoenix_client import build_artefact_fields, normalise_base_image

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
NAME_LABEL = "aquasecurity:trivy:Labels:org.opencontainers.image.base.name"
DIGEST_LABEL = "aquasecurity:trivy:Labels:org.opencontainers.image.base.digest"
IMAGE_DIGEST = "sha256:" + "c" * 64


def sbom(name=None, digest=None):
    props = []
    if name is not None:
        props.append({"name": NAME_LABEL, "value": name})
    if digest is not None:
        props.append({"name": DIGEST_LABEL, "value": digest})
    return {
        "bomFormat": "CycloneDX",
        "metadata": {
            "component": {
                "name": "registry.example.com/team/app:1.0",
                "purl": f"pkg:oci/app@{IMAGE_DIGEST}?repository_url=registry.example.com/team/app",
                "properties": props,
            }
        },
        "components": [],
        "vulnerabilities": [],
    }


class TestBaseImageFromSbom:
    def test_reads_both_trivy_labels(self):
        fields, warning = base_image_from_sbom(sbom("registry.example.com/team/base:1.4", DIGEST))
        assert warning is None
        assert fields == {
            "baseImageName": "registry.example.com/team/base:1.4",
            "baseImageDigest": DIGEST,
        }

    def test_upper_case_label_digest_is_lowercased(self):
        fields, warning = base_image_from_sbom(sbom("team/base:1", DIGEST.upper().replace("SHA256", "sha256")))
        assert warning is None
        assert fields["baseImageDigest"] == DIGEST

    def test_label_name_with_a_matching_digest_is_stripped(self):
        fields, warning = base_image_from_sbom(sbom(f"team/base@{DIGEST.upper().replace('SHA256', 'sha256')}", DIGEST))
        assert warning is None
        assert fields == {"baseImageName": "team/base", "baseImageDigest": DIGEST}

    def test_only_the_name_label_gives_a_warning_and_no_fields(self):
        fields, warning = base_image_from_sbom(sbom("team/base:1", None))
        assert fields == {}
        assert "must be sent together" in warning

    def test_malformed_digest_label_gives_a_warning_and_no_fields(self):
        fields, warning = base_image_from_sbom(sbom("team/base:1", "sha256:nothex"))
        assert fields == {}
        assert "baseImageDigest must match sha256:<64 hex chars>" in warning

    def test_label_name_over_512_chars_gives_a_warning_and_no_fields(self):
        fields, warning = base_image_from_sbom(sbom("a" * 513, DIGEST))
        assert fields == {}
        assert "baseImageName must be at most 512 characters" in warning

    def test_label_name_with_a_different_digest_gives_a_warning_and_no_fields(self):
        fields, warning = base_image_from_sbom(sbom(f"team/base@{OTHER_DIGEST}", DIGEST))
        assert fields == {}
        assert "baseImageName digest does not match baseImageDigest" in warning

    def test_label_name_with_a_space_gives_a_warning_and_no_fields(self):
        fields, warning = base_image_from_sbom(sbom("team/base 1", DIGEST))
        assert fields == {}
        assert "baseImageName must be an image reference" in warning

    def test_no_labels_gives_no_fields_and_no_warning(self):
        assert base_image_from_sbom(sbom()) == ({}, None)

    def test_blank_labels_count_as_absent(self):
        assert base_image_from_sbom(sbom("  ", "")) == ({}, None)


class TestNormaliseBaseImage:
    def test_both_blank_is_absent(self):
        assert normalise_base_image(None, "  ") == (None, None)

    def test_name_is_trimmed(self):
        fields, err = normalise_base_image("  team/base:1 ", DIGEST)
        assert err is None and fields["baseImageName"] == "team/base:1"


class TestBuildArtefactFields:
    def test_sends_base_image_name_and_digest_for_container(self):
        fields = build_artefact_fields(
            artefact_type="CONTAINER",
            container_name="app",
            base_image_name="team/base:1",
            base_image_digest=DIGEST,
        )
        assert fields["baseImageName"] == "team/base:1"
        assert fields["baseImageDigest"] == DIGEST

    def test_omits_base_unless_both_are_set(self):
        fields = build_artefact_fields(
            artefact_type="CONTAINER", container_name="app", base_image_name="team/base:1"
        )
        assert "baseImageName" not in fields and "baseImageDigest" not in fields

    def test_refuses_base_for_build_file(self):
        with pytest.raises(ValueError, match="base image fields require artefact_type CONTAINER"):
            build_artefact_fields(
                artefact_type="BUILD_FILE", base_image_name="team/base:1", base_image_digest=DIGEST
            )


def write_sbom(tmp_path, **kw):
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(sbom(**kw)))
    return str(path)


def run_main(monkeypatch, tmp_path, argv, **sbom_kw):
    full = [
        "prog",
        "--sbom-file", write_sbom(tmp_path, **sbom_kw),
        "--repo", "org/app", "--file-path", "Dockerfile", "--branch", "main",
        "--method", "sbom",
        "--dry-run",
        "--config", str(tmp_path / "missing.ini"),
    ] + argv
    monkeypatch.setattr(sys, "argv", full)
    return cli.main()


class TestResolve:
    def args(self, **kw):
        base = dict(
            artefact_type="CONTAINER", build_file=None, container_name=None, container_version=None,
            container_digest=None, registry=None, file_path=None,
            base_image_name=None, base_image_digest=None,
        )
        base.update(kw)
        return argparse.Namespace(**base)

    def test_flags_win_over_labels(self):
        args = self.args(base_image_name="flag/base:2", base_image_digest=DIGEST)
        fields, source = cli.resolve_artefact_fields(args, sbom("label/base:1", OTHER_DIGEST))
        assert fields["baseImageName"] == "flag/base:2"
        assert fields["baseImageDigest"] == DIGEST
        assert source == "flags"

    def test_labels_are_not_read_on_the_translate_route(self):
        fields, source = cli.resolve_artefact_fields(
            self.args(), sbom("label/base:1", DIGEST), read_base=False
        )
        assert "baseImageName" not in fields and "baseImageDigest" not in fields
        assert source == "none"

    def test_labels_are_not_read_without_artefact_type(self):
        fields, source = cli.resolve_artefact_fields(
            self.args(artefact_type=None), sbom("label/base:1", DIGEST)
        )
        assert fields == {}
        assert source == "no-artefact-type"

    def test_labels_are_read_for_container(self, capsys):
        fields, source = cli.resolve_artefact_fields(self.args(), sbom("label/base:1", DIGEST))
        assert source == "labels" and fields["baseImageDigest"] == DIGEST

    def test_bad_label_warns_on_stderr_and_sends_nothing(self, capsys):
        fields, source = cli.resolve_artefact_fields(self.args(), sbom("label/base 1", DIGEST))
        err = capsys.readouterr().err
        assert "baseImageName" not in fields and source == "none"
        assert "Warning: baseImageName must be an image reference; uploading without a base image" in err


class TestMainExitCodes:
    def test_name_without_digest_exits_1(self, monkeypatch, tmp_path, capsys):
        rc = run_main(monkeypatch, tmp_path, ["--artefact-type", "CONTAINER", "--base-image-name", "team/base:1"])
        err = capsys.readouterr().err
        assert rc == 1
        assert "--base-image-name and --base-image-digest must be given together" in err

    def test_digest_without_name_exits_1(self, monkeypatch, tmp_path, capsys):
        rc = run_main(monkeypatch, tmp_path, ["--artefact-type", "CONTAINER", "--base-image-digest", DIGEST])
        err = capsys.readouterr().err
        assert rc == 1
        assert "--base-image-name and --base-image-digest must be given together" in err

    def test_base_flags_with_build_file_exit_1(self, monkeypatch, tmp_path, capsys):
        rc = run_main(
            monkeypatch, tmp_path,
            ["--artefact-type", "BUILD_FILE", "--base-image-name", "team/base:1", "--base-image-digest", DIGEST],
        )
        assert rc == 1
        assert "need --artefact-type CONTAINER" in capsys.readouterr().err

    def test_base_flags_without_artefact_type_exit_1(self, monkeypatch, tmp_path, capsys):
        rc = run_main(
            monkeypatch, tmp_path, ["--base-image-name", "team/base:1", "--base-image-digest", DIGEST]
        )
        assert rc == 1
        assert "need --artefact-type CONTAINER" in capsys.readouterr().err

    def test_bad_flag_digest_exits_1(self, monkeypatch, tmp_path, capsys):
        rc = run_main(
            monkeypatch, tmp_path,
            ["--artefact-type", "CONTAINER", "--base-image-name", "team/base:1", "--base-image-digest", "sha256:zz"],
        )
        err = capsys.readouterr().err
        assert rc == 1
        assert "--base-image-name/--base-image-digest: baseImageDigest must match sha256:<64 hex chars>" in err

    def test_base_flags_with_scan_type_exit_1(self, monkeypatch, tmp_path, capsys):
        rc = run_main(
            monkeypatch, tmp_path,
            ["--artefact-type", "CONTAINER", "--scan-type", "Trivy Scan",
             "--base-image-name", "team/base:1", "--base-image-digest", DIGEST],
        )
        assert rc == 1
        assert "need the stateful sbom upload" in capsys.readouterr().err

    def test_base_flags_with_scan_type_only_in_config_exit_1(self, monkeypatch, tmp_path, capsys):
        ini = tmp_path / "cfg.ini"
        ini.write_text("[phoenix]\nscan_type = Trivy Scan\n")
        full = [
            "prog", "--sbom-file", write_sbom(tmp_path), "--repo", "org/app", "--file-path", "Dockerfile", "--branch", "main", "--method", "sbom",
            "--dry-run", "--config", str(ini), "--artefact-type", "CONTAINER",
            "--base-image-name", "team/base:1", "--base-image-digest", DIGEST,
        ]
        monkeypatch.setattr(sys, "argv", full)
        rc = cli.main()
        err = capsys.readouterr().err
        assert rc == 1
        assert "scan_type in config.ini" in err

    def test_base_flags_with_vulnerability_method_exit_1(self, monkeypatch, tmp_path, capsys):
        full = [
            "prog", "--sbom-file", write_sbom(tmp_path), "--repo", "org/app", "--file-path", "Dockerfile", "--branch", "main", "--method", "vulnerability",
            "--dry-run", "--config", str(tmp_path / "missing.ini"),
            "--base-image-name", "team/base:1", "--base-image-digest", DIGEST,
        ]
        monkeypatch.setattr(sys, "argv", full)
        rc = cli.main()
        err = capsys.readouterr().err
        assert rc == 1
        assert "--base-image-name and --base-image-digest apply only to --method sbom" in err


class TestDryRunOutput:
    def test_prints_base_fields_and_their_source(self, monkeypatch, tmp_path, capsys):
        rc = run_main(
            monkeypatch, tmp_path, ["--artefact-type", "CONTAINER"],
            name="registry.example.com/team/base:1.4", digest=DIGEST,
        )
        out = capsys.readouterr().out
        assert rc == 0
        artefact_line = [l for l in out.splitlines() if l.startswith("Artefact:")][0]
        assert "baseImageDigest=sha256:" in artefact_line
        assert "Base image source: labels" in out

    def test_labels_are_not_read_without_artefact_type(self, monkeypatch, tmp_path, capsys):
        rc = run_main(monkeypatch, tmp_path, [], name="team/base:1", digest=DIGEST)
        out = capsys.readouterr().out
        assert rc == 0
        assert "baseImage" not in out.replace("Base image source", "")
        assert "Base image source: none (no --artefact-type)" in out
