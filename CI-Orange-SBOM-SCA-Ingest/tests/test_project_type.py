"""
The "PhxSbomSca:<projectType>" suffix.

Worth covering because getting it wrong is invisible at the API boundary: dep-scan is the only
consumer, and an ecosystem it does not recognise yields a thinner import that still returns 200.
"""

from cyclonedx_sbom import detect_project_types, purl_type
from upload_plan import describe_report, resolve_project_type


def bom(*purls, **kwargs):
    components = [{"name": "c%d" % i, "purl": p} for i, p in enumerate(purls)]
    return {"bomFormat": "CycloneDX", "components": components, **kwargs}


class TestPurlType:
    def test_reads_the_type_segment(self):
        assert purl_type("pkg:npm/left-pad@1.3.0") == "npm"
        assert purl_type("pkg:maven/com.google.guava/guava@31.1") == "maven"
        assert purl_type("pkg:golang/github.com/gin-gonic/gin@v1.9.1") == "golang"

    def test_tolerates_a_missing_scheme_and_qualifiers(self):
        assert purl_type("npm/left-pad@1.3.0") == "npm"
        assert purl_type("pkg:deb/debian/libc6@2.36?arch=amd64") == "deb"

    def test_returns_empty_rather_than_raising_on_junk(self):
        # One malformed component should not stop the rest of the BOM being classified.
        assert purl_type("") == ""
        assert purl_type(None) == ""
        assert purl_type("not-a-purl") == ""


class TestDetectProjectTypes:
    def test_maps_ecosystems_onto_phoenix_types(self):
        assert detect_project_types(bom("pkg:npm/a@1")) == ["npm"]
        assert detect_project_types(bom("pkg:maven/g/a@1")) == ["java"]
        assert detect_project_types(bom("pkg:pypi/a@1")) == ["python"]
        assert detect_project_types(bom("pkg:nuget/a@1")) == ["dotnet"]

    def test_orders_by_component_count(self):
        detected = detect_project_types(bom("pkg:npm/a@1", "pkg:npm/b@1", "pkg:maven/g/c@1"))
        assert detected == ["npm", "java"]

    def test_an_image_bom_is_universal(self):
        # Mostly OS packages: no single language type is honest about a container.
        detected = detect_project_types(
            bom("pkg:deb/debian/libc6@2.36", "pkg:deb/debian/openssl@3", "pkg:npm/express@4")
        )
        assert detected == ["universal"]

    def test_a_repository_vendoring_one_os_package_is_not_an_image(self):
        # Decided on the OS share, not on "any OS package at all".
        detected = detect_project_types(
            bom("pkg:npm/a@1", "pkg:npm/b@1", "pkg:npm/c@1", "pkg:deb/debian/libc6@2.36")
        )
        assert detected == ["npm"]

    def test_drops_ecosystems_below_the_share_threshold(self):
        purls = ["pkg:maven/g/a%d@1" % i for i in range(40)] + ["pkg:gem/rake@13"]
        assert detect_project_types(bom(*purls)) == ["java"]

    def test_returns_empty_when_nothing_is_classifiable(self):
        # The caller decides the fallback and says so; detection does not guess.
        assert detect_project_types(bom()) == []
        assert detect_project_types(bom("", "not-a-purl")) == []


class TestResolveProjectType:
    def test_auto_reads_the_bom(self, capsys):
        assert resolve_project_type("auto", bom("pkg:npm/a@1")) == "npm"
        assert "detected npm" in capsys.readouterr().out

    def test_auto_falls_back_to_universal_with_a_warning(self, capsys):
        assert resolve_project_type("auto", bom()) == "universal"
        assert "could not determine the project type" in capsys.readouterr().err

    def test_blank_is_treated_as_auto(self):
        assert resolve_project_type("", bom("pkg:pypi/a@1")) == "python"

    def test_an_explicit_value_wins_over_the_bom(self):
        assert resolve_project_type("java", bom("pkg:npm/a@1")) == "java"

    def test_maps_the_cdxgen_spellings(self):
        # PROJECT_TYPE feeds cdxgen -t as well, where the ecosystem is "js", not "npm".
        assert resolve_project_type("js", bom()) == "npm"
        assert resolve_project_type("nodejs", bom()) == "npm"
        assert resolve_project_type("typescript", bom()) == "npm"
        assert resolve_project_type("kotlin", bom()) == "java"

    def test_accepts_a_list_and_deduplicates_it(self):
        assert resolve_project_type("java,python", bom()) == "java,python"
        assert resolve_project_type("java,kotlin,scala", bom()) == "java"

    def test_drops_an_unknown_token_and_warns(self, capsys):
        assert resolve_project_type("java,cobol", bom()) == "java"
        assert "unrecognised project type(s) cobol" in capsys.readouterr().err

    def test_all_unknown_falls_back_rather_than_failing_the_build(self):
        # The SBOM has already been produced and uploaded by this point.
        assert resolve_project_type("cobol", bom()) == "universal"

    def test_universal_absorbs_the_specific_types(self):
        assert resolve_project_type("universal,java", bom()) == "universal"


class FakeResponse:
    status_code = 200
    text = '{"id": "req-1"}'

    def json(self):
        return {"id": "req-1"}


class CapturingSession:
    """Records what upload_sbom_file actually put on the wire."""

    def __init__(self):
        self.data = None

    def post(self, url, **kwargs):
        self.url = url
        self.data = kwargs.get("data")
        return FakeResponse()


def make_config(**overrides):
    from phoenix_client import PhoenixConfig

    defaults = dict(
        client_id="id",
        client_secret="secret-never-printed",
        api_base_url="https://api.example.invalid",
        import_type="merge",
        assessment_name="a",
        verify_tls=True,
        timeout_seconds=5,
        method="sbom",
        project_type="auto",
        wait_for_completion=False,
        poll_interval_seconds=1,
        poll_timeout_seconds=10,
    )
    defaults.update(overrides)
    return PhoenixConfig(**defaults)


class TestTransmittedScanType:
    """
    The scan type that is *sent*, not the one that is printed.

    A live import against the demo tenant recorded scanType "PhxSbomSca:auto" while the build
    log said "PhxSbomSca:java,npm": the resolved value was printed but never reached the
    request, because the client re-derived it from the unresolved config. dep-scan received
    ?type=auto.
    """

    def upload(self, tmp_path, **kwargs):
        from phoenix_client import upload_sbom_file

        sbom = tmp_path / "sbom.cdx.json"
        sbom.write_text('{"bomFormat": "CycloneDX", "components": []}')
        session = CapturingSession()
        upload_sbom_file(
            cfg=kwargs.pop("cfg", make_config()),
            session=session,
            token="t",
            sbom_path=str(sbom),
            repo="acme/api",
            file_path="pom.xml",
            auto_import=True,
            scan_target=None,
            **kwargs
        )
        return session.data

    def test_sends_the_resolved_type_not_the_configured_one(self, tmp_path):
        data = self.upload(tmp_path, project_type="java,npm")
        assert data["scanType"] == "PhxSbomSca:java,npm"

    def test_falls_back_to_the_configured_type_when_none_is_passed(self, tmp_path):
        data = self.upload(tmp_path, cfg=make_config(project_type="java"))
        assert data["scanType"] == "PhxSbomSca:java"

    def test_an_explicit_scan_type_still_wins(self, tmp_path):
        data = self.upload(tmp_path, cfg=make_config(scan_type="Trivy Scan"), project_type="java")
        assert data["scanType"] == "Trivy Scan"


class TestContainerRootComponent:
    """
    metadata.component decides, before any counting.

    A live Trivy scan of node:12-alpine produced 457 components - roughly 440 npm against 15 apk -
    and the share heuristic alone called it "npm". dep-scan would then never have been asked about
    the image's OS packages.
    """

    def image_bom(self, root, *purls):
        return {
            "bomFormat": "CycloneDX",
            "metadata": {"component": root},
            "components": [{"name": "c%d" % i, "purl": p} for i, p in enumerate(purls)],
        }

    def test_a_container_root_is_universal_however_the_components_lean(self):
        sbom = self.image_bom(
            {"type": "container", "name": "node:12-alpine"},
            *["pkg:npm/p%d@1" % i for i in range(40)]
        )
        assert detect_project_types(sbom) == ["universal"]

    def test_an_oci_purl_on_the_root_is_enough(self):
        sbom = self.image_bom(
            {"name": "node:12-alpine", "purl": "pkg:oci/node@sha256:abc?repository_url=index.docker.io/node"},
            *["pkg:npm/p%d@1" % i for i in range(40)]
        )
        assert detect_project_types(sbom) == ["universal"]

    def test_an_application_root_still_detects_its_ecosystems(self):
        # Three npm to one maven, so the ranking is unambiguous rather than an alphabetical tiebreak.
        sbom = self.image_bom(
            {"type": "application", "name": "api"},
            "pkg:npm/a@1", "pkg:npm/b@1", "pkg:npm/c@1", "pkg:maven/g/d@1",
        )
        assert detect_project_types(sbom) == ["npm", "java"]


class TestDescribeReport:
    """
    The one line the build log shows. Extracted from run_sbom_upload, so pin the behaviour.
    """

    def test_names_the_trap_when_findings_would_be_discarded(self):
        sbom = {"bomFormat": "CycloneDX", "components": [{}], "vulnerabilities": [{}, {}]}
        contents, analysis = describe_report(sbom, None, "s.json", "PhxSbomSca:java")
        assert "vulnerabilities-in-file=2" in contents
        assert "IGNORE the 2 vulnerabilities" in analysis

    def test_says_translate_when_a_literal_scan_type_is_set(self):
        sbom = {"bomFormat": "CycloneDX", "components": [{}], "vulnerabilities": [{}]}
        _, analysis = describe_report(sbom, "CycloneDX Scan", "s.json", "CycloneDX Scan")
        assert analysis == "Phoenix will translate the 1 findings in the file"

    def test_plain_dep_scan_for_an_inventory(self):
        sbom = {"bomFormat": "CycloneDX", "components": [{}], "vulnerabilities": []}
        _, analysis = describe_report(sbom, None, "s.json", "PhxSbomSca:java")
        assert analysis == "Phoenix will run dep-scan"

    def test_a_non_cyclonedx_report_is_not_counted(self):
        # Trivy's native JSON nests findings under Results[]; counting CycloneDX keys reports 0
        # for a file full of them.
        contents, analysis = describe_report({"Results": []}, "Trivy Scan", "/tmp/t.json", "Trivy Scan")
        assert contents == "file=t.json"
        assert analysis == "Phoenix will translate it as 'Trivy Scan'"
