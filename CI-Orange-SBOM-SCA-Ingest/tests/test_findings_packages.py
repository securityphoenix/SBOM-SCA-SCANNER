"""
finding.packages on the vulnerability method.

Worth covering because Phoenix builds PACKAGE_VERSION remedies from this field and nothing else:
leaving it out still returns 200 and imports every finding, just with no remedies. A package
missing a name or version is worse - the validator rejects the whole import.
"""

import json

from cyclonedx_sbom import build_findings, build_packages, build_payload, build_ref_to_component


def comp(ref, name, version=None, **kwargs):
    out = {"bom-ref": ref, "name": name, **kwargs}
    if version is not None:
        out["version"] = version
    return out


def bom(components, vulnerabilities):
    return {"bomFormat": "CycloneDX", "components": components, "vulnerabilities": vulnerabilities}


def vuln(*refs, **kwargs):
    return {"id": "CVE-2021-23337", "affects": [{"ref": r} for r in refs], **kwargs}


def packages_of(sbom):
    return build_packages(sbom["vulnerabilities"][0], build_ref_to_component(sbom))


class TestPackages:
    def test_one_package_per_affected_component(self):
        sbom = bom([comp("a", "lodash", "4.17.20"), comp("b", "minimist", "1.2.5")], [vuln("a", "b")])
        assert packages_of(sbom) == [
            {"name": "lodash", "version": "4.17.20"},
            {"name": "minimist", "version": "1.2.5"},
        ]

    def test_resolves_nested_components(self):
        parent = comp("p", "app", "1.0", components=[comp("n", "log4j-core", "2.14.1")])
        assert packages_of(bom([parent], [vuln("n")])) == [{"name": "log4j-core", "version": "2.14.1"}]

    def test_skips_what_the_validator_would_reject(self):
        sbom = bom([comp("a", "lodash"), comp("b", "", "1.0")], [vuln("a", "b", "missing")])
        assert packages_of(sbom) == []

    def test_dedupes_repeated_refs_and_never_sends_cpe(self):
        sbom = bom([comp("a", "lodash", "4.17.20", purl="pkg:npm/lodash@4.17.20")], [vuln("a", "a")])
        assert packages_of(sbom) == [{"name": "lodash", "version": "4.17.20"}]


class TestFixVersions:
    def test_unaffected_versions_become_fix_versions_and_ranges_are_ignored(self):
        v = {
            "id": "CVE-1",
            "affects": [{
                "ref": "a",
                "versions": [
                    {"version": "4.17.20", "status": "affected"},
                    {"range": "vers:npm/>=4.17.21", "status": "unaffected"},
                    {"version": "4.17.21", "status": "unaffected"},
                ],
            }],
        }
        assert packages_of(bom([comp("a", "lodash", "4.17.20")], [v]))[0]["fixVersions"] == ["4.17.21"]

    def test_recommendation_is_read_for_a_single_component(self):
        sbom = bom([comp("a", "lodash", "4.17.20")], [vuln("a", recommendation="Upgrade lodash to version 4.17.21.")])
        assert packages_of(sbom)[0]["fixVersions"] == ["4.17.21"]

    def test_recommendation_is_not_attributed_across_components(self):
        sbom = bom(
            [comp("a", "lodash", "4.17.20"), comp("b", "lodash-es", "4.17.20")],
            [vuln("a", "b", recommendation="Update to 4.17.21")],
        )
        assert all("fixVersions" not in p for p in packages_of(sbom))

    def test_vague_recommendation_gives_no_version(self):
        sbom = bom([comp("a", "lodash", "4.17.20")], [vuln("a", recommendation="See the advisory")])
        assert "fixVersions" not in packages_of(sbom)[0]


class TestFindings:
    def test_finding_without_resolvable_components_has_no_packages_key(self):
        findings = build_findings(bom([], [vuln("missing")]), {}, "r/f:main")
        assert len(findings) == 1
        assert "packages" not in findings[0]

    def test_payload_carries_valid_packages(self):
        sbom = bom([comp("a", "lodash", "4.17.20"), comp("b", "nover")], [vuln("a", "b")])
        payload = build_payload(sbom, "assess", "merge", "org/repo", "package-lock.json", "main", "cyclonedx-sca")
        json.dumps(payload)
        finding = payload["assets"][0]["findings"][0]
        assert finding["packages"] == [{"name": "lodash", "version": "4.17.20"}]
        assert all(p["name"] and p["version"] for p in finding["packages"])
