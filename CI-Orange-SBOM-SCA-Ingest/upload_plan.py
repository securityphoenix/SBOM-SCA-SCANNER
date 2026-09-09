"""
What this upload asks Phoenix to do, and how to say it in one line.

Both questions come from the same place - the scan type. `PhxSbomSca:<projectType>` asks Phoenix
to derive vulnerabilities from the components with dep-scan; a literal scan type asks it to
translate the findings the report already carries. So resolving the project type and describing
what the upload will do belong together, and neither belongs in the driver.
"""

import os
import sys

from cyclonedx_sbom import PURL_TYPE_TO_PROJECT_TYPE, detect_project_types

# Spellings accepted for --project-type that are not what Phoenix calls the ecosystem. cdxgen's
# -t vocabulary and Phoenix's disagree - cdxgen says "js" where Phoenix says "npm" - and a single
# PROJECT_TYPE in the CI templates feeds both, so translate here instead of asking anyone to keep
# two values in step. Phoenix normalises the same aliases server-side; doing it here as well is
# what turns a silently narrowed scan into a warning the build log shows.
PROJECT_TYPE_ALIASES = {
    "js": "npm",
    "ts": "npm",
    "node": "npm",
    "nodejs": "npm",
    "javascript": "npm",
    "typescript": "npm",
    "kotlin": "java",
    "groovy": "java",
    "scala": "java",
    "py": "python",
    "golang": "go",
    "csharp": "dotnet",
    "c#": "dotnet",
    ".net": "dotnet",
    "net": "dotnet",
    "c++": "c",
    "cpp": "c",
}

KNOWN_PROJECT_TYPES = set(PURL_TYPE_TO_PROJECT_TYPE.values()) | {"universal"}


def _normalise_explicit(value: str) -> str:
    """
    Map a caller-supplied project type onto Phoenix's vocabulary, dropping what it cannot place.

    Accepts a comma-separated list for a polyglot repository. Never returns an empty string:
    "universal" is the fallback, because the SBOM has already been produced by the time anyone
    finds out the type was wrong, and a broad scan beats a failed build.
    """
    resolved = []
    unknown = []
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        mapped = token if token in KNOWN_PROJECT_TYPES else PROJECT_TYPE_ALIASES.get(token)
        if mapped is None:
            unknown.append(token)
        elif mapped not in resolved:
            resolved.append(mapped)

    if unknown:
        print(
            f"Warning: unrecognised project type(s) {', '.join(unknown)} - dropped. "
            f"Known: {', '.join(sorted(KNOWN_PROJECT_TYPES))} (or 'auto' to read it from the BOM).",
            file=sys.stderr,
            flush=True,
        )

    if not resolved:
        print("Warning: no usable project type left - scanning as 'universal'.", file=sys.stderr, flush=True)
        return "universal"

    # "universal" already covers every ecosystem; pairing it with a specific type only makes the
    # scan type harder to read.
    if "universal" in resolved and len(resolved) > 1:
        return "universal"

    return ",".join(resolved)


def resolve_project_type(configured: str, sbom: dict) -> str:
    """
    Decide the "PhxSbomSca:<projectType>" suffix for this upload.

    The value has exactly one consumer - dep-scan's ?type= - so an unusable one is reported here
    rather than discovered later by noticing an asset looks thin. "auto" (the default) reads the
    ecosystems out of the BOM; an explicit value goes through `_normalise_explicit`.
    """
    value = (configured or "").strip().lower()
    if value not in ("", "auto"):
        return _normalise_explicit(value)

    detected = detect_project_types(sbom)
    if detected:
        print(f"project-type: detected {','.join(detected)} from the BOM", flush=True)
        return ",".join(detected)

    print(
        "Warning: could not determine the project type from the BOM (no recognisable "
        "package URLs) - scanning as 'universal'. Pass --project-type to name it.",
        file=sys.stderr,
        flush=True,
    )
    return "universal"


def describe_report(sbom: dict, literal_scan_type, sbom_path: str, scan_type: str):
    """
    One line saying what is in the file and what Phoenix will do with it.

    components/vulnerabilities are CycloneDX's own top-level arrays. A report in any other format
    keeps its findings elsewhere - Trivy's native JSON nests them under Results[] - so counting
    those keys there yields 0 for a file full of findings. Report the counts only when they mean
    something.
    """
    if str(sbom.get("bomFormat") or "").lower() != "cyclonedx":
        return f"file={os.path.basename(sbom_path)}", f"Phoenix will translate it as {scan_type!r}"

    vuln_count = len(sbom.get("vulnerabilities", []))
    contents = f"components={len(sbom.get('components', []))}, vulnerabilities-in-file={vuln_count}"

    if literal_scan_type:
        return contents, f"Phoenix will translate the {vuln_count} findings in the file"
    if vuln_count:
        # Worth saying plainly: this is the case where the upload throws away work the pipeline
        # already paid for, and it is silent server-side.
        return contents, (
            f"Phoenix will run dep-scan and IGNORE the {vuln_count} vulnerabilities already "
            f"in the file - pass --scan-type 'CycloneDX Scan' to import those instead"
        )
    return contents, "Phoenix will run dep-scan"
