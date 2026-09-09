"""
Shared pytest setup for the single-repo SBOM importer.

Adds the package directory to `sys.path` so the sibling modules under test (`cyclonedx_sbom.py`,
`sbom_sca_single_repo_to_phoenix.py`) import the way they do when deployed together in CI, per
this tool's "deploy these files together" convention - the same idiom as ci-purple-ingest's
conftest.
"""

import os
import sys

_PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PACKAGE_DIR not in sys.path:
    sys.path.insert(0, _PACKAGE_DIR)
