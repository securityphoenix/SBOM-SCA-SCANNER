# Changelog

All notable changes to the SBOM / SCA scanner pipeline.

This file is the release gate. `scripts/publish-release.sh vX.Y.Z` refuses to publish
unless a `## [vX.Y.Z]` heading for that exact version already exists below.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v1.0.1] - 2026-09-09

### Added

- `artefacts/` - Phoenix Purple banner and the SCA/SBOM supply-chain infographic.
- `README.md` - a "What it covers" table stating the four coverage areas explicitly:
  SBOM inventory, dependency vulnerabilities in CI, container image vulnerabilities,
  and EU CRA readiness. Both images are embedded in the description.

### Changed

- `README.md`, `.gitignore` and `artefacts/` now live in the private repo and sync out,
  so the private tree really is the only source of truth. `publish-release.sh` no longer
  needs its `protect` filters for them.
- `secret-scan.sh` skips binary files (images, archives, fonts). Random bytes cannot be a
  readable credential and were a false-positive risk.

### Security

- `Legacy_SBOM-SCA/` is excluded from the public sync pending a delete/keep decision.
  Publishing it would restore the incorrect container-asset claim fixed in v1.0.0.

### Added

- `scripts/secret-scan.sh` - the single source of truth for credential-leak detection.
  Scans a working tree or git-staged content. Called by `publish-release.sh` and by the
  optional pre-commit hook.
- `scripts/install-hooks.sh` - installs a pre-commit hook that blocks a commit carrying
  credential material.
- `docs/PUBLISHING.md` - the private-to-public publishing rule.
- `CHANGELOG.md` - this file.

### Changed

- `scripts/publish-release.sh` now calls `secret-scan.sh` instead of an inline pattern
  list, requires a matching `CHANGELOG.md` entry, and aborts rather than deleting a
  top-level directory that exists only in the public repo. `--dry-run` rehearses on a
  throwaway copy, so it never writes to the real public working tree.
- `Legacy_SBOM-SCA/` moved into the private repo, so the private tree is again the only
  source of truth.

  **Not yet published.** It is a stale duplicate of `CI-Orange-SBOM-SCA-Ingest/`: the two
  differ only in `README.md` and `jenkins_sbom_single_repo_pipeline.groovy`, and the Legacy
  copy still carries the incorrect claim that `PHOENIX_SCAN_TYPE='Trivy Scan'` produces a
  `CONTAINER` asset - the very error corrected in v1.0.0. Decide whether to delete it or to
  publish it clearly marked as superseded before the next release.

## [v1.0.0] - 2026-09-09

First public release, published to
<https://github.com/securityphoenix/SBOM-SCA-SCANNER>.

### Added

- `CI-Orange-SBOM-SCA-Ingest/` - importer for the classic Phoenix asset import API
  (`/v1/import/assets*`), authenticating with `client_id` + `client_secret`.
  - Two import methods: `sbom` (Phoenix runs dep-scan on the upload) and
    `vulnerability` (the pipeline scans before upload).
  - Three import types: `new`, `merge` (default), `delta`.
  - Asset identity `repo/file:branch`, recorded as a Phoenix `BUILD` asset.
  - Pipeline templates for GitHub Actions, Jenkins and Bitbucket Pipelines.
  - `local-jenkins/` - a throwaway local Jenkins that runs the whole pipeline against a
    fake build and a fake container image.
  - `depscan_vdb_warm.sh` - pre-populates the ~4 GB dep-scan vulnerability database
    (measured: cold 187 s, warm 9 s).
- `ci-purple-ingest/` - client for the CI-PURPLE asynchronous ingest API
  (`/api/v1/external/sca/ingest`), authenticating with a scoped API key exchanged for a
  short-lived token.
  - Auto-detects GitHub Actions, Azure Pipelines and Jenkins. Bitbucket exits `2` and
    points at the CI-Orange tool.
  - Asset kinds `REPO` and `CONTAINER_IMAGE`.
  - `--wait` polls to a terminal state, retries a server-retryable failed job up to four
    times, and exits `3` on a `BLOCK` verdict so a build can gate on it.
  - Pipeline templates for GitHub Actions (repo and container) and Jenkins.
- Top-level `README.md` - quick start covering both importers.
- `.gitignore` - blocks `.claude/`, `config.ini`, caches and scan output from the public repo.
- 175 contract tests running against frozen fixtures, needing no live Phoenix tenant
  (147 in `ci-purple-ingest`, 28 in `CI-Orange-SBOM-SCA-Ingest`).

### Security

- `config.ini` is excluded from the public sync and from git. Credentials are supplied
  through environment variables or the CI secret store.
- Secrets are masked in the tools' own log output.

### Fixed

- Corrected the container-asset claim in `CI-Orange-SBOM-SCA-Ingest/README.md` and in the
  Jenkins pipeline's `PHOENIX_SCAN_TYPE` help text. Measured against a live tenant,
  `PHOENIX_SCAN_TYPE='Trivy Scan'` produces a `BUILD` asset, not a `CONTAINER` asset. No
  route this pipeline can send yields container identity.
