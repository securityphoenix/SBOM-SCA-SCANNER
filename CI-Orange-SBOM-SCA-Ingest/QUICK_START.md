# sbom-single-repo — Quick Start

## 1) Move to utility folder and install dependencies

```bash
# from repository root
cd Utils/SBOM-SCA-CONTAINER-PIPELINE/sbom-single-repo
python3 -m pip install -r requirements.txt
```

## 2) Configure Phoenix credentials

Precedence: CLI flags > environment variables > `config.ini`.

Option A - environment variables (recommended for CI):

```bash
export PHOENIX_CLIENT_ID="<your-client-id>"
export PHOENIX_CLIENT_SECRET="<your-client-secret>"
export PHOENIX_API_BASE_URL="https://api.securityphoenix.cloud"
```

Option B - local config file (never commit it):

```bash
cp config.ini.template config.ini
chmod 600 config.ini
# edit config.ini with your values
```

Option C - Jenkins: add `phoenix-client-id` and `phoenix-client-secret` as **Secret text**
credentials. `jenkins_sbom_single_repo_pipeline.groovy` binds them for you.

## 3) Generate the SBOM

`--scanners vuln` is required for `--method vulnerability` - without it the SBOM has no
vulnerabilities and Phoenix receives zero findings. For `--method sbom` leave it off: Phoenix
runs dep-scan over the uploaded SBOM and derives the vulnerabilities itself.

```bash
# container image (needs the Docker socket)
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD:/workspace" \
  aquasec/trivy:latest image --scanners vuln --format cyclonedx \
    --output /workspace/sbom.cdx.json myregistry.io/payments-api:1.4.2

# repository build files (no Docker socket needed)
docker run --rm -v "$PWD:/workspace" \
  aquasec/trivy:latest fs --scanners vuln --format cyclonedx \
    --output /workspace/sbom.cdx.json /workspace
```

With Trivy installed locally, drop the `docker run` wrapper:
`trivy image --scanners vuln --format cyclonedx --output sbom.cdx.json <image>`.

## 4) Run import

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo acme/payments \
  --file-path package-lock.json \
  --branch main \
  --import-type merge
```

## 5) Dry-run and payload preview (recommended first run)

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo acme/payments \
  --file-path package-lock.json \
  --branch main \
  --dry-run \
  --payload-out payload-preview.json
```

## 6) Bitbucket Pipelines mode

If running in Bitbucket Pipelines, use:

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --file-path package-lock.json \
  --from-bitbucket-env \
  --import-type merge
```

You can still override any value manually (for example `--repo` or `--branch`).

## 7) Jenkins mode

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --file-path package-lock.json \
  --from-jenkins-env \
  --import-type merge
```

Picks up `GIT_URL`, `BRANCH_NAME`/`GIT_BRANCH`, `GIT_COMMIT`, `BUILD_NUMBER`, and `BUILD_URL`.
Or use the ready-made `jenkins_sbom_single_repo_pipeline.groovy` and set `SCAN_MODE` to
`buildfile` or `image`.

## 8) Quick repo navigation commands

```bash
# return to Utils root
cd ../..

# inspect top-level utilities
/bin/ls -a

# open ecosystem map
open UTILS_SYSTEM_MAP.md

# open docs router
open DOC_INDEX.md
```

## 9) Utils subfolder purpose map

Use this as a quick "what is where" reference when navigating `Utils/`.

| Subfolder | Purpose |
| --- | --- |
| `Backstage Translator/` | Backstage/ServiceNow catalog translation into Phoenix data models |
| `Config_File_autogen/` | Automated Phoenix configuration generation |
| `Gating/` | Security policy gate execution in CI/CD |
| `Jenkins Integration/` | Jenkins integration helpers |
| `Loading_Script_V2/` | Legacy import scripts (deprecated) |
| `Loading_Script_V5/` | Multi-scanner import (private repo canonical copy; sanitized export for public repo) |
| `Nucleus/` | Legacy Nucleus integration |
| `Nucleustophoenix/` | Nucleus-to-Phoenix migration utility |
| `Shodan conversion/` | Shodan data conversion scripts |
| `Test/` | Utility tests/scratch datasets |
| `asset-count-scripts/` | Cloud/git/Wiz asset inventory counters |
| `asset-translator/` | Asset normalization/translation scripts |
| `client scripts/` | Client-specific translators and workflows |
| `container scan/` | Container scan helper tools |
| `container3rp/` | Third-party container report ingestion |
| `csv_translator/` | CSV/JSON vulnerability conversion + upload |
| `docs/` | Shared Utils documentation |
| `logos/` | Branding assets |
| `pentest-import/` | Pentest findings import |
| `prowler extractor/` | Prowler output extraction/transform |
| `report-Team_dashboard_report/` | Team dashboard reporting |
| `report-asset_and_vulnerability_report/` | Asset and vulnerability reporting |
| `report-dashboard/` | Executive dashboard reporting |
| `report-vulnerability_report/` | Vulnerability-focused reporting |
| `SBOM-SCA-CONTAINER-PIPELINE/` | SBOM/SCA and container pipeline utilities, including this one |
| `technology-determination/` | Technology detection/classification |

## 10) Linked docs (authoritative)

- `../../UTILS_SYSTEM_MAP.md` - Utils system map and architecture overview
- `../../DOC_INDEX.md` - docs router (best first stop)
- `../../UTILS_MASTER_INDEX.md` - utility selection + shared config model

## Notes

- Asset identity is sent as `buildFile=repo/file:branch`
- Findings are imported from CycloneDX `vulnerabilities[]`
- Components are attached as `installedSoftware[]`
- Severity is the highest rating across all CycloneDX sources (ghsa, nvd, redhat, ...), not the first one listed
- For `--method vulnerability`, generate the SBOM with `--scanners vuln`, otherwise Trivy emits components only and no findings are imported (`--method sbom` wants the inventory-only SBOM instead):
  - build files: `trivy fs --scanners vuln --format cyclonedx --output sbom.cdx.json .`
  - container image: `trivy image --scanners vuln --format cyclonedx --output sbom.cdx.json <image>`
- In Jenkins use `--from-jenkins-env` to pick up repo, branch, commit, build number, and build URL
