# SBOM / SCA Scanner Pipeline for Phoenix Security

Scan a repository or a container image, produce a CycloneDX SBOM, and import the results into
[Phoenix Security](https://phoenix.security).

This repository ships **two independent importers**. They target two different Phoenix APIs.
Pick one — you do not need both.

| Directory | Phoenix API | Auth | Use it when |
| --- | --- | --- | --- |
| [`CI-Orange-SBOM-SCA-Ingest/`](CI-Orange-SBOM-SCA-Ingest/) | `/v1/import/assets*` (classic asset import) | `client_id` + `client_secret` | You are on the established Phoenix import API. Supports Bitbucket. |
| [`ci-purple-ingest/`](ci-purple-ingest/) | `/api/v1/external/sca/ingest` (CI-PURPLE ingest) | scoped API key → short-lived token | You are on the newer asynchronous ingest contract with job polling and a build verdict. |

Each directory has its own full reference README. This page is the fast path.

---

## Requirements

- Python **3.7+** and `pip`
- A CycloneDX JSON SBOM producer — [Trivy](https://github.com/aquasecurity/trivy),
  [OWASP dep-scan](https://github.com/owasp-dep-scan/dep-scan), `cdxgen`, or Grype
- Phoenix Security credentials (see [Credentials](#credentials))
- Docker, only if you run the scanners as containers

---

## Step 1 — generate the SBOM

The scanner is not part of this repository. You produce a CycloneDX JSON file first, then import it.

### Scan a repository (SCA of build files and lockfiles)

```bash
trivy fs \
  --scanners vuln \
  --format cyclonedx \
  --output sbom.cdx.json \
  .
```

### Scan a container image

```bash
trivy image \
  --scanners vuln \
  --format cyclonedx \
  --output sbom.cdx.json \
  myregistry.io/payments-api:1.4.2
```

### Without a local Trivy install

```bash
# repository — no Docker socket needed, it only reads files
docker run --rm -v "$PWD:/workspace" aquasec/trivy:latest fs \
  --scanners vuln --format cyclonedx --output /workspace/sbom.cdx.json /workspace

# container image — needs the Docker socket to read the image
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD:/workspace" \
  aquasec/trivy:latest image \
  --scanners vuln --format cyclonedx --output /workspace/sbom.cdx.json \
  myregistry.io/payments-api:1.4.2
```

> **`--scanners vuln` matters.** Leave it off and Trivy writes an inventory-only SBOM with an empty
> `vulnerabilities` array. The import still succeeds, but Phoenix receives **zero findings**. That is
> the most common cause of "the import worked but there are no vulnerabilities".
>
> The exception is `CI-Orange` with `--method sbom`: there an inventory-only SBOM is what you want,
> because Phoenix runs dep-scan over the uploaded file itself.

Any CycloneDX JSON producer works. See
[`CI-Orange-SBOM-SCA-Ingest/README.md`](CI-Orange-SBOM-SCA-Ingest/README.md#choosing-a-scanner)
for a scanner comparison, dep-scan usage, and the ~4 GB dep-scan database warm-up.

---

## Step 2 — import into Phoenix

### Option A — `CI-Orange-SBOM-SCA-Ingest` (classic import API)

```bash
cd CI-Orange-SBOM-SCA-Ingest
python3 -m pip install -r requirements.txt

export PHOENIX_CLIENT_ID="your-client-id"
export PHOENIX_CLIENT_SECRET="your-client-secret"
export PHOENIX_API_BASE_URL="https://api.securityphoenix.cloud"

python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo acme/payments \
  --file-path package-lock.json \
  --branch main \
  --import-type merge
```

Creates one Phoenix `BUILD` asset with the identity `repo/file:branch` — for example
`acme/payments/package-lock.json:main`.

Dry run first — no credentials needed, no API call made:

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo acme/payments --file-path package-lock.json --branch main \
  --dry-run --payload-out payload-preview.json
```

**Import types** — set with `--import-type`:

| Value | Behaviour |
| --- | --- |
| `new` | Baseline. Removes every vulnerability previously imported for this assessment, then imports this report. |
| `merge` | Default. Adds new findings, keeps matching ones, and **deletes previously imported findings this report does not contain**. |
| `delta` | Partial report. Adds and updates, and never removes anything absent from the report. |

Use `delta` when the scan is deliberately partial (one manifest out of several).

**Import methods** — set with `--method`:

| | `--method sbom` | `--method vulnerability` (default) |
| --- | --- | --- |
| Who finds the vulnerabilities | Phoenix, by running dep-scan on the upload | Your pipeline, before upload |
| SBOM must contain vulnerabilities | No | **Yes** |
| Result | Asynchronous — poll with `--wait` | Synchronous |

### Option B — `ci-purple-ingest` (CI-PURPLE ingest API)

```bash
cd ci-purple-ingest
python3 -m pip install -r requirements.txt

export PHOENIX_API_KEY="your-scoped-ci-ingest-key"

python3 ci_purple_sbom_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --asset-kind REPO \
  --build-file-path package-lock.json \
  --wait
```

For a container image:

```bash
python3 ci_purple_sbom_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --asset-kind CONTAINER_IMAGE \
  --registry myregistry.io \
  --image payments-api \
  --tag 1.4.2 \
  --digest sha256:<64-hex-digest> \
  --dockerfile-path Dockerfile \
  --wait
```

Repository, branch, commit, and CI provenance are **auto-detected**. Supported CI systems:
GitHub Actions, Azure Pipelines, and Jenkins. Bitbucket is **not supported** here — the tool exits
`2` and points you at `CI-Orange-SBOM-SCA-Ingest`, which does support it.

The API key must be created with **exactly** `scopes: ["ci:ingest"]`. Any other scope set is
rejected with `403 ci_ingest_scope_required`.

---

## Credentials

**Never hardcode credentials. Never commit `config.ini`.** It is listed in `.gitignore`.

### CI-Orange

Resolved in this order, highest precedence first:

1. CLI flags `--client-id` / `--client-secret` — ad-hoc debugging only
2. Environment variables `PHOENIX_CLIENT_ID` / `PHOENIX_CLIENT_SECRET` — **recommended for CI**
3. `config.ini`, section `[phoenix]` — local workstation use

`PHOENIX_API_BASE_URL` sets the tenant URL. It defaults to `https://api.securityphoenix.cloud`.

### ci-purple-ingest

Set `PHOENIX_API_KEY` as an environment variable. **Do not use the `--api-key` flag in a pipeline** —
a command-line value is visible to any other process on the runner through `ps` and lands in shell
history. The client mints a short-lived (1-hour) token from the key per run and holds it in memory
only.

Store the secret as:

- GitHub Actions — a repository secret named `PHOENIX_API_KEY`
- Jenkins — a **Secret text** credential, bound with `credentials('phoenix-ci-ingest-api-key')`
- Azure DevOps — a secret pipeline variable, or a variable group backed by a secrets store

### Local setup

```bash
cp config.ini.template config.ini
chmod 600 config.ini
# then fill in the values
```

---

## CI pipeline templates

Ready-to-use pipeline definitions ship with each tool.

| Platform | CI-Orange | ci-purple-ingest |
| --- | --- | --- |
| GitHub Actions | `github-actions-sbom-phoenix.yml.example` | `github-actions-ci-purple-ingest.yml.example`, `github-actions-ci-purple-container.yml.example` |
| Jenkins | `jenkins_sbom_single_repo_pipeline.groovy` | `jenkins_ci_purple_ingest_pipeline.groovy` |
| Bitbucket Pipelines | `bitbucket-pipelines.yml.example` | not supported |

Copy the file into your repository, then set the credential as a CI secret.

`CI-Orange-SBOM-SCA-Ingest/local-jenkins/` runs a throwaway local Jenkins against a fake build and a
fake container image, so you can test the whole pipeline before touching a real one.

---

## Exit codes

### CI-Orange

| Code | Meaning |
| --- | --- |
| `0` | Import submitted, or settled successfully with `--wait`. |
| `1` | Handled failure — bad config, unreadable or non-CycloneDX SBOM, auth failure, non-2xx response, or a poll timeout. Reason on stderr. |
| `2` | Invalid command line. |

### ci-purple-ingest

| Code | Meaning |
| --- | --- |
| `0` | Ingest submitted, or `--wait` finished with a verdict other than `BLOCK`. |
| `1` | Handled runtime failure. Reason on stderr. |
| `2` | Invalid command line, **or** the detected CI provider is Bitbucket. Nothing was submitted. |
| `3` | `--wait` finished and the verdict is `BLOCK`. Use this to gate the build. |

A poll timeout exits `1`, but the upload was already accepted. Check the job before you treat it as
a failed import.

---

## Proxies and private certificate authorities

`HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` are honoured automatically.

For a self-hosted Phoenix deployment or a TLS-inspecting proxy with a private CA, pass
`--ca-bundle /path/to/ca.pem` (or set `PHOENIX_CA_BUNDLE` for `ci-purple-ingest`).

`--no-verify-tls` disables certificate verification. Use it only as a short-lived diagnostic against
an internal endpoint. Never use it against a public tenant.

---

## Tests

Contract tests run against frozen server fixtures. No live Phoenix tenant is needed.

```bash
cd ci-purple-ingest && python3 -m pytest tests/ -q
cd CI-Orange-SBOM-SCA-Ingest && python3 -m pytest tests/ -q
```

---

## Security

- Never hardcode credentials in source files or pipeline scripts
- Keep `config.ini` out of version control and `chmod 600` it
- Prefer environment variables and the CI secret store over files
- Secrets are masked in this tool's own log output — see each README's "Secret-safe logs" section

---

## Full documentation

- [`CI-Orange-SBOM-SCA-Ingest/README.md`](CI-Orange-SBOM-SCA-Ingest/README.md) — complete option
  reference, scanner comparison, Jenkins and Bitbucket setup, severity mapping, request size limits
- [`CI-Orange-SBOM-SCA-Ingest/QUICK_START.md`](CI-Orange-SBOM-SCA-Ingest/QUICK_START.md) — fastest setup
- [`ci-purple-ingest/README.md`](ci-purple-ingest/README.md) — CI auto-detection, scoped keys, retry
  model, asset kinds, known limits
