# sbom-single-repo

Single-repo SCA utility for importing CycloneDX SBOM findings into Phoenix.

## Purpose

This utility is designed for teams that want to import **one repository SBOM at a time**
into Phoenix with a stable build-oriented identity.

It specifically:

- Reads one CycloneDX JSON SBOM file
- Builds one Phoenix `BUILD` asset identity using `repo/file:branch`
- Imports vulnerabilities and component metadata through Phoenix asset import APIs
- Preserves source context (repository, file path, branch, and CI metadata) using tags

Use this when your pipeline produces a per-repo SBOM (GitHub, Bitbucket Cloud, or Bitbucket
on-prem CI) and you want predictable mapping between SBOM source and Phoenix `BUILD` assets.

This utility creates one `BUILD` asset using an asset identity format:

- `repo/file:branch`

Example:

- `acme/payments/package-lock.json:main`

It can also auto-read Bitbucket Pipeline metadata with `--from-bitbucket-env`.

## Why this utility

Phoenix currently supports `BUILD` imports through `buildFile` and related metadata.  
If your preferred source identity model (`repo/file:branch`) is not natively modeled yet, this utility encodes it into:

- `attributes.buildFile`
- tags (`repository`, `sourceFile`, `branch`, `assetKeyMode`)

This keeps imports usable now while preserving your desired identity convention.

## What it imports

- CycloneDX JSON SBOM (`bomFormat: CycloneDX`)
- Vulnerabilities as Phoenix findings
- Components as `installedSoftware`

## Files

- `sbom_sca_single_repo_to_phoenix.py` - CLI entry point (deploy the four `.py` files together)
- `phoenix_client.py` - configuration and every Phoenix HTTP call
- `cyclonedx_sbom.py` - CycloneDX parsing, severity mapping, payload construction
- `ci_context.py` - repository and CI metadata resolution
- `jenkins_sbom_single_repo_pipeline.groovy` - Jenkins pipeline (both methods, both scan modes)
- `github-actions-sbom-phoenix.yml.example` - GitHub Actions workflow (same matrix)
- `bitbucket-pipelines.yml.example` - Bitbucket Pipelines example
- `depscan_vdb_warm.sh` - pre-populate the dep-scan vulnerability DB on a build agent
- `local-jenkins/` - throwaway local Jenkins that runs the whole pipeline against a fake build
  and a fake container image (see [Testing it locally](#testing-it-locally-with-jenkins))
- `config.ini.template` - config template
- `requirements.txt` - Python dependencies
- `QUICK_START.md` - fast setup/run

## Step 1 - generate the CycloneDX SBOM

Whether you need `--scanners vuln` depends on the import method you are heading for.

For `--method vulnerability` it is **required**. Without it Trivy emits an inventory-only SBOM
whose `vulnerabilities` array is empty, the import still succeeds, and Phoenix receives the
asset and its `installedSoftware` but **zero findings**. This is the single most common cause
of an "import worked but there are no vulnerabilities" report.

For `--method sbom` an inventory-only SBOM is exactly what is wanted: Phoenix runs dep-scan
over the uploaded file and derives the vulnerabilities itself, so scanning here would only
produce a result the upload discards. The examples below include the flag because they feed
the vulnerability method; drop it for the sbom method.

### Container image

```bash
# Trivy installed locally
trivy image \
  --scanners vuln \
  --format cyclonedx \
  --output sbom.cdx.json \
  myregistry.io/payments-api:1.4.2

# Trivy via Docker (no local install; needs the Docker socket to read the image)
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD:/workspace" \
  aquasec/trivy:latest image \
    --scanners vuln \
    --format cyclonedx \
    --output /workspace/sbom.cdx.json \
    myregistry.io/payments-api:1.4.2
```

For an image, set `--file-path` to something that identifies the build source, for example
`Dockerfile`, so the asset key reads `acme/payments/Dockerfile:main`.

### Repository build files (SCA)

Scans dependency manifests and lockfiles in the working tree - `package-lock.json`,
`yarn.lock`, `requirements.txt`, `poetry.lock`, `go.sum`, `pom.xml`, `Gemfile.lock`, and so on.

```bash
# Trivy installed locally
trivy fs \
  --scanners vuln \
  --format cyclonedx \
  --output sbom.cdx.json \
  .

# Trivy via Docker (no Docker socket needed - it only reads files)
docker run --rm \
  -v "$PWD:/workspace" \
  aquasec/trivy:latest fs \
    --scanners vuln \
    --format cyclonedx \
    --output /workspace/sbom.cdx.json \
    /workspace
```

Any CycloneDX JSON producer works here, not just Trivy - Grype (`grype -o cyclonedx-json`),
Syft plus a vulnerability source, `cdxgen`, or a vendor SBOM. The importer only requires
`bomFormat: CycloneDX`; components become `installedSoftware` and `vulnerabilities` become findings.
An SBOM with no `vulnerabilities` array imports cleanly as an inventory-only asset.

### Choosing a scanner

| Scanner | Produces | Build files | Container images | Use with |
| --- | --- | --- | --- | --- |
| `cdxgen` | inventory SBOM, no vulnerabilities | yes | **no** (see below) | `--method sbom` |
| `trivy` | CycloneDX, with or without vulnerabilities | yes | yes | either method |
| `dep-scan` | CycloneDX VDR (`sbom-<type>.vdr.json`) | yes | yes | `--method vulnerability` |

**cdxgen cannot scan a container image from inside its own container.** Invoked as
`cdxgen -t docker <image>` with the Docker socket mounted, it fails with `Unable to pull <image>`
even when the image is present locally, because it exports the image through its own OCI path
rather than the mounted socket. Container inventory SBOMs therefore come from Trivy with the
vulnerability scanners left off:

```bash
trivy image --format cyclonedx --output sbom.cdx.json myregistry.io/payments-api:1.4.2
```

That produces a plain CycloneDX inventory (measured: 97 components, 0 vulnerabilities on
`debian:11-slim`) - exactly what `--method sbom` wants. Both pipelines pick Trivy automatically
for image-mode SBOMs and reject an explicit `cdxgen` + image combination with that explanation.

**OWASP dep-scan** resolves transitive dependencies through cdxgen, so it typically reports more
components than Trivy on the same repository. Its VDR imports with no special handling - the
`affects[].ref` values match the component `bom-ref` values, so finding locations resolve cleanly.

```bash
# build files
docker run --rm -v depscan-vdb:/vdb -e VDB_HOME=/vdb -u root \
  -v "$PWD:/app:ro" -v "$PWD/reports:/reports" \
  ghcr.io/owasp-dep-scan/dep-scan:latest \
  depscan --no-banner --vdb-scope app --src /app --reports-dir /reports

# container image (add the Docker socket and the OS vulnerability data)
docker run --rm -v depscan-vdb:/vdb -e VDB_HOME=/vdb -u root \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/reports:/reports" \
  ghcr.io/owasp-dep-scan/dep-scan:latest \
  depscan --no-banner --vdb-scope app+os --src myregistry.io/payments-api:1.4.2 --reports-dir /reports
```

Three things to know about dep-scan:

- The image has **no default entrypoint** - `depscan` must be given explicitly.
- It downloads a **~4GB vulnerability database**. Mount a named Docker volume and point
  `VDB_HOME` at it, or every build pays that cost again: measured cold 187s, warm **9s**.
- The VDR filename is `sbom-<project_type>.vdr.json`, defaulting to `sbom-universal.vdr.json`.
  Locate it by glob rather than by a hardcoded name.

**cdxgen** ships inside the dep-scan image and produces the inventory SBOM for `--method sbom`.
It refuses to run as root, so run it as the image's default user:

```bash
docker run --rm -v "$PWD:/app:ro" -v "$PWD/reports:/reports" \
  --entrypoint cdxgen ghcr.io/owasp-dep-scan/dep-scan:latest \
  -t universal -o /reports/sbom.cdx.json /app
```

## Import methods

Phoenix accepts CI results two different ways, and this utility supports both. Pick with
`--method` (or `method` in `config.ini`).

| | `--method sbom` | `--method vulnerability` |
| --- | --- | --- |
| Endpoint | `POST /v1/import/assets/file/translate` | `POST /v1/import/assets` |
| Body | multipart: the SBOM file itself | JSON: parsed findings |
| scanType | `PhxSbomSca:<projectType>` | n/a |
| Who finds the vulnerabilities | **Phoenix**, by running dep-scan over the uploaded SBOM | **the pipeline**, before upload |
| SBOM must contain vulnerabilities | No - an inventory SBOM is enough | Yes |
| Result | asynchronous; poll with `--wait` | synchronous |
| Jenkins/Actions `auto` picks it for | build files | container images |
| CLI default | | **yes** - the importer defaults to `vulnerability` when neither `--method` nor a config file sets one |

Rule of thumb: if the pipeline already ran a vulnerability scanner, send the findings
(`vulnerability`). If it only produced an inventory SBOM, send the SBOM and let Phoenix analyse
it (`sbom`).

### sbom method

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo acme/payments --file-path package-lock.json --branch main \
  --method sbom --project-type auto \
  --import-type merge --wait
```

`--project-type` becomes the `PhxSbomSca:` suffix that tells Phoenix's dep-scan service which
ecosystems to analyse. It reaches dep-scan and nothing else — the scan type handed to the
translator is rewritten to `CycloneDX Scan` first — so a value dep-scan does not recognise costs
enrichment *silently*: the import still succeeds, with fewer vulnerabilities than the SBOM could
have yielded.

The default `auto` reads the ecosystems out of the BOM's package URLs, so the value describes what
was actually resolved rather than what someone typed once:

| BOM | Detected |
| --- | --- |
| `pkg:npm/…` and `pkg:maven/…` components | `npm,java` |
| mostly `pkg:deb/…` — a container or OS image | `universal` |
| no recognisable purls | `universal`, with a warning |

An explicit value still wins, may be a comma-separated list for a polyglot repository, and is
mapped onto Phoenix's vocabulary: cdxgen calls the Node ecosystem `js`, Phoenix calls it `npm`, and
a single `PROJECT_TYPE` in the CI templates feeds both. Unrecognised tokens are dropped with a
warning rather than forwarded. Phoenix applies the same mapping server-side; the client does it too
so the build log shows it.

#### Importing a report that already has vulnerabilities

`PhxSbomSca:` asks Phoenix to *derive* vulnerabilities from the component list, so it ignores
any the report already carries. To have Phoenix translate those instead, name the report
format with `--scan-type`:

```bash
# an enriched CycloneDX SBOM - findings translated, not re-derived
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json --method sbom \
  --scan-type 'CycloneDX Scan' \
  --repo acme/payments --file-path package-lock.json --branch main --wait

# native Trivy JSON - translated by Phoenix's Trivy translator rather than re-analysed
trivy image --scanners vuln --format json --output trivy.json myregistry.io/api:1.4.2
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file trivy.json --method sbom \
  --scan-type 'Trivy Scan' \
  --repo acme/payments --file-path Dockerfile --branch main --wait
```

`--scan-type` takes any value from Phoenix's scanType catalogue (`CycloneDX Scan`,
`Trivy Scan`, `Anchore Grype`, `Snyk Scan`, ...) and must match the format of the file being
uploaded. It replaces the derived `PhxSbomSca:<projectType>` entirely, so `--project-type`
has no effect alongside it and the script warns if both are given.

Two reasons to prefer it over `--method vulnerability` for an enriched report:

- **Fidelity.** The server-side translators carry package metadata, misconfigurations and
  secrets; this script's own CycloneDX parser carries only vulnerabilities and components.
- **Speed and volume.** Dep-scan is skipped entirely, so the import completes in seconds rather
  than minutes and carries the findings the report already holds.

> **Asset typing does not work this way.** An earlier version of this document claimed the Trivy
> translator reads `container_image` out of the report and produces a `CONTAINER` asset. Measured
> against a live tenant, it does not: an image imported through `--scan-type 'Trivy Scan'` lands as
> a `BUILD` asset, exactly like the derived `PhxSbomSca:` route and the vulnerability method. No
> route this tool can drive produces container identity today.
>
> To record a genuine `CONTAINER` asset, post the Trivy report through the multi-scanner loading
> script instead. It uses `POST /v1/import/assets`, where the asset type is an explicit field on the
> payload rather than something the server has to infer:
>
> ```bash
> python3 phoenix_multi_scanner_import.py --file trivy.json \
>   --scanner trivy --asset-type CONTAINER --import-type merge
> ```

The file is uploaded, not parsed, so with `--scan-type` set the input no longer has to be
CycloneDX. Without it, the CycloneDX check applies exactly as before.

The upload returns immediately with a request id. `--wait` polls
`GET /v1/import/assets/file/translate/request/{id}` until the status reaches `IMPORTED`, and
fails the build on `ERROR`; without it the script returns as soon as the file is accepted.
`--no-auto-import` stages the translation for review instead of importing it.

**Known server-side limitation: concurrent uploads collide.** Measured against a live tenant,
`PhxSbomSca` translate requests submitted close together do not all complete. Three *identical*
SBOMs uploaded 40ms apart produced one `IMPORTED` after four minutes and two that never did. The
same pattern appeared in three separate unplanned occurrences: whenever two uploads landed within
~20 seconds of each other, the first imported in four to five minutes and the second did not.
Requests submitted in isolation imported reliably every time.

A collided request is lost, not merely slow. Every one observed sat in `TRANSLATING` for around an
hour and then terminated in `ERROR: ResourceAccessException` - none ever recovered. That is
consistent with the backend's own timeout: `DepscanServiceApiClient` calls the dep-scan service
with `setReadTimeout(Duration.ofMinutes(60))`, and `ResourceAccessException` is what Spring's
`RestTemplate` raises when a read timeout fires. The likely cause is limited concurrency on that
service, so simultaneous uploads queue behind one another until the caller gives up.

This matters because a CI fleet produces exactly that pattern - several repositories building at
once, each uploading an SBOM. Until it is fixed server-side:

- **Serialise sbom-method uploads** where you can. In Jenkins, `disableConcurrentBuilds()` covers
  one job; across jobs, set `PHOENIX_UPLOAD_LOCK` to a shared Lockable Resource name so every job
  using it queues on the same lock.
- **Prefer the vulnerability method for anything fan-out.** It is a single synchronous POST with
  no server-side queue, and Trivy covers both build files and container images.
- **Do not treat a stuck `TRANSLATING` as your bug.** Check whether another upload from the same
  organization was in flight at the same moment.

**How long a successful import takes.** An uncontended request - build file or container, 5 or 98
components - imports in roughly four to five minutes. Anything much beyond that has usually
collided with another upload rather than simply being slow.

Two consequences for `--wait`, which is why it is opt-in in both CI pipelines:

- A poll timeout only bounds how long the build waits; the request keeps translating server-side
  and may still import, so the error message prints its URL. Do not read a timeout as success
  either - if the upload collided with another, it will end in `ERROR` about an hour later.
- A terminal `ERROR` is real and does fail the build, with whatever detail Phoenix returned.

### vulnerability method

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo acme/payments --file-path Dockerfile --branch main \
  --method vulnerability --import-type merge
```

This is the default, and the behaviour described in the rest of this document. If the SBOM has
components but no vulnerabilities, the script warns rather than silently importing zero findings.

## Step 2 - import the SBOM into Phoenix

```bash
# from repo root
cd Utils/SBOM-SCA-CONTAINER-PIPELINE/sbom-single-repo
python3 -m pip install -r requirements.txt

# import one SBOM (credentials resolved as described below)
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo acme/payments \
  --file-path package-lock.json \
  --branch main \
  --import-type merge

# preview the payload only - no credentials needed, no API call made
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo acme/payments \
  --file-path package-lock.json \
  --branch main \
  --dry-run \
  --payload-out payload-preview.json
```

On success the script prints the assets/findings count, then the API response:

```text
Prepared payload: assets=1, findings=83
Import submitted successfully.
{
  "status": "accepted"
}
```

### Import types

| `--import-type` | Behaviour |
| --- | --- |
| `new` | Baseline import. **Removes every vulnerability previously imported for this assessment**, then imports this report |
| `merge` | Update. Adds new findings, leaves matching ones unchanged, and **deletes previously imported findings this report does not contain** (default) |
| `delta` | Partial report. Adds and updates, and **never removes** anything absent from the report |

`merge` is the default and it *is* destructive for findings the current scan did not see -
that is what makes it a full-scope update. Reach for `delta` when the report is deliberately
partial (one manifest out of several, a sub-project), because only `delta` leaves the rest of
the assessment alone.

## Credentials

The importer needs a Phoenix **client ID** and **client secret**. It resolves them from three
places, highest precedence first:

| Precedence | Source | Use it for |
| --- | --- | --- |
| 1 | CLI flags `--client-id` / `--client-secret` | Ad-hoc runs and debugging |
| 2 | Environment variables `PHOENIX_CLIENT_ID` / `PHOENIX_CLIENT_SECRET` | **CI pipelines (recommended)** |
| 3 | `config.ini`, section `[phoenix]` | Local workstation use |

`PHOENIX_API_BASE_URL` (env) or `api_base_url` (config) sets the tenant URL and defaults to
`https://api.securityphoenix.cloud`. `--api-base-url` overrides both.

### Option A - environment variables (recommended for CI)

```bash
export PHOENIX_CLIENT_ID="your-client-id"
export PHOENIX_CLIENT_SECRET="your-client-secret"
export PHOENIX_API_BASE_URL="https://api.securityphoenix.cloud"

python3 sbom_sca_single_repo_to_phoenix.py --sbom-file sbom.cdx.json ...
```

### Option B - config.ini (local use)

Copy the template and fill it in. **`config.ini` holds a live secret - never commit it.**

```bash
cp config.ini.template config.ini
chmod 600 config.ini
```

```ini
[phoenix]
client_id = your-client-id
client_secret = your-client-secret
api_base_url = https://api.securityphoenix.cloud
import_type = merge
assessment_name = single-repo-sca-sbom

[options]
verify_tls = true
timeout_seconds = 60
```

Point at it with `--config config.ini` (it is also the default when present in the working directory).

### Option C - Jenkins credentials store

Do **not** put secrets in the pipeline script. Add two **Secret text** credentials in Jenkins
(Manage Jenkins -> Credentials), then bind them in the pipeline:

| Jenkins credential ID | Value |
| --- | --- |
| `phoenix-client-id` | Phoenix client ID |
| `phoenix-client-secret` | Phoenix client secret |

`jenkins_sbom_single_repo_pipeline.groovy` already binds them, which is why no credential
values appear anywhere in the script:

```groovy
environment {
    PHOENIX_CLIENT_ID = credentials('phoenix-client-id')
    PHOENIX_CLIENT_SECRET = credentials('phoenix-client-secret')
}
```

Jenkins masks these in console output. Use the same IDs for the SonarQube integration in
`Utils/Jenkins Integration/` so one credential pair covers both pipelines.

### Verifying credentials

`--dry-run` deliberately does **not** need credentials, so it cannot confirm them. To check
auth and connectivity, run a real import of the small sample SBOM:

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo test/connectivity --file-path package-lock.json --branch main \
  --import-type new --assessment-name phoenix-connectivity-check
```

Bad credentials fail fast and non-zero:

```
Error: Token request failed: HTTP 401 - {"error":"bad credentials"}
```

### Upload flow

The script performs a two-call sequence against Phoenix API v1.25:

1. `GET {api_base_url}/v1/auth/access_token` with HTTP Basic auth (`client_id:client_secret`),
   returning a bearer token
2. `POST {api_base_url}/v1/import/assets` with `Authorization: Bearer <token>` and
   `Content-Type: application/json`, carrying the generated payload

Non-2xx responses at either step raise and exit non-zero, so a failed upload fails the build
rather than passing silently.

TLS verification is on by default. For an internal endpoint with a private CA, install that CA
in the runner's trust store (or point `REQUESTS_CA_BUNDLE` / `SSL_CERT_FILE` at it) - that
keeps verification working. `--no-verify-tls` is **not** the fix for that: it disables
certificate verification entirely, so anything able to intercept the connection can present its
own certificate and read the credentials and SBOM. Treat it as a short-lived diagnostic for
confirming a certificate problem, never as a standing setting in a pipeline.

The importer also refuses an `http://` API URL outright, because the token call sends
client_id and client_secret as HTTP Basic. `--allow-insecure-http` overrides that for a local
mock or lab endpoint and warns each time.

## Options reference

Every option the importer accepts, what sets it, and when it matters.

### Required

| Option | Notes |
| --- | --- |
| `--sbom-file PATH` | The CycloneDX JSON to import. The only always-required flag. |
| `--file-path PATH` | Manifest path recorded in the asset key, e.g. `package-lock.json`. For image scans use something stable like `Dockerfile`. |
| `--repo OWNER/NAME` | Repository identifier. Supplied directly, or derived by one of the `--from-*-env` flags. |
| `--branch NAME` | Branch name. Supplied directly, or derived by one of the `--from-*-env` flags. |

`--repo` and `--branch` are only required in the sense that they must end up populated; a
`--from-*-env` flag can fill either. Missing values fail before any network call, and the error
names which ones and which CI mode might supply them.

### Asset identity and CI context

| Option | Default | Purpose |
| --- | --- | --- |
| `--from-jenkins-env` | off | Fill repo/branch/commit/build number/build URL from `GIT_URL`, `BRANCH_NAME` or `GIT_BRANCH`, `GIT_COMMIT`, `BUILD_NUMBER`, `BUILD_URL`. Requires a checkout step to have run. |
| `--from-github-env` | off | Same from `GITHUB_REPOSITORY`, `GITHUB_HEAD_REF`/`GITHUB_REF_NAME`, `GITHUB_SHA`, `GITHUB_RUN_NUMBER`, `GITHUB_RUN_ID`. Prefers the head ref, because `GITHUB_REF_NAME` is `<pr>/merge` on pull_request events. |
| `--from-bitbucket-env` | off | Same from `BITBUCKET_*`. |
| `--origin VALUE` | `cyclonedx-sca` | Recorded as the asset's origin. |

The three `--from-*-env` flags are mutually exclusive and fail immediately if combined. Anything
you pass explicitly wins over the environment, so you can let CI supply the branch while pinning
the repository name by hand.

### Import method

| Option | Default | Applies to | Purpose |
| --- | --- | --- | --- |
| `--method sbom\|vulnerability` | `vulnerability` | both | Which Phoenix API to use. See [Import methods](#import-methods). |
| `--project-type NAME` | `auto` | sbom | Becomes the `PhxSbomSca:<projectType>` scan type. `auto` reads it from the BOM; otherwise `universal`, `java`, `npm`, `python`, `go`, … or a comma-separated list. cdxgen spellings (`js`, `nodejs`) are mapped onto Phoenix's (`npm`) |
| `--scan-target VALUE` | the `--file-path` value | sbom | What the import records as the thing scanned. Useful for an image reference. |
| `--no-auto-import` | off | sbom | Stage the translation for review instead of importing it. The request settles at `READY_FOR_IMPORT`. |
| `--wait` | off | sbom | Poll until the request finishes. With `--no-auto-import`, `READY_FOR_IMPORT` counts as finished. |
| `--import-type new\|merge\|delta` | `merge` | both | `merge` keeps findings this scan did not see; `delta` closes them; `new` replaces. |
| `--assessment-name NAME` | `single-repo-sca-sbom` | both | Assessment the import is recorded under. |

`--wait` and `--no-auto-import` describe the asynchronous translate request, so passing either
with `--method vulnerability` is rejected rather than silently ignored.

### Artefact identity (sbom method)

Declare what the SBOM describes instead of leaving Phoenix to infer it from the BOM. All
optional; omitting `--artefact-type` reproduces the previous behaviour exactly.

| Option | Artefact type | Purpose |
| --- | --- | --- |
| `--artefact-type BUILD_FILE\|CONTAINER` | both | Turns the rest on. Omit for inferred identity |
| `--build-file PATH` | BUILD_FILE | Relative build file path, e.g. `services/api/pom.xml`. Defaults to `--file-path`. Rejected if absolute or containing `..` |
| `--container-name NAME` | CONTAINER | Image name; required for CONTAINER |
| `--container-version TAG` | CONTAINER | Image tag |
| `--container-digest sha256:…` | CONTAINER | Must be `sha256:` plus 64 hex characters |
| `--registry HOST` | CONTAINER | Registry host |

For `CONTAINER`, anything not passed is read from the BOM's `metadata.component` - a Trivy image
SBOM already carries name, tag, digest and registry - so a pipeline usually needs only
`--artefact-type CONTAINER`. Explicit flags always win.

Every option in this section belongs to `--method sbom`; passing any of them with
`--method vulnerability` is rejected rather than silently ignored, because that method posts
findings parsed from the BOM and sends no artefact identity at all. `--dry-run` validates them
and prints the resolved identity without calling the API.

These parameters take effect only against a Phoenix organization with in-house translation
enabled; elsewhere Phoenix validates and discards them, which is why they are safe to send
unconditionally.

### Connection and credentials

| Option | Default | Purpose |
| --- | --- | --- |
| `--api-base-url URL` | `https://api.securityphoenix.cloud` | Phoenix tenant. |
| `--client-id ID` / `--client-secret SECRET` | unset | Credentials. Prefer environment variables in CI; a value on the command line is visible in the process list and in build logs. |
| `--config PATH` | `config.ini` | INI file to read. Missing file is not an error if the settings come from elsewhere. |
| `--verify-tls` / `--no-verify-tls` | verification on | `--no-verify-tls` disables certificate verification entirely. For a private CA, install it in the runner's trust store instead. |
| `--allow-insecure-http` | off | Permit an `http://` base URL. Credentials are sent as HTTP Basic, so this exposes them; intended for a local mock. |

### Diagnostics

| Option | Purpose |
| --- | --- |
| `--dry-run` | Build the payload and stop. No credentials needed, no request made. The fastest way to check asset identity and finding counts. |
| `--payload-out PATH` | Write the generated JSON payload to a file. Combines with `--dry-run`. |

### Where each setting comes from

Precedence differs by setting, which matters when a config file and a pipeline disagree:

| Setting | Order |
| --- | --- |
| `client_id`, `client_secret`, `api_base_url` | CLI flag → environment variable → `config.ini` → built-in default |
| `method`, `project_type`, `import_type`, `assessment_name` | CLI flag → `config.ini` → built-in default |
| `verify_tls` | `config.ini` → `--verify-tls` → `--no-verify-tls` (last flag wins) |
| `allow_insecure_http`, `wait_for_completion` | CLI flag, otherwise `config.ini` |
| `timeout_seconds`, `poll_interval_seconds`, `poll_timeout_seconds` | `config.ini` only |

Only three settings read the environment — `PHOENIX_CLIENT_ID`, `PHOENIX_CLIENT_SECRET` and
`PHOENIX_API_BASE_URL`. There is deliberately no `PHOENIX_METHOD` or `PHOENIX_IMPORT_TYPE`: those
change what gets written into Phoenix, so they are set explicitly per run rather than inherited
from an exported shell variable.

### config.ini

```ini
[phoenix]
client_id =
client_secret =
api_base_url = https://api.securityphoenix.cloud
import_type = merge                  ; new | merge | delta
assessment_name = single-repo-sca-sbom
method = vulnerability               ; vulnerability | sbom
project_type = auto                  ; sbom method: PhxSbomSca:<project_type>, auto = read from the BOM

[options]
verify_tls = true
allow_insecure_http = false          ; permit http:// - exposes credentials
timeout_seconds = 60                 ; per-request HTTP timeout
wait_for_completion = false          ; sbom method: poll until the import settles
poll_interval_seconds = 10
poll_timeout_seconds = 1800          ; bounds the wait only; the request keeps running
```

Keep this file out of version control - it holds a credential pair. `config.ini.template` is the
copy to commit.

### GitHub Actions inputs

| Input | Default | Notes |
| --- | --- | --- |
| `phoenix_method` | `auto` | `auto`, `sbom`, `vulnerability` |
| `scan_mode` | `buildfile` | `buildfile`, `image` |
| `scanner` | `auto` | `auto`, `cdxgen`, `trivy`, `depscan` |
| `scan_path` | `.` | buildfile mode: path within the checkout |
| `container_image` | *(blank)* | image mode: required, validated during resolution |
| `project_type` | `auto` | cdxgen `-t` and the `PhxSbomSca:` suffix. `auto` passes `universal` to cdxgen and detects the suffix from the BOM |
| `file_path` | `package-lock.json` | manifest path in the asset key |
| `import_type` | `merge` | `new`, `merge`, `delta` |
| `wait_for_completion` | `false` | bounded by the job's 45-minute timeout |

Secrets: `PHOENIX_CLIENT_ID` and `PHOENIX_CLIENT_SECRET`. The tenant URL comes from the
`PHOENIX_API_BASE_URL` repository variable, falling back to production.

### Choosing options

| Goal | Options |
| --- | --- |
| Inventory a repository, let Phoenix analyse it | `--method sbom` with a cdxgen or plain-Trivy SBOM; leave `--project-type` at `auto` |
| Inventory a container image the same way | `--method sbom --scan-target <image>`, SBOM from `trivy image` with no `--scanners vuln`. Detection returns `universal`, and the import lands on a **BUILD** asset |
| Give a container image a CONTAINER asset | `--method sbom --scan-type 'Trivy Scan'` with `trivy image --format json`. The derived `PhxSbomSca:` type cannot do this — it is rewritten to `CycloneDX Scan` before translation |
| Scan locally and send findings | `--method vulnerability`, SBOM from `trivy … --scanners vuln` |
| Close findings that are no longer present | add `--import-type delta` |
| Block the build until the import lands | `--method sbom --wait` (expect minutes, and see the concurrency note above) |
| Stage an import for review | `--method sbom --no-auto-import` (add `--wait` to confirm it reached `READY_FOR_IMPORT`) |
| Check identity and counts without uploading | `--dry-run --payload-out payload.json` |

### Request size limits

The API sits behind an AWS API Gateway HTTP API, which rejects any request over **10MB** at the
edge. That is not a Phoenix setting and cannot be raised from the application side; the caller
gets a gateway error rather than a Phoenix one, so the cause is not obvious from the failure.

The two methods approach that ceiling along different curves:

| Method | What crosses the gateway | Grows with | Measured |
| --- | --- | --- | --- |
| `vulnerability` | the JSON findings payload | number of findings, ~2.4KB each | 113 findings = 0.26MB; 4,000 = 9.2MB |
| `sbom` | the inventory SBOM file | size of the image or dependency tree, **not** finding count | container inventory SBOM = 197KB (~52x headroom); build-file SBOM = 4KB |

Two things follow that are easy to get backwards:

- For the `sbom` method, a minimal application on a large base image is closer to the limit than
  a heavily vulnerable application on a slim one. Vulnerability count is irrelevant here, because
  Phoenix does the analysis after upload - the enriched SBOM never crosses the gateway.
- For the `vulnerability` method, the reverse holds: findings are the whole payload.

The importer warns above 8MB, naming the finding count, and turns a rejection into a message
that explains it rather than surfacing the gateway's response body. If you hit it, split the scan
by manifest or sub-project; retrying unchanged will not help.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Import submitted, or accepted and - with `--wait` - settled successfully. |
| `1` | Any handled failure: bad configuration, unreadable or non-CycloneDX SBOM, missing context, auth failure, non-2xx response, terminal `ERROR`, or a poll timeout. The reason is printed to stderr. |
| `2` | Invalid command line, from argument parsing. |

A poll timeout exits `1`, but the upload was already accepted - see the note under
[sbom method](#sbom-method) before treating it as a failed import.

## Security

- Never hardcode credentials in source files or pipeline scripts
- Use the Jenkins credentials store in CI, environment variables elsewhere
- `config.ini` contains a live secret: keep it out of version control (`chmod 600`) and prefer
  environment variables on shared machines
- Auth flow follows Phoenix API v1.25 - see [Upload flow](#upload-flow) above
- `--no-verify-tls` disables certificate verification; use it only for internal endpoints with a
  private CA, never against a public tenant

## GitHub Actions

Copy `github-actions-sbom-phoenix.yml.example` to `.github/workflows/sbom-phoenix.yml` in the
repository you want to scan, then add two repository secrets: `PHOENIX_CLIENT_ID` and
`PHOENIX_CLIENT_SECRET`. Optionally set the `PHOENIX_API_BASE_URL` repository variable to point
at a non-default tenant.

The workflow exposes the same three choices as the Jenkins pipeline - `phoenix_method`,
`scan_mode`, `scanner` - with the same `auto` resolution and the same rejection of contradictory
combinations. It runs on `workflow_dispatch` and is callable from another workflow via
`workflow_call`:

```yaml
jobs:
  sbom:
    uses: ./.github/workflows/sbom-phoenix.yml
    with:
      scan_mode: buildfile
      file_path: package-lock.json
    secrets:
      PHOENIX_CLIENT_ID: ${{ secrets.PHOENIX_CLIENT_ID }}
      PHOENIX_CLIENT_SECRET: ${{ secrets.PHOENIX_CLIENT_SECRET }}
```

Repository, branch, commit, run number, and a link back to the run are picked up automatically
through `--from-github-env`:

| GitHub variable | Lands in Phoenix as |
| --- | --- |
| `GITHUB_REPOSITORY` | `repository` tag + asset key |
| `GITHUB_HEAD_REF`, else `GITHUB_REF_NAME` | `branch` tag + asset key |
| `GITHUB_SHA` | `commit` tag |
| `GITHUB_RUN_NUMBER` | `ciBuildNumber` tag |
| `GITHUB_SERVER_URL` + repo + `GITHUB_RUN_ID` | `ciPipelineUrl` tag |

`GITHUB_HEAD_REF` is preferred because on `pull_request` events `GITHUB_REF_NAME` is
`<pr-number>/merge` rather than a branch name.

The generated SBOM is uploaded as a build artifact (30-day retention) so a run can be audited
after the fact.

**Runner sizing.** `cdxgen` and `trivy` run fine on hosted runners. `depscan` needs a multi-GB
vulnerability database that exceeds the GitHub Actions cache budget and would be re-fetched every
run, so restrict `scanner=depscan` to self-hosted runners with a warmed `depscan-vdb` volume.

## Warming the dep-scan database

`depscan_vdb_warm.sh` populates the Docker volume that the pipelines mount at `/vdb`:

```bash
./depscan_vdb_warm.sh          # app scope, for build-file scanning (~3.7GB)
./depscan_vdb_warm.sh app+os   # app+os scope, for container scanning (~4.4GB)
```

Run it once per build agent before enabling dep-scan. It retries the download more patiently than
dep-scan itself does, and verifies the result by producing a VDR from a small fixture rather than
just checking that the download finished.

Two things to know:

- The two scopes are **different artifacts** (`vdbxz-app` vs `vdbxz`). Switching an agent from
  build-file to container scanning re-downloads the whole database rather than topping it up.
- A failed download **leaves its partial data in the volume**, so the volume grows across retries
  and scope switches. Reclaim it with `docker volume rm depscan-vdb` and re-warm. A volume that
  has survived several failed attempts is much larger than one database: an app-scope volume here
  measured 6.7GB after earlier failures, against a ~3.7GB database.
- **The download itself is unreliable.** It is one large streamed transfer and any dropped
  connection fails it outright. It took several attempts across sessions here before one
  completed; that is why the script retries far more patiently than dep-scan does. Warm agents
  out of band, never on the critical path of a build.

The Jenkins pipeline checks the volume before scanning and warns when it looks cold, so a build
does not silently begin a multi-GB download.

## Bitbucket Pipeline mode

Use Bitbucket environment variables for repository and branch:

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --file-path package-lock.json \
  --from-bitbucket-env \
  --import-type merge
```

The script reads:

- `BITBUCKET_REPO_FULL_NAME` -> `repository`
- `BITBUCKET_BRANCH` -> `branch`
- `BITBUCKET_COMMIT` -> extra tag `commit`
- `BITBUCKET_BUILD_NUMBER` -> extra tag `ciBuildNumber`
- `BITBUCKET_WORKSPACE` + `BITBUCKET_REPO_SLUG` + build number -> extra tag `ciPipelineUrl`

## Jenkins Pipeline mode

Use Jenkins environment variables for repository, branch, and CI provenance:

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --file-path package-lock.json \
  --from-jenkins-env \
  --import-type merge
```

The script reads:

- `GIT_URL` -> `repository` (falls back to `JOB_NAME`)
- `BRANCH_NAME`, else `GIT_BRANCH` with the `origin/` prefix stripped -> `branch`
- `GIT_COMMIT` -> extra tag `commit`
- `BUILD_NUMBER` -> extra tag `ciBuildNumber`
- `BUILD_URL` -> extra tag `ciPipelineUrl`

`--repo` and `--branch` still take precedence when supplied, so you can override either value.
`--from-jenkins-env` and `--from-bitbucket-env` are mutually exclusive.

### Setting up the pipeline job

1. Add the two Phoenix credentials as **Secret text** (see
   [Option C - Jenkins credentials store](#option-c---jenkins-credentials-store)):
   `phoenix-client-id` and `phoenix-client-secret`.
2. Ensure the Jenkins agent can run `docker` and `python3`.
3. Create a Pipeline job. For `buildfile` mode use **Pipeline script from SCM** pointing at your
   repository so the workspace is checked out and Jenkins exports `GIT_URL` / `GIT_BRANCH` /
   `GIT_COMMIT`. For `image` mode a plain **Pipeline script** job is enough.
4. Paste `jenkins_sbom_single_repo_pipeline.groovy`, or point the job at it in SCM.
5. Run with **Build with Parameters**.

### Running Jenkins itself in a container

If the Jenkins controller or agent is itself a container with the Docker socket mounted, one rule
decides whether anything works: **the workspace must live at the same absolute path on the host as
it does inside the container.**

The pipeline hands workspace paths to `docker run -v` so the scanners can read the source. The
Docker daemon resolves bind-mount sources on the *host*, not inside whichever container issued the
command, so a path that exists only inside Jenkins mounts as an empty directory. The failure is
quiet: the scanner writes its SBOM to a host directory nobody reads, and the build fails later with
a confusing "No such file or directory" from a plain `cp`.

Start such a controller with `JENKINS_HOME` bind-mounted onto itself:

```bash
docker run -d --name jenkins \
    -u root \
    -e JENKINS_HOME=/data/jenkins_home \
    -v /data/jenkins_home:/data/jenkins_home \
    -v /var/run/docker.sock:/var/run/docker.sock \
    jenkins/jenkins:lts-jdk17
```

Scan reports are deliberately written under `$WORKSPACE/.phoenix-sbom-reports` rather than `/tmp`
for the same reason - the workspace is the one directory that must already be mount-visible.

### Testing it locally with Jenkins

`local-jenkins/` builds a disposable Jenkins that exercises every mode end to end without touching
a real repository. It builds a Jenkins image with the Docker CLI, python3 and the required plugins,
builds a deliberately outdated `phoenix-fake-app:1.0` image to scan, assembles a seed git repository
holding a fake npm project plus this importer, and pre-creates the parameterised job.

```bash
cp config.ini.template config.ini    # fill in client_id / client_secret / api_base_url
./local-jenkins/run.sh               # build and start Jenkins; no scans, no uploads
./local-jenkins/run.sh --trigger     # run the four modes and upload to the live tenant
./local-jenkins/run.sh --stop        # tear it down
```

Scanning sits behind `--trigger` deliberately: it imports into a real Phoenix tenant and
creates assets and findings there, which starting a test instance should not do as a side
effect. `--trigger` runs all four modes even if one fails, then exits non-zero naming the
failures, so it is usable as a check rather than something whose output has to be read.

Credentials are read from the gitignored `config.ini` and passed to Jenkins as environment
variables, so `local-jenkins/casc.yaml` holds no secrets. The instance is unsecured and bound to
`127.0.0.1` only - it is a test harness, not a template for a real controller.

Two quirks the script works around. A job's **first** build only registers the Jenkinsfile's
`parameters` block, it cannot receive parameter values - `buildWithParameters` returns HTTP 400
until one build has run, so `run.sh` fires an unparameterised bootstrap build first. And Jenkins
answers `/api/json` with 200 part way through boot before falling back to 503, so the script waits
on the JCasC-created job instead, several times over, and allows up to twelve minutes for it.

Give the machine room. Jenkins, the scanner containers and the image under test all run on the same
Docker daemon; on a host already running a large stack, boot takes minutes and Docker itself starts
misbehaving - creating a container and then reporting "No such container" for its own id. `run.sh`
checks the container's real state and retries rather than trusting exit codes, but a badly loaded
daemon is still worth clearing first.

The npm fixture is stored as `package.json.fixture` / `package-lock.json.fixture` and renamed
into place by `run.sh`. It pins deliberately outdated packages so a scan finds something; under
the real filenames Dependabot reads it as a manifest of this repository and raises upgrade PRs
against a fixture whose whole purpose is to stay vulnerable.

Jenkins keeps its home under `${TMPDIR:-/tmp}/phoenix-local-jenkins`, not in the repository.
Override it with `PHOENIX_JENKINS_STATE=/some/path`, but keep it off a bind mount that macOS has
to share into Docker through a git working tree: the same container scan measured about two
minutes with the home in `/tmp` and roughly an hour with it inside the checkout. Delete that
directory for a clean slate.

### Pipeline parameters

| Parameter | Default | Purpose |
| --- | --- | --- |
| `PHOENIX_METHOD` | `auto` | `sbom`, `vulnerability`, or `auto`. auto = `sbom` for build files, `vulnerability` for images |
| `SCAN_MODE` | `buildfile` | `buildfile` scans workspace manifests, `image` scans a container image |
| `SCANNER` | `auto` | `cdxgen`, `trivy`, `depscan`, or `auto`. auto = cdxgen for the sbom method, trivy for the vulnerability method |
| `SCAN_PATH` | `.` | `buildfile` mode: path within the workspace to scan |
| `CONTAINER_IMAGE` | `nginx:latest` | `image` mode: image reference to scan |
| `PROJECT_TYPE` | `auto` | cdxgen `-t` value, and the `PhxSbomSca:<projectType>` suffix. `auto` passes `universal` to cdxgen (which has no such notion) and detects the suffix from the BOM cdxgen produced |
| `PHOENIX_SCAN_TYPE` | *(blank)* | sbom method: literal scanType instead of the derived `PhxSbomSca:`. Only `CycloneDX Scan` and `Trivy Scan` are accepted, because those are the two formats this pipeline can produce; anything else is rejected during resolution rather than uploaded as the wrong format. `Trivy Scan` selects Trivy and switches it to native JSON in both scan modes — the only route to a `CONTAINER` asset today. Not valid with `SCANNER=cdxgen`, whose inventory SBOM carries no findings to translate |
| `PHOENIX_UPLOAD_LOCK` | *(blank)* | Name of a Lockable Resource held across the upload, to serialise sbom uploads across jobs. Requires the Lockable Resources plugin when set |
| `REPO_NAME` | *(blank)* | Repository identifier; blank derives it from `GIT_URL` |
| `FILE_PATH` | `package-lock.json` | Manifest path in the asset key; use `Dockerfile` for image mode |
| `BRANCH` | *(blank)* | Branch; blank derives it from `BRANCH_NAME` / `GIT_BRANCH` |
| `PHOENIX_IMPORT_TYPE` | `merge` | `new`, `merge`, or `delta` |
| `WAIT_FOR_COMPLETION` | `false` | sbom method: hold the build until Phoenix finishes importing. Successful imports measured 4-5 minutes against a live tenant; a request still translating well past that has usually collided with another upload and will end in `ERROR` around the 60-minute mark, so waiting mostly costs executor time |
| `PHOENIX_API_BASE_URL` | `https://api.securityphoenix.cloud` | Phoenix tenant URL |
| `TRIVY_IMAGE` / `DEPSCAN_IMAGE` | upstream `latest` | Pin these for reproducible builds |
| `DEPSCAN_VDB_VOLUME` | `depscan-vdb` | Docker volume caching dep-scan's ~4GB vulnerability DB |

### Default behaviour

| Scan mode | Method | Scanner | What happens |
| --- | --- | --- | --- |
| `buildfile` | `sbom` | cdxgen | Inventory SBOM uploaded; Phoenix runs dep-scan over it |
| `image` | `vulnerability` | trivy | Image scanned for vulnerabilities; findings posted as JSON |

Forcing the other combinations is supported too: `PHOENIX_METHOD=sbom` with `SCAN_MODE=image`
uploads a container inventory SBOM (Trivy, vulnerability scanners off) for Phoenix to analyse,
and `PHOENIX_METHOD=vulnerability` with `SCAN_MODE=buildfile` scans manifests locally with Trivy
or dep-scan and posts the findings.

The pipeline resolves `auto` in its first stage and rejects contradictory combinations early:
`SCANNER=cdxgen` with `PHOENIX_METHOD=vulnerability` (nothing to import), `SCANNER=depscan` with
`PHOENIX_METHOD=sbom` (Phoenix would repeat the analysis), and `SCANNER=cdxgen` with
`SCAN_MODE=image` (cdxgen cannot export an image through a mounted Docker socket).

The two scan modes are:

- `buildfile` - runs `trivy fs` over the checked-out workspace to scan dependency manifests
  (`package-lock.json`, `requirements.txt`, `go.sum`, ...). The job must check the repository
  out into the workspace first. No Docker socket needed.
- `image` - runs `trivy image` against `CONTAINER_IMAGE`. Mounts `/var/run/docker.sock`, so the
  agent needs Docker socket access.

Whether Trivy is given `--scanners vuln` depends on the method, not the scan mode. The
vulnerability method requires it - without it Trivy emits an inventory-only SBOM with an empty
`vulnerabilities` array, and the import creates the asset with `installedSoftware` but zero
findings. The sbom method deliberately omits it, because Phoenix does that analysis server-side
and scanning here would only produce a result the upload discards.

The SBOM is written to `$WORKSPACE/sbom.cdx.json` and deleted in `post { always }` so it is not
left on the agent.

### Severity mapping

CycloneDX carries one rating per advisory source (ghsa, nvd, redhat, ubuntu, ...) in no guaranteed
order. The importer takes the **highest** rating across all sources - both the maximum CVSS score
and the maximum severity label, then the higher of the two - rather than whichever rating happens
to appear first.

| Phoenix severity | Source rating |
| --- | --- |
| `10.0` | CVSS >= 9.0, or label `critical` |
| `8.0` | CVSS >= 7.0, or label `high` |
| `5.0` | CVSS >= 4.0, or label `medium` / `moderate`, or no usable rating |
| `2.0` | CVSS > 0.0, or label `low` |
| `1.0` | CVSS 0.0, or label `info` / `none` |

Because a vendor sometimes publishes a qualitative label below the raw CVSS score it also
publishes (Red Hat rating a 7.4 CVSS finding as `medium`, for example), a small number of findings
land one level above the scanner's own headline severity. This is deliberate: the import errs
toward the higher risk rating.

### Multi-manifest repositories

`trivy fs` over a repository root scans every manifest it finds, but this utility maps the whole
SBOM onto **one** `BUILD` asset keyed by the single `--file-path` you pass. Findings keep their
own per-package `location`, so the data is correct, but the asset identity names only one manifest.
For per-manifest identity, run the importer once per manifest with `--import-type merge`.

## Utils repository map (top-level folders and purpose)

This utility is part of the broader `Utils/` ecosystem. Use this map as a quick index when you need related tooling.

| Subfolder | Purpose |
| --- | --- |
| `Backstage Translator/` | Convert Backstage/ServiceNow catalog data into Phoenix-compatible YAML/config structures |
| `Config_File_autogen/` | Auto-generate Phoenix configuration files from repository or metadata inputs |
| `Gating/` | CI/CD policy gating (pass/fail) based on vulnerability and risk thresholds |
| `Jenkins Integration/` | Jenkins pipeline integration templates/scripts for Phoenix workflows |
| `Loading_Script_V2/` | Legacy scanner import (deprecated) |
| `Loading_Script_V5/` | Multi-scanner import (canonical private copy: translators, service, lambda, synthetic tooling; sanitized for public repo) |
| `Nucleus/` | Legacy Nucleus integration scripts |
| `Nucleustophoenix/` | Migration tooling from Nucleus into Phoenix |
| `Shodan conversion/` | Convert Shodan outputs into Phoenix-consumable formats |
| `Test/` | Utility-level test assets/scratch validation content |
| `asset-count-scripts/` | Asset counting/inventory scripts for cloud, git, and Wiz sources |
| `asset-translator/` | Normalize and transform asset files into Phoenix-ready structures |
| `client scripts/` | Client-specific translators/automation (for example Q2 and Okta workflows) |
| `container scan/` | Container scan-related helper scripts/data transformations |
| `container3rp/` | Third-party container report processing and Phoenix import support |
| `csv_translator/` | Convert CSV/JSON vulnerability exports and upload to Phoenix |
| `docs/` | Shared Utils architecture, operations, and development documentation |
| `logos/` | Branding/media assets for Utils documentation and reporting |
| `pentest-import/` | Import penetration-test findings from CSV-like sources |
| `prowler extractor/` | Parse/reshape Prowler output for downstream ingestion/reporting |
| `report-Team_dashboard_report/` | Team-focused dashboard report generation |
| `report-asset_and_vulnerability_report/` | Combined asset + vulnerability report generation |
| `report-dashboard/` | Executive dashboard/report generation (PDF/Excel) |
| `report-vulnerability_report/` | Vulnerability-centric report generator |
| `SBOM-SCA-CONTAINER-PIPELINE/` | SBOM/SCA and container scanning pipeline utilities (includes this `sbom-single-repo` tool) |
| `technology-determination/` | Technology stack detection/classification using NVD/CPE mappings |

## Linked documentation (start here)

- Utils system map: `../../UTILS_SYSTEM_MAP.md`
- Utils docs router: `../../DOC_INDEX.md`
- Utility selection guide: `../../UTILS_MASTER_INDEX.md`
- SCA quick runbook: `./QUICK_START.md`
