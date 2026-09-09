# ci-purple-ingest

CI-provider-agnostic client for Phoenix's **CI-PURPLE SBOM ingest** contract
(`POST /api/v1/external/sca/ingest` and its status/result/retry siblings) - a different, newer
API surface from the sibling [`sbom-single-repo/`](../sbom-single-repo/README.md) tool, which keeps
targeting Phoenix's older `/v1/import/assets*` routes unchanged.

## Naming/placement decision

This lives in its own sibling directory, `Utils/SBOM-SCA-CONTAINER-PIPELINE/ci-purple-ingest/`,
rather than as a new mode on `sbom-single-repo/sbom_sca_single_repo_to_phoenix.py` or a bare
sibling script in that directory. Reasoning:

- **Genuinely different API surface.** Auth is a scoped-key-to-short-lived-token exchange (not
  `client_id`/`client_secret` HTTP Basic), the ingest call is asynchronous with a job id to poll
  (not a synchronous import), and the request/response shapes share no fields with the older
  contract's payload.
- **Different failure/retry model.** The new contract is idempotent (a duplicate submission
  returns the SAME job) and has its own server-side job-retry endpoint; the old contract's own
  `phoenix_client.py` explicitly does NOT retry its POST because it is non-idempotent. Folding both
  into one CLI would mean two incompatible retry philosophies behind one `--method` flag.
- **What IS reused**: `cyclonedx_sbom.read_sbom`'s file-shape checks were ported near-verbatim into
  `ci_purple_sbom.read_sbom` (see that module's docstring) - the two contracts need the identical
  "is this actually a CycloneDX JSON document" check. Everything else in `cyclonedx_sbom.py`
  (`build_payload`, finding extraction, severity mapping) is specific to the OLD payload shape and
  was not reused, because the new contract embeds the CycloneDX document close to as-is rather than
  parsing findings out of it client-side.
- A brand-new `ci_context.py` was written rather than extending the existing one, because the new
  contract needs a full git remote URL + full 40-hex commit SHA + auto-detected provider (the old
  one derives an `owner/repo` string and requires an explicit `--from-*-env` flag) - the shapes are
  different enough that adapting the existing file in place would have made it harder to read for
  users of either tool, not easier.

The existing `sbom-single-repo/` tool's behavior is unchanged by this addition.

## Files

| File | Purpose |
| --- | --- |
| `ci_purple_sbom_to_phoenix.py` | CLI entry point (deploy all four `.py` files together) |
| `ci_context.py` | CI-provider auto-detection (GitHub Actions, Jenkins, Azure DevOps, Bitbucket) and git remote/branch/commit/provenance resolution |
| `ci_purple_sbom.py` | CycloneDX file reading, local pre-flight validation, request-body construction |
| `ci_purple_transport.py` | HTTP transport primitives: config, error mapping, `Retry-After`-aware bounded backoff, `request_with_retry`, guarded JSON decoding. Auth- and endpoint-agnostic |
| `ci_purple_client.py` | CI-PURPLE contract: token exchange, ingest submit, status/result/retry, and `wait_for_terminal`'s polling + JOB-level retry. Re-exports the transport surface so callers keep one import |
| `github-actions-ci-purple-ingest.yml.example` | Worked GitHub Actions workflow |
| `jenkins_ci_purple_ingest_pipeline.groovy` | Worked Jenkins pipeline |
| `tests/` | Contract tests against frozen server fixtures (mocked HTTP, no live Phoenix needed) |

## Quick start

```bash
pip install -r requirements.txt

python3 ci_purple_sbom_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --asset-kind REPO \
  --build-file-path package-lock.json \
  --wait
```

Repository/branch/commit and CI provenance are auto-detected - see "CI-provider auto-detection"
below. The Phoenix API key must be created with **exactly** `scopes: ["ci:ingest"]`; any other
scope set (default/no scope, a combination, etc.) is rejected by the token-mint endpoint with
`403 ci_ingest_scope_required`. **Set it via `PHOENIX_API_KEY`, not `--api-key`** - see "Scoped API
key" below for why.

## CI-provider auto-detection

Unlike `sbom-single-repo` (which needs an explicit `--from-jenkins-env`/`--from-github-env`/
`--from-bitbucket-env` flag), this client detects the running CI system automatically from
provider-published environment markers:

| Provider | Detected via | `ciSystem` sent |
| --- | --- | --- |
| GitHub Actions | `GITHUB_ACTIONS=true` | `GITHUB_ACTIONS` |
| Azure Pipelines | `TF_BUILD=True` (Microsoft's own documented marker) | `AZURE_DEVOPS` |
| Jenkins | `JENKINS_URL` (if the admin configured it), else `BUILD_TAG` (`jenkins-<job>-<build>`, set unconditionally by Jenkins core) | `JENKINS` |
| Bitbucket Pipelines | `BITBUCKET_BUILD_NUMBER` | *(never sent - see below)* |

`gitRemoteUrl` and `commitSha` prefer asking `git` directly (`git remote get-url origin` /
`git rev-parse HEAD`) over any provider environment variable - the checkout itself is the most
authoritative source and is identical across providers. `branch` does the OPPOSITE: it prefers the
provider's own environment variable over `git`, because every supported provider checks out a
**detached HEAD** for the commit under test, so `git branch --show-current` returns empty in
exactly the environment this needs to work in.

Override any of it explicitly with `--ci-provider`, `--git-remote-url`, `--branch`, `--commit-sha`,
`--run-url`, `--runner`, `--pipeline-id` - useful for a bare-metal/self-hosted runner with no
recognized marker, or for testing.

### Azure DevOps notes (judgment calls - see task-8-report.md Concerns)

- `pipelineId` uses `Build.BuildId` (`BUILD_BUILDID`) - a numeric id unique across the whole Azure
  DevOps organization, matching design Sec 3.1's "provider run/build id" description most directly.
- `branch` prefers `System.PullRequest.SourceBranch` (set only on PR-triggered builds) over
  `Build.SourceBranch`, mirroring the same PR-source-branch preference GitHub Actions needs
  (`GITHUB_HEAD_REF` over `GITHUB_REF_NAME`).
- `branch` deliberately does **not** use `Build.SourceBranchName` even though Azure exposes it as a
  ready-made short name: for a branch containing a slash (e.g. `feature/foo`), Azure derives that
  variable by taking only the LAST path segment (`foo`), silently discarding the `feature/` prefix.
  This client strips `refs/heads/` from `Build.SourceBranch` itself instead, which keeps the full
  branch name intact - see `test_resolve_branch_azure_strips_refs_heads_not_last_segment` for the
  regression guard.
- These were reasoned from Azure DevOps's own documented predefined variables, not verified against
  a live Azure Pipelines run in this task - flagged as a Concern.

### Bitbucket: not supported (exit 2)

Design D18 / the server's own `422 unsupported_ci_system` mean Bitbucket Pipelines is explicitly
out of scope for CI-PURPLE ingest in v1. If this client detects Bitbucket, it exits **`2`**
immediately - before reading the SBOM or requiring any credential - with a message pointing at the
sibling `sbom-single-repo/` tool, which DOES support Bitbucket:

```bash
python3 ../sbom-single-repo/sbom_sca_single_repo_to_phoenix.py \
    --sbom-file <path> --file-path <manifest> --from-bitbucket-env --import-type merge
```

## Scoped API key

Create a Phoenix API key with **exactly** `scopes: ["ci:ingest"]` (no other scope, no
combination - a general-purpose key is rejected here).

**Supply it via the `PHOENIX_API_KEY` environment variable - not the `--api-key` flag.** A value
passed on the command line is visible to any other process on the runner via `ps` and lands in
shell history; both shipped pipeline templates use the environment variable exclusively.
`--api-key` exists only for local ad-hoc debugging (e.g. `--dry-run` against a scratch SBOM on your
own workstation) and should never appear in a committed pipeline definition.

Store it as a CI secret:

- GitHub Actions: repository secret `PHOENIX_API_KEY` (see the example workflow, which passes it
  through as the `PHOENIX_API_KEY` environment variable).
- Jenkins: a **Secret text** credential (see `jenkins_ci_purple_ingest_pipeline.groovy`'s
  `environment { PHOENIX_API_KEY = credentials('phoenix-ci-ingest-api-key') }` binding - Jenkins
  masks this in console output automatically).
- Azure DevOps: a secret pipeline variable, or a variable group backed by a secrets store.

The client mints a short-lived (**1-hour TTL**) `phx_at_*` CI-ingest token from this key per run,
via `POST /api/v1/external/auth/ci-ingest-token`, and re-mints automatically (~60s before
expiry, or immediately on an unexpected `401`) for a run that takes longer than an hour. The
minted token is held in memory only for the life of the process - **never** written to disk or a CI
cache, and never reused across separate pipeline invocations.

## Two asset kinds

| `--asset-kind` | Required flags | Notes |
| --- | --- | --- |
| `REPO` (default) | `--build-file-path` | A dependency-manifest SBOM (build.gradle.kts, package-lock.json, ...). |
| `CONTAINER_IMAGE` | `--registry --image --tag --digest --dockerfile-path` | A container-image SBOM. `--digest` must be an exact `sha256:<64 hex>` digest. `provenance.builtFromRepo`/`builtFromCommit` are DERIVED from `gitRemoteUrl`/`commitSha` automatically (the server requires them to be exactly equal) - you never pass them separately. `--from-line`/`--base-image-ref` are optional. |

Conditional fields from the other asset kind are rejected client-side with a clear message before
any network call (matching the server's own "rejected, not ignored" contract).

## Two retry concepts (do not conflate them)

- **Transport-level retry** (`ci_purple_client.request_with_retry`): a network error, `429`
  (honouring the server's `Retry-After` header EXACTLY, never a computed backoff for that
  response), or `503`, on ANY call (token exchange, ingest submit, status poll, result fetch).
  Bounded exponential backoff with jitter, `--max-retry-attempts` (default 5). Applied uniformly -
  every authenticated call routes through this one function in `ci_purple_transport.py`. Each poll
  additionally runs with its transport budget shrunk to the time left on `--wait-timeout-seconds`,
  so a degraded status poll cannot overshoot the deadline the flag advertises.
- **Job-level retry** (`POST /ingest/{jobId}/retry`): re-runs a server-classified-retryable
  `FAILED` job. This is orchestrated automatically inside `--wait`'s polling loop
  (`ci_purple_client.wait_for_terminal`) up to **4 job-level retry calls** (**5 total attempts**
  including the initial submit) - one call short of the server's own cumulative ceiling
  (`SbomJobQueueRepository.MAX_ATTEMPTS = 5`), so this client never issues the retry call the
  server is guaranteed to reject with `409 retry_attempts_exhausted`. Without `--wait`, no
  job-level retry happens (the process has already exited after the `202`).

## `--wait` and exit codes

Without `--wait`, the tool submits and exits `0` immediately after a `202` - for pipelines that
want fire-and-forget ingest with a separate later check (`GET /ingest/{jobId}`).

With `--wait`, it polls (`--poll-interval-seconds`, default 10) until a terminal state
(`SUCCEEDED`/`DEGRADED`/`FAILED`) or `--wait-timeout-seconds` (default 1800) elapses, auto-retrying
a retryable `FAILED` job as above, then fetches `GET /ingest/{jobId}/result`.

| Exit code | Meaning |
| --- | --- |
| `0` | Ingest submitted (no `--wait`), or `--wait` completed with a terminal verdict other than `BLOCK`. |
| `1` | Any handled runtime failure: bad configuration, unreadable/non-CycloneDX/locally-invalid SBOM, unresolvable CI context, auth failure, non-2xx response, terminal `FAILED` (not retryable or retries exhausted), or a `--wait` timeout. Reason printed to stderr. |
| `2` | Invalid command line (argparse's own default), **or** the detected CI provider is Bitbucket (unsupported in v1). Both reuse `2` deliberately - matching `sbom-single-repo`'s own precedent of giving `2` a specific, non-generic meaning - and both mean "nothing was submitted." |
| `3` | `--wait` completed and the terminal result's `verdict` is `BLOCK` - use this to gate the build specifically, distinct from a client-side error (`1`). |

## Proxy / custom CA

Standard `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` environment variables are honoured automatically
(`requests`' own `trust_env` default, left untouched - see `ci_purple_client.build_session`'s
docstring). For a self-hosted Phoenix deployment or a corporate TLS-inspecting proxy with a private
CA, pass `--ca-bundle /path/to/ca.pem` (or set `PHOENIX_CA_BUNDLE`) - this maps directly onto
`requests`' own `verify=<path>` contract and takes precedence over `REQUESTS_CA_BUNDLE`.
`--no-verify-tls` disables certificate verification entirely; treat it as a short-lived diagnostic
only, per the same reasoning `sbom-single-repo/README.md`'s "Upload flow" section gives.

## Secret-safe logs

Per `.claude/rules/env-secret-handling.md` (agent-code-analyzer-r2 repo; the doctrine applies here
regardless of which repository the rule file lives in): the raw API key and the minted `phx_at_*`
token are **never** logged, printed, or included in any error message, exception, or stack trace -
not even a truncated prefix. Both values are used ONLY to build the `Authorization` header passed
directly to `requests`; every error path in `ci_purple_client.py` (`CiPurpleApiError`) builds its
message from the HTTP status code and the server's own JSON error body only, never from request
headers or from `str(exc)` on a caught `requests` exception (which can otherwise carry a
`PreparedRequest`, including its headers, in its string form). `tests/test_cli.py`'s
`test_cli_never_prints_api_key_or_token` exercises the most error-message-heavy path (submit, wait,
terminal FAILED) end-to-end and asserts neither value appears on stdout or stderr.

## Contract tests

```bash
pip install -r requirements.txt pytest
python3 -m pytest tests/ -v
```

No live Phoenix instance is required - the HTTP layer is mocked with `unittest.mock`/pytest's
`monkeypatch` (this repository has no `pytest.ini`/`tox.ini` establishing a different convention,
and `requests`+`unittest.mock` needs no new dependency, so `pytest` was the reasonable default -
also already the convention several other `Utils/` subprojects in this repository use, e.g.
`Utils/client scripts/q2-translators/q2-yaml-translator/tests/`).

`tests/fixtures/*.json` are copied **verbatim** from
`code-analyzer-service/docs/openapi/ci-ingest-examples/` in the `agent-code-analyzer-r2` repository
(design Sec 3.1's frozen Task 1 fixtures) - every request/response/status shape this client sends
or parses is tested directly against them, not against a hand-rolled approximation.

| Test file | Covers |
| --- | --- |
| `test_ci_context.py` | Provider auto-detection, git-vs-env precedence, provenance construction per provider, the Azure branch-name gotcha regression guard |
| `test_ci_purple_sbom.py` | SBOM reading/format checks, local pre-flight validation against the frozen fixtures, request-body construction (byte-for-byte against `request-repo-valid.json`/`request-container-valid.json`), the gateway size budget |
| `test_ci_purple_client_token.py` | Token mint/reuse/re-mint, the nanosecond-precision-instant parsing guard, config/TLS |
| `test_ci_purple_client_transport.py` | Transport retry (backoff, `Retry-After` honoured exactly, non-retryable statuses not retried) |
| `test_ci_purple_client_endpoints.py` | All six frozen status shapes, result/retry, `wait_for_terminal`'s auto-retry-then-succeed and retry-ceiling behaviour, the secret-safety guarantee (split from one `test_ci_purple_client.py`, now `conftest.py`-shared, to stay under `.agent/rules/02-modularity.md`'s 500-LOC file limit) |
| `test_cli.py` | End-to-end exit codes (`0`/`1`/`2`/`3`), Bitbucket refusal, dry-run, missing-credential handling, and the full submit+wait+FAILED secret-safety check |

## Known limits / Concerns

See `task-8-report.md`'s "Concerns" section for the full list, including: local pre-flight
validation is best-effort (not a guarantee of server acceptance, and not guaranteed exhaustive on
rejection); Azure DevOps field choices were reasoned from documentation, not a live Azure Pipelines
run; and no live Phoenix instance has ever received a request from this client (the ingest endpoint
is itself feature-flagged OFF by default server-side, per the design's S2 hard-gate sequencing -
this client is built against the frozen contract and fixtures, not against a running deployment).
