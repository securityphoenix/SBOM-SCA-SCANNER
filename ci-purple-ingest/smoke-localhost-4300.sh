#!/usr/bin/env bash
#
# CI-PURPLE ingest smoke test against a LOCAL dev stack (default: http://localhost:4300).
#
# Covers the full objective matrix in one run -- both asset kinds, each with and without
# vulnerabilities already in the document:
#
#   1. REPO             inventory-only   (server's dep-scan supplies every finding)
#   2. REPO             with findings    (server UNIONS them with dep-scan's, deduplicated by CVE)
#   3. CONTAINER_IMAGE  inventory-only
#   4. CONTAINER_IMAGE  with findings
#
# PREREQUISITES -- the run fails fast and tells you which one is missing:
#   * The stack is up and phx.sca.ci-ingest-enabled=true on the analyzer. While the flag is false
#     the controller 404s the whole surface by design, so a 404 here means "flag off", NOT
#     "endpoint missing".
#   * PHOENIX_API_KEY exports an API key scoped EXACTLY ["ci:ingest"].
#
# Usage:
#   export PHOENIX_API_KEY=...            # never hardcode it here
#   ./smoke-localhost-4300.sh             # dry-run by default: builds + validates, no API calls
#   ./smoke-localhost-4300.sh --live      # actually submits all four
#
set -euo pipefail

BASE_URL="${PHOENIX_API_BASE_URL:-http://localhost:4300}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI="$HERE/ci_purple_sbom_to_phoenix.py"
PYTHON="${PYTHON:-python3}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

MODE="--dry-run"
if [ "${1:-}" = "--live" ]; then MODE=""; fi

if [ -z "${PHOENIX_API_KEY:-}" ]; then
  echo "PHOENIX_API_KEY is not set. Create a key scoped exactly [\"ci:ingest\"] and export it." >&2
  echo "It is read from the environment on purpose -- never write it into config.ini in a shared checkout." >&2
  exit 1
fi

# Two fixtures differing ONLY in whether `vulnerabilities` is populated, so a difference in the
# server's response is attributable to that and nothing else.
cat > "$WORK/inventory.cdx.json" <<'J'
{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,
 "metadata":{"component":{"type":"application","name":"purple-smoke","version":"1.0.0","bom-ref":"root"}},
 "components":[
   {"type":"library","name":"lodash","version":"4.17.20","purl":"pkg:npm/lodash@4.17.20","bom-ref":"c1"},
   {"type":"library","name":"minimist","version":"1.2.5","purl":"pkg:npm/minimist@1.2.5","bom-ref":"c2"}]}
J
$PYTHON - "$WORK/inventory.cdx.json" "$WORK/enriched.cdx.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
# Both CVEs are real advisories for these exact pinned versions, and both are CVE-form ids --
# a GHSA-/OSV-only id is rejected with unsupported_vulnerability_id by design.
doc["vulnerabilities"] = [
    {"id": "CVE-2021-23337", "affects": [{"ref": "c1"}], "ratings": [{"severity": "high"}]},
    {"id": "CVE-2021-44906", "affects": [{"ref": "c2"}], "ratings": [{"severity": "critical"}]},
]
json.dump(doc, open(sys.argv[2], "w"), indent=1)
PY

# asset.digest is REQUIRED for CONTAINER_IMAGE -- the client refuses the request without it,
# because the digest is the immutable identity Phoenix keys a container asset on. This is a
# syntactically valid placeholder for a smoke run; a real pipeline reads the true digest back
# from the registry (see github-actions-ci-purple-container.yml.example).
SMOKE_DIGEST="sha256:$(printf '0%.0s' $(seq 1 64))"

COMMON=(--api-base-url "$BASE_URL" --allow-insecure-http
        --ci-provider GITHUB_ACTIONS
        --git-remote-url https://github.com/securityphoenix/purple-smoke.git
        --branch main --commit-sha 1111111111111111111111111111111111111111
        --run-url "http://localhost/smoke" --pipeline-id "smoke-$$")

run_case() {
  local label="$1"; shift
  echo
  echo "=================================================================="
  echo "  $label"
  echo "=================================================================="
  # Never `set -e`-abort the whole matrix on one case: a per-case exit code is the result.
  if $PYTHON "$CLI" "${COMMON[@]}" $MODE "$@"; then
    echo "RESULT: $label -> exit 0"
  else
    echo "RESULT: $label -> exit $?  (3 = BLOCK verdict; 1 = client/ingest error)"
  fi
}

echo "Base URL : $BASE_URL"
echo "Mode     : ${MODE:---live (submits)}"

run_case "1. REPO, inventory-only" \
  --sbom-file "$WORK/inventory.cdx.json" --asset-kind REPO --build-file-path package-lock.json
run_case "2. REPO, with vulnerabilities" \
  --sbom-file "$WORK/enriched.cdx.json" --asset-kind REPO --build-file-path package-lock.json
run_case "3. CONTAINER_IMAGE, inventory-only" \
  --sbom-file "$WORK/inventory.cdx.json" --asset-kind CONTAINER_IMAGE \
  --registry ghcr.io --image securityphoenix/purple-smoke --tag v1.0.0 \
  --digest "$SMOKE_DIGEST" --dockerfile-path Dockerfile
run_case "4. CONTAINER_IMAGE, with vulnerabilities" \
  --sbom-file "$WORK/enriched.cdx.json" --asset-kind CONTAINER_IMAGE \
  --registry ghcr.io --image securityphoenix/purple-smoke --tag v1.0.0 \
  --digest "$SMOKE_DIGEST" --dockerfile-path Dockerfile

echo
echo "Done. In --live mode, add --wait to any case above to block on the terminal verdict."
