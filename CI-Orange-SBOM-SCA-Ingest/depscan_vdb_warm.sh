#!/usr/bin/env bash
#
# Pre-populate the OWASP dep-scan vulnerability database into a named Docker volume.
#
# Why this exists: dep-scan downloads a large vulnerability database on first use - roughly 3.7GB
# for --vdb-scope app and 4.4GB for app+os. The download is a single streamed transfer, and a
# dropped connection fails it outright; dep-scan retries three times and then gives up, which
# fails the whole build. The two scopes are different artifacts (vdbxz-app vs vdbxz), so switching
# a runner from build-file scanning to container scanning discards the cache and re-fetches
# everything.
#
# Run this once per build agent, out of band, before enabling dep-scan in a pipeline. It retries
# the download more patiently than dep-scan does and leaves the result in a Docker volume the
# pipelines mount at /vdb via VDB_HOME.
#
# Usage:
#   ./depscan_vdb_warm.sh                     # app scope (build-file scanning)
#   ./depscan_vdb_warm.sh app+os              # app+os scope (container scanning)
#   VDB_VOLUME=my-vol ./depscan_vdb_warm.sh   # custom volume name
#
# Disk: a failed download leaves partial data behind, so the volume can grow well past the size
# of one database. Reset it with "docker volume rm depscan-vdb" and re-warm if a runner runs low.
#
# Exit codes: 0 warmed (or already warm), 1 failed after all attempts, 2 prerequisites missing.

set -euo pipefail

SCOPE="${1:-app}"
VDB_VOLUME="${VDB_VOLUME:-depscan-vdb}"
# Pinned by digest, not a tag. ":latest" silently changes what a build runs, and the
# vulnerability database format is tied to the dep-scan version - a moved tag can
# invalidate a warmed volume. This digest is the image these scripts were tested against.
DEPSCAN_IMAGE="${DEPSCAN_IMAGE:-ghcr.io/owasp-dep-scan/dep-scan@sha256:c305f241a3c2e35a90472ef7cb971b03904f719a6b736ab40b4a0039ce8470c4}"
ATTEMPTS="${ATTEMPTS:-5}"
BACKOFF_SECONDS="${BACKOFF_SECONDS:-30}"

case "$SCOPE" in
    app|app+os) ;;
    *) echo "ERROR: scope must be 'app' or 'app+os', got '$SCOPE'" >&2; exit 2 ;;
esac

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is not on PATH" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "ERROR: cannot reach the Docker daemon" >&2; exit 2; }

echo "Warming dep-scan VDB"
echo "  volume : $VDB_VOLUME"
echo "  scope  : $SCOPE"
echo "  image  : $DEPSCAN_IMAGE"

docker volume create "$VDB_VOLUME" >/dev/null

volume_size() {
    docker run --rm -v "$VDB_VOLUME:/vdb" alpine du -sh /vdb 2>/dev/null | awk '{print $1}' || echo "unknown"
}

# A minimal project gives dep-scan something to analyse so it populates the DB and exits, rather
# than downloading and then doing nothing.
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
mkdir -p "$WORK_DIR/src" "$WORK_DIR/reports"
chmod 777 "$WORK_DIR/reports"
cat > "$WORK_DIR/src/package.json" <<'JSON'
{ "name": "vdb-warmup", "version": "1.0.0", "dependencies": { "lodash": "4.17.11" } }
JSON
# A lockfile is required: without one cdxgen resolves no packages ("No packages were found in
# the project"), dep-scan exits 0 with no VDR, and the warm-up cannot confirm the DB is usable.
cat > "$WORK_DIR/src/package-lock.json" <<'JSON'
{
  "name": "vdb-warmup",
  "version": "1.0.0",
  "lockfileVersion": 2,
  "requires": true,
  "packages": {
    "": { "name": "vdb-warmup", "version": "1.0.0", "dependencies": { "lodash": "4.17.11" } },
    "node_modules/lodash": { "version": "4.17.11", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.11.tgz" }
  },
  "dependencies": {
    "lodash": { "version": "4.17.11", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.11.tgz" }
  }
}
JSON

echo "  size before: $(volume_size)"

attempt=1
while [ "$attempt" -le "$ATTEMPTS" ]; do
    echo
    echo "=== attempt $attempt/$ATTEMPTS ==="

    if docker run --rm -u root \
        -v "$VDB_VOLUME:/vdb" -e VDB_HOME=/vdb \
        -v "$WORK_DIR/src:/app:ro" \
        -v "$WORK_DIR/reports:/reports:rw" \
        "$DEPSCAN_IMAGE" \
        depscan --no-banner --vdb-scope "$SCOPE" --src /app --reports-dir /reports; then

        if ls -1 "$WORK_DIR/reports"/*.vdr.json >/dev/null 2>&1; then
            echo
            echo "VDB warmed successfully."
            echo "  volume     : $VDB_VOLUME"
            echo "  scope      : $SCOPE"
            echo "  size after : $(volume_size)"
            echo
            echo "Mount it in a pipeline with:"
            echo "  docker run --rm -v $VDB_VOLUME:/vdb -e VDB_HOME=/vdb ... $DEPSCAN_IMAGE depscan ..."
            exit 0
        fi
        echo "WARNING: dep-scan exited 0 but produced no VDR - treating as a failed warm-up." >&2
    fi

    # A failed download leaves its partial data in the volume rather than being replaced, so the
    # volume grows across retries and across scope switches (measured: 4.4G of partial app+os data
    # plus a later successful app warm = 7.0G). Reclaim it with "docker volume rm $VDB_VOLUME"
    # when a runner is low on disk.
    if [ "$attempt" -lt "$ATTEMPTS" ]; then
        wait_for=$(( BACKOFF_SECONDS * attempt ))
        echo "Attempt $attempt failed. Retrying in ${wait_for}s (current volume size: $(volume_size))..." >&2
        sleep "$wait_for"
    fi
    attempt=$(( attempt + 1 ))
done

cat >&2 <<EOF

ERROR: could not warm the dep-scan VDB after $ATTEMPTS attempts.

The usual cause is the vulnerability-database download being interrupted; it is a single large
transfer (~3.7GB for app scope, ~4.4GB for app+os) and any connection drop fails it.

Options:
  - Re-run this script; each attempt starts a fresh download and often succeeds later on.
  - Reset the volume first if disk is tight: docker volume rm $VDB_VOLUME
  - Check that the agent has enough free disk - partial downloads accumulate in the volume.
  - Use scanner=trivy instead. Trivy needs a ~110MB database and covers both container images
    and build files, at the cost of not resolving transitive dependencies the way dep-scan does.
EOF
exit 1
