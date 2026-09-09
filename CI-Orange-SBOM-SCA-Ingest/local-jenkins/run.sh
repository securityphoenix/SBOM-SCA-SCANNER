#!/usr/bin/env bash
#
# Stand up a throwaway local Jenkins that runs the Phoenix SBOM/SCA pipeline against a fake
# build and a fake container image, so the whole path - scan, upload, import - can be exercised
# before it is pointed at a real repository.
#
# What it does:
#   1. builds a Jenkins image with docker CLI, python3 and the plugins the pipeline needs
#   2. builds a deliberately outdated container image to scan (phoenix-fake-app:1.0)
#   3. assembles a seed git repository holding the fixture, the importer and the Jenkinsfile
#   4. starts Jenkins with credentials taken from ../config.ini and the job pre-created
#
# Usage:
#   ./run.sh                 # build everything and start Jenkins (no scans, no uploads)
#   ./run.sh --trigger       # run all four scan modes; uploads to the live Phoenix tenant
#   ./run.sh --stop          # remove the container
#
# Scanning is behind an explicit --trigger because it imports into a real tenant, creating
# assets and findings there. Starting the harness should not have that side effect.
#
# Requires a ../config.ini holding real Phoenix credentials. That file is gitignored; see
# config.ini.template. Jenkins is bound to 127.0.0.1 and runs unsecured - it is a test harness.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(dirname "$HERE")"
# Deliberately outside the repository. Jenkins keeps its whole home here - extracted war,
# workspaces, build records, hundreds of MB - and the scanners bind-mount the workspace
# into their own containers. Under the repo on macOS that path goes through Docker
# Desktop's file sharing on top of a git working tree, and the same container scan that
# takes about two minutes from /tmp took an hour. Keeping it out also means no multi-GB
# tree in the working copy relying on a .gitignore line to stay untracked.
STATE="${PHOENIX_JENKINS_STATE:-${TMPDIR:-/tmp}/phoenix-local-jenkins}"
IMAGE=phoenix-jenkins-test:1.0
NAME=phoenix-jenkins
APP_IMAGE=phoenix-fake-app:1.0
JENKINS_URL=http://127.0.0.1:8080

if [ "${1:-}" = "--stop" ]; then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    echo "Stopped $NAME. State kept in $STATE (delete it for a clean slate)."
    exit 0
fi

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is not on PATH" >&2; exit 2; }
docker info >/dev/null 2>&1 || { echo "ERROR: cannot reach the Docker daemon" >&2; exit 2; }
[ -f "$SRC/config.ini" ] || { echo "ERROR: $SRC/config.ini not found - copy config.ini.template and fill it in" >&2; exit 2; }

CID=$(cd "$SRC" && python3 -c "import configparser;p=configparser.ConfigParser();p.read('config.ini');print(p['phoenix']['client_id'].strip())")
CSEC=$(cd "$SRC" && python3 -c "import configparser;p=configparser.ConfigParser();p.read('config.ini');print(p['phoenix']['client_secret'].strip())")
BASE=$(cd "$SRC" && python3 -c "import configparser;p=configparser.ConfigParser();p.read('config.ini');print(p['phoenix']['api_base_url'].strip())")
[ -n "$CID" ] && [ -n "$CSEC" ] || { echo "ERROR: client_id/client_secret are empty in $SRC/config.ini" >&2; exit 2; }

ensure_private_dir() {
    # A predictable path under /tmp: create it 0700 and refuse to reuse one that is not ours
    # or that others can reach. The Jenkins home below it ends up holding the Phoenix
    # credentials that JCasC injects, plus every build's workspace.
    local d="$1" owner perms
    # Ownership is checked before anything is changed: chmod on a directory belonging to
    # someone else fails with a bare "Operation not permitted", which reads like a bug rather
    # than the refusal it is.
    if [ -e "$d" ]; then
        owner=$(stat -f '%u' "$d" 2>/dev/null || stat -c '%u' "$d" 2>/dev/null || echo "")
        if [ -n "$owner" ] && [ "$owner" != "$(id -u)" ]; then
            echo "ERROR: $d is owned by uid $owner, not $(id -u). Refusing to use it." >&2
            echo "       Remove it, or point PHOENIX_JENKINS_STATE at a directory you own." >&2
            exit 2
        fi
        if [ ! -d "$d" ]; then
            echo "ERROR: $d exists but is not a directory. Refusing to use it." >&2
            exit 2
        fi
    fi
    mkdir -p "$d"
    chmod 700 "$d"
    perms=$(stat -f '%Lp' "$d" 2>/dev/null || stat -c '%a' "$d" 2>/dev/null || echo "")
    if [ -n "$perms" ] && [ "$perms" != "700" ]; then
        echo "ERROR: $d is mode $perms, expected 700 - it could not be secured." >&2
        exit 2
    fi
}

SEED="$STATE/seed-repo"
# JENKINS_HOME must resolve to the same absolute path on the host and inside the container.
# The pipeline hands workspace paths to "docker run -v", and the daemon resolves bind-mount
# sources on the host - a path that only exists inside the Jenkins container mounts empty.
JHOME="$STATE/home"

if [ "${1:-}" != "--trigger" ]; then
    echo "==> Building Jenkins image"
    docker build -q -t "$IMAGE" "$HERE" >/dev/null

    echo "==> Building the fake container image to scan ($APP_IMAGE)"
    APPCTX="$STATE/app-context"
    rm -rf "$APPCTX"; mkdir -p "$APPCTX/app"
    cp "$HERE/fixture/Dockerfile.app" "$APPCTX/Dockerfile"
    # Named *.fixture in the repo and renamed here. The lockfile pins deliberately outdated
    # packages so the scan finds something; under the real names Dependabot treats it as a
    # manifest of this repository and raises upgrade PRs against a fixture that must not move.
    cp "$HERE/fixture/package.json.fixture" "$APPCTX/app/package.json"
    cp "$HERE/fixture/package-lock.json.fixture" "$APPCTX/app/package-lock.json"
    docker build -q -t "$APP_IMAGE" "$APPCTX" >/dev/null

    echo "==> Assembling the seed repository"
    rm -rf "$SEED"; mkdir -p "$SEED/Utils/SBOM-SCA-CONTAINER-PIPELINE/sbom-single-repo" "$SEED/app"
    cp "$HERE/fixture/index.js" "$SEED/"
    cp "$HERE/fixture/Dockerfile.app" "$SEED/Dockerfile"
    for d in "$SEED" "$SEED/app"; do
        cp "$HERE/fixture/package.json.fixture" "$d/package.json"
        cp "$HERE/fixture/package-lock.json.fixture" "$d/package-lock.json"
    done
    cp "$SRC"/*.py "$SRC/requirements.txt" "$SEED/Utils/SBOM-SCA-CONTAINER-PIPELINE/sbom-single-repo/"
    cp "$SRC/jenkins_sbom_single_repo_pipeline.groovy" "$SEED/Jenkinsfile"
    ( cd "$SEED" && git init -q && git symbolic-ref HEAD refs/heads/main \
        && git config user.email "local@example.invalid" && git config user.name "local-jenkins" \
        && git add -A && git commit -q -m "Fake service and Phoenix SBOM pipeline" )

    ensure_private_dir "$STATE"
    ensure_private_dir "$JHOME"
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    echo "==> Starting Jenkins on $JENKINS_URL"
    # `docker create` then `docker start` rather than `docker run -d`: on a loaded daemon the
    # combined form was observed to hang for minutes and leave the container in "created"
    # without ever starting it, while an explicit start of that same container succeeded
    # immediately. Splitting the two makes the failure visible and recoverable.
    docker create --name "$NAME" \
        -p 127.0.0.1:8080:8080 \
        -u root \
        -e JENKINS_HOME="$JHOME" \
        -e CASC_JENKINS_CONFIG=/var/jenkins_conf/casc.yaml \
        -e PHOENIX_CLIENT_ID="$CID" \
        -e PHOENIX_CLIENT_SECRET="$CSEC" \
        -e JAVA_OPTS="-Djenkins.install.runSetupWizard=false -Dhudson.plugins.git.GitSCM.ALLOW_LOCAL_CHECKOUT=true" \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$JHOME:$JHOME" \
        -v "$SEED:/seed-repo" \
        -v "$HERE/casc.yaml:/var/jenkins_conf/casc.yaml:ro" \
        "$IMAGE" >/dev/null
    docker start "$NAME" >/dev/null 2>&1 || true

    # Confirm it is actually up rather than trusting an exit code: on a loaded daemon a container
    # can sit in "created" after a start that reported nothing wrong. Retry the start a few times
    # before giving up.
    for _ in 1 2 3 4 5 6; do
        # Strip whitespace and treat empty as missing: a failing `docker inspect` can still emit
        # a newline on stdout, which left $state as "\nmissing" and stopped the case below from
        # ever matching the missing branch.
        state=$(docker inspect -f '{{.State.Status}}' "$NAME" 2>/dev/null | tr -d '[:space:]')
        [ -n "$state" ] || state=missing
        case "$state" in
            running) break ;;
            missing) echo "ERROR: $NAME was not created. Is the Docker daemon healthy?" >&2; exit 1 ;;
            *)       echo "   container is '$state', starting it"; docker start "$NAME" >/dev/null 2>&1 || true; sleep 5 ;;
        esac
    done
    [ "$(docker inspect -f '{{.State.Status}}' "$NAME" 2>/dev/null)" = "running" ] || {
        echo "ERROR: $NAME will not stay running. Check: docker logs $NAME" >&2
        exit 1
    }

    # /api/json answers 200 part way through boot and then falls back to 503, and extensions can
    # still be registering even once it responds - triggering a build in that window fails with
    # "DefaultCrumbIssuer is missing its descriptor". Require the job that JCasC creates to be
    # servable several times in a row before trusting the instance.
    printf "==> Waiting for Jenkins"
    ready=0
    for _ in $(seq 1 150); do
        if curl -sf -o /dev/null "$JENKINS_URL/job/phoenix-sbom-scan/api/json" 2>/dev/null; then
            ready=$((ready + 1))
            if [ "$ready" -ge 3 ]; then echo " ready."; break; fi
        else
            ready=0
        fi
        printf "."; sleep 5
    done
    if [ "$ready" -lt 3 ]; then
        echo
        echo "ERROR: Jenkins did not become ready. Check: docker logs $NAME" >&2
        exit 1
    fi
fi

crumb() { curl -s -c "$STATE/cookies" "$JENKINS_URL/crumbIssuer/api/json" \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['crumbRequestField']+':'+d['crumb'])"; }

build_result() {
    curl -s "$JENKINS_URL/job/phoenix-sbom-scan/$1/api/json" 2>/dev/null \
        | python3 -c "import json,sys; d=json.loads(sys.stdin.read(),strict=False); print('RUNNING' if d.get('building') else (d.get('result') or 'RUNNING'))" 2>/dev/null || echo PENDING
}

run_build() {
    local label="$1"; shift
    local c next code st
    c=$(crumb)
    next=$(curl -s "$JENKINS_URL/job/phoenix-sbom-scan/api/json" | python3 -c "import json,sys; print(json.loads(sys.stdin.read(),strict=False)['nextBuildNumber'])")
    local args=(); for kv in "$@"; do args+=(--data-urlencode "$kv"); done
    # A job's first build only registers the Jenkinsfile's parameters; it cannot receive them.
    if [ "$next" = "1" ]; then
        curl -s -b "$STATE/cookies" -X POST -H "$c" "$JENKINS_URL/job/phoenix-sbom-scan/build" -o /dev/null
    else
        # ${args[@]+...} guards the empty-array case: bash 3.2, still the default on macOS,
        # treats an empty "${args[@]}" as an unbound variable under `set -u`.
        # Retry briefly: a just-started controller can still reject the first trigger.
        code=000
        for _ in 1 2 3 4 5; do
            code=$(curl -s -b "$STATE/cookies" -X POST -H "$c" ${args[@]+"${args[@]}"} \
                "$JENKINS_URL/job/phoenix-sbom-scan/buildWithParameters" -o /dev/null -w '%{http_code}')
            [ "$code" = "201" ] && break
            sleep 10
            c=$(crumb)
        done
        [ "$code" = "201" ] || echo "  warning: trigger returned HTTP $code"
    fi
    printf "  [%s] build #%s " "$label" "$next"
    for _ in $(seq 1 180); do
        st=$(build_result "$next")
        if [ "$st" != "RUNNING" ] && [ "$st" != "PENDING" ]; then
            echo "-> $st"
            [ "$st" = "SUCCESS" ] && return 0
            FAILED_SCENARIOS="${FAILED_SCENARIOS}${FAILED_SCENARIOS:+, }${label} (#${next} ${st})"
            return 1
        fi
        printf "."; sleep 10
    done
    echo "-> still running after 30m"
    FAILED_SCENARIOS="${FAILED_SCENARIOS}${FAILED_SCENARIOS:+, }${label} (#${next} timed out)"
    return 1
}

if [ "${1:-}" = "--trigger" ]; then
    echo "==> Registering pipeline parameters (first build cannot take them)"
    FAILED_SCENARIOS=""
    run_build "bootstrap" >/dev/null 2>&1 || true
    FAILED_SCENARIOS=""
    echo "==> Running the four scan modes against $BASE"
    common=(SCANNER=auto BRANCH=main PHOENIX_IMPORT_TYPE=merge WAIT_FOR_COMPLETION=false "PHOENIX_API_BASE_URL=$BASE")
    run_build "buildfile / sbom only" PHOENIX_METHOD=sbom SCAN_MODE=buildfile SCAN_PATH=. PROJECT_TYPE=js \
        FILE_PATH=package-lock.json REPO_NAME=phoenix-security/local-fake-build "${common[@]}" || true
    run_build "container / sbom only" PHOENIX_METHOD=sbom SCAN_MODE=image "CONTAINER_IMAGE=$APP_IMAGE" \
        PROJECT_TYPE=universal FILE_PATH=Dockerfile REPO_NAME=phoenix-security/local-fake-container "${common[@]}" || true
    run_build "buildfile / vulnerabilities" PHOENIX_METHOD=vulnerability SCAN_MODE=buildfile SCAN_PATH=. PROJECT_TYPE=js \
        FILE_PATH=package-lock.json REPO_NAME=phoenix-security/local-fake-build "${common[@]}" || true
    run_build "container / vulnerabilities" PHOENIX_METHOD=vulnerability SCAN_MODE=image "CONTAINER_IMAGE=$APP_IMAGE" \
        PROJECT_TYPE=universal FILE_PATH=Dockerfile REPO_NAME=phoenix-security/local-fake-container "${common[@]}" || true

    if [ -n "$FAILED_SCENARIOS" ]; then
        echo
        echo "ERROR: scenarios failed: $FAILED_SCENARIOS" >&2
        echo "Console output: $JENKINS_URL/job/phoenix-sbom-scan/" >&2
        exit 1
    fi
    echo
    echo "All four scan modes succeeded."
fi

echo
echo "Jenkins:  $JENKINS_URL/job/phoenix-sbom-scan/"
if [ "${1:-}" != "--trigger" ]; then
    echo "Scan:     $HERE/run.sh --trigger    # runs the four modes and uploads to $BASE"
fi
echo "Stop it:  $HERE/run.sh --stop"
