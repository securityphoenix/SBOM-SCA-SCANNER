// CI-PURPLE SBOM ingest -> Phoenix, for Jenkins.
//
// Targets the NEW CI-PURPLE ingest contract (/api/v1/external/sca/ingest), NOT the older
// /v1/import/assets* routes the sibling sbom-single-repo/ pipeline uses - see this directory's
// own README "Naming/placement decision" section for why they are two separate tools.
//
// Flow: generate a CycloneDX build-file SBOM with cdxgen -> mint a short-lived CI-ingest token ->
// submit -> optionally wait and gate the build on the terminal verdict (exit 3 on BLOCK).
//
// Repository/branch/commit and Jenkins provenance (BUILD_TAG, BUILD_URL, NODE_NAME) are
// auto-detected from the Jenkins environment by ci_context.py - no --from-jenkins-env-style flag
// is needed (unlike sbom-single-repo's client, this one auto-detects the CI provider). Requires a
// "Pipeline script from SCM" job so a real checkout (with an `origin` remote) exists for the
// REPOSITORY UNDER SCAN.
//
// The ci-purple-ingest CLIENT ITSELF is checked out separately, into .phoenix-utils/, by the
// "Check out the ci-purple-ingest client" stage below - mirroring
// github-actions-ci-purple-ingest.yml.example's own checkout of the same repository. A copy of
// this Jenkinsfile pasted into an unrelated job's pipeline (the common way a Jenkinsfile is
// adopted) would otherwise `cd` into a path that simply does not exist in that job's own
// workspace.
//
// Bitbucket is not a supported CI-PURPLE system in v1 - if this ever runs somewhere Jenkins
// happens to expose Bitbucket-shaped variables it still auto-detects as Jenkins (Jenkins's own
// JENKINS_URL/BUILD_TAG markers take precedence in ci_context.py), so no special handling is
// needed here; see sbom-single-repo's own Bitbucket example for that CI system instead.

pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    parameters {
        string(name: 'BUILD_FILE_PATH', defaultValue: 'package-lock.json', description: 'Manifest path within the workspace to scan (recorded as asset.buildFilePath)')
        string(name: 'SCAN_PATH', defaultValue: '.', description: 'Directory cdxgen scans to produce the SBOM')
        string(name: 'PROJECT_TYPE', defaultValue: 'universal', description: 'cdxgen -t value (universal, js, python, java, go, ...)')
        booleanParam(name: 'WAIT_FOR_COMPLETION', defaultValue: false, description: 'Poll until the ingest job reaches a terminal state and fail the build on a BLOCK verdict. Off = fire-and-forget (submit and exit 0 on 202)')
        string(name: 'PHOENIX_API_BASE_URL', defaultValue: 'https://api.securityphoenix.cloud', description: 'Phoenix API URL')
        string(name: 'DEPSCAN_IMAGE', defaultValue: 'ghcr.io/owasp-dep-scan/dep-scan@sha256:c305f241a3c2e35a90472ef7cb971b03904f719a6b736ab40b4a0039ce8470c4', description: 'OWASP dep-scan image (also provides cdxgen), pinned by digest')
        string(name: 'UTILS_REPO_URL', defaultValue: 'https://github.com/securityphoenix/autoconfig-priv-PYRUS-PRIV-NEW.git', description: 'Repository holding the ci-purple-ingest client (defaults to this repository)')
        string(name: 'UTILS_REF', defaultValue: 'main', description: 'Ref of UTILS_REPO_URL to check out')
        string(name: 'UTILS_CHECKOUT_CREDENTIALS_ID', defaultValue: '', description: 'Jenkins credentials ID for a private UTILS_REPO_URL. Leave blank for a public repository - matches the GitHub Actions templates optional PHOENIX_UTILS_TOKEN')
    }

    environment {
        // Add a "Secret text" credential in Jenkins (Manage Jenkins -> Credentials) with this ID,
        // holding an API key created with EXACTLY scopes: ["ci:ingest"]. Never put the key
        // literal in this script - Jenkins masks credentials() bindings in console output, a
        // hardcoded value would not be masked.
        PHOENIX_API_KEY = credentials('phoenix-ci-ingest-api-key')
        SBOM_FILE = "${WORKSPACE}/sbom.cdx.json"
        // See jenkins_sbom_single_repo_pipeline.groovy's own comment on why this lives inside
        // WORKSPACE rather than /tmp when Jenkins itself runs in a container: Docker bind-mount
        // sources resolve on the HOST, and WORKSPACE is the one directory guaranteed visible to
        // both Jenkins and the scanner container.
        SCAN_REPORTS = "${WORKSPACE}/.ci-purple-sbom-reports"
    }

    stages {
        stage('Prepare') {
            steps {
                script {
                    // First build of a fresh job runs without parameter values injected into env -
                    // bind them explicitly so this stage behaves identically on build #1.
                    env.BUILD_FILE_PATH = params.BUILD_FILE_PATH
                    env.SCAN_PATH = params.SCAN_PATH
                    env.PROJECT_TYPE = params.PROJECT_TYPE
                    env.WAIT_FOR_COMPLETION = params.WAIT_FOR_COMPLETION ? 'true' : 'false'
                    env.PHOENIX_API_BASE_URL = params.PHOENIX_API_BASE_URL
                    env.DEPSCAN_IMAGE = params.DEPSCAN_IMAGE
                    env.UTILS_REPO_URL = params.UTILS_REPO_URL
                    env.UTILS_REF = params.UTILS_REF
                }
                sh 'rm -rf "$SCAN_REPORTS"; mkdir -p "$SCAN_REPORTS"; chmod 777 "$SCAN_REPORTS"'
            }
        }

        stage('Generate SBOM') {
            steps {
                // Copilot review fix: the shebang MUST be the literal first two characters of the
                // script Jenkins' durable-task step writes to disk - a leading blank line (as this
                // block previously had, from `sh '''` followed by a newline before the `#!` line)
                // means the file does NOT start with `#!`, so Jenkins falls back to its default
                // shell interpreter instead of bash, and `set -o pipefail` below (a bashism, not
                // POSIX sh) can then fail or silently not apply depending on the agent's `/bin/sh`.
                sh '''#!/usr/bin/env bash
set -euo pipefail
docker run --rm \
    -v "$WORKSPACE:/app:ro" \
    -v "$SCAN_REPORTS:/reports:rw" \
    --entrypoint cdxgen "$DEPSCAN_IMAGE" \
    -t "$PROJECT_TYPE" -o /reports/sbom.cdx.json "/app/$SCAN_PATH"
cp "$SCAN_REPORTS/sbom.cdx.json" "$SBOM_FILE"
'''
            }
        }

        // M-5 fix: without this stage the "Submit to CI-PURPLE ingest" stage's `cd` targets a path
        // that only happens to exist when this Jenkinsfile itself runs from inside its own repo
        // checkout - copying this file into an unrelated job's pipeline (the ordinary way a
        // Jenkinsfile gets adopted) would otherwise fail with "no such file or directory" on the
        // very first line of that stage. Mirrors github-actions-ci-purple-ingest.yml.example's own
        // "Check out the ci-purple-ingest client" step into .phoenix-utils/.
        stage('Check out the ci-purple-ingest client') {
            steps {
                dir('.phoenix-utils') {
                    script {
                        if (params.UTILS_CHECKOUT_CREDENTIALS_ID?.trim()) {
                            git branch: env.UTILS_REF, url: env.UTILS_REPO_URL, credentialsId: params.UTILS_CHECKOUT_CREDENTIALS_ID
                        } else {
                            git branch: env.UTILS_REF, url: env.UTILS_REPO_URL
                        }
                    }
                }
            }
        }

        stage('Submit to CI-PURPLE ingest') {
            steps {
                // Copilot review fix: see the "Generate SBOM" stage's own comment above - the
                // shebang must be the literal first characters of this string, not preceded by a
                // blank line, or Jenkins invokes the agent's default shell instead of bash.
                sh '''#!/usr/bin/env bash
set -euo pipefail

# N-1 fix (re-review round 1): this stage MUST NOT `cd` anywhere - it must stay
# in $WORKSPACE, the repository under scan, for its entire duration. The client
# auto-detects gitRemoteUrl/commitSha via `git remote get-url origin` /
# `git rev-parse HEAD` run against the CURRENT WORKING DIRECTORY
# (ci_context.py, which prefers git over any env var for these two fields). The
# previous `cd ".phoenix-utils/..."` here silently resolved BOTH values against
# Phoenix's own utils repository instead of the customer's scanned repo - exit
# 0, no warning, wrong asset identity, reproduced live by re-review. Reference
# the client by PATH instead, exactly like
# github-actions-ci-purple-ingest.yml.example's own invocation (which never
# `cd`s either, for the same reason) - Python puts the invoked script's own
# directory on sys.path[0] independent of cwd, so the sibling `import
# ci_context` still resolves.
CLIENT_DIR=".phoenix-utils/Utils/SBOM-SCA-CONTAINER-PIPELINE/ci-purple-ingest"

# Same install-fallback ladder as jenkins_sbom_single_repo_pipeline.groovy's
# own "Send to Phoenix" stage - avoids a `pip install` outright failing on a
# PEP 668 "externally-managed-environment" agent, without hardcoding one path.
VENV="${WORKSPACE_TMP:-/tmp}/ci-purple-ingest-venv"
PY=python3
if ! python3 -c "import requests" >/dev/null 2>&1; then
    if python3 -m venv "$VENV" >/dev/null 2>&1; then
        PY="$VENV/bin/python"
        "$PY" -m pip install --quiet -r "$CLIENT_DIR/requirements.txt"
    else
        python3 -m pip install --quiet --user -r "$CLIENT_DIR/requirements.txt"
    fi
fi
"$PY" -c "import requests" || {
    echo "Cannot import requests. Install it on the agent, or make python3-venv available." >&2
    exit 1
}

wait_flag=""
if [ "$WAIT_FOR_COMPLETION" = "true" ]; then
    wait_flag="--wait"
fi

# PHOENIX_API_KEY is exported by the `environment { }` credentials() binding
# above - never echoed here, never passed as a CLI argument (which would land
# in `ps` output and Jenkins' own recorded command line). Invoked by path, cwd
# untouched - see the comment above.
"$PY" "$CLIENT_DIR/ci_purple_sbom_to_phoenix.py" \
    --sbom-file "$SBOM_FILE" \
    --asset-kind REPO \
    --build-file-path "$BUILD_FILE_PATH" \
    --api-base-url "$PHOENIX_API_BASE_URL" \
    $wait_flag
# Exit codes: 0 = accepted (and, with --wait, terminal verdict PASS/WARN);
# 1 = a client or ingest error (see the console log); 3 = --wait completed and
# the verdict is BLOCK - this stage then fails the build on its own non-zero
# exit, no extra post-processing needed.
'''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'sbom.cdx.json', allowEmptyArchive: true, fingerprint: true
            sh 'rm -f "$SBOM_FILE"; rm -rf "$SCAN_REPORTS"'
        }
    }
}
