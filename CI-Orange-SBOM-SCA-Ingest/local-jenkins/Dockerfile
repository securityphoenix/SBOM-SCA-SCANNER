FROM jenkins/jenkins:lts-jdk17

USER root

# The pipeline shells out to docker (scanner containers) and python3 (the importer),
# neither of which ships in the base Jenkins image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv ca-certificates curl gnupg \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
 && chmod a+r /etc/apt/keyrings/docker.gpg \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
        > /etc/apt/sources.list.d/docker.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends docker-ce-cli \
 && rm -rf /var/lib/apt/lists/*

# Skip the setup wizard; everything is provisioned through JCasC instead.
ENV JAVA_OPTS="-Djenkins.install.runSetupWizard=false"
ENV CASC_JENKINS_CONFIG=/var/jenkins_conf/casc.yaml

COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
# --latest=false honours the pinned versions in plugins.txt; without it the CLI upgrades
# transitive dependencies to their newest releases and the build stops being reproducible.
RUN jenkins-plugin-cli --latest=false --plugin-file /usr/share/jenkins/ref/plugins.txt

USER jenkins
