# Fake container fixture for Phoenix SBOM/vulnerability pipeline testing.
# debian:11-slim is old enough to carry a realistic set of OS CVEs, and the copied
# node manifest gives the scanners application-layer packages to find as well.
FROM debian:11-slim

COPY app/package.json      /srv/app/package.json
COPY app/package-lock.json /srv/app/package-lock.json

WORKDIR /srv/app
CMD ["true"]
