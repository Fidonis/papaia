# papaia-docker-gate: the manager's only way to the Docker socket (docker-compose.yml next
# to this file).
#
# Built by tools/build-images from the files listed for it in compat/own-images.yaml,
# nothing else is in the build context. The build is reproducible: the same inputs give
# the same digest, which the compose file pins.
#
# Only files are copied onto the pinned base image, no command runs at build time, so
# the amd64 and the arm64 variant are built the same way on any host. The Debian base
# keeps the copyright file of every package it installs (/usr/share/doc/*/copyright),
# so the image carries the full license text of each runtime component.
FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ARG VERSION=0.0.0
LABEL org.opencontainers.image.title="papaia-docker-gate" \
      org.opencontainers.image.description="Docker socket broker of the papAIa manager: status and start/stop of named projects only" \
      org.opencontainers.image.vendor="Fidonis GmbH" \
      org.opencontainers.image.source="https://github.com/Fidonis/papaia" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.base.name="docker.io/library/python:3.12.16-slim-trixie" \
      org.opencontainers.image.base.digest="sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"

# Notice files (LICENSE, the runtime components and their full license texts).
COPY LICENSE /usr/share/licenses/papaia-docker-gate/LICENSE
COPY src/infra/docker-gate/THIRD_PARTY_LICENSES.md /usr/share/licenses/papaia-docker-gate/THIRD_PARTY_LICENSES.md
COPY --from=python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b /usr/local/lib/python3.12/LICENSE.txt /usr/share/licenses/papaia-docker-gate/texts/Python-2.0.txt

COPY src/infra/docker-gate/docker_gate.py /opt/papaia-docker-gate/docker_gate.py

ENV PYTHONDONTWRITEBYTECODE=1
# Not root; compose adds the group that owns the Docker socket on the host.
USER 65532:65532
CMD ["python3", "-I", "/opt/papaia-docker-gate/docker_gate.py"]
