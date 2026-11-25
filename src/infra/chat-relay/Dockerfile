# papaia-chat-relay: the core's relay from the chat to tool servers outside the suite
# (docker-compose.yml next to this file, ADR 0029).
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
LABEL org.opencontainers.image.title="papaia-chat-relay" \
      org.opencontainers.image.description="Chat relay of the papAIa stack: one-audience token exchange for tool servers outside the suite" \
      org.opencontainers.image.vendor="Fidonis GmbH" \
      org.opencontainers.image.source="https://github.com/Fidonis/papaia" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.base.name="docker.io/library/python:3.12.16-slim-trixie" \
      org.opencontainers.image.base.digest="sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"

# Notice files (LICENSE, the runtime components and their full license texts).
COPY LICENSE /usr/share/licenses/papaia-chat-relay/LICENSE
COPY src/infra/chat-relay/THIRD_PARTY_LICENSES.md /usr/share/licenses/papaia-chat-relay/THIRD_PARTY_LICENSES.md
COPY --from=python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b /usr/local/lib/python3.12/LICENSE.txt /usr/share/licenses/papaia-chat-relay/texts/Python-2.0.txt

COPY src/infra/chat-relay/relay.py /opt/papaia-chat-relay/relay.py

ENV PYTHONDONTWRITEBYTECODE=1
# Not root; compose runs it as the user that owns the configuration directory.
USER 65532:65532
# The base image brings the openssl command line the relay signs its client assertion
# with (ES256). The compose file names the command and its paths; alone the image only
# explains itself.
CMD ["python3", "-I", "/opt/papaia-chat-relay/relay.py", "--help"]
