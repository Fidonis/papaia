# papaia-chat-relay: the core's relay from the chat to tool servers outside the suite
# (docker-compose.yml next to this file, ADR 0029).
#
# Built by tools/build-images from the files listed for it in compat/own-images.yaml,
# nothing else is in the build context. The build is reproducible: the same inputs give
# the same digest, which the compose file pins.
#
# The final stage only copies files onto the pinned base image. The one stage that runs
# a command runs on the build platform and only fetches and unpacks Debian packages of
# the target platform, so the amd64 and the arm64 variant are built the same way on any
# host and without emulation. The Debian base keeps the copyright file of every package
# it installs (/usr/share/doc/*/copyright), so the image carries the full license text
# of each runtime component.
#
# Debian security fixes the pinned base does not carry yet: CVE-2026-124851 (libzstd1)
# and CVE-2026-85091 (zlib1g). The packages come in exactly the fixed versions from the
# Debian sources of the base (apt checks the archive signature and the hash of each
# package); dpkg installs them into a copy of the target base without running any of
# its programs, and only the files the upgrade changes reach the final stage. Remove the
# two stages and the COPY from debian-fixes once the base digest carries these versions.
FROM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS debian-base

FROM --platform=$BUILDPLATFORM python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS debian-fixes
ARG TARGETARCH
COPY --from=debian-base / /target/
WORKDIR /debs
RUN set -eu; \
    dpkg --add-architecture "$TARGETARCH"; \
    apt-get update; \
    mkdir /out; \
    chown _apt /debs; \
    apt-get download \
        "libzstd1:$TARGETARCH=1.5.7+dfsg-1+deb13u1" \
        "zlib1g:$TARGETARCH=1:1.3.dfsg+really1.3.1-1+deb13u1"; \
    dpkg --root=/target --force-script-chrootless --install /debs/*.deb; \
    for pkg in "libzstd1:$TARGETARCH" "zlib1g:$TARGETARCH"; do \
        dpkg-query --admindir=/target/var/lib/dpkg --listfiles "$pkg" > "/debs/$pkg.files"; \
        while read -r path; do \
            if [ -L "/target$path" ] || [ -f "/target$path" ]; then cp -a --parents "/target$path" /out/; fi; \
        done < "/debs/$pkg.files"; \
        cp -a --parents /target/var/lib/dpkg/info/"$pkg".* /out/; \
    done; \
    cp -a --parents /target/var/lib/dpkg/status /out/; \
    rm -rf /var/lib/apt/lists/*

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

# The fixed Debian packages (the debian-fixes stage).
COPY --from=debian-fixes /out/target/ /

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
