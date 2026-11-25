# papaia-audit: ingest, the store's schema step, chain verification, signed chain
# heads, retention and the SIEM export (docker-compose.yml next to this file, docs/audit.md).
#
# Built by tools/build-images from the files listed for it in compat/own-images.yaml,
# nothing else is in the build context. The build is reproducible: the same inputs give
# the same digest, which the compose file pins.
#
# The Python packages are wheels pinned by hash (requirements.txt). The first stage runs
# on the build platform and only unpacks the wheels of the target platform, without
# compiling or running them, so the amd64 and the arm64 variant are built the same way
# on any host and without emulation. The final stage only copies files.
#
# Alpine security fixes the pinned base does not carry yet: krb5-libs 1.22.3-r0
# (CVE-2026-107364, CVE-2026-112315 to CVE-2026-112323, CVE-2026-118380, CVE-2026-119079,
# CVE-2026-40355, CVE-2026-40356, CVE-2026-71199, CVE-2026-71200). The alpine-fixes stage
# runs on the build platform: apk fetches exactly this version for the target
# architecture from the Alpine repositories of the base, checks it with the base's
# signing keys and installs it into a copy of the target base without running any of
# its programs; only the files of the package and the apk database reach the final
# stage. A version the repositories no longer serve fails the build. Remove the two
# stages and the COPY from alpine-fixes once the base digest carries this version.
FROM python:3.12.16-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89 AS alpine-base

FROM --platform=$BUILDPLATFORM python:3.12.16-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89 AS alpine-fixes
ARG TARGETARCH
COPY --from=alpine-base / /target/
RUN set -eu; \
    case "$TARGETARCH" in \
        amd64) arch=x86_64 ;; \
        arm64) arch=aarch64 ;; \
        *) echo "unsupported platform $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    test "$(cat /target/etc/apk/arch)" = "$arch"; \
    apk add --root=/target --arch="$arch" --no-scripts --no-cache --no-interactive \
        "krb5-libs=1.22.3-r0"; \
    mkdir /out; \
    apk info --root=/target -L krb5-libs > /tmp/krb5-libs.files; \
    { \
        read -r _header; \
        while read -r path; do \
            if [ -n "$path" ]; then cp -a --parents "/target/$path" /out/; fi; \
        done; \
    } < /tmp/krb5-libs.files; \
    cp -a --parents /target/lib/apk/db/installed /out/

FROM --platform=$BUILDPLATFORM python:3.12.16-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89 AS wheels

ARG TARGETARCH
COPY src/infra/audit/requirements.txt /tmp/requirements.txt
RUN set -eu; \
    case "$TARGETARCH" in \
        amd64) arch=x86_64 ;; \
        arm64) arch=aarch64 ;; \
        *) echo "unsupported platform $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    pip install --no-cache-dir --root-user-action=ignore --disable-pip-version-check \
        --require-hashes --only-binary=:all: --no-deps --no-compile \
        --platform "musllinux_1_2_${arch}" --implementation cp --python-version 3.12 \
        --target /opt/wheels -r /tmp/requirements.txt; \
    rm -rf /opt/wheels/bin

FROM python:3.12.16-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89

ARG VERSION=0.0.0
LABEL org.opencontainers.image.title="papaia-audit" \
      org.opencontainers.image.description="Audit store of the papAIa stack: ingest over mutual TLS with a hash chain per source" \
      org.opencontainers.image.vendor="Fidonis GmbH" \
      org.opencontainers.image.source="https://github.com/Fidonis/papaia" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.base.name="docker.io/library/python:3.12.16-alpine3.24" \
      org.opencontainers.image.base.digest="sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89"

# The fixed Alpine packages (the alpine-fixes stage).
COPY --from=alpine-fixes /out/target/ /

# Notice files (LICENSE, the runtime components and their full license texts).
COPY LICENSE /usr/share/licenses/papaia-audit/LICENSE
COPY src/infra/audit/THIRD_PARTY_LICENSES.md /usr/share/licenses/papaia-audit/THIRD_PARTY_LICENSES.md
COPY --from=python:3.12.16-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89 /usr/local/lib/python3.12/LICENSE.txt /usr/share/licenses/papaia-audit/texts/Python-2.0.txt

# The packages keep their license files in their *.dist-info folders.
COPY --from=wheels /opt/wheels/ /usr/local/lib/python3.12/site-packages/
COPY src/infra/audit/papaia_audit/__init__.py src/infra/audit/papaia_audit/__main__.py src/infra/audit/papaia_audit/access.py src/infra/audit/papaia_audit/person_requests.py src/infra/audit/papaia_audit/core.py src/infra/audit/papaia_audit/idp.py src/infra/audit/papaia_audit/read.py src/infra/audit/papaia_audit/report.py src/infra/audit/papaia_audit/retention.py src/infra/audit/papaia_audit/siem.py src/infra/audit/papaia_audit/watch.py src/infra/audit/papaia_audit/audit.v1.schema.json src/infra/audit/papaia_audit/schema.sql src/infra/audit/papaia_audit/schema_read.sql src/infra/audit/papaia_audit/schema_retention.sql src/infra/audit/papaia_audit/schema_access.sql src/infra/audit/papaia_audit/schema_siem.sql src/infra/audit/papaia_audit/schema_person.sql /usr/local/lib/python3.12/site-packages/papaia_audit/

ENV PYTHONDONTWRITEBYTECODE=1
# Not root; compose runs it as the user that owns the configuration directory.
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["python3", "-I", "-m", "papaia_audit"]
CMD ["--help"]
