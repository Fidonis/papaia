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

# Notice files (LICENSE, the runtime components and their full license texts).
COPY LICENSE /usr/share/licenses/papaia-audit/LICENSE
COPY src/infra/audit/THIRD_PARTY_LICENSES.md /usr/share/licenses/papaia-audit/THIRD_PARTY_LICENSES.md
COPY --from=python:3.12.16-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89 /usr/local/lib/python3.12/LICENSE.txt /usr/share/licenses/papaia-audit/texts/Python-2.0.txt

# The packages keep their license files in their *.dist-info folders.
COPY --from=wheels /opt/wheels/ /usr/local/lib/python3.12/site-packages/
COPY src/infra/audit/papaia_audit/__init__.py src/infra/audit/papaia_audit/__main__.py src/infra/audit/papaia_audit/access.py src/infra/audit/papaia_audit/core.py src/infra/audit/papaia_audit/read.py src/infra/audit/papaia_audit/retention.py src/infra/audit/papaia_audit/siem.py src/infra/audit/papaia_audit/audit.v1.schema.json src/infra/audit/papaia_audit/schema.sql src/infra/audit/papaia_audit/schema_read.sql src/infra/audit/papaia_audit/schema_retention.sql src/infra/audit/papaia_audit/schema_access.sql /usr/local/lib/python3.12/site-packages/papaia_audit/

ENV PYTHONDONTWRITEBYTECODE=1
# Not root; compose runs it as the user that owns the configuration directory.
USER 65532:65532
EXPOSE 8443
ENTRYPOINT ["python3", "-I", "-m", "papaia_audit"]
CMD ["--help"]
