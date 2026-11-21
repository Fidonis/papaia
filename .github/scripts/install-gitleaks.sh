#!/usr/bin/env bash
# Install the gitleaks release pinned in the workflow (GITLEAKS_VERSION, GITLEAKS_SHA256)
# into DEST (default: $RUNNER_TEMP/bin) and put it on the job's PATH.
#
# The archive is checked against the pinned sha256 before it is unpacked, so a replaced
# release asset fails the job instead of running.
set -euo pipefail

version="${GITLEAKS_VERSION:?GITLEAKS_VERSION is not set}"
sha256="${GITLEAKS_SHA256:?GITLEAKS_SHA256 is not set}"
dest="${1:-${RUNNER_TEMP:?RUNNER_TEMP is not set}/bin}"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid GITLEAKS_VERSION" >&2; exit 2; }
[[ "$sha256" =~ ^[0-9a-f]{64}$ ]] || { echo "invalid GITLEAKS_SHA256" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
asset="gitleaks_${version}_linux_x64.tar.gz"
curl -fsSL -o "$work/$asset" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${version}/${asset}"
echo "${sha256}  $work/$asset" | sha256sum -c -
tar -xzf "$work/$asset" -C "$work" gitleaks
mkdir -p "$dest"
install -m 0755 "$work/gitleaks" "$dest/gitleaks"
if [[ -n "${GITHUB_PATH:-}" ]]; then
  echo "$dest" >> "$GITHUB_PATH"
fi
"$dest/gitleaks" version
