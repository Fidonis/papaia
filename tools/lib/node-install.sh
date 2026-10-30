#!/usr/bin/env bash
# papAIa node install script. papaia-ctl fills in the @...@ values for one node and ships
# it in that node's join archive (see tools/lib/nodes.py).
# Run as root on the node: sudo ./install.sh
# Creates the unprivileged user '@USER@' (member of the docker group), the node directory
# @ROOT@ with the first checkout, and the authorized_keys entry that lets the controller
# run 'papaia-ctl node-shell' -- and nothing else -- as that user. Safe to run again.
set -euo pipefail

NODE='@NODE@'
NODE_USER='@USER@'
ROOT='@ROOT@'
VERSION='@VERSION@'
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

fail() { printf '[error] %s\n' "$*" >&2; exit 1; }
info() { printf '[papaia-node] %s\n' "$*"; }

[ "$(id -u)" -eq 0 ] || fail "run this script as root (sudo ./install.sh)"
command -v docker >/dev/null 2>&1 || fail "docker is not installed"
docker compose version >/dev/null 2>&1 || fail "the docker compose plugin is not installed"
command -v python3 >/dev/null 2>&1 || fail "python3 is not installed (3.10 or newer)"
python3 -c 'import yaml' >/dev/null 2>&1 \
    || fail "PyYAML is not installed for python3 (python3-yaml)"
getent group docker >/dev/null 2>&1 || fail "there is no 'docker' group on this host"

if ! id "$NODE_USER" >/dev/null 2>&1; then
    info "creating user $NODE_USER"
    useradd --system --home-dir "$ROOT" --shell /bin/sh "$NODE_USER"
fi
usermod -aG docker "$NODE_USER"

install -d -m 0750 -o "$NODE_USER" -g "$NODE_USER" "$ROOT"
for dir in releases config staging .ssh; do
    install -d -m 0700 -o "$NODE_USER" -g "$NODE_USER" "$ROOT/$dir"
done

release="$ROOT/releases/$VERSION"
if [ ! -f "$release/tools/papaia-ctl" ]; then
    info "installing release $VERSION"
    rm -rf "$release.incoming"
    install -d -m 0700 -o "$NODE_USER" -g "$NODE_USER" "$release.incoming"
    tar -xf "$HERE/checkout.tar" -C "$release.incoming" --no-same-owner
    chown -R "$NODE_USER:$NODE_USER" "$release.incoming"
    mv "$release.incoming" "$release"
fi
ln -sfn "releases/$VERSION" "$ROOT/checkout.new"
mv -T "$ROOT/checkout.new" "$ROOT/checkout"
chown -h "$NODE_USER:$NODE_USER" "$ROOT/checkout"

printf '%s\n' "$NODE" > "$ROOT/node-name"
chown "$NODE_USER:$NODE_USER" "$ROOT/node-name"
chmod 0600 "$ROOT/node-name"

install -m 0600 -o "$NODE_USER" -g "$NODE_USER" "$HERE/authorized_keys" "$ROOT/.ssh/authorized_keys"

info "node '$NODE' is ready. The controller's key has the fingerprint:"
info "  $(cat "$HERE/controller.fingerprint")"
info "This host's SSH host keys (the controller asks you to confirm one of them):"
for key in /etc/ssh/ssh_host_*_key.pub; do
    [ -f "$key" ] && ssh-keygen -l -E sha256 -f "$key" | sed 's/^/[papaia-node]   /'
done
