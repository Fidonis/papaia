#!/bin/sh
# papAIa startup wrapper for LibreChat.
# Applies in-place patches to the bundled API before starting the server.
set -e

cd /app

node /app/patches/mcp-user-headers.js
node /app/patches/agents-init.js
node /app/patches/prompts-init.js

# Both agents and prompts need ACL entries before they appear in the UI.
# LibreChat ships idempotent migration scripts for both; running them on
# every start keeps newly-bind-mounted YAMLs / MDs visible without manual
# kubectl-exec follow-up.
npm run migrate:agent-permissions --silent || true
npm run migrate:prompt-permissions --silent || true

exec npm run backend
