#!/bin/sh
# papAIa startup wrapper for LibreChat.
# Applies in-place patches to the bundled API before starting the server.
set -e

cd /app

node /app/patches/mcp-user-headers.js
node /app/patches/agents-init.js
node /app/patches/prompts-init.js

exec npm run backend
