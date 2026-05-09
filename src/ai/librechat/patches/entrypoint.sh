#!/bin/sh
# papAIa startup wrapper for LibreChat.
# Applies in-place patches to the bundled API before starting the server.
set -e

cd /app

node /app/patches/mcp-user-headers.js

exec npm run backend
