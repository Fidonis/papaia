#!/usr/bin/env node
/**
 * Patches LibreChat's bundled API bundle to forward user identity headers
 * (x-librechat-user-email, x-librechat-user-id) to MCP servers.
 *
 * The patch targets MCPManager.callTool where MCP connection headers are set,
 * injecting the user object's email and ID that are already in scope there.
 *
 * Run once at container startup before `npm run backend`.
 * Re-running is safe — the marker prevents double-patching.
 */
'use strict';

const fs = require('fs');

const TARGET = '/app/packages/api/dist/index.js';
const MARKER = '/* papaia:mcp-user-headers */';

let content;
try {
  content = fs.readFileSync(TARGET, 'utf8');
} catch (e) {
  process.stderr.write(`[papaia] ERROR: cannot read ${TARGET}: ${e.message}\n`);
  process.exit(1);
}

if (content.includes(MARKER)) {
  process.stdout.write('[papaia] mcp-user-headers already patched — skipping.\n');
  process.exit(0);
}

// Match the setRequestHeaders call inside the headers branch of MCPManager.callTool.
// The `user` object with user.id and user.email is in scope at this point.
const blockRe = /if\s*\(\s*'headers'\s+in\s+currentOptions\s*\)\s*\{\s*connection\.setRequestHeaders\(\s*currentOptions\.headers\s*\|\|\s*\{\}\s*\);\s*\}/;

if (!blockRe.test(content)) {
  process.stderr.write(
    '[papaia] ERROR: mcp-user-headers patch target not found in index.js.\n' +
    '         LibreChat version may have changed — check patches/mcp-user-headers.js.\n'
  );
  process.exit(1);
}

// Replace only the inner setRequestHeaders call, preserving the surrounding if-block structure.
const patched = content.replace(blockRe, (match) =>
  match.replace(
    /connection\.setRequestHeaders\(\s*currentOptions\.headers\s*\|\|\s*\{\}\s*\);/,
    `const _h = Object.assign({}, currentOptions.headers || {}); ${MARKER}\n` +
    `        if (user && user.email) { _h['x-librechat-user-email'] = user.email; }\n` +
    `        if (user && user.id) { _h['x-librechat-user-id'] = String(user.id); }\n` +
    `        connection.setRequestHeaders(_h);`
  )
);

fs.writeFileSync(TARGET, patched);
process.stdout.write('[papaia] mcp-user-headers patched successfully.\n');
