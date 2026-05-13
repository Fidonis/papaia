# ═══════════════════════════════════════════════════════════════════════════
# crm-demo — EspoMCP (stdio) + supergateway HTTP bridge
# by Fidonis GmbH · https://fidonis.de
# ═══════════════════════════════════════════════════════════════════════════
# Upstream EspoMCP (github.com/zaphod-black/EspoMCP) is stdio-only. We clone
# and build it here, then run it under supergateway which exposes it over
# Streamable HTTP (/mcp) and SSE (/sse) on $MCP_PORT.
# ═══════════════════════════════════════════════════════════════════════════
FROM node:20-alpine

ARG ESPOMCP_REF=main

RUN apk add --no-cache git

WORKDIR /app

# Build EspoMCP from source. The actual Node project lives in the EspoMCP/
# subdirectory of the repo.
RUN git clone --depth 1 --branch ${ESPOMCP_REF} \
        https://github.com/zaphod-black/EspoMCP.git /tmp/EspoMCP \
 && cp -r /tmp/EspoMCP/EspoMCP/. /app/ \
 && rm -rf /tmp/EspoMCP \
 && npm install \
 && npm run build \
 && npm prune --omit=dev \
 && npm install -g supergateway \
 && chmod +x /app/build/index.js

ENV NODE_ENV=production \
    MCP_PORT=8000

EXPOSE 8000

# supergateway spawns the stdio MCP server and exposes it as Streamable HTTP
# at /mcp and SSE at /sse. Health endpoint: /healthz
CMD ["sh", "-c", "supergateway --stdio 'node /app/build/index.js' --outputTransport streamableHttp --port ${MCP_PORT} --healthEndpoint /healthz"]
