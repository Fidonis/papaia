# Parallel Search MCP in LibreChat (opt-in)

This guide connects LibreChat to the hosted [Parallel MCP server](https://docs.parallel.ai/integrations/mcp/quickstart)
through the customer overlay. It adds two tools to LibreChat: `web_search` (search the
public web) and `web_fetch` (read the content of given URLs). Nothing in the shipped
configuration changes, and the server stays off unless an operator adds it.

## What leaves the installation

Parallel is a hosted service outside the self-hosted deployment. Once the server is
configured, every tool call sends the following to Parallel:

- the search objective and queries the model writes, which are usually derived from the
  user's chat,
- the URLs the model asks to fetch,
- the API key, when one is configured.

Parallel's MCP documentation does not state a retention period for queries or fetched
pages. Check Parallel's terms and privacy policy against your data-protection requirements
before you enable it. Use it for research on public information, not for questions that
contain personal or confidential data.

The bundled alternative that keeps search inside the installation is LibreChat's web
search with SearXNG and Firecrawl (the `librechat-websearch` profile and the
`FirecrawlMCP` server).

## Enable it

1. Create or edit `$PAPAIA_CONFIG_DIR/overlay/ai/librechat/librechat.yaml` and add:

   ```yaml
   mcpServers:
     ParallelSearch:
       title: 'Parallel Search'
       description: 'Public web search and page fetching through the hosted Parallel MCP server. Queries and URLs leave this installation.'
       type: streamable-http
       url: https://mcp.parallel.ai/mcp

   mcpSettings:
     allowedDomains:
       - "mcp.parallel.ai"
   ```

   The render deep-merges the overlay onto the shipped `librechat.yaml` and any add-on
   fragments, and appends list items, so `FirecrawlMCP`, the add-on MCP servers and the
   shipped `allowedDomains` entries stay in place. LibreChat refuses MCP servers whose host
   is not in `allowedDomains`, which is why the domain is added as well.

   If the overlay already has an `mcpServers` or `mcpSettings` key, add the new entries
   under the existing key. YAML does not merge a key that appears twice in one file: the
   second one replaces the first, and the servers listed under the first are lost without
   an error.

2. Optionally, check the result before you apply it. From `tools/`:

   ```sh
   python3 -m lib.cli --repo-root .. --config-dir "$PAPAIA_CONFIG_DIR" render-preview \
     --target=ai/librechat/librechat.yaml \
     --overlay-file="$PAPAIA_CONFIG_DIR/overlay/ai/librechat/librechat.yaml"
   ```

   The `preview` field of the JSON output is the configuration LibreChat will read. It
   must still list your existing MCP servers next to `ParallelSearch`.

3. Apply it. A render writes a new `librechat.yaml`, and LibreChat keeps the file it was
   created with, so recreate the container instead of restarting it:

   ```sh
   tools/papaia-ctl stop --clean-up --profiles=librechat
   tools/papaia-ctl start
   ```

## Optional: an API key

Without a key the server answers anonymously at lower rate limits. The `web_research` tool
of the same server needs a key; without one, only `web_search`, `web_fetch` and
`web_decisions` work. With a key, usage is billed to the Parallel account.

1. Add the key to `$PAPAIA_CONFIG_DIR/ai/librechat/.env`. `papaia-ctl` keeps variables it
   does not ship:

   ```sh
   PARALLEL_API_KEY=<your key>
   ```

2. Reference it in the server entry. LibreChat expands `${VAR}` from its container
   environment:

   ```yaml
   mcpServers:
     ParallelSearch:
       # ... as above
       headers:
         Authorization: "Bearer ${PARALLEL_API_KEY}"
   ```

3. Recreate LibreChat as in step 3 above.

## Check it

1. Watch LibreChat start and look for the server's initialization:

   ```sh
   docker compose -f src/docker-compose.yml --env-file src/.env logs librechat \
     | grep -i parallel
   ```

   An error that names the domain means the `allowedDomains` entry is missing.

2. In LibreChat, open a new chat, select **Parallel Search** in the MCP server menu below
   the input, and ask a question about current public information, for example the latest
   release of an open-source project. The answer should show a `web_search` tool call and
   cite public sources.

3. Ask the model to summarize a specific public URL. The answer should show a `web_fetch`
   tool call for that URL.

4. Check that the other MCP servers are still listed in the same menu.

## Disable it

Remove the `ParallelSearch` entry and the `mcp.parallel.ai` line from the overlay, and the
`Authorization` header and `PARALLEL_API_KEY` if you added them, then recreate LibreChat as
in step 3. An overlay file that is left empty is valid. The shipped configuration never
contained the server, so nothing else needs to be undone.

## Legacy endpoint

Parallel also runs its earlier standalone Search MCP server at
`https://search.parallel.ai/mcp`, with the same `web_search` and `web_fetch` tools. Its
documentation marks it as legacy and directs new setups to `https://mcp.parallel.ai/mcp`. If
you still use it, list `search.parallel.ai` in `allowedDomains` instead.
