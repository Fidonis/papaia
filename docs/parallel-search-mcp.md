# Parallel Search MCP in LibreChat (opt-in)

This guide connects LibreChat to the hosted [Parallel MCP server](https://docs.parallel.ai/integrations/mcp/quickstart)
through the customer overlay. LibreChat offers every tool the server lists, and the server
decides that list: Parallel can add, change or remove tools at any time, without a change in
this installation. In November 2026 the list without a key was:

- `web_search`: search the public web,
- `web_fetch`: read the content of given URLs,
- `web_decisions`: answer typed questions about a subject (a probability, a pick among
  options, a score) from web evidence,
- `find_verticals`: find specialized data sources beyond web search, such as PubMed,
  ClinicalTrials.gov or a registry of US healthcare providers, each with a price per call,
- `search_vertical`: query one of these sources.

A key adds `web_research`. The log line under [Check it](#check-it) shows the current list.
Nothing in the shipped configuration changes, and the server stays off unless an operator
adds it.

## What leaves the installation

Parallel is a hosted service outside the self-hosted deployment. Once the server is
configured, every tool call sends Parallel the arguments the model fills in. The model
writes them from the chat, so treat the content of a chat that uses the server as content
that can leave the installation. Which fields a tool takes is decided by the server, not by
this guide. For the tools listed above (November 2026) they are:

- `web_search`: the search objective and queries,
- `web_fetch`: the URLs to fetch, optionally with an objective and queries,
- `web_decisions`: the subject of the questions as JSON (`state`) and the questions
  themselves. Of these tools, it is the most likely to carry chat content verbatim,
- `find_verticals`: what the user wants to find, in natural language (`objective`),
- `search_vertical`: the id of a source and the search arguments for it,
- with `web_search` and `web_fetch`, optionally the name of the model (`client_model`) and a
  `session_id` from an earlier result.

The API key is sent as well, when one is configured.

After every recreate of LibreChat, compare the `Tools:` line under [Check it](#check-it)
with this list. Before users rely on a tool that is not on it, check what it sends: the
server describes each tool and its input fields.

```sh
curl -s https://mcp.parallel.ai/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | sed -n 's/^data: //p' | python3 -m json.tool
```

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
       description: 'Web search and related tools of the hosted Parallel MCP server. Queries, URLs and questions from the chat leave this installation.'
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

Where papaia-manager is installed, steps 1 to 3 can be done in Settings → Overlay instead:
it shows the diff against the current file and recreates LibreChat on *Apply*.

## Optional: an API key

Without a key the server answers anonymously at lower rate limits. The `web_research` tool
of the same server needs a key; without one, only the tools listed at the top work. With a key, usage is billed to the Parallel account.

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
     | grep -F '[MCP][ParallelSearch]'
   ```

   A working server logs `[MCP][ParallelSearch] Tools: web_search, web_fetch, …`. A plain
   `grep -i parallel` always matches, since LibreChat logs the loaded configuration at
   startup, so it says nothing about the connection.

   - An error that names the domain means the `allowedDomains` entry is missing.
   - `Invalid API key` after three attempts means the key is wrong, or the header is in
     place but `PARALLEL_API_KEY` is missing from `ai/librechat/.env`. The server then has
     no tools at all; it does not fall back to anonymous access.

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
