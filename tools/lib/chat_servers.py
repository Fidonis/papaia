"""The chat's tool servers from the platform catalog (V-10 step 13).

A tool server that a module declares in `exposes:` with `kind: mcp` reaches LibreChat
without a description of its own: the core derives the `mcpServers` entry and the
audience mapper on the `librechat` client from the catalog entry, so address, audience
and title are the ones the catalog lists.

Only entries the chat may call qualify: `trust: platform` (a module of the suite; the
core sets it, never the add-on), identity `person` (LibreChat sends the person's own
token) and an internal address and audience. LibreChat passes one token that carries the
audience of every such server; a server outside the suite must not receive it.

- The `mcpServers` entry is generated only where the module ships no chat fragment of its
  own (`integration/ai/librechat/librechat.yaml` of an add-on or of a core profile): a
  shipped fragment stays the description of that module until the module drops it.
- The audience mapper is generated for every qualifying entry. It is named
  `<audience>-audience` and is left out where the rendered realm's `librechat` client
  already maps that audience (the template's mappers of the core profiles).

The server is named after its audience (`mcp-<system>`, V-12), which is unique in the
catalog's view of one installation.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from . import catalog, deployment

LIBRECHAT_CLIENT = "librechat"
LIBRECHAT_FRAGMENT = "ai/librechat/librechat.yaml"
# LibreChat replaces the placeholder with the signed-in person's access token.
_BEARER = "Bearer {{LIBRECHAT_OPENID_ACCESS_TOKEN}}"
_AUDIENCE_MAPPER = "oidc-audience-mapper"


@dataclass(frozen=True)
class ChatServer:
    provider: str
    catalog_id: str
    audience: str
    url: str
    title: str
    description: str


def servers(config_dir: Path, repo_root: Path) -> list[ChatServer]:
    """The catalog entries LibreChat may call, sorted by audience; empty while the
    installation has no catalog. Raises catalog.CatalogError for a declaration the
    catalog refuses."""
    doc = catalog.build(config_dir, repo_root)
    if doc is None:
        return []
    found: dict[str, ChatServer] = {}
    for entry in doc["services"]:
        if (
            entry.get("kind") != "mcp"
            or entry.get("trust") != "platform"
            or "person" not in (entry.get("identity") or ())
            or not entry.get("audience")
            or not entry.get("address")
        ):
            continue
        server = ChatServer(
            provider=entry["provider"],
            catalog_id=entry["id"],
            audience=entry["audience"],
            url=entry["address"],
            title=entry["title"]["en"],
            description=(entry.get("description") or entry["title"])["en"],
        )
        other = found.get(server.audience)
        if other is not None and other.url != server.url:
            raise catalog.CatalogError(
                f"audience '{server.audience}' is served by '{other.catalog_id}' "
                f"({other.url}) and '{server.catalog_id}' ({server.url}); the chat can "
                "reach one address per audience"
            )
        found.setdefault(server.audience, server)
    return [found[key] for key in sorted(found)]


def shipping_fragments(
    config_dir: Path, repo_root: Path, profile_fragments: dict[str, str]
) -> set[str]:
    """The catalog providers (add-on name, `core:<profile>`) whose module ships a chat
    fragment of its own."""
    shipped = {
        f"core:{profile}"
        for profile, path in profile_fragments.items()
        if (repo_root / path / "integration" / LIBRECHAT_FRAGMENT).is_file()
    }
    for addon in deployment.active_addons(deployment.load(config_dir)):
        if not addon.get("name"):
            continue
        path = deployment.resolve_addon_path(addon, repo_root)
        if (path / "integration" / LIBRECHAT_FRAGMENT).is_file():
            shipped.add(str(addon["name"]))
    return shipped


def _origin(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def fragment(
    chat: list[ChatServer], shipped: set[str], relayed: list[ChatServer] | None = None
) -> dict:
    """The generated layer of librechat.yaml: one entry per server whose module ships no
    fragment, one per add-on outside the suite the operator allowed (`relayed`, pointing
    to the chat relay, lib/chat_optin.py), and their origins among the allowed domains.
    Empty when there is none."""
    entries = [server for server in chat if server.provider not in shipped]
    direct = {server.audience for server in chat}
    entries += [server for server in relayed or [] if server.audience not in direct]
    if not entries:
        return {}
    origins: list[str] = []
    for server in entries:
        if _origin(server.url) not in origins:
            origins.append(_origin(server.url))
    return {
        "mcpServers": {
            server.audience: {
                "title": server.title,
                "description": server.description,
                "type": "streamable-http",
                "url": server.url,
                "headers": {"Authorization": _BEARER},
                # The server checks a real person token; LibreChat connects on first
                # use, when it has one, instead of at its start without any.
                "startup": False,
            }
            for server in entries
        },
        "mcpSettings": {"allowedDomains": origins},
    }


def audience_mapper(audience: str) -> dict:
    """The mapper that puts `audience` into the access tokens of the `librechat` client."""
    return {
        "name": f"{audience}-audience",
        "protocol": "openid-connect",
        "protocolMapper": _AUDIENCE_MAPPER,
        "consentRequired": False,
        "config": {
            "included.client.audience": audience,
            "id.token.claim": "false",
            "access.token.claim": "true",
            "introspection.token.claim": "true",
        },
    }


def add_audience_mappers(realm: dict, chat: list[ChatServer]) -> list[str]:
    """Add the audience mapper of every server to the `librechat` client of the realm
    representation `realm` where that client does not map the audience yet. Returns the
    audiences added."""
    client = next(
        (c for c in realm.get("clients") or [] if c.get("clientId") == LIBRECHAT_CLIENT), None
    )
    if client is None:
        return []
    mappers = client.setdefault("protocolMappers", [])
    names = {m.get("name") for m in mappers}
    mapped = {
        (m.get("config") or {}).get("included.client.audience")
        for m in mappers
        if m.get("protocolMapper") == _AUDIENCE_MAPPER
    }
    added = []
    for server in chat:
        mapper = audience_mapper(server.audience)
        if server.audience in mapped or mapper["name"] in names:
            continue
        mappers.append(mapper)
        added.append(server.audience)
    return added


def generated_audiences(config_dir: Path, repo_root: Path) -> set[str]:
    """The audiences whose `librechat` mapper the core generates; empty when the catalog
    cannot be built (the render reports why)."""
    try:
        return {server.audience for server in servers(config_dir, repo_root)}
    except catalog.CatalogError:
        return set()
