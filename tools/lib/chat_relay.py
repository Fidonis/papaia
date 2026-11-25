"""The core chat relay `papaia-chat-relay` (ADR 0029): its names, its key and the add-ons
it may serve.

A tool server outside the suite (`trust: addon`) reaches the chat only through the relay.
The relay accepts the person's chat token, exchanges it at the identity provider for a
token with exactly the add-on's audience and forwards the call with that token; the
add-on never receives the shared chat token (src/infra/chat-relay/relay.py).

This module holds what the rest of the core needs to know about it:

- the names (client and audience `papaia-chat-relay`, the client attribute the realm
  policy `chat-relay` names, the audience mapper on the `librechat` client), all in the
  platform kit's register;
- the relay's key pair for `private_key_jwt` (ES256 on P-256), made by `render` on
  `papaia-ctl start` into `$PAPAIA_CONFIG_DIR/security/chat-relay/private-key.pem` (0600,
  folder 0700) and mounted read-only into the relay alone; the realm sync registers its
  public key at the relay's client;
- the folder of the relay's list of allowed servers (`$PAPAIA_CONFIG_DIR/chat-relay/`,
  `servers.json`, format `papaia.chat-relay-servers/1`), which `render` creates empty;
  without the list the relay refuses every call;
- which audiences an opt-in may name (`eligible`): an MCP entry of an installed add-on
  outside the suite that serves persons, with an address and a registered audience, whose
  add-on does not attach `librechat` to one of its networks.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from . import service_account_keys as sak

RELAY = "papaia-chat-relay"
CHAT_CLIENT = "librechat"
# The client attribute only the relay's client carries; the realm policy names it.
MARK = "papaia.chat-relay"
POLICY = "chat-relay"
# The audience mapper on the `librechat` client while at least one opt-in is confirmed
# (the name chat_servers.audience_mapper gives it).
MAPPER = f"{RELAY}-audience"
# Keycloak's standard token exchange: never a refresh token for an exchanged token.
NO_REFRESH = {"standard.token.exchange.enableRefreshRequestedTokenType": "NO"}
KEY_DIR = Path("security") / "chat-relay"
KEY_REF = f"{KEY_DIR.as_posix()}/{sak.KEY_FILE}"
LIST_DIR = Path("chat-relay")
SERVERS_FILE = "servers.json"
SERVERS_FORMAT = "papaia.chat-relay-servers/1"
# The realm's limit of exchange scopes per client.
MAX_SERVERS = 12


class ChatRelayError(Exception):
    """The relay's key or folders cannot be prepared."""


class _RelayKeys(sak.KeyStore):
    """The relay's one key pair: the store's root is the relay's key folder."""

    def folder(self, account_id: str) -> Path:
        if account_id != RELAY:
            raise ValueError(f"{account_id!r} is not the chat relay")
        return self.root


def keystore(config_dir: Path) -> sak.KeyStore:
    return _RelayKeys(config_dir / KEY_DIR)


def public_jwks(config_dir: Path) -> list[dict] | None:
    """The public JWK set of the relay's key, None when there is no key file."""
    try:
        jwk = keystore(config_dir).public_jwk(RELAY)
    except sak.KeyFileError as exc:
        raise ChatRelayError(str(exc)) from None
    return None if jwk is None else [jwk]


def servers_path(config_dir: Path) -> Path:
    return config_dir / LIST_DIR / SERVERS_FILE


def render(config_dir: Path) -> None:
    """The relay's key (made once, kept on later runs) and its list folder, both of
    which its container mounts; Compose must not create them. The list itself is written
    by the opt-in; an empty folder lets the relay refuse every call."""
    store = keystore(config_dir)
    try:
        if store.public_jwk(RELAY) is None:
            store.generate(RELAY)
    except sak.KeyFileError as exc:
        raise ChatRelayError(f"key: {exc}") from None
    folder = config_dir / LIST_DIR
    try:
        folder.mkdir(mode=0o755)
    except FileExistsError:
        pass
    st = os.lstat(folder)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise ChatRelayError(f"{folder} is not a folder (a symbolic link is refused)")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        os.chmod(folder, stat.S_IMODE(st.st_mode) & ~(stat.S_IWGRP | stat.S_IWOTH))


def eligible_entries(doc: dict | None, attaches_chat: set[str]) -> dict[str, str]:
    """{audience: add-on} of the catalog document `doc` that an opt-in may name: an MCP
    entry of an add-on (never a core profile) with `trust: addon`, identity `person`, an
    address and an audience, whose add-on is not in `attaches_chat`."""
    found: dict[str, str] = {}
    for entry in (doc or {}).get("services") or []:
        provider = entry.get("provider")
        if (
            entry.get("kind") != "mcp"
            or entry.get("trust") != "addon"
            or not isinstance(provider, str)
            or provider.startswith("core:")
            or provider in attaches_chat
            or "person" not in (entry.get("identity") or ())
            or not entry.get("address")
            or not entry.get("audience")
        ):
            continue
        found.setdefault(entry["audience"], provider)
    return found


def attaches_chat(manifest: dict | None) -> bool:
    """Whether an add-on's manifest puts `librechat` on one of its networks
    (`networks.attach` or an entry of `networks.isolated`): a direct path to the chat."""
    networks = (manifest or {}).get("networks")
    if not isinstance(networks, dict):
        return False
    lists = [networks.get("attach")]
    isolated = networks.get("isolated")
    if isinstance(isolated, list):
        lists += [entry.get("attach") for entry in isolated if isinstance(entry, dict)]
    return any(isinstance(names, list) and CHAT_CLIENT in names for names in lists)


def eligible(config_dir: Path, repo_root: Path) -> dict[str, str]:
    """{audience: add-on} an opt-in of this installation may name (see eligible_entries).
    Raises catalog.CatalogError for a declaration the catalog refuses."""
    from . import catalog, deployment  # catalog reaches the realm sync, which imports this

    attaches: set[str] = set()
    for addon in deployment.active_addons(deployment.load(config_dir) or {}):
        name = addon.get("name")
        manifest, _ = deployment.load_addon_manifest(
            deployment.resolve_addon_path(addon, repo_root)
        )
        if isinstance(name, str) and attaches_chat(manifest):
            attaches.add(name)
    return eligible_entries(catalog.build(config_dir, repo_root), attaches)
