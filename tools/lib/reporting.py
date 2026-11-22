"""Operator-facing checklists ("views") printed by papaia-ctl.

Pure rendering over already-resolved state -- no file mutation, no
resolution logic. Kept out of cli.py so the checklist content is directly
unit-testable without argparse plumbing.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from . import chat_servers, common, envtree, hosted_model, keycloak_role_sync, secrets, smtp

# The operator notice when the model server is outside the installation (betrieb BE-05),
# in the operator's language as specified.
MODEL_OUTSIDE_NOTICE = (
    "Inhalte der Anfragen verlassen Ihr Netz. Prüfen Sie Auftragsverarbeitung und Übermittlung."
)


def print_model_location(config_dir: Path, repo_root: Path) -> None:
    """Print where the models of the installation run. Inside: every route of LiteLLM
    goes to a service of the stack or the native LocalAI of this host. Outside: a route
    leaves the stack (row K-20 of the communication matrix, through papaia-egress); any
    model server papaia does not run counts as outside, so the notice is never missed."""
    names = hosted_model.rendered_stack_names(config_dir, repo_root)
    try:
        found = hosted_model.route(config_dir, names)
    except hosted_model.HostedModelError as exc:
        print(f"Model source: cannot be determined ({exc})")
        return
    if found is None:
        print(
            "Model source: inside the installation (the models run in the stack or on this host)."
        )
        return
    host, port = found
    print(f"Model source: outside the installation ({host}:{port}).")
    print(f"  {MODEL_OUTSIDE_NOTICE}")


def print_external_oidc_checklist(config_dir: Path, tree: envtree.EnvTree) -> None:
    """Print a step-by-step operator checklist for completing an external OIDC
    setup. Called after persist_tree so all resolved values are available."""
    root = tree.get("", {})
    librechat = tree.get("ai/librechat", {})
    litellm = tree.get("ai/litellm", {})

    issuer = root.get("OIDC_ISSUER", "<OIDC_ISSUER>")
    app_host = root.get("PAPAIA_HOST", "<PAPAIA_HOST>")
    librechat_url = librechat.get("DOMAIN_SERVER") or app_host
    litellm_redirect = litellm.get("GENERIC_REDIRECT_URI", "")

    # Collect env files that still contain REPLACE_WITH_VALID_SECRET
    placeholder = secrets._EXTERNAL_SECRET_PLACEHOLDER
    needs_edit: list[tuple[str, str]] = []
    for rel_dir, values in sorted(tree.items()):
        for key, value in sorted(values.items()):
            if value == placeholder:
                env_file = f"{rel_dir}/.env" if rel_dir else ".env"
                needs_edit.append((env_file, key))

    clients = [
        ("librechat", f"{librechat_url}/oauth/openid/callback"),
        ("litellm", litellm_redirect or f"{app_host}/sso/callback"),
        ("oauth2-proxy", f"{app_host}/oauth2/callback"),
    ]
    active_profiles = _active_profiles(root)
    rag_active = "rag" in active_profiles
    knowledge_map_active = "knowledge-map" in active_profiles

    sep = "─" * 65
    print()
    print("External OIDC — manual steps required before 'papaia-ctl start'")
    print(sep)
    print()
    print(f"1. Register these OIDC clients on {issuer}:")
    print()
    id_w = max(len(c[0]) for c in clients) + 2
    for client_id, redirect_uri in clients:
        print(f"   {client_id:<{id_w}} {redirect_uri}")
    print()
    if rag_active:
        print("   RAG system (profile rag), in the same provider:")
        print("   - resource-server clients 'mcp-qdrant' and 'mcp-qdrant-ingest' (no login flows),")
        print("     and an audience mapper for each on the 'librechat' client's access tokens")
        print("   - the realm roles 'qdrant-ingest-operator' (required for the ingest MCP tools)")
        print("     and 'qdrant-admin'")
        print()
    if knowledge_map_active:
        print("   Knowledge map (profile knowledge-map), in the same provider:")
        print("   - a resource-server client 'mcp-knowledge-map' (no login flows), and an")
        print("     audience mapper for it on the 'librechat' client's access tokens")
        print("   - access tokens must carry the realm roles (flat 'roles' claim or")
        print("     'realm_access.roles') for the role-based map trimming")
        print()
    if needs_edit:
        print("2. Replace REPLACE_WITH_VALID_SECRET in:")
        print()
        path_w = max(len(e[0]) for e in needs_edit) + 2
        for env_file, key in needs_edit:
            print(f"   {env_file:<{path_w}} {key}")
        print()
    print("3. Apply and start the stack:")
    print()
    print("   papaia-ctl setup -y && papaia-ctl start")
    print()
    print(
        "See src/infra/keycloak/README.md"
        " 'Switching to an External OIDC Provider' for details."
    )


def _active_profiles(root: dict[str, str]) -> set[str]:
    return {p.strip() for p in root.get("COMPOSE_PROFILES", "").split(",") if p.strip()}


def _registered_models(config_dir: Path) -> set[str]:
    """The model names the rendered LiteLLM configuration lists (the generated LocalAI
    entries and those of an overlay); models added in the Admin UI are not known here."""
    path = config_dir / "ai" / "litellm" / "config.yaml"
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return set()
    entries = data.get("model_list") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return set()
    return {e["model_name"] for e in entries if isinstance(e, dict) and "model_name" in e}


def print_rag_next_steps(config_dir: Path, tree: envtree.EnvTree) -> None:
    """Print the steps that remain by hand after the RAG system was switched on.

    The ingester has no web interface. Connections, collections and ingest jobs are
    managed in papaia-manager, which creates the connection `default` to the integrated
    Qdrant itself, so setup seeds nothing and no secret is printed."""
    root = tree.get("", {})
    steps = []
    embedding_model = tree.get("ai/librechat", {}).get("RAG_EMBEDDINGS_MODEL") or "nomic-embed-text"
    if embedding_model not in _registered_models(config_dir):
        steps.append(
            [
                f"Add the embedding model '{embedding_model}' to LiteLLM (or activate its line",
                "in the LocalAI models.txt). Nothing can be embedded or searched before that.",
            ]
        )
    steps.append(
        [
            "Give the people who run ingestion through the MCP tools the realm role",
            "'qdrant-ingest-operator'.",
        ]
    )
    if "manager" in _active_profiles(root):
        steps.append(
            [
                "Manage connections, collections and ingest jobs in papaia-manager (menu RAG,",
                "administrators only). It creates the connection 'default' to http://qdrant:6333.",
            ]
        )
    else:
        steps.append(
            [
                "Connections, collections and ingest jobs are managed in papaia-manager,",
                "which is not enabled. Switch it on with 'papaia-ctl setup --manager', or",
                f"edit the catalog files in {config_dir / 'ai' / 'rag' / 'catalog'} by hand.",
            ]
        )
    print()
    print("RAG system enabled — after 'papaia-ctl start':")
    for number, lines in enumerate(steps, start=1):
        print(f"  {number}. {lines[0]}")
        for line in lines[1:]:
            print(f"     {line}")
    print("See README 'RAG system' for details.")


def print_smtp_next_steps(tree: envtree.EnvTree) -> None:
    """Print what the mail relay does and checks after it was switched on.

    Never prints the upstream password or the login."""
    module = tree.get(smtp.MODULE_DIR, {})
    sender = module.get(smtp.KEY_FROM, "")
    print()
    print("Mail relay enabled — after 'papaia-ctl start':")
    print("  1. Keycloak sends through the relay. The login page offers 'Forgot password?',")
    if tree.get("", {}).get("AUTH_PROVIDER", "internal_keycloak") == "internal_keycloak":
        print("     and an existing realm is updated by 'start' itself.")
    else:
        print("     once you point your own identity provider at smtp-relay:587.")
    print("  2. Run 'papaia-ctl doctor' to check the connection to your mail server.")
    print(f"  3. Mails go out as {sender}; your provider may only accept addresses it knows.")
    print("     The relay queues mail and retries for a day, so a send that reports success")
    print("     has been handed to the relay, not yet delivered. Recipient domains must resolve.")
    print("See README 'Outbound mail' for details.")


def _mapper_audience(addon_path: Path, rel: object) -> str | None:
    """The audience an add-on's mapper export adds, or None when it adds none, cannot be
    read or lies outside the add-on (the step stays then)."""
    if not isinstance(rel, str):
        return None
    path = (addon_path / rel).resolve()
    if not path.is_relative_to(addon_path.resolve()):
        return None
    try:
        mapper = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(mapper, dict) or mapper.get("protocolMapper") != "oidc-audience-mapper":
        return None
    audience = (mapper.get("config") or {}).get("included.client.audience")
    return audience if isinstance(audience, str) else None


def _declared_audiences(manifest: dict) -> set[str]:
    section = manifest.get("exposes")
    if not isinstance(section, list):
        return set()
    return {e["audience"] for e in section if isinstance(e, dict) and e.get("audience")}


def print_keycloak_checklist(
    name: str,
    manifest: dict,
    addon_path: Path,
    config_dir: Path,
    generated: set[str] = frozenset(),
) -> None:
    """`generated`: the audiences whose `librechat` mapper the core derives from the
    catalog (chat_servers). With the bundled Keycloak the core creates them, so the
    add-on's copy is no manual step; with an external provider the operator adds one per
    audience, whether the add-on ships an export or not."""
    integration = manifest.get("integration") or {}
    keycloak_cfg = integration.get("keycloak") or {}
    # Clients named under `client_secrets` are created by `start` (keycloak_role_sync);
    # the others remain a manual import.
    managed_entries = keycloak_role_sync.managed_clients(manifest)
    managed = [c["path"] for c in managed_entries]
    clients = [c for c in keycloak_cfg.get("clients") or [] if c not in managed]
    mappers = keycloak_cfg.get("client_mappers") or {}
    root = common.parse_env_file(config_dir / ".env")
    internal = root.get("AUTH_PROVIDER", "internal_keycloak") == "internal_keycloak"
    own = _declared_audiences(manifest) & set(generated)
    exports = mappers.get(chat_servers.LIBRECHAT_CLIENT) if isinstance(mappers, dict) else None
    exports = exports if isinstance(exports, list) else []
    shipped = {_mapper_audience(addon_path, rel) for rel in exports}
    if internal and own and isinstance(mappers, dict):
        kept = [rel for rel in exports if _mapper_audience(addon_path, rel) not in own]
        mappers = {k: v for k, v in mappers.items() if k != chat_servers.LIBRECHAT_CLIENT}
        if kept:
            mappers[chat_servers.LIBRECHAT_CLIENT] = kept
    missing = sorted(own - shipped) if not internal else []
    replace_secret_cfg = manifest.get("env_replace_secrets") or {}

    bundle_env = config_dir / "addons" / name / ".env"
    bundle_vals = common.parse_env_file(bundle_env)
    # A managed client's secret may still carry the placeholder of a manual import (the
    # form an older core needs); `addon start` generates it, so nothing is entered by hand.
    managed_keys = {c["secret_env"] for c in managed_entries}
    replace_keys = [
        k
        for k, v in bundle_vals.items()
        if v.startswith("REPLACE_WITH_") and k not in managed_keys
    ]

    notes = manifest.get("install_notes") or []
    # Written by hand in the manifest: a single step as a plain string is a list of one,
    # not one step per character.
    if isinstance(notes, str):
        notes = [notes]

    if managed:
        print()
        print(
            f"Addon '{name}' — Keycloak clients created by 'papaia-ctl start' or "
            "'papaia-ctl addon start' (their secrets are generated):"
        )
        for rel in managed:
            print(f"   {addon_path / rel}")

    if not clients and not mappers and not missing and not replace_keys and not notes:
        return

    sep = "─" * 65
    print()
    print(f"Addon '{name}' — manual steps required before 'papaia-ctl addon start'")
    print(sep)
    print()
    step = 1
    if clients:
        print(f"{step}. Import these OIDC clients in the 'papaia' realm:")
        print()
        for rel in clients:
            print(f"   {addon_path / rel}")
        print()
        print("   Keycloak Admin UI → Clients → Import client.")
        print()
        step += 1
    if mappers:
        print(f"{step}. Add protocol mappers to these existing clients:")
        print()
        for client_name, mapper_paths in mappers.items():
            for rel in mapper_paths:
                print(f"   {client_name}: {addon_path / rel}")
        print()
        print("   Clients → <client> → Client scopes → Dedicated → Add mapper → By configuration.")
        print()
        step += 1
    if missing:
        print(f"{step}. Add an audience mapper to the access tokens of the 'librechat' client")
        print("   for each of these audiences (the chat reaches the tool server with them):")
        print()
        for audience in missing:
            print(f"   {audience}")
        print()
        step += 1
    if replace_keys:
        print(f"{step}. After importing, enter the client secrets in:")
        print(f"   {bundle_env}")
        print()
        key_w = max(len(k) for k in replace_keys) + 2
        for key in replace_keys:
            hint = (replace_secret_cfg.get(key) or {}).get("hint", "")
            suffix = f"  {hint}" if hint else ""
            print(f"   {key:<{key_w}}{suffix}")
        print()
        step += 1
    for note in notes:
        # A multi-line note (a YAML `|` block) keeps the indent of the other steps.
        print(f"{step}. " + str(note).rstrip().replace("\n", "\n   "))
        print()
        step += 1
