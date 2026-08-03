"""Sticky/derived default computation behind `papaia-ctl defaults`.

Pure logic: reads the config-dir tree and returns the KEY=VALUE map the
bash dispatcher prefills its prompts from. Printing stays in cli.py.
"""

from __future__ import annotations

from pathlib import Path

from . import common, envtree, resolve


def compute_defaults(config_dir: Path, repo_root: Path) -> dict[str, str]:
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    root = tree.get("", {})
    librechat = tree.get("ai/librechat", {})
    app_host = root.get("PAPAIA_HOST", "")
    keycloak_port = root.get("KEYCLOAK_EXT_PORT", "8110")
    auth_host_sticky = root.get("AUTH_HOST", "")
    profiles = [p for p in root.get("COMPOSE_PROFILES", "").split(",") if p]
    # Only surface a sticky LibreChat URL once the config dir is actually seeded:
    # on a fresh checkout the tree falls back to the shipped .env.example, whose
    # DOMAIN_SERVER (host.docker.internal:8000) differs from the localhost-based
    # default bash should prefill -- gating avoids a wrong sticky prefill.
    config_seeded = (config_dir / ".env").is_file()
    librechat_sticky = librechat.get("DOMAIN_SERVER", "") if config_seeded else ""
    if common.is_placeholder(librechat_sticky):
        librechat_sticky = ""
    localai_sticky = root.get("LOCALAI_PUBLIC_URL", "") if config_seeded else ""
    if common.is_placeholder(localai_sticky):
        localai_sticky = ""
    localai_variant_sticky = root.get("LOCALAI_IMAGE_VARIANT", "") if config_seeded else ""
    if common.is_placeholder(localai_variant_sticky):
        localai_variant_sticky = ""
    litellm_sticky = root.get("LITELLM_PUBLIC_URL", "") if config_seeded else ""
    if common.is_placeholder(litellm_sticky):
        litellm_sticky = ""
    manager_sticky = root.get("MANAGER_PUBLIC_URL", "") if config_seeded else ""
    if common.is_placeholder(manager_sticky):
        manager_sticky = ""
    jinaai = tree.get("ai/jinaai", {})
    reranker_model_sticky = jinaai.get("RERANKER_MODEL", "") if config_seeded else ""
    if common.is_placeholder(reranker_model_sticky):
        reranker_model_sticky = ""
    return {
        "APP_HOST_STICKY": app_host,
        "AUTH_HOST_STICKY": auth_host_sticky,
        "AUTH_HOST_DERIVED": resolve.derive_auth_host_default(
            app_host or "http://host.docker.internal", keycloak_port
        ),
        "LIBRECHAT_HOST_STICKY": librechat_sticky,
        "LIBRECHAT_EXT_PORT": root.get("LIBRECHAT_EXT_PORT", "8000"),
        "LOCALAI_HOST_STICKY": localai_sticky,
        "LOCALAI_EXT_PORT": root.get("LOCALAI_EXT_PORT", "8080"),
        "LOCALAI_VARIANT_STICKY": localai_variant_sticky,
        "LITELLM_HOST_STICKY": litellm_sticky,
        "LITELLM_EXT_PORT": root.get("LITELLM_EXT_PORT", "8200"),
        "MANAGER_HOST_STICKY": manager_sticky,
        "MANAGER_EXT_PORT": root.get("MANAGER_EXT_PORT", "8120"),
        "LOCAL_AI_STICKY": (
            ("true" if "localai" in profiles else "false") if config_seeded else ""
        ),
        "MANAGER_STICKY": (
            ("true" if "manager" in profiles else "false") if config_seeded else ""
        ),
        "AUTH_PROVIDER_STICKY": root.get("AUTH_PROVIDER", ""),
        "REVERSE_PROXY_PROVIDER_STICKY": root.get("REVERSE_PROXY_PROVIDER", ""),
        "NPM_ADMIN_HOST_STICKY": root.get("NPM_ADMIN_HOST", "") if config_seeded else "",
        "NPM_ADMIN_HOST_DERIVED": resolve.derive_npm_admin_host_default(
            app_host or "http://host.docker.internal",
            root.get("NPM_ADMIN_EXT_PORT", "8100"),
        ),
        "EXTERNAL_REVERSE_PROXY_STICKY": (
            "false" if "nginx" in profiles else ("true" if profiles else "")
        ),
        "WEB_SEARCH_STICKY": (
            (
                "true"
                if "librechat-websearch" in profiles
                or any(p in resolve._WEB_SEARCH_LEGACY_PROFILES for p in profiles)
                else "false"
            )
            if config_seeded
            else ""
        ),
        "RERANKER_MODEL_STICKY": reranker_model_sticky,
        "BACKUP_DIR_STICKY": root.get("PAPAIA_BACKUP_DIR", "") if config_seeded else "",
        "COMPOSE_PROFILES_STICKY": ",".join(profiles),
        "PLATFORM_VERSION": envtree.resolve_platform_version(repo_root),
        "CONFIG_SEEDED": "true" if config_seeded else "false",
    }
