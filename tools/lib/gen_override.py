"""Seam-1 (network) and auth-provider Docker Compose override generation.

For each active addon, attaches the core containers it declares to its
own bridge network via a generated override file at
$PAPAIA_CONFIG_DIR/overrides/docker-compose.<name>.override.yml. The core
compose itself is never mutated.

On the lean core, `deployment.yaml`'s `addons` list is always empty, so
`generate_overrides()` produces zero files -- a real, generically correct
no-op rather than a special case.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

from . import (
    audit,
    common,
    compat,
    deployment,
    egress,
    federation,
    gpu_detect,
    hosted_model,
    images,
    paperless_gate,
    sql_uplink,
)

# `${VAR}` / `${VAR:-default}` — the two interpolation forms an add-on's
# `networks.app_network` may use to scope its bridge name to the deployment
# (in practice `${PAPAIA_PROJECT:-papaia}-<name>-net`).
_ENV_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand_env_refs(value: str, env: dict[str, str]) -> str:
    """Resolve `${VAR}` / `${VAR:-default}` in *value* against *env*, matching
    docker compose interpolation: an unset or empty `VAR` falls back to the
    default (or "" when none is given). Text without a `${...}` match is
    returned untouched."""

    def repl(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        resolved = env.get(name) or ""
        if resolved:
            return resolved
        return default if default is not None else ""

    return _ENV_REF_RE.sub(repl, value)


def resolve_app_network(raw: str, config_dir: Path) -> str:
    """The add-on's Seam-1 network name with any deployment-scoping reference
    (`${PAPAIA_PROJECT:-papaia}-<name>-net`) resolved against the rendered core
    `.env`, so the generated override names the same bridge the add-on's own
    compose file creates. The same `.env` is passed to that compose file as an
    --env-file, so both sides read the identical value. A plain literal (no
    `${`) is returned unchanged, which keeps pre-templating manifests working."""
    if "${" not in raw:
        return raw
    return _expand_env_refs(raw, common.parse_env_file(config_dir / ".env"))


def generate_override(
    addon_manifest: dict, config_dir: Path, addon_path: Path | None = None
) -> Path | None:
    """Generate a single addon's network-attachment override.

    `addon_manifest` is the parsed papaia-app.yaml-shaped dict for one
    active addon, expected to carry:
        networks:
          app_network: papaia-<name>-net
          attach: [nginx, librechat, ...]

    Returns the written path, or None if the manifest declares no networks
    section (nothing to attach).
    """
    name = addon_manifest.get("name")
    networks = addon_manifest.get("networks") or {}
    app_network = networks.get("app_network")
    attach = list(networks.get("attach") or [])
    if _serves_ingress(addon_manifest, config_dir) and INGRESS_PROXY not in attach:
        # Generation 12: the bundled proxy reaches the interfaces of `integration.nginx`
        # on the add-on's network (lib/ingress.py), without the manifest attaching it.
        attach.append(INGRESS_PROXY)
    # Generation 16: the add-on's isolated networks, validated again here so that no
    # path around the compatibility check puts more than LiteLLM on one of them.
    isolated = _isolated_networks(addon_manifest, config_dir, addon_path)
    if name and isolated and not (app_network and attach):
        return _write_override(name, _with_isolated({"services": {}, "networks": {}}, isolated),
                               config_dir)
    if not name or not app_network or not attach:
        return None

    sealed = sorted(set(attach) & compat.NEVER_ATTACHABLE)
    if sealed:
        # The compatibility check refuses such an add-on; this keeps the override from
        # ever putting the audit database on an add-on network.
        raise ValueError(f"add-on '{name}' may not attach {', '.join(sealed)}")

    app_network = resolve_app_network(app_network, config_dir)

    override = {
        "services": {service: {"networks": [app_network]} for service in attach},
        "networks": {app_network: {"external": True}},
    }
    if name in paperless_gate.FRONT_SERVICES:
        # The add-on takes the person from a request header: only the proxy joins its
        # network. Every other core service it attaches (the chat service) joins the
        # front network instead, where only the add-on's MCP server is.
        # Without an MCP server in the add-on's compose file (`addon_path` given) there is
        # no front network, and those services are not attached at all.
        front = front_network_name(name, config_dir)
        has_front = addon_path is None or bool(_front_services(name, addon_path))
        services = {}
        for service in attach:
            if service in paperless_gate.PROXY_SERVICES:
                services[service] = {"networks": [app_network]}
            elif has_front:
                services[service] = {"networks": [front]}
            else:
                print(
                    f"WARNING: addon '{name}': '{service}' is not attached; the add-on has"
                    f" none of {', '.join(paperless_gate.FRONT_SERVICES[name])}",
                    file=sys.stderr,
                )
        override["services"] = services
        if any(body["networks"] == [front] for body in services.values()):
            override["networks"][front] = {"external": True}
        if not services and not isolated:
            (config_dir / "overrides" / f"docker-compose.{name}.override.yml").unlink(
                missing_ok=True
            )
            return None

    return _write_override(name, _with_isolated(override, isolated), config_dir)


def _write_override(name: str, override: dict, config_dir: Path) -> Path:
    out_path = config_dir / "overrides" / f"docker-compose.{name}.override.yml"
    common.atomic_write(
        out_path, yaml.safe_dump(override, sort_keys=False, default_flow_style=False)
    )
    return out_path


def _isolated_networks(
    addon_manifest: dict, config_dir: Path, addon_path: Path | None
) -> list[tuple[str, list[str]]]:
    """The add-on's `networks.isolated` entries (addon_api 16) with each network name
    resolved against the root .env, or [] when it declares none.

    Raises ValueError for every declaration the compatibility check refuses, and also
    when the add-on's directory is unknown: without its compose file, `internal: true`
    cannot be checked, and an isolated network with a route out is no isolation."""
    entries = compat.isolated_networks(addon_manifest)
    if not entries:
        return []
    name = addon_manifest.get("name")
    if addon_path is None:
        raise ValueError(
            f"add-on '{name}': networks.isolated needs the add-on's directory to check"
            " internal: true"
        )
    compat.check_isolated_internal(entries, addon_path)
    env = common.parse_env_file(config_dir / ".env")
    core = egress.core_networks(env)
    networks = addon_manifest.get("networks") or {}
    app_network = networks.get("app_network")
    own = resolve_app_network(app_network, config_dir) if isinstance(app_network, str) else None
    resolved: list[tuple[str, list[str]]] = []
    for index, (raw, attach) in enumerate(entries):
        network = resolve_app_network(raw, config_dir)
        if network in core:
            raise ValueError(
                f"add-on '{name}': networks.isolated[{index}].network {network!r} is"
                f" {core[network]}"
            )
        if network == own:
            raise ValueError(
                f"add-on '{name}': networks.isolated[{index}].network {network!r} is the"
                " add-on's app_network"
            )
        resolved.append((network, attach))
    return resolved


def _with_isolated(override: dict, isolated: list[tuple[str, list[str]]]) -> dict:
    """`override` with each isolated network joined by exactly its listed services, after
    the networks they already have here. Nothing else joins an isolated network."""
    for network, attach in isolated:
        for service in attach:
            body = override["services"].setdefault(service, {"networks": []})
            if network not in body["networks"]:
                body["networks"].append(network)
        override["networks"][network] = {"external": True}
    return override


# The bundled proxy's service in the core compose (src/infra/nginx/docker-compose.yml).
INGRESS_PROXY = "nginx-proxy-manager"


def _serves_ingress(addon_manifest: dict, config_dir: Path) -> bool:
    """Whether the bundled proxy serves this add-on's interfaces: ingress entries in
    the list form of generation 12, and the installation runs the bundled proxy."""
    nginx = (addon_manifest.get("integration") or {}).get("nginx")
    if not isinstance(nginx, list) or not nginx:
        return False
    provider = common.parse_env_file(config_dir / ".env").get("REVERSE_PROXY_PROVIDER")
    return (provider or "internal_nginx") == "internal_nginx"


def front_network_name(name: str, config_dir: Path) -> str:
    """The resolved name of the front network of a header-identity add-on."""
    return resolve_app_network(paperless_gate.front_network(name)[1], config_dir)


def has_front_network(name: str, addon_path: Path) -> bool:
    """Whether the add-on's project creates a front network (lib/paperless_gate.py)."""
    return bool(_front_services(name, addon_path))


def _front_services(name: str, addon_path: Path) -> list[str]:
    """The services of the add-on that join its front network: those of FRONT_SERVICES
    its compose file has."""
    compose = addon_path / "docker-compose.yml"
    if not compose.is_file():
        return []
    doc = yaml.safe_load(compose.read_text(encoding="utf-8")) or {}
    present = set((doc.get("services") or {}).keys())
    return [s for s in paperless_gate.FRONT_SERVICES.get(name, ()) if s in present]


def _write_front_override(name: str, active: bool, path: Path, config_dir: Path) -> None:
    """The add-on side of the front network: its MCP server joins a network the
    add-on's project creates, next to the networks it already has. Removed when the
    add-on is not active."""
    out_path = config_dir / "overrides" / "addons" / f"docker-compose.{name}-front.override.yml"
    services = _front_services(name, path) if active else []
    if not services:
        out_path.unlink(missing_ok=True)
        return
    key, _ = paperless_gate.front_network(name)
    override = {
        "services": {
            service: {"networks": [*_service_networks(path, service), key]} for service in services
        },
        "networks": {key: {"name": front_network_name(name, config_dir)}},
    }
    common.atomic_write(
        out_path, yaml.safe_dump(override, sort_keys=False, default_flow_style=False)
    )


def generate_overrides(config_dir: Path, repo_root: Path | None = None) -> list[Path]:
    """Read deployment.yaml's active addons and (re-)generate every
    Seam-1 override, plus the attachment of papaia-egress to each add-on's
    egress network (lib/egress.py) and, while the test stack's hosted model is on, the
    override that puts LiteLLM behind papaia-egress (lib/hosted_model.py).

    `repo_root` is used as the base when resolving relative addon paths
    from deployment.yaml (matching render_core.render's behaviour). When
    omitted, Path.cwd() is used — kept for backwards compatibility but
    callers should always supply repo_root.
    """
    # LiteLLM behind papaia-egress while the test stack's hosted model is on.
    hosted = hosted_model.generate_override(config_dir, repo_root)
    written: list[Path] = [hosted] if hosted is not None else []
    # papaia-audit behind papaia-egress while a SIEM target is set (lib/audit.py).
    siem = audit.generate_siem_override(config_dir)
    if siem is not None:
        written.append(siem)
    # papaia-lifecycle behind papaia-egress while the federation's status sync is on.
    federated = federation.generate_override(
        config_dir, repo_root if repo_root is not None else Path.cwd()
    )
    if federated is not None:
        written.append(federated)
    deployed = deployment.load(config_dir)
    if not deployed:
        return written

    base = repo_root if repo_root is not None else Path.cwd()
    _check_isolated_claims(deployed, base, config_dir)
    for addon in deployment.active_addons(deployed):
        addon_path = deployment.resolve_addon_path(addon, base)
        manifest, _ = deployment.load_addon_manifest(addon_path)
        if manifest is None:
            continue
        result = generate_override(manifest, config_dir, addon_path)
        if result is not None:
            written.append(result)
    written.extend(egress.generate_overrides(config_dir, base))
    return written


def _check_isolated_claims(deployed: dict, base: Path, config_dir: Path) -> None:
    """An isolated network (addon_api 16) belongs to one add-on: refuse the render when
    the isolated network of an active add-on is a network another add-on (active or not)
    names. The scope prefix alone does not ensure it: `papaia-a-b-net` is scoped to both
    `a` and `a-b`."""
    claims: list[tuple[str, str, str]] = []
    for addon in deployed.get("addons") or []:
        if not addon.get("path"):
            continue
        manifest, _ = deployment.load_addon_manifest(deployment.resolve_addon_path(addon, base))
        if manifest is not None:
            claims.extend(
                (network, owner, kind, bool(addon.get("active")))
                for network, owner, kind in egress.claims_of(
                    manifest, str(addon.get("name")), config_dir
                )
            )
    for network, owner, kind, active in claims:
        if not active or kind != "isolated network":
            continue
        for other_network, other, other_kind, _ in claims:
            if other_network == network and other != owner:
                raise ValueError(
                    f"add-on '{owner}': networks.isolated: {network!r} is also the"
                    f" {other_kind} of add-on '{other}'"
                )


def external_networks(override_path: Path) -> list[str]:
    """The names of all `external: true` networks declared in one override
    file. The bash dispatcher uses this to skip overrides whose addon
    networks don't exist yet (the addon isn't running)."""
    if not override_path.is_file():
        return []
    doc = yaml.safe_load(override_path.read_text(encoding="utf-8")) or {}
    return [
        name
        for name, cfg in (doc.get("networks") or {}).items()
        if (cfg or {}).get("external")
    ]


def _service_networks(addon_path: Path, service: str) -> list[str]:
    """The networks `service` already joins in the addon's own compose file, or
    ["default"] when it names none. A compose `networks:` override replaces the
    service's list, so the join override has to repeat them."""
    compose = addon_path / "docker-compose.yml"
    if not compose.is_file():
        return ["default"]
    doc = yaml.safe_load(compose.read_text(encoding="utf-8")) or {}
    networks = ((doc.get("services") or {}).get(service) or {}).get("networks")
    if isinstance(networks, dict):
        return list(networks) or ["default"]
    if isinstance(networks, list):
        return [n for n in networks if isinstance(n, str)] or ["default"]
    return ["default"]


def generate_addon_join_overrides(config_dir: Path, repo_root: Path) -> None:
    """Write or remove each addon's `networks.join_addons` override.

    For an active addon that declares

        networks:
          join_addons:
            - addon: <required addon>
              services: [<service>, ...]

    the listed services join the required addon's resolved `app_network`
    (declared external); every other service of the addon stays off it. The
    file lives in overrides/addons/ and is applied to the addon's own compose
    project by `papaia-ctl addon start`, like the ssl-cert overrides.
    """
    deployed = deployment.load(config_dir)
    entries = deployed.get("addons") or [] if deployed else []
    manifests: dict[str, tuple[dict, Path]] = {}
    for addon in entries:
        if not addon.get("name") or not addon.get("path"):
            continue
        path = deployment.resolve_addon_path(addon, repo_root)
        manifest, _ = deployment.load_addon_manifest(path)
        if manifest is not None:
            manifests[addon["name"]] = (manifest, path)

    for addon in entries:
        name = addon.get("name")
        if not name:
            continue
        manifest, path = manifests.get(name, ({}, Path()))
        if name in paperless_gate.FRONT_SERVICES:
            _write_front_override(name, bool(addon.get("active")), path, config_dir)
        out_path = config_dir / "overrides" / "addons" / f"docker-compose.{name}-join.override.yml"
        try:
            joins = compat.joined_addons(manifest) if addon.get("active") else []
        except ValueError:
            joins = []  # the compatibility gate reports the malformed manifest
        services: dict[str, list[str]] = {}
        external: dict[str, dict] = {}
        for target, joining in joins:
            target_manifest = manifests.get(target, ({}, Path()))[0]
            raw = (target_manifest.get("networks") or {}).get("app_network")
            if not raw:
                print(
                    f"WARNING: addon '{name}': '{target}' declares no networks.app_network;"
                    " join_addons entry skipped",
                    file=sys.stderr,
                )
                continue
            network = resolve_app_network(raw, config_dir)
            external[network] = {"external": True}
            for service in joining:
                current = services.setdefault(service, _service_networks(path, service))
                if network not in current:
                    current.append(network)
        if not services:
            out_path.unlink(missing_ok=True)
            continue
        override = {
            "services": {service: {"networks": nets} for service, nets in services.items()},
            "networks": external,
        }
        common.atomic_write(
            out_path, yaml.safe_dump(override, sort_keys=False, default_flow_style=False)
        )
    # The direct route of `mcp-mssql` to the SQL source (lib/sql_uplink.py), also an
    # override of the add-on's own project.
    sql_uplink.generate_override(config_dir, repo_root)
    generate_addon_logging_overrides(config_dir, repo_root)


# Log rotation of every container (BE-27): the core fragments set it per service; an
# add-on's compose file is not the core's to change, so its project gets this override.
LOGGING = {"driver": "json-file", "options": {"max-size": "10m", "max-file": "5"}}


def _addon_services(addon_path: Path) -> list[str]:
    try:
        document = yaml.safe_load((addon_path / "docker-compose.yml").read_text("utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    services = (document or {}).get("services") if isinstance(document, dict) else None
    return [str(name) for name in services] if isinstance(services, dict) else []


def generate_addon_logging_overrides(config_dir: Path, repo_root: Path) -> None:
    """Write `docker-compose.<name>-logging.override.yml` for every active add-on (the
    rotation of every one of its services) and remove it for every other one; `addon
    start` applies it to the add-on's project like the other files in overrides/addons/."""
    deployed = deployment.load(config_dir)
    for addon in deployed.get("addons") or [] if deployed else []:
        name = addon.get("name")
        if not name:
            continue
        out_path = (
            config_dir / "overrides" / "addons" / f"docker-compose.{name}-logging.override.yml"
        )
        services = (
            _addon_services(deployment.resolve_addon_path(addon, repo_root))
            if addon.get("active") and addon.get("path") else []
        )
        if not services:
            out_path.unlink(missing_ok=True)
            continue
        override = {"services": {service: {"logging": LOGGING} for service in services}}
        common.atomic_write(
            out_path, yaml.safe_dump(override, sort_keys=False, default_flow_style=False)
        )


# Services that mount the local Keycloak CA cert via SSL_CERT_FILE.  For
# external OIDC the cert file is absent, so SSL_CERT_FILE must be cleared to
# let Python's ssl module fall back to the system CA bundle.
_SSL_CERT_SERVICES = (
    "litellm",
    "oauth2-proxy",
    "localai",
    "papaia-manager",
    "qdrant-mcp",
    "qdrant-ingest",
    "knowledge-map-mcp",
    "me-web",
    "prefs",
    "connections",
)


def _load_addon_local_ca_env(addon: dict, repo_root: Path) -> dict:
    """Return the manifest's local_ca_env mapping (service -> list of env
    vars) for one deployment.yaml addon entry, or {} when the manifest is
    missing or declares none."""
    if not addon.get("path"):
        return {}
    manifest, _ = deployment.load_addon_manifest(deployment.resolve_addon_path(addon, repo_root))
    if manifest is None:
        return {}
    return manifest.get("local_ca_env") or {}


def generate_addon_ssl_cert_overrides(
    config_dir: Path, auth_provider: str, repo_root: Path
) -> None:
    """Write or remove the per-addon SSL cert overrides for external OIDC.

    Addons whose services mount the bundled Keycloak CA cert declare the
    affected env vars in their manifest:

        local_ca_env:
          <service>: [REQUESTS_CA_BUNDLE, ...]

    With external OIDC, certs/ is empty — those vars must be cleared so
    requests/httpx fall back to the system CA bundle instead of failing on
    the absent local-ca.crt.  The files live in overrides/addons/ so the
    core compose loop (which globs overrides/docker-compose.*.override.yml)
    does not pick them up; `papaia-ctl addon start` instead applies the
    files there that `py_cli addon-override-files` attributes to the addon
    being started.
    """
    deployed = deployment.load(config_dir)

    for addon in deployed.get("addons") or []:
        name = addon.get("name")
        if not name:
            continue
        out_path = (
            config_dir / "overrides" / "addons" / f"docker-compose.{name}-ssl-cert.override.yml"
        )
        local_ca_env = _load_addon_local_ca_env(addon, repo_root)
        if not addon.get("active") or auth_provider != "external_oidc" or not local_ca_env:
            out_path.unlink(missing_ok=True)
            continue

        override = {
            "services": {
                service: {
                    "environment": {
                        var: ""
                        for var in ([env] if isinstance(env, str) else env)
                    }
                }
                for service, env in local_ca_env.items()
            }
        }
        common.atomic_write(
            out_path, yaml.safe_dump(override, sort_keys=False, default_flow_style=False)
        )


_LOCALAI_COMPOSE = "src/ai/localai/docker-compose.yml"


def _localai_base_image(repo_root: Path) -> tuple[str, str] | None:
    """The (name, version) of the LocalAI image pinned in the core compose file.

    The version is never persisted to the config dir: reading it back here on
    every run means a release that bumps the pin carries straight through to the
    native LocalAI, instead of a stale version surviving `papaia-ctl upgrade`
    via sticky reuse. The accelerator images have their own pins
    (_localai_gpu_images).
    """
    try:
        doc = yaml.safe_load((repo_root / _LOCALAI_COMPOSE).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return None
    image = ((doc.get("services") or {}).get("localai") or {}).get("image")
    if not isinstance(image, str):
        return None
    # `name:tag@sha256:...`: the version is the tag.
    image = image.partition("@")[0]
    name, sep, version = image.rpartition(":")
    # No separator, or a colon that belongs to a registry:port rather than a
    # tag -- an unpinned image cannot be rewritten into a variant.
    if not sep or "/" in version:
        return None
    return name, version


def _localai_gpu_images(repo_root: Path) -> dict[str, str]:
    """The accelerator image per LocalAI variant, pinned with its digest in the core
    compose file next to the CPU image and read back on every render."""
    try:
        doc = yaml.safe_load((repo_root / _LOCALAI_COMPOSE).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    pinned = doc.get("x-papaia-localai-gpu-images")
    if not isinstance(pinned, dict):
        return {}
    return {k: v for k, v in pinned.items() if isinstance(v, str)}


def generate_localai_gpu_override(
    config_dir: Path,
    repo_root: Path,
    variant: str,
    dev_root: Path = Path("/dev"),
    mirror: str = "",
) -> None:
    """Write or remove the LocalAI accelerator override.

    CPU is the image pinned in the core compose file, so it needs no override
    at all -- the file is removed instead, which is also what makes switching
    a host back from GPU to CPU actually take effect.
    """
    out_path = config_dir / "overrides" / "docker-compose.localai-gpu.override.yml"

    suffix = gpu_detect.TAG_SUFFIX.get(variant)
    image = _localai_gpu_images(repo_root).get(variant) if suffix else None
    if not suffix or image is None:
        out_path.unlink(missing_ok=True)
        return

    service: dict = {"image": mirror + image}
    service.update(gpu_detect.compose_fragment(variant, dev_root))

    override = {"services": {"localai": service}}
    common.atomic_write(
        out_path, yaml.safe_dump(override, sort_keys=False, default_flow_style=False)
    )


LOCALAI_RUNTIME_OVERRIDE = "docker-compose.localai-runtime.override.yml"


def generate_localai_runtime_override(config_dir: Path, runtime: str, home: Path | None) -> None:
    """Write or remove the override of the native LocalAI runtime (ADR 0012).

    The services stay declared, because the add-on contract pins `localai` and
    `localai-model-init` (ATTACHABLE_SERVICES): `localai` gets no container (`replicas: 0`)
    and is never pulled (`pull_policy: never`; `replicas: 0` alone still pulls the
    multi-GB image), and the init job writes the models into the host directory the
    native process reads, instead of the `localai-models` volume. Removed for `container`,
    which is what brings the container back."""
    out_path = config_dir / "overrides" / LOCALAI_RUNTIME_OVERRIDE
    if runtime != "native" or home is None:
        out_path.unlink(missing_ok=True)
        return
    override = {
        "services": {
            "localai": {"pull_policy": "never", "deploy": {"replicas": 0}},
            "localai-model-init": {
                "volumes": [
                    {
                        "type": "bind",
                        "source": str(home / "models"),
                        "target": "/models",
                        "bind": {"create_host_path": True},
                    }
                ]
            },
        }
    }
    common.atomic_write(
        out_path, yaml.safe_dump(override, sort_keys=False, default_flow_style=False)
    )


_VOICE_COMPOSE = "src/ai/voice/docker-compose.yml"

# voice variant id -> gpu_detect variant whose Compose device fragment applies.
# The voice catalogue is shorter than LocalAI's because upstream publishes
# fewer accelerator builds (see the x-papaia-voice-tts-gpu-images mapping).
_VOICE_VARIANT_FRAGMENT = {
    "nvidia": gpu_detect.NVIDIA_CUDA_12,
    "hipblas": gpu_detect.HIPBLAS,
}


def _voice_gpu_images(repo_root: Path) -> dict[str, str]:
    """The accelerator image per voice variant, pinned in the voice compose file.

    Read back on every render for the same reason as _localai_base_image: a
    release that bumps the pins must carry through without a stale image
    surviving in the generated override."""
    try:
        doc = yaml.safe_load((repo_root / _VOICE_COMPOSE).read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return {}
    images = doc.get("x-papaia-voice-tts-gpu-images")
    if not isinstance(images, dict):
        return {}
    return {k: v for k, v in images.items() if isinstance(v, str)}


def generate_voice_gpu_override(
    config_dir: Path,
    repo_root: Path,
    variant: str,
    dev_root: Path = Path("/dev"),
    mirror: str = "",
) -> None:
    """Write or remove the voice TTS accelerator override.

    CPU is the image pinned in the voice compose file, so it needs no override
    at all -- the file is removed instead, which is also what makes switching
    a host back from GPU to CPU actually take effect."""
    out_path = config_dir / "overrides" / "docker-compose.voice-gpu.override.yml"

    # cpu (and anything unknown) short-circuits before the compose file is
    # parsed, like the LocalAI counterpart above.
    fragment_variant = _VOICE_VARIANT_FRAGMENT.get(variant) if variant else None
    if fragment_variant is None:
        out_path.unlink(missing_ok=True)
        return
    image = _voice_gpu_images(repo_root).get(variant)
    if image is None:
        out_path.unlink(missing_ok=True)
        return

    # The accelerator images are published for linux/amd64, same as the CPU
    # build, so the platform pin of the base service stays correct.
    service: dict = {"image": mirror + image}
    service.update(gpu_detect.compose_fragment(fragment_variant, dev_root))

    override = {"services": {"chatterbox": service}}
    common.atomic_write(
        out_path, yaml.safe_dump(override, sort_keys=False, default_flow_style=False)
    )


IMAGE_MIRROR_OVERRIDE = "docker-compose.image-mirror.override.yml"
_IMAGE_VARIANT_OVERRIDES = (
    "docker-compose.localai-gpu.override.yml",
    "docker-compose.voice-gpu.override.yml",
)


def generate_image_mirror_override(config_dir: Path, repo_root: Path, mirror: str) -> None:
    """Write or remove the override that pulls every core image through a mirror.

    Each service gets `<mirror><image>`, its pinned reference behind the mirror's
    prefix; digests stay the same, so the image check still applies. A service an
    accelerator override replaces gets that override's image, so the result does not
    depend on the order in which Compose reads the override files. Run after the
    accelerator overrides; they put the same prefix in front of their own image."""
    out_path = config_dir / "overrides" / IMAGE_MIRROR_OVERRIDE
    if not mirror:
        out_path.unlink(missing_ok=True)
        return
    images.validate_mirror(mirror)
    chosen = images.compose_services(repo_root)
    for name in _IMAGE_VARIANT_OVERRIDES:
        path = config_dir / "overrides" / name
        if not path.is_file():
            continue
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for service, body in (doc.get("services") or {}).items():
            if isinstance(body, dict) and isinstance(body.get("image"), str):
                chosen[service] = body["image"].removeprefix(mirror)
    override = {
        "services": {
            service: {"image": mirror + image} for service, image in sorted(chosen.items())
        }
    }
    common.atomic_write(
        out_path, yaml.safe_dump(override, sort_keys=False, default_flow_style=False)
    )


def generate_ssl_cert_override(config_dir: Path, auth_provider: str) -> None:
    """Write or remove the SSL_CERT_FILE override for external OIDC.

    With external OIDC, $PAPAIA_CONFIG_DIR/certs/ is empty (the local CA cert
    is only generated for bundled Keycloak).  Setting SSL_CERT_FILE to an empty
    string is falsy in Python's ssl.create_default_context, so it skips
    load_verify_locations and uses system CAs instead of crashing on the
    missing file path.
    """
    out_path = config_dir / "overrides" / "docker-compose.ssl-cert.override.yml"
    if auth_provider != "external_oidc":
        out_path.unlink(missing_ok=True)
        return

    override = {
        "services": {
            svc: {"environment": {"SSL_CERT_FILE": ""}}
            for svc in _SSL_CERT_SERVICES
        }
    }
    common.atomic_write(
        out_path, yaml.safe_dump(override, sort_keys=False, default_flow_style=False)
    )
