"""Shared builders for the status and doctor tests.

A synthetic papAIa checkout (core Compose fragments), a config directory and one
active add-on, all in tmp_path, plus a stand-in for the `docker` binary. The
shared `fixtures/repo` carries no `de.fidonis.*` labels and is pinned by
test_contract_surface, so it is not used here.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import yaml

from lib.status import CommandResult

NOW = datetime(2026, 9, 27, 10, 15, 0, tzinfo=timezone.utc)

PROJECT = "papaia"


def ps_line(
    name: str,
    state: str,
    status_text: str,
    service: str,
    module: str = "",
    role: str = "",
    *,
    project: str = PROJECT,
    ports: str = "",
) -> str:
    return "\t".join(
        [name, state, status_text, project, service, module, role, ports],
    )


class FakeDocker:
    """Stands in for `docker`: answers ps/inspect/version/compose/info with
    canned text and records every call."""

    def __init__(
        self,
        ps: list[str] | None = None,
        *,
        ps_result: CommandResult | None = None,
        policies: dict[str, str] | None = None,
        engine: CommandResult | None = None,
        compose: CommandResult | None = None,
        root_dir: str = "",
    ):
        self.ps_result = ps_result or CommandResult(0, "\n".join(ps or []) + "\n", "")
        self.policies = policies or {}
        self.engine = engine or CommandResult(0, "27.0.3\n", "")
        self.compose = compose or CommandResult(0, "2.29.1\n", "")
        self.root_dir = root_dir
        self.calls: list[list[str]] = []

    def __call__(self, cmd, timeout):
        cmd = list(cmd)
        self.calls.append(cmd)
        if cmd[:3] == ["docker", "ps", "-a"]:
            return self.ps_result
        if cmd[:2] == ["docker", "inspect"]:
            names = [n for n in cmd if n in self.policies]
            return CommandResult(0, "".join(f"/{n}\t{self.policies[n]}\n" for n in names), "")
        if cmd[:2] == ["docker", "version"]:
            return self.engine
        if cmd[:3] == ["docker", "compose", "version"]:
            return self.compose
        if cmd[:2] == ["docker", "info"]:
            if self.root_dir:
                return CommandResult(0, self.root_dir + "\n", "")
            return CommandResult(1, "", "no data root")
        raise AssertionError(f"unexpected command: {cmd}")


def _write_yaml(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def _service(profile: str | None, module: str, role: str, ports: list[str] | None = None) -> dict:
    body: dict = {"image": "example/image:1"}
    if profile:
        body["profiles"] = [profile]
    if module:
        body["labels"] = {"de.fidonis.module": module, "de.fidonis.role": role}
    if ports:
        body["ports"] = ports
    return body


def build_stack(tmp_path: Path) -> dict[str, Path]:
    """A synthetic repo (core fragments), config dir and one active add-on."""
    repo = tmp_path / "repo"
    (repo / "VERSION").parent.mkdir(parents=True)
    (repo / "VERSION").write_text("1.3.0\n", encoding="utf-8")
    src = repo / "src"
    _write_yaml(
        src / "docker-compose.yml",
        {
            "include": [
                {"path": "./infra/keycloak/docker-compose.yml"},
                "./infra/oauth2-proxy/docker-compose.yml",
                {"path": "./search/docker-compose.yml"},
                {"path": "./ai/localai/docker-compose.yml"},
            ]
        },
    )
    _write_yaml(
        src / "infra" / "keycloak" / "docker-compose.yml",
        {
            "services": {
                "keycloak": _service(
                    "keycloak",
                    "papaia-keycloak",
                    "identity-provider",
                    ["${HOST_IP:-0.0.0.0}:${KEYCLOAK_EXT_PORT}:8443"],
                ),
                "keycloak-db": _service("keycloak", "papaia-keycloak", "database"),
            }
        },
    )
    _write_yaml(
        src / "infra" / "oauth2-proxy" / "docker-compose.yml",
        {"services": {"oauth2-proxy": _service("oauth2-proxy", "papaia-auth", "forward-auth")}},
    )
    _write_yaml(
        src / "search" / "docker-compose.yml",
        {
            "services": {
                "firecrawl-api": _service("librechat-websearch", "papaia-firecrawl", "web-crawler"),
                "searxng": _service("librechat-websearch", "papaia-searxng", "search-engine"),
            }
        },
    )
    _write_yaml(
        src / "ai" / "localai" / "docker-compose.yml",
        {
            "services": {
                "localai-model-init": _service("localai", "papaia-localai", "model-init"),
                "localai": _service("localai", "papaia-localai", "inference-engine"),
            }
        },
    )

    addon = tmp_path / "addons" / "paperless"
    _write_yaml(
        addon / "docker-compose.yml",
        {"services": {"paperless": {"image": "x"}, "paperless-db": {"image": "x"}}},
    )
    (addon / "papaia-app.yaml").write_text(
        'name: paperless\npapaia_compat: ">=1.0.0"\n', encoding="utf-8"
    )

    config = tmp_path / "papaia-config"
    config.mkdir()
    (config / ".env").write_text(
        f"COMPOSE_PROJECT_NAME={PROJECT}\n"
        "COMPOSE_PROFILES=keycloak,oauth2-proxy,librechat-websearch\n"
        "HOST_IP=0.0.0.0\n"
        "KEYCLOAK_EXT_PORT=8110\n",
        encoding="utf-8",
    )
    _write_yaml(
        config / "deployment.yaml",
        {
            "platform_version": "1.3.0",
            "core": {"profiles": ["keycloak", "oauth2-proxy", "librechat-websearch"]},
            "addons": [
                {"name": "paperless", "path": str(addon), "active": True},
                {"name": "dormant", "path": str(tmp_path / "addons" / "dormant"), "active": False},
            ],
        },
    )
    return {"repo": repo, "config": config, "addon": addon}


def healthy_core() -> list[str]:
    return [
        ps_line(
            "papaia-keycloak-1",
            "running",
            "Up 2 hours (healthy)",
            "keycloak",
            "papaia-keycloak",
            "identity-provider",
            ports="0.0.0.0:8110->8443/tcp, :::8110->8443/tcp",
        ),
        ps_line(
            "papaia-keycloak-db-1",
            "running",
            "Up 2 hours (healthy)",
            "keycloak-db",
            "papaia-keycloak",
            "database",
        ),
        ps_line(
            "papaia-oauth2-proxy-1",
            "running",
            "Up 2 hours",
            "oauth2-proxy",
            "papaia-auth",
            "forward-auth",
        ),
        ps_line(
            "papaia-firecrawl-api-1",
            "running",
            "Up 2 hours",
            "firecrawl-api",
            "papaia-firecrawl",
            "web-crawler",
        ),
        ps_line(
            "papaia-searxng-1",
            "running",
            "Up 2 hours (healthy)",
            "searxng",
            "papaia-searxng",
            "search-engine",
        ),
    ]


def healthy_addon() -> list[str]:
    return [
        ps_line(
            "paperless-paperless-1",
            "running",
            "Up 1 hour (healthy)",
            "paperless",
            project="paperless",
        ),
        ps_line(
            "paperless-paperless-db-1",
            "running",
            "Up 1 hour (healthy)",
            "paperless-db",
            project="paperless",
        ),
    ]
