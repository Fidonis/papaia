"""The model gateway with real containers (PLT-41-A1 with a stand-in model, PLT-67).

A configuration set up with `--local-ai` is rendered as `papaia-ctl` renders it: the
named default model routes to the `localai` service, and the aliases point at it. The
pinned LiteLLM and its database start with that configuration; a small OpenAI-compatible
server stands in for LocalAI under its service name, so no model has to be downloaded.
Then:

* a module gets its own key through the core (`lib.model_gateway`), and with that key
  `GET /v1/models` lists the aliases only and a minimal chat request to an alias returns
  200 with an answer; the model itself is refused;
* a marker sent in that request is found nowhere in the gateway's database (dump and
  data files) or its log, while the usage of the module key is counted, without a
  person;
* the gateway mounts the folder of the platform halt as the shipped Compose file does;
  with the halt set, the module key is refused with `platform_halt`, and served again
  once it is lifted;
* revoking the key writes `key_revoke` into the erasure journal `model-gateway`, and
  the key stops working.

Needs Docker; skipped without it. The Compose project and the address range can be set
with PAPAIA_MODEL_GATEWAY_TEST_PROJECT and PAPAIA_MODEL_GATEWAY_TEST_SUBNET so the test
does not collide with other stacks on the same host. Nothing is published on the host.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import secrets
import shutil
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from lib import common, envtree, halt, model_gateway, render_core, resolve
from lib import secrets as core_secrets

REPO = Path(__file__).resolve().parents[2]
LITELLM_COMPOSE = REPO / "src" / "ai" / "litellm" / "docker-compose.yml"
PROJECT = os.environ.get("PAPAIA_MODEL_GATEWAY_TEST_PROJECT", "papaia-model-gateway-test")
SUBNET = ipaddress.ip_network(
    os.environ.get("PAPAIA_MODEL_GATEWAY_TEST_SUBNET", "10.250.79.0/24")
)
MODULE = "probe"
# Where papaia_hooks looks for the halt file.
HALT_MOUNT = "/run/papaia-halt"
MARKER = "MARK-" + secrets.token_hex(8)


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


pytestmark = pytest.mark.skipif(not _docker_available(), reason="Docker is not available")

# Stands in for LocalAI: answers every chat request with a fixed text, and only with
# the key LiteLLM is configured to send (LOCALAI_API_KEY).
_LOCALAI = (
    "import http.server,json,os,time\n"
    "class H(http.server.BaseHTTPRequestHandler):\n"
    "    def do_POST(self):\n"
    "        self.rfile.read(int(self.headers.get('Content-Length','0')))\n"
    "        if self.headers.get('Authorization')!='Bearer '+os.environ['LOCALAI_API_KEY']:\n"
    "            self.send_response(401);self.end_headers();return\n"
    "        body=json.dumps({'id':'c','object':'chat.completion','created':int(time.time()),\n"
    "            'model':'local','choices':[{'index':0,'finish_reason':'stop',\n"
    "            'message':{'role':'assistant','content':'pong'}}],\n"
    "            'usage':{'prompt_tokens':3,'completion_tokens':1,'total_tokens':4}}).encode()\n"
    "        self.send_response(200);self.send_header('Content-Type','application/json')\n"
    "        self.send_header('Content-Length',str(len(body)));self.end_headers()\n"
    "        self.wfile.write(body)\n"
    "    def log_message(self,*a):pass\n"
    "http.server.ThreadingHTTPServer(('',8080),H).serve_forever()\n"
)

# Runs inside the LiteLLM container as a module would call it: the module key comes in on
# stdin with the request; prints {"status", "body"}.
_MODULE_CALL = (
    "import json,sys,urllib.request,urllib.error\n"
    "r=json.load(sys.stdin)\n"
    "data=None if r['body'] is None else json.dumps(r['body']).encode()\n"
    "q=urllib.request.Request('http://127.0.0.1:4000'+r['path'],data=data,method=r['method'],\n"
    "  headers={'Authorization':'Bearer '+r['key'],'Content-Type':'application/json'})\n"
    "o=urllib.request.build_opener(urllib.request.ProxyHandler({}))\n"
    "try:\n"
    "  with o.open(q,timeout=60) as s: st,b=s.status,s.read()\n"
    "except urllib.error.HTTPError as e: st,b=e.code,e.read()\n"
    "print(json.dumps({'status':st,'body':b.decode('utf-8','replace')}))\n"
)


def _run(*args: str, stdin: str | None = None, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(args), input=stdin, capture_output=True, text=True, timeout=300, check=check
    )


def _install_localai(repo_root: Path) -> None:
    target = repo_root / "src" / "ai" / "localai"
    for path in (REPO / "src" / "ai" / "localai" / "models").glob("*.yaml"):
        shutil.copy(path, target / "models" / path.name)
    shutil.copy(REPO / "src" / "ai" / "localai" / "models.txt", target / "models.txt")
    root = repo_root / "src" / "docker-compose.yml"
    doc = yaml.safe_load(root.read_text(encoding="utf-8")) or {}
    doc.setdefault("include", []).append({"path": "./ai/localai/docker-compose.yml"})
    root.write_text(yaml.safe_dump(doc), encoding="utf-8")
    # The shipped gateway configuration, not the fixture's.
    shutil.copy(REPO / "src/ai/litellm/config.yaml", repo_root / "src/ai/litellm/config.yaml")


def _set_up_with_local_ai(repo_root: Path, config_dir: Path, backup: Path) -> None:
    """`papaia-ctl setup --local-ai` as far as the gateway is concerned, then the render."""
    envtree.init(config_dir, repo_root, env_name="papaia")
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    tree = core_secrets.generate_missing_secrets(tree, envtree.load_seed_tree(repo_root))
    args = resolve.SetupArgs(
        config_dir=config_dir,
        app_host="http://host.docker.internal",
        non_interactive=True,
        enable_local_ai=True,
    )
    tree = resolve.resolve_hostnames(tree, args)
    tree = resolve.resolve_multi_env(tree, args)
    tree = resolve.resolve_reverse_proxy(tree, args)
    tree = resolve.resolve_local_ai(tree, args)
    tree = resolve.resolve_localai_variant(tree, args)
    tree = resolve.resolve_default_model(tree, args)
    root = tree[""]
    root["COMPOSE_PROJECT_NAME"] = PROJECT
    root["COMPOSE_PROFILES"] = root["COMPOSE_PROFILES"] + ",lifecycle"
    root["PAPAIA_BACKUP_DIR"] = str(backup)
    envtree.persist_tree(tree, config_dir, repo_root)
    render_core.render(config_dir, repo_root)


def _halt_mount(real: dict, config_dir: Path) -> dict:
    """The shipped bind of the halt folder, pointed at the test's configuration. Without
    it the hook fails closed and refuses every request (docs/halt.md)."""
    (mount,) = [
        m for m in real["litellm"]["volumes"]
        if isinstance(m, dict) and m.get("target") == HALT_MOUNT
    ]  # fmt: skip
    prefix = "${PAPAIA_CONFIG_DIR}/"
    assert mount["source"].startswith(prefix), mount
    return {**mount, "source": str(config_dir / mount["source"][len(prefix):])}


def _compose_file(tmp_path: Path, config_dir: Path, master_key: str, local_key: str) -> Path:
    real = yaml.safe_load(LITELLM_COMPOSE.read_text(encoding="utf-8"))["services"]
    environment = {
        k: v for k, v in real["litellm"]["environment"].items() if k != "SSL_CERT_FILE"
    }
    environment.update(
        DATABASE_URL="postgresql://llmproxy:test-db-password@litellm-db:5432/litellm",
        LITELLM_MASTER_KEY=master_key,
        LITELLM_SALT_KEY="sk-" + secrets.token_hex(16),
        LOCALAI_API_KEY=local_key,
    )
    (tmp_path / "localai.py").write_text(_LOCALAI, encoding="utf-8")
    doc = {
        "name": PROJECT,
        "services": {
            "litellm": {
                "image": real["litellm"]["image"],
                "environment": environment,
                "command": ["--config=/app/config.yaml"],
                "volumes": [
                    f"{config_dir / 'ai/litellm/config.yaml'}:/app/config.yaml:ro",
                    f"{REPO / 'src/ai/litellm/papaia_hooks.py'}:/app/papaia_hooks.py:ro",
                    _halt_mount(real, config_dir),
                ],
                "depends_on": {"litellm-db": {"condition": "service_healthy"}},
            },
            "litellm-db": {
                "image": real["litellm-db"]["image"],
                "environment": {
                    "POSTGRES_DB": "litellm",
                    "POSTGRES_USER": "llmproxy",
                    "POSTGRES_PASSWORD": "test-db-password",
                },
                "volumes": ["litellm-postgresql:/var/lib/postgresql/data"],
                "healthcheck": real["litellm-db"]["healthcheck"],
            },
            "localai": {
                "image": "python:3.12.16-slim-trixie@sha256:5e2bdb1b0d542d5039cffb8181c65930"
                "093949194a65c365dfb1b0fe13a4fa5b",
                "environment": {"LOCALAI_API_KEY": local_key},
                "volumes": [f"{tmp_path / 'localai.py'}:/localai.py:ro"],
                "command": ["python", "-I", "/localai.py"],
            },
        },
        "networks": {
            "default": {
                "name": f"{PROJECT}-net",
                "internal": True,
                "ipam": {"config": [{"subnet": str(SUBNET)}]},
            }
        },
        "volumes": {"litellm-postgresql": {"name": f"{PROJECT}-litellm-postgresql"}},
    }
    path = tmp_path / "compose.yml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


@pytest.fixture
def gateway(tmp_path, repo_root, config_dir):
    backup = tmp_path / "backup"
    backup.mkdir()
    _install_localai(repo_root)
    _set_up_with_local_ai(repo_root, config_dir, backup)
    (config_dir / "addons" / MODULE).mkdir(parents=True)
    (config_dir / "addons" / MODULE / ".env").write_text("PROBE=1\n", encoding="utf-8")
    compose = _compose_file(tmp_path, config_dir, "sk-" + secrets.token_hex(16),
                            secrets.token_hex(16))
    base = ["docker", "compose", "-p", PROJECT, "-f", str(compose)]
    try:
        _run(*base, "up", "-d", "--wait", "litellm-db", "localai")
        _run(*base, "up", "-d", "litellm")
        yield {"config_dir": config_dir, "repo_root": repo_root, "backup": backup,
               "compose": base}
    finally:
        _run(*base, "down", "-v", "--remove-orphans", check=False)


def _container(service: str) -> str:
    out = _run(
        "docker", "ps", "-q",
        "--filter", f"label=com.docker.compose.project={PROJECT}",
        "--filter", f"label=com.docker.compose.service={service}",
    ).stdout.split()  # fmt: skip
    assert len(out) == 1, out
    return out[0]


def _as_module(key: str, method: str, path: str, body: object = None) -> tuple[int, str]:
    request = json.dumps({"key": key, "method": method, "path": path, "body": body})
    result = _run("docker", "exec", "-i", _container("litellm"), "python", "-I", "-c",
                  _MODULE_CALL, stdin=request)
    doc = json.loads(result.stdout.strip().splitlines()[-1])
    return doc["status"], doc["body"]


def _chat_until(key: str, chat: dict, wanted: int, within: float = 60) -> tuple[int, str]:
    deadline = time.monotonic() + within
    while True:
        status, body = _as_module(key, "POST", "/v1/chat/completions", chat)
        if status == wanted or time.monotonic() > deadline:
            return status, body
        time.sleep(2)


def _psql(sql: str) -> str:
    return _run("docker", "exec", _container("litellm-db"), "psql", "-U", "llmproxy",
                "-d", "litellm", "-Atc", sql).stdout.strip()


def test_local_ai_serves_the_alias_to_a_module_key_and_keeps_no_contents(gateway):
    config_dir, repo_root = gateway["config_dir"], gateway["repo_root"]
    rendered = yaml.safe_load((config_dir / "ai/litellm/config.yaml").read_text("utf-8"))
    assert {e["model_name"] for e in rendered["model_list"]} >= {
        "papaia-chat", "papaia-structured", model_gateway.CPU_DEFAULT
    }

    admin = model_gateway.connect(config_dir)
    model_gateway.wait_ready(admin, timeout=240)
    outcome = model_gateway.ensure_module_key(
        config_dir, repo_root, MODULE, ["papaia-chat", "papaia-structured"], admin
    )
    assert outcome == "created"
    key = common.parse_env_file(config_dir / "addons" / MODULE / ".env")["PAPAIA_MODEL_KEY"]
    token = hashlib.sha256(key.encode()).hexdigest()

    status, body = _as_module(key, "GET", "/v1/models")
    assert status == 200, body
    assert sorted(m["id"] for m in json.loads(body)["data"]) == [
        "papaia-chat", "papaia-structured"
    ]
    status, body = _as_module(key, "POST", "/v1/chat/completions", {
        "model": "papaia-chat",
        "messages": [{"role": "user", "content": f"say pong {MARKER}"}],
    })
    assert status == 200, body
    assert json.loads(body)["choices"][0]["message"]["content"] == "pong"
    status, _ = _as_module(key, "POST", "/v1/chat/completions", {
        "model": model_gateway.CPU_DEFAULT,
        "messages": [{"role": "user", "content": "x"}],
    })
    assert status == 403, "a module key reaches the aliases only"

    # The usage is counted per module key (written in batches), without a person.
    deadline = time.monotonic() + 120
    rows = ""
    while time.monotonic() < deadline:
        rows = _psql('select api_key, count(*), coalesce(max("user"), \'\') '
                     'from "LiteLLM_SpendLogs" group by api_key')
        if rows:
            break
        time.sleep(3)
    # One counter row, for the module key (the refused call is counted as well), no person.
    (row,) = rows.splitlines()
    api_key, count, user = row.split("|")
    assert (api_key, user) == (token, "") and int(count) >= 1, rows

    dump = _run("docker", "exec", _container("litellm-db"), "pg_dump", "-U", "llmproxy",
                "-d", "litellm", "--data-only").stdout
    assert token in dump and MARKER not in dump
    files = _run("docker", "exec", _container("litellm-db"), "grep", "-rl", MARKER,
                 "/var/lib/postgresql/data", check=False)
    assert files.returncode == 1 and files.stdout == "", files.stdout
    logs = _run("docker", "logs", _container("litellm"))
    assert MARKER not in logs.stdout + logs.stderr

    # The halt reaches the gateway through the mounted folder, and lifting it serves again,
    # each within the 60 s docs/halt.md allows for model calls (a bind mount of the host
    # folder may show the renamed file a little late).
    chat = {"model": "papaia-chat", "messages": [{"role": "user", "content": "say pong"}]}
    halt.set_halt(config_dir, "probe")
    status, body = _chat_until(key, chat, 503)
    assert status == 503 and "platform_halt" in body, body
    halt.clear_halt(config_dir, "probe over")
    status, body = _chat_until(key, chat, 200)
    assert status == 200, body

    assert model_gateway.revoke_module_key(
        config_dir, repo_root, MODULE, admin, reason="addon_uninstall"
    ) == "revoked"
    status, _ = _as_module(key, "GET", "/v1/models")
    assert status == 401
    journal = gateway["backup"] / "erasure-journal" / "model-gateway.jsonl"
    (entry,) = [json.loads(line) for line in journal.read_text("utf-8").splitlines()]
    assert (entry["kind"], entry["object_ref"]) == ("key_revoke", token)
    assert key not in journal.read_text("utf-8")
