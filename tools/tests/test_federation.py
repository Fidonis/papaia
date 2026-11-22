"""Federation with an upstream provider (OPS-16, OPS-03; docs/federation.md).

`lib/federation.py` (the files, the realm, the override of papaia-lifecycle) against an
in-memory Admin API, and the status sync of papaia-lifecycle against an in-memory
upstream directory. `test_federation_live.py` runs the same code against two throwaway
Keycloaks of the pinned version (RS-F).
"""

from __future__ import annotations

import io
import json
import os
import urllib.error
import urllib.parse
from pathlib import Path

import pytest
import yaml

from lib import egress
from lib import federation as fd
from lib import realm_sync as rs
from tests.test_lifecycle import (
    OTHER,
    PERSON,
    THIRD,
    Clock,
    FakeKeycloak,
    _published,
    _rows,
    lc,
)

REPO = Path(__file__).resolve().parents[2]
UP_ANNA = "a1a1a1a1-0000-4000-8000-000000000001"
UP_BEN = "b2b2b2b2-0000-4000-8000-000000000002"
G_BUCH = "11111111-2222-4333-8444-555555555555"
G_VERTRIEB = "66666666-7777-4888-8999-000000000000"
CONTACT = "IT-Service, Durchwahl 100"


# ─────────────────────────────────────────────────────────────────────────
# files
# ─────────────────────────────────────────────────────────────────────────


def _idp(**changes) -> dict:
    doc = {
        "format": fd.IDP_FORMAT,
        "issuer": "https://login.firma.example/realms/firma",
        "authorization_url": "https://login.firma.example/realms/firma/protocol/openid-connect/auth",
        "token_url": "https://login.firma.example/realms/firma/protocol/openid-connect/token",
        "jwks_url": "https://login.firma.example/realms/firma/protocol/openid-connect/certs",
        "client_id": "papaia-broker",
        "acr_values": ["1", "2"],
        "contact": CONTACT,
        "status_sync": {
            "kind": "keycloak",
            "url": "https://login.firma.example",
            "realm": "firma",
            "client_id": "papaia-status-sync",
        },
    }
    doc.update(changes)
    return doc


def _map(*rows: tuple[str, str]) -> dict:
    rows = rows or ((G_BUCH, "buchhaltung"), (G_VERTRIEB, "vertrieb"))
    return {"format": fd.MAP_FORMAT, "groups": [{"upstream_id": i, "group": g} for i, g in rows]}


def _write(path: Path, doc: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    path.chmod(0o600)


@pytest.fixture
def config(tmp_path) -> Path:
    folder = tmp_path / "config"
    folder.mkdir(mode=0o700)
    (folder / ".env").write_text("COMPOSE_PROFILES=keycloak,lifecycle\n", encoding="utf-8")
    return folder


def _federated(config: Path, idp: dict | None = None, group_map: dict | None = None) -> None:
    _write(config / fd.IDP_FILE, idp or _idp())
    _write(config / fd.MAP_FILE, group_map or _map())


def test_without_idp_yaml_there_is_no_federation(config):
    assert fd.load(config) is None


def test_a_complete_federation_is_read(config):
    _federated(config)
    fed = fd.load(config)
    assert fed.groups == ((G_BUCH, "buchhaltung"), (G_VERTRIEB, "vertrieb"))
    assert fed.status_sync.url == "https://login.firma.example"
    assert fed.acr_values == ("1", "2")


def test_idp_yaml_without_the_group_map_is_refused(config):
    _write(config / fd.IDP_FILE, _idp())
    with pytest.raises(fd.FederationError, match="idp-group-map.yaml is missing"):
        fd.load(config)


@pytest.mark.parametrize(
    ("idp", "message"),
    [
        (_idp(extra=1), "unknown field extra"),
        (_idp(format="papaia.idp/2"), "format"),
        (_idp(issuer="http://login.firma.example/realms/firma"), "https"),
        (_idp(issuer="https://user:pw@login.firma.example/x"), "nothing else"),
        (_idp(token_url="https://login.firma.example/t?x=1"), "nothing else"),
        (_idp(client_id="bad id"), "client_id"),
        (_idp(acr_values=[]), "acr_values"),
        (_idp(acr_values=["1", "1"]), "acr_values"),
        (_idp(contact="see https://evil.example"), "contact"),
        (_idp(contact="{x}"), "contact"),
        (_idp(contact="a\nb"), "contact"),
        (_idp(status_sync={"kind": "ldap", "url": "https://x.example", "realm": "r",
                           "client_id": "c"}), "kind"),
        (_idp(status_sync={"kind": "keycloak", "url": "https://x.example/path", "realm": "r",
                           "client_id": "c"}), "without a path"),
        (_idp(status_sync={"kind": "keycloak", "url": "https://x.example", "realm": "r",
                           "client_id": "c", "secret": "s"}), "unknown field secret"),
    ],
)
def test_idp_yaml_is_checked_at_the_boundary(idp, message):
    with pytest.raises(fd.FederationError, match=message):
        fd.parse(idp, _map())


def test_http_is_accepted_on_a_loopback_address_only():
    fed = fd.parse(_idp(jwks_url="http://127.0.0.1:8080/certs"), _map())
    assert fed.jwks_url == "http://127.0.0.1:8080/certs"
    with pytest.raises(fd.FederationError, match="https"):
        fd.parse(_idp(jwks_url="http://10.0.0.1/certs"), _map())


@pytest.mark.parametrize(
    ("group_map", "message"),
    [
        ({"format": fd.MAP_FORMAT, "groups": [{"upstream_id": "Buchhaltung Nord",
                                               "group": "buchhaltung"}]}, "immutable group id"),
        (_map((G_BUCH, "buchhaltung"), (G_BUCH, "vertrieb")), "mapped twice"),
        (_map((G_BUCH, "../admin"),), "group of the realm"),
        ({"format": fd.MAP_FORMAT, "groups": [{"upstream_id": G_BUCH, "group": "b",
                                               "role": "admin"}]}, "unknown field role"),
        ({"format": fd.MAP_FORMAT, "groups": [{"upstream_id": G_BUCH, "group": "b"}] * 501},
         "at most 500"),
        ({"format": "papaia.idp-group-map/9", "groups": []}, "format"),
    ],
)
def test_the_group_map_binds_immutable_ids_and_is_checked(group_map, message):
    with pytest.raises(fd.FederationError, match=message):
        fd.parse(_idp(), group_map)


def test_a_group_map_others_may_write_is_refused(config):
    _federated(config)
    (config / fd.MAP_FILE).chmod(0o666)
    with pytest.raises(rs.RealmSyncError, match="writable by group or others"):
        fd.load(config)


def test_a_symlinked_idp_yaml_is_refused(config, tmp_path):
    _federated(config)
    target = tmp_path / "elsewhere.yaml"
    _write(target, _idp())
    (config / fd.IDP_FILE).unlink()
    (config / fd.IDP_FILE).symlink_to(target)
    with pytest.raises(fd.FederationError, match="cannot be opened safely"):
        fd.load(config)


def test_render_writes_the_status_sync_key_and_file_and_keeps_the_key(config):
    _federated(config)
    jwk = fd.render(config)
    assert jwk["kty"] == "EC" and "d" not in jwk
    folder = fd.status_keys(config).folder(fd.STATUS_ACCOUNT)
    doc = json.loads((folder / fd.STATUS_FILE).read_bytes())
    assert doc == {
        "format": fd.STATUS_FORMAT,
        "alias": fd.ALIAS,
        "kind": "keycloak",
        "url": "https://login.firma.example",
        "realm": "firma",
        "client_id": "papaia-status-sync",
        "groups": sorted([G_BUCH, G_VERTRIEB]),
    }
    # papaia-lifecycle reads the same file, checked field by field.
    assert lc.read_status_file(folder)["groups"] == doc["groups"]
    assert fd.render(config) == jwk
    (config / fd.IDP_FILE).unlink()
    assert fd.render(config) is None
    assert not (folder / fd.STATUS_FILE).exists()
    assert fd.status_keys(config).public_jwk(fd.STATUS_ACCOUNT) == jwk


@pytest.mark.parametrize(
    "change",
    [
        {"kind": "scim"},
        {"url": "http://login.firma.example"},
        {"groups": ["not an id"]},
        {"extra": True},
    ],
)
def test_lifecycle_refuses_a_status_file_it_does_not_know(config, change):
    _federated(config)
    fd.render(config)
    folder = fd.status_keys(config).folder(fd.STATUS_ACCOUNT)
    doc = json.loads((folder / fd.STATUS_FILE).read_bytes())
    doc.update(change)
    (folder / fd.STATUS_FILE).write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(lc.LifecycleError):
        lc.read_status_file(folder)


# ─────────────────────────────────────────────────────────────────────────
# Compose: the way out of papaia-lifecycle
# ─────────────────────────────────────────────────────────────────────────


def test_the_egress_source_allows_the_directory_host_alone(config):
    assert fd.egress_source(config) is None
    _federated(config)
    source = fd.egress_source(config)
    assert source["name"] == fd.EGRESS_SOURCE
    assert source["allow"] == [{"host": "login.firma.example", "ports": [443]}]
    assert source["internal"] == []


def test_the_rendered_exit_lists_lifecycle_while_the_federation_is_on(config):
    egress.render(config)
    rendered = json.loads((config / egress.CONFIG_FILE).read_text(encoding="utf-8"))
    assert [s["name"] for s in rendered["sources"]] == []
    _federated(config)
    egress.render(config)
    rendered = json.loads((config / egress.CONFIG_FILE).read_text(encoding="utf-8"))
    [source] = rendered["sources"]
    assert source["name"] == fd.EGRESS_SOURCE
    assert source["allow"] == [{"host": "login.firma.example", "ports": [443]}]


def test_the_override_puts_lifecycle_behind_egress_with_the_folder_read_only(config):
    with (config / ".env").open("a", encoding="utf-8") as fh:
        fh.write("PAPAIA_OPERATIONS_MAIL=betrieb@firma.example\n")
    _federated(config)
    out = fd.generate_override(config, REPO)
    doc = yaml.safe_load(out.read_text(encoding="utf-8"))
    service = doc["services"][fd.LIFECYCLE_SERVICE]
    assert "--federation-dir=/run/papaia-lifecycle/federation" in service["command"]
    # The mail relay is off: no warning mail flags (doctor still reports the failure).
    assert not any(c.startswith("--alert-to") for c in service["command"])
    assert service["environment"]["HTTPS_PROXY"].startswith("http://")
    assert set(service["environment"]["NO_PROXY"].split(",")) == {"keycloak", fd.MAIL_RELAY}
    [mount] = service["volumes"]
    assert mount["read_only"] is True
    assert mount["target"] == "/run/papaia-lifecycle/federation"
    assert mount["source"].endswith(f"security/federation/{fd.STATUS_ACCOUNT}")
    net = fd.network({})
    assert doc["networks"][net] == {"name": net, "internal": True}
    assert set(service["networks"]) == {"papaia-lifecycle-net", net}
    assert fd.MAIL_RELAY not in doc["services"]


def test_the_override_is_removed_without_federation_or_without_the_profile(config):
    _federated(config)
    out = fd.generate_override(config, REPO)
    assert out.exists()
    (config / ".env").write_text("COMPOSE_PROFILES=keycloak\n", encoding="utf-8")
    assert fd.generate_override(config, REPO) is None
    assert not out.exists()


def test_the_operations_address_must_be_one_address(config):
    with (config / ".env").open("a", encoding="utf-8") as fh:
        fh.write("PAPAIA_OPERATIONS_MAIL=a@x.example,b@y.example\n")
    _federated(config)
    with pytest.raises(fd.FederationError, match="one mail address"):
        fd.render(config)
    with pytest.raises(fd.FederationError, match="one mail address"):
        fd.generate_override(config, REPO)


def test_the_warning_mail_flags_need_relay_address_and_sender():
    base = ["python3", "lifecycle.py", "run"]
    assert fd.lifecycle_command(base, "", "papaia@firma.example") == [
        *base, "--federation-dir=/run/papaia-lifecycle/federation"
    ]
    full = fd.lifecycle_command(base, "betrieb@firma.example", "papaia@firma.example")
    assert "--alert-to=betrieb@firma.example" in full
    assert "--alert-from=papaia@firma.example" in full
    assert any(c.startswith(f"--mail-relay={fd.MAIL_RELAY}:") for c in full)


# ─────────────────────────────────────────────────────────────────────────
# realm
# ─────────────────────────────────────────────────────────────────────────


def _http(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("http://keycloak", code, "error", {}, None)


class FakeAdmin:
    """The Admin API calls of `federation.align`, with a log of every write."""

    def __init__(self, groups=("buchhaltung", "vertrieb")) -> None:
        self.seq = 0
        self.writes: list[tuple[str, str]] = []
        self.groups = {name: {"id": self._id(), "name": name, "path": f"/{name}"}
                       for name in groups}
        self.roles: dict[str, dict] = {}
        self.provider: dict | None = None
        self.mappers: dict[str, dict] = {}
        self.configs: dict[str, dict] = {}
        self.events = {"eventsEnabled": False, "enabledEventTypes": []}
        # flow alias -> {"id", "top", "rows": [execution]}; an execution of a sub-flow
        # carries "flow" (the sub-flow's alias).
        self.flows: dict[str, dict] = {}
        self._flow("browser", top=True)
        self._add("browser", {"providerId": "auth-cookie", "requirement": "ALTERNATIVE"})
        self._add("browser", {"providerId": "identity-provider-redirector",
                              "requirement": "ALTERNATIVE"})

    def _id(self) -> str:
        self.seq += 1
        return f"id-{self.seq:04d}"

    def _flow(self, alias: str, *, top: bool) -> None:
        self.flows[alias] = {"id": self._id(), "alias": alias, "top": top, "rows": []}

    def _add(self, alias: str, row: dict) -> dict:
        row = {"id": self._id(), "requirement": "DISABLED", **row}
        self.flows[alias]["rows"].append(row)
        return row

    def _rows(self, alias: str, level: int = 0) -> list[dict]:
        out = []
        for row in self.flows[alias]["rows"]:
            rep = {k: v for k, v in row.items() if k != "flow"}
            rep["level"] = level
            if "flow" in row:
                rep["displayName"] = row["flow"]
                rep["authenticationFlow"] = True
                out.append(rep)
                out.extend(self._rows(row["flow"], level + 1))
            else:
                out.append(rep)
        return out

    def _find(self, eid: str) -> tuple[str, dict]:
        for alias, flow in self.flows.items():
            for row in flow["rows"]:
                if row["id"] == eid:
                    return alias, row
        raise _http(404)

    def call(self, method: str, path: str, body=None):
        if method != "GET":
            self.writes.append((method, path))
        base, _, query = path.partition("?")
        parts = [urllib.parse.unquote(p) for p in base.strip("/").split("/")] if base else []
        if not parts:
            return {"realm": "papaia", "browserFlow": "browser"}
        if parts == ["groups"]:
            name = urllib.parse.parse_qs(query)["search"][0]
            return [dict(self.groups[name])] if name in self.groups else []
        if parts == ["roles"] and method == "GET":
            return [dict(r) for r in self.roles.values()]
        if parts[0] == "roles":
            if method == "POST":
                self.roles[body["name"]] = dict(body, id=self._id())
                return None
            if parts[1] not in self.roles:
                raise _http(404)
            if method == "DELETE":
                del self.roles[parts[1]]
                return None
            return self.roles[parts[1]]
        if parts == ["events", "config"]:
            if method == "PUT":
                self.events = dict(body)
                return None
            return dict(self.events)
        if parts[:2] == ["identity-provider", "instances"]:
            return self._provider(method, parts[2:], body)
        if parts[0] == "authentication":
            return self._auth(method, parts[1:], body)
        raise AssertionError(f"unexpected call {method} {path}")

    def _provider(self, method, rest, body):
        if not rest:
            if method == "GET":
                return [json.loads(json.dumps(self.provider))] if self.provider else []
            assert method == "POST"
            self.provider = json.loads(json.dumps(body))
            return None
        if self.provider is None or rest[0] != self.provider["alias"]:
            raise _http(404)
        if len(rest) == 1:
            if method == "DELETE":
                self.provider, self.mappers = None, {}
                return None
            if method == "PUT":
                self.provider = json.loads(json.dumps(body))
                return None
            return json.loads(json.dumps(self.provider))
        if len(rest) == 2:
            if method == "POST":
                mid = self._id()
                self.mappers[mid] = dict(json.loads(json.dumps(body)), id=mid)
                return None
            return [json.loads(json.dumps(m)) for m in self.mappers.values()]
        if method == "DELETE":
            del self.mappers[rest[2]]
        elif method == "PUT":
            self.mappers[rest[2]] = json.loads(json.dumps(body))
        return None

    def _auth(self, method, rest, body):
        if rest == ["flows"]:
            if method == "POST":
                self._flow(body["alias"], top=True)
                return None
            return [{"id": f["id"], "alias": a} for a, f in self.flows.items() if f["top"]]
        if rest[0] == "flows" and len(rest) == 2 and method == "DELETE":
            alias = next(a for a, f in self.flows.items() if f["id"] == rest[1])
            del self.flows[alias]
            return None
        if rest[0] == "flows" and rest[2] == "executions":
            alias = rest[1]
            if alias not in self.flows:
                raise _http(404)
            if len(rest) == 3 and method == "GET":
                return self._rows(alias)
            if len(rest) == 3 and method == "PUT":
                _, row = self._find(body["id"])
                row["requirement"] = body["requirement"]
                return None
            if rest[3] == "execution":
                self._add(alias, {"providerId": body["provider"]})
                return None
            if rest[3] == "flow":
                self._flow(body["alias"], top=False)
                self._add(alias, {"flow": body["alias"]})
                return None
        if rest[0] == "executions" and len(rest) == 2 and method == "DELETE":
            alias, row = self._find(rest[1])
            self.flows[alias]["rows"].remove(row)
            if "flow" in row:
                del self.flows[row["flow"]]
            return None
        if rest[0] == "executions" and rest[2:] == ["config"]:
            _, row = self._find(rest[1])
            cid = self._id()
            self.configs[cid] = dict(body, id=cid)
            row["authenticationConfig"] = cid
            return None
        if rest[0] == "config":
            if rest[1] not in self.configs:
                raise _http(404)
            if method == "PUT":
                self.configs[rest[1]] = dict(body)
                return None
            if method == "DELETE":
                del self.configs[rest[1]]
                for flow in self.flows.values():
                    for row in flow["rows"]:
                        if row.get("authenticationConfig") == rest[1]:
                            del row["authenticationConfig"]
                return None
            return dict(self.configs[rest[1]])
        raise AssertionError(f"unexpected call {method} authentication/{'/'.join(rest)}")


class Audit:
    def __init__(self) -> None:
        self.rows: list[tuple] = []

    def write(self, change, result, error_code, *, master):
        self.rows.append((change.kind, change.name, change.operation, change.effect, result))


@pytest.fixture
def fed():
    return fd.parse(_idp(), _map())


def test_align_sets_up_the_broker_without_a_secret_and_with_force_sync(fed):
    admin, audit = FakeAdmin(), Audit()
    changes = fd.align(admin.call, fed, apply=True, audit=audit)
    assert changes and len(audit.rows) == len(changes)
    assert all(r[4] == "allowed" and r[2].startswith("federation_") for r in audit.rows)
    provider = admin.provider
    assert provider["alias"] == fd.ALIAS
    assert provider["trustEmail"] is False and provider["storeToken"] is False
    assert provider["firstBrokerLoginFlowAlias"] == fd.FIRST_FLOW
    assert provider["postBrokerLoginFlowAlias"] == fd.CHECK_FLOW
    config = provider["config"]
    assert config["clientAuthMethod"] == "private_key_jwt"
    assert config["syncMode"] == "FORCE"
    assert config["pkceMethod"] == "S256"
    assert config["validateSignature"] == "true"
    assert not any("secret" in k.lower() for k in config)
    assert set(admin.roles) == set(fd.MARKER_ROLES)
    assert fd.REFUSED_EVENT in admin.events["enabledEventTypes"]


def test_each_mapping_binds_the_immutable_group_id_to_the_group_path(fed):
    admin = FakeAdmin()
    fd.align(admin.call, fed, apply=True)
    groups = {
        json.loads(m["config"]["claims"])[0]["value"]: m["config"]["group"]
        for m in admin.mappers.values()
        if m["identityProviderMapper"] == "oidc-advanced-group-idp-mapper"
    }
    assert groups == {G_BUCH: "/buchhaltung", G_VERTRIEB: "/vertrieb"}
    assert all(m["config"]["syncMode"] == "FORCE" for m in admin.mappers.values())
    exact = [m for m in admin.mappers.values() if m["name"].startswith("group ")]
    assert all(m["config"]["are.claim.values.regex"] == "false" for m in exact)


def test_the_post_sign_in_flow_refuses_with_the_fixed_text(fed):
    admin = FakeAdmin()
    fd.align(admin.call, fed, apply=True)
    texts = [c["config"].get("denyErrorMessage") for c in admin.configs.values()]
    overflow = fd.OVERFLOW_TEXT.format(contact=CONTACT)
    assert texts.count(overflow) == 2  # no groups claim, overage reference
    assert fd.ACR_TEXT.format(contact=CONTACT) in texts
    rows = admin._rows(fd.CHECK_FLOW)
    assert rows[-1]["providerId"] == "allow-access-authenticator"
    assert [r["requirement"] for r in rows if r["level"] == 0][:3] == ["CONDITIONAL"] * 3
    assert [r["providerId"] for r in admin._rows(fd.FIRST_FLOW)] == ["idp-create-user-if-unique"]


def test_the_sign_in_page_leads_to_the_provider_without_a_choice(fed):
    admin = FakeAdmin()
    fd.align(admin.call, fed, apply=True)
    redirector = next(r for r in admin._rows("browser")
                      if r["providerId"] == "identity-provider-redirector")
    config = admin.configs[redirector["authenticationConfig"]]
    assert config["config"] == {"defaultProvider": fd.ALIAS}


def test_a_second_run_changes_nothing(fed):
    admin = FakeAdmin()
    fd.align(admin.call, fed, apply=True)
    admin.writes.clear()
    assert fd.align(admin.call, fed, apply=False) == []
    assert fd.align(admin.call, fed, apply=True) == []
    assert admin.writes == []


def test_check_reports_without_writing(fed, capsys):
    admin = FakeAdmin()
    changes = fd.align(admin.call, fed, apply=False)
    assert changes
    assert admin.writes == []
    assert "fail: identity-provider upstream: created" in capsys.readouterr().out


def test_a_changed_map_realigns_the_mappers_only(fed):
    admin = FakeAdmin()
    fd.align(admin.call, fed, apply=True)
    admin.writes.clear()
    smaller = fd.parse(_idp(), _map((G_BUCH, "buchhaltung")))
    changes = fd.align(admin.call, smaller, apply=True)
    assert [(c.kind, c.name, c.effect) for c in changes] == [
        ("idp-mapper", f"group {G_VERTRIEB}", "delete")
    ]


def test_a_tampered_provider_is_realigned(fed):
    admin = FakeAdmin()
    fd.align(admin.call, fed, apply=True)
    admin.provider["trustEmail"] = True
    admin.provider["config"]["syncMode"] = "IMPORT"
    [change] = fd.align(admin.call, fed, apply=True)
    assert "trustEmail" in change.action and "config.syncMode" in change.action
    assert admin.provider["trustEmail"] is False
    assert admin.provider["config"]["syncMode"] == "FORCE"


def test_a_tampered_flow_is_rebuilt(fed):
    admin = FakeAdmin()
    fd.align(admin.call, fed, apply=True)
    row = next(r for r in admin.flows["papaia-federation-overage"]["rows"]
               if r["providerId"] == "deny-access-authenticator")
    row["requirement"] = "DISABLED"
    changes = fd.align(admin.call, fed, apply=True)
    assert [(c.kind, c.name) for c in changes] == [("flow", fd.CHECK_FLOW)]
    assert fd.align(admin.call, fed, apply=False) == []


def test_a_mapping_to_a_group_the_realm_lacks_refuses_before_any_write(fed):
    admin = FakeAdmin(groups=("buchhaltung",))
    with pytest.raises(fd.FederationError, match="no group 'vertrieb'"):
        fd.align(admin.call, fed, apply=True)
    assert admin.writes == []


def test_without_federation_the_sync_removes_what_it_set_up(fed):
    admin, audit = FakeAdmin(), Audit()
    fd.align(admin.call, fed, apply=True)
    fd.align(admin.call, None, apply=True, audit=audit)
    assert admin.provider is None
    assert fd.CHECK_FLOW not in admin.flows and fd.FIRST_FLOW not in admin.flows
    assert admin.roles == {}
    redirector = next(r for r in admin._rows("browser")
                      if r["providerId"] == "identity-provider-redirector")
    assert "authenticationConfig" not in redirector
    assert audit.rows and all(r[3] == "delete" for r in audit.rows)
    assert fd.align(admin.call, None, apply=False) == []


def test_a_browser_flow_without_a_redirector_is_refused(fed):
    admin = FakeAdmin()
    admin.flows["browser"]["rows"] = [r for r in admin.flows["browser"]["rows"]
                                      if r["providerId"] != "identity-provider-redirector"]
    with pytest.raises(fd.FederationError, match="redirector"):
        fd.align(admin.call, fed, apply=True)


# ─────────────────────────────────────────────────────────────────────────
# status sync in papaia-lifecycle
# ─────────────────────────────────────────────────────────────────────────


class FederatedKeycloak(FakeKeycloak):
    """The fake realm of test_lifecycle plus what the status sync asks for: the link
    to the upstream person, the realm roles of an account, enabling and disabling."""

    def __init__(self) -> None:
        super().__init__()
        self.links: dict[str, str] = {}
        self.realm_roles: dict[str, list[str]] = {}
        self.puts: list[tuple[str, dict]] = []
        # Accounts whose PUT fails (a round that breaks off partway).
        self.fail_puts: set[str] = set()
        # Accounts whose logout fails (a round that breaks off after the disable).
        self.fail_logouts: set[str] = set()

    def call(self, method: str, path: str, body=None):
        parts = path.partition("?")[0].strip("/").split("/")
        if parts[0] == "users" and len(parts) >= 2 and parts[1] in self.users:
            uid = parts[1]
            if parts[2:] == ["federated-identity"]:
                self.calls.append((method, path))
                if uid not in self.links:
                    return []
                return [{"identityProvider": fd.ALIAS, "userId": self.links[uid],
                         "userName": "x"}]
            if parts[2:] == ["logout"] and method == "POST" and uid in self.fail_logouts:
                self.calls.append((method, path))
                raise lc.HttpError(500)
            if parts[2:] == ["role-mappings", "realm"]:
                self.calls.append((method, path))
                return [{"name": n} for n in self.realm_roles.get(uid, [])]
            if len(parts) == 2 and method == "PUT":
                self.calls.append((method, path))
                if uid in self.fail_puts:
                    raise lc.HttpError(500)
                self.puts.append((uid, body))
                self.users[uid]["enabled"] = body["enabled"]
                return None
        return super().call(method, path, body)


class FakeDirectory:
    """The upstream directory as StatusSync reads it."""

    def __init__(self) -> None:
        self.users: dict[str, dict] = {}
        self.members: dict[str, set[str]] = {G_BUCH: set(), G_VERTRIEB: set()}
        self.error: Exception | None = None
        self.reads = 0

    def person(self, uid: str, name: str, *groups: str) -> None:
        self.users[uid] = {"enabled": True, "not_before": 0, "username": name}
        for gid in groups:
            self.members[gid].add(uid)

    def snapshot(self) -> dict:
        self.reads += 1
        if self.error is not None:
            raise self.error
        return {
            "users": json.loads(json.dumps(self.users)),
            "members": {g: set(ids) for g, ids in self.members.items()},
        }


class Mailer:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []
        self.error: Exception | None = None

    def send(self, subject: str, text: str) -> None:
        if self.error is not None:
            raise self.error
        self.sent.append((subject, text))


@pytest.fixture
def fstack(tmp_path):
    key_dir, state_dir = tmp_path / "key", tmp_path / "state"
    key_dir.mkdir(mode=0o700)
    state_dir.mkdir()
    target, local = tmp_path / "backup" / "erasure-journal", key_dir / "erasure-journal"
    target.mkdir(parents=True)
    keycloak, directory, mailer = FederatedKeycloak(), FakeDirectory(), Mailer()
    clock, out = Clock(), io.StringIO()
    journal = lc.ErasureJournal(
        "identity", key=os.urandom(32), target_dir=target, local_dir=local, clock=clock
    )
    sync = lc.StatusSync(directory, mailer=mailer, clock=clock)
    service = lc.Lifecycle(
        keycloak,
        lc.Store(key_dir),
        lc.Publisher(state_dir, lc.Signer(key_dir)),
        out=out,
        clock=clock,
        journal=journal,
        federation=sync,
    )
    # Anna and Ben are federated, the third account (break-glass) is local.
    keycloak.add_user(PERSON, consents=("flow-engine", "assist-gate"))
    keycloak.add_user(OTHER)
    keycloak.add_user(THIRD)
    keycloak.links.update({PERSON: UP_ANNA, OTHER: UP_BEN})
    directory.person(UP_ANNA, "anna", G_BUCH)
    directory.person(UP_BEN, "ben", G_VERTRIEB)
    service.start()
    service.step()
    keycloak.calls.clear()

    class S:
        pass

    s = S()
    s.keycloak, s.directory, s.mailer, s.clock, s.out = keycloak, directory, mailer, clock, out
    s.service, s.sync, s.state_dir, s.key_dir = service, sync, state_dir, key_dir
    return s


def _round(s, seconds: int = lc.STATUS_SYNC_SECONDS, *, poll: bool = False) -> None:
    s.clock.now += seconds
    s.service.step(force_poll=poll)


def _events(s, name: str) -> list[dict]:
    return [r for r in _rows(s.out) if r["event"] == name]


def test_the_first_round_links_accounts_once_and_changes_nothing(fstack):
    s = fstack
    assert s.directory.reads == 1
    _round(s)
    assert s.directory.reads == 2
    # Links are read once per account and kept; no call per account per round.
    assert not [c for c in s.keycloak.calls if c[1].endswith("/federated-identity")]
    assert s.keycloak.puts == []
    assert _published(s.state_dir)["entries"] == []


def test_a_person_locked_upstream_is_disabled_and_revoked_in_one_round(fstack):
    """PLT-58-A4, GV-32 F3: within one round (60 s) the account is disabled, listed,
    logged out and every consent is gone; one correlation id per account."""
    s = fstack
    s.directory.users[UP_ANNA]["enabled"] = False
    _round(s)
    assert s.keycloak.puts == [(PERSON, {"enabled": False})]
    assert ("POST", f"/users/{PERSON}/logout") in s.keycloak.calls
    assert s.keycloak.consents[PERSON] == []
    assert s.keycloak.consents[OTHER] == ["flow-engine"]
    [entry] = _published(s.state_dir)["entries"]
    assert entry["sub"] == PERSON and entry["reason"] == "upstream_disabled"
    rows = [r for r in _rows(s.out) if r["object_ref"].get("id") == PERSON]
    operations = {r["operation"].split(".")[-1] for r in rows}
    assert operations >= {"account_disable", "logout", "consent_delete"}
    assert len({r["correlation_id"] for r in rows}) == 1
    disable = next(r for r in rows if r["operation"].endswith("account_disable"))
    assert disable["effect"] == "write"
    _round(s)
    assert s.keycloak.puts == [(PERSON, {"enabled": False})]


def test_a_person_deleted_upstream_is_disabled_and_revoked(fstack):
    s = fstack
    del s.directory.users[UP_BEN]
    _round(s)
    assert s.keycloak.users[OTHER]["enabled"] is False
    [entry] = _published(s.state_dir)["entries"]
    assert entry["reason"] == "upstream_deleted"


def test_a_local_account_is_never_touched(fstack):
    s = fstack
    s.directory.users.clear()
    _round(s)
    assert s.keycloak.users[THIRD]["enabled"] is True
    assert not [c for c in s.keycloak.calls if f"/users/{THIRD}" in c[1]]


def test_enabled_upstream_again_the_account_returns_without_its_old_delegations(fstack):
    """GV-32 F3/F12: re-enabled, the account is enabled; consents from before the lock
    are removed, so no old delegation comes back."""
    s = fstack
    s.directory.users[UP_ANNA]["enabled"] = False
    _round(s)
    # A consent Keycloak still holds from before the lock (e.g. restored).
    s.keycloak.grant(PERSON, "flow-engine", int((s.clock.now - 10) * 1000))
    s.directory.users[UP_ANNA]["enabled"] = True
    _round(s)
    assert s.keycloak.puts[-1] == (PERSON, {"enabled": True})
    assert s.keycloak.consents[PERSON] == []
    _round(s)
    assert s.keycloak.puts[-1] == (PERSON, {"enabled": True})
    assert len(s.keycloak.puts) == 2


def test_an_account_disabled_here_stays_disabled_when_unlocked_upstream(fstack):
    """PLT-60-A2: a deactivation by papaia's own administration is not lifted by the
    upstream directory; only a lock the status sync set itself is."""
    s = fstack
    s.keycloak.users[PERSON]["enabled"] = False
    s.directory.users[UP_ANNA]["enabled"] = False
    _round(s)
    s.directory.users[UP_ANNA]["enabled"] = True
    _round(s)
    _round(s)
    assert s.keycloak.puts == []
    assert s.keycloak.users[PERSON]["enabled"] is False
    assert not [r for r in _rows(s.out) if r["operation"].endswith("account_enable")]


def test_an_account_disabled_here_is_not_revoked_again_each_round(fstack):
    s = fstack
    s.keycloak.users[PERSON]["enabled"] = False
    s.directory.users[UP_ANNA]["enabled"] = False
    for _ in range(3):
        _round(s)
    assert not [c for c in s.keycloak.calls if c[1] == f"/users/{PERSON}/logout"]


def test_a_round_that_breaks_off_keeps_what_it_did(fstack):
    """A round that fails at the second account keeps the first account's result, so
    the next round does not disable, revoke and audit it again."""
    s = fstack
    s.directory.users[UP_ANNA]["enabled"] = False
    s.directory.users[UP_BEN]["enabled"] = False
    s.keycloak.fail_puts.add(OTHER)
    _round(s)
    assert s.keycloak.users[PERSON]["enabled"] is False
    assert s.keycloak.users[OTHER]["enabled"] is True
    s.keycloak.fail_puts.clear()
    _round(s)
    assert s.keycloak.users[OTHER]["enabled"] is False
    logouts = [c for c in s.keycloak.calls if c[1] == f"/users/{PERSON}/logout"]
    assert len(logouts) == 1
    disables = [
        r for r in _rows(s.out)
        if r["operation"].endswith("account_disable") and r["object_ref"]["id"] == PERSON
    ]
    assert len(disables) == 1
    # Unlocked upstream, the account the sync disabled comes back.
    s.directory.users[UP_ANNA]["enabled"] = True
    _round(s)
    assert s.keycloak.users[PERSON]["enabled"] is True


def test_a_failing_re_enable_keeps_the_lock_of_the_status_sync(fstack):
    """docs/federation.md: unlocked upstream, an account the status sync disabled is
    enabled again. A PUT that fails on the way back must not turn the sync's own lock
    into a local deactivation that is never lifted."""
    s = fstack
    s.directory.users[UP_ANNA]["enabled"] = False
    _round(s)
    assert s.keycloak.users[PERSON]["enabled"] is False
    s.directory.users[UP_ANNA]["enabled"] = True
    s.keycloak.fail_puts.add(PERSON)
    _round(s)
    assert s.keycloak.users[PERSON]["enabled"] is False
    s.keycloak.fail_puts.clear()
    _round(s)
    _round(s)
    assert s.keycloak.users[PERSON]["enabled"] is True
    enables = [
        r["result"] for r in _rows(s.out)
        if r["operation"].endswith("account_enable") and r["object_ref"]["id"] == PERSON
    ]
    # The failed attempt is an error row, the one that worked an allowed row.
    assert enables == ["error", "allowed"]


def test_a_failing_logout_after_the_disable_keeps_the_lock_of_the_status_sync(fstack):
    """The disable PUT succeeds, the logout fails: the account is recorded as locked by
    the status sync, so it comes back once the person is unlocked upstream."""
    s = fstack
    s.directory.users[UP_ANNA]["enabled"] = False
    s.keycloak.fail_logouts.add(PERSON)
    _round(s)
    assert s.keycloak.users[PERSON]["enabled"] is False
    s.keycloak.fail_logouts.clear()
    _round(s)
    assert s.keycloak.users[PERSON]["enabled"] is False
    disables = [
        r for r in _rows(s.out)
        if r["operation"].endswith("account_disable") and r["object_ref"]["id"] == PERSON
    ]
    assert len(disables) == 1
    s.directory.users[UP_ANNA]["enabled"] = True
    _round(s)
    _round(s)
    assert s.keycloak.users[PERSON]["enabled"] is True


def test_a_lock_while_the_service_was_stopped_is_found_at_start(fstack, tmp_path):
    """GV-32 F12: no event in the realm; the first round after the start finds it."""
    s = fstack
    s.directory.users[UP_BEN]["enabled"] = False
    sync = lc.StatusSync(s.directory, mailer=s.mailer, clock=s.clock)
    again = lc.Lifecycle(
        s.keycloak,
        s.service.store,
        s.service.publisher,
        out=s.out,
        clock=s.clock,
        journal=s.service.journal,
        federation=sync,
    )
    again.start()
    again.step()
    assert s.keycloak.users[OTHER]["enabled"] is False
    assert s.keycloak.consents[OTHER] == []


def test_sessions_revoked_upstream_end_here_without_a_lock(fstack):
    """GV-32 F11: a newer "sessions valid from" upstream revokes, the account stays."""
    s = fstack
    s.directory.users[UP_ANNA]["not_before"] = int(s.clock.now)
    _round(s)
    s.directory.users[UP_ANNA]["not_before"] = int(s.clock.now)
    _round(s)
    assert s.keycloak.puts == []
    assert ("POST", f"/users/{PERSON}/logout") in s.keycloak.calls
    assert s.keycloak.consents[PERSON] == []
    [entry] = _published(s.state_dir)["entries"]
    assert entry["reason"] == "upstream_sessions_revoked"


def test_a_group_change_upstream_ends_the_sessions_and_journals_the_removal(fstack):
    """GV-32 F2: the next sign-in maps anew (sync mode FORCE)."""
    s = fstack
    s.directory.members[G_BUCH].discard(UP_ANNA)
    s.directory.members[G_VERTRIEB].add(UP_ANNA)
    _round(s)
    logouts = [r for r in _events(s, "role_changed") if r["operation"].endswith("logout")]
    assert [r["object_ref"]["id"] for r in logouts] == [PERSON]
    assert logouts[0]["detail"] == {"upstream_groups": 2}
    assert s.keycloak.users[PERSON]["enabled"] is True
    assert s.keycloak.consents[PERSON] == ["flow-engine", "assist-gate"]


def test_a_renamed_group_changes_nothing(fstack):
    """F10: the directory keeps the id; a rename is no change of membership."""
    s = fstack
    _round(s)
    assert not _events(s, "role_changed")
    assert not [c for c in s.keycloak.calls if c[1].endswith("/logout")]


@pytest.mark.parametrize(
    "error", [lc.HttpError(429), lc.HttpError(403), OSError("unreachable"), lc.LifecycleError("x")]
)
def test_a_failing_status_sync_is_reported_once_after_300_seconds(fstack, error):
    """GV-32 F7, Ä-40: throttling counts as failure; after 300 s one
    `status_sync_failed` row, one warning mail and health `fail`."""
    s = fstack
    s.directory.error = error
    _round(s)
    for _ in range(5):
        _round(s)
        code, report = lc.health(s.state_dir, s.key_dir, now=s.clock.now)
        assert not _events(s, "status_sync_failed")
    _round(s)
    [row] = _events(s, "status_sync_failed")
    assert row["result"] == "error"
    assert row["detail"]["failing_seconds"] > lc.STATUS_SYNC_FAIL_SECONDS
    assert len(s.mailer.sent) == 1
    assert "Statusabgleich" in s.mailer.sent[0][0]
    [mail] = [r for r in _rows(s.out) if r["operation"].endswith("alert_mail")]
    assert mail["result"] == "allowed"
    code, report = lc.health(s.state_dir, s.key_dir, now=s.clock.now)
    assert code == 1 and report["status"] == "fail"
    assert report["status_sync_failing_seconds"] > lc.STATUS_SYNC_FAIL_SECONDS
    _round(s)
    _round(s)
    assert len(_events(s, "status_sync_failed")) == 1
    assert len(s.mailer.sent) == 1
    # Nothing was changed on the way.
    assert s.keycloak.puts == []
    s.directory.error = None
    _round(s)
    code, report = lc.health(s.state_dir, s.key_dir, now=s.clock.now)
    assert report["status_sync_failing_seconds"] == 0
    assert report["status_sync_age_seconds"] == 0


def test_a_warning_mail_that_cannot_be_sent_is_an_audit_row(fstack):
    s = fstack
    s.directory.error = lc.HttpError(503)
    s.mailer.error = OSError("relay down")
    for _ in range(7):
        _round(s)
    [mail] = [r for r in _rows(s.out) if r["operation"].endswith("alert_mail")]
    assert mail["result"] == "error" and mail["error_code"] == "mail_failed"


def test_health_reports_the_status_sync_only_with_federation(stack_plain):
    code, report = lc.health(stack_plain.state_dir, stack_plain.key_dir,
                             now=stack_plain.clock.now)
    assert "status_sync_age_seconds" not in report


def test_without_the_federation_the_status_sync_state_goes_and_health_stays_ok(fstack):
    """Removing idp.yaml removes what the federation set up: papaia-lifecycle started
    without the federation folder drops the status sync state, so health does not fail
    for a status sync that no longer runs."""
    s = fstack
    s.directory.users[UP_ANNA]["enabled"] = False
    _round(s)
    plain = lc.Lifecycle(
        s.keycloak,
        s.service.store,
        s.service.publisher,
        out=s.out,
        clock=s.clock,
        journal=s.service.journal,
    )
    plain.start()
    for _ in range(10):
        s.clock.now += 60
        plain.step()
    state = s.service.store.load()
    assert state["federation"] == lc._RECONCILE_DEFAULTS["federation"]
    code, report = lc.health(s.state_dir, s.key_dir, now=s.clock.now)
    assert "status_sync_age_seconds" not in report
    assert report["status"] == "ok" and code == 0


@pytest.fixture
def stack_plain(tmp_path):
    key_dir, state_dir = tmp_path / "key", tmp_path / "state"
    key_dir.mkdir(mode=0o700)
    state_dir.mkdir()
    clock = Clock()
    service = lc.Lifecycle(FakeKeycloak(), lc.Store(key_dir),
                           lc.Publisher(state_dir, lc.Signer(key_dir)),
                           out=io.StringIO(), clock=clock)
    service.start()
    service.step()

    class S:
        pass

    s = S()
    s.state_dir, s.key_dir, s.clock = state_dir, key_dir, clock
    return s


def _refusal(s, name: str, code: str = "c-1") -> None:
    s.keycloak.user_events.append(
        {
            "id": f"u{len(s.keycloak.user_events):04d}",
            "time": int(s.clock.now * 1000) + 1,
            "type": "IDENTITY_PROVIDER_POST_LOGIN_ERROR",
            "realmId": "papaia",
            "clientId": "librechat",
            "userId": None,
            "error": "access_denied",
            "details": {"identity_provider": fd.ALIAS, "identity_provider_identity": name,
                        "code_id": code},
        }
    )


def test_a_refused_sign_in_with_an_overage_reference_is_idp_group_overflow(fstack):
    """GV-33, GV-32 F4: one row per attempt, never a silent removal of bundles."""
    s = fstack
    s.keycloak.realm_roles[PERSON] = [fd.GROUPS_ROLE, fd.OVERAGE_ROLE]
    _refusal(s, "anna")
    _refusal(s, "anna")  # Keycloak writes the same attempt more than once
    _round(s, 1, poll=True)
    [row] = _events(s, "idp_group_overflow")
    assert row["object_ref"] == {"type": "user", "id": PERSON}
    assert row["result"] == "denied" and row["error_code"] == "idp_group_overflow"
    assert s.keycloak.puts == []


def test_a_refused_sign_in_without_a_groups_claim_is_idp_group_overflow(fstack):
    s = fstack
    s.keycloak.realm_roles[OTHER] = []
    _refusal(s, "ben", "c-2")
    _round(s, 1, poll=True)
    [row] = _events(s, "idp_group_overflow")
    assert row["object_ref"]["id"] == OTHER


def test_a_refused_sign_in_for_its_strength_is_not_an_overflow(fstack):
    s = fstack
    s.keycloak.realm_roles[PERSON] = [fd.GROUPS_ROLE, fd.ACR_ROLE]
    _refusal(s, "anna", "c-3")
    _round(s, 1, poll=True)
    assert not _events(s, "idp_group_overflow")
    [row] = [r for r in _rows(s.out) if r.get("error_code") == "idp_acr_refused"]
    assert row["result"] == "denied"


def test_refused_sign_ins_by_unknown_names_read_the_directory_once_per_round(fstack):
    s = fstack
    for n, name in enumerate(("zed", "yan", "xi")):
        _refusal(s, name, f"c-u{n}")
    before = s.directory.reads
    _round(s, 1, poll=True)
    # One read for the round, at most one more for the names it did not know.
    assert s.directory.reads - before <= 2
    _refusal(s, "wu", "c-u9")
    _round(s, 1, poll=True)
    assert s.directory.reads - before <= 4


def test_the_marker_roles_match_the_service():
    assert lc.GROUPS_ROLE == fd.GROUPS_ROLE
    assert lc.OVERAGE_ROLE == fd.OVERAGE_ROLE
    assert lc.FEDERATION_ALIAS == fd.ALIAS
    assert lc.STATUS_FILE == fd.STATUS_FILE
    assert lc.STATUS_FORMAT == fd.STATUS_FORMAT
    assert lc.IDP_ERROR_TYPES == (fd.REFUSED_EVENT,)


@pytest.mark.parametrize(
    ("to", "sender"),
    [
        ("betrieb@firma.example\r\nBcc: x@evil.example", "papaia@firma.example"),
        ("a@x.example,b@y.example", "papaia@firma.example"),
        ("betrieb@firma.example", "no address"),
    ],
)
def test_the_warning_mail_refuses_addresses_that_are_not_one_plain_address(to, sender):
    with pytest.raises(lc.LifecycleError):
        lc.Mailer("smtp-relay:2525", to, sender)


def test_the_warning_mail_goes_to_the_relay(monkeypatch):
    sent = []

    class Relay:
        def __init__(self, host, port, timeout):
            sent.append((host, port))

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def send_message(self, message, from_addr, to_addrs):
            sent.append((from_addr, to_addrs, message))

    monkeypatch.setattr(lc.smtplib, "SMTP", Relay)
    lc.Mailer("smtp-relay:2525", "betrieb@firma.example", "papaia@firma.example").send(
        "Betreff", "Text"
    )
    assert sent[0] == ("smtp-relay", 2525)
    sender, to, message = sent[1]
    assert (sender, to) == ("papaia@firma.example", ["betrieb@firma.example"])
    assert message["Subject"] == "Betreff"
    assert message.get_content() == "Text\n"
