"""Federation with an upstream OpenID Connect provider (OPS-16; docs/federation.md).

Persons come from the directory of the company: Keycloak brokers the sign-in to the
upstream provider, and papaia-lifecycle compares the account states of the federated
persons with the upstream directory every 60 s (status sync). Two files of the
configuration directory describe it, both optional; without `security/idp.yaml` there
is no federation and the realm sync removes what it set up:

- `security/idp.yaml` (format `papaia.idp/1`): the provider (issuer, endpoints, client),
  the accepted `acr` values, the contact point named in the refusal text, and the
  read-only account of the status sync;
- `security/idp-group-map.yaml` (format `papaia.idp-group-map/1`): upstream group id ->
  group of the realm. Always the immutable id the provider puts into the `groups` claim
  (for Entra ID the object id), never a name: a renamed group stays mapped.

What `papaia-ctl realm sync` keeps in the `papaia` realm (master admin, one
`papaia.audit/1` row per change):

- the identity provider `upstream` (OIDC, authorisation code with PKCE S256, client
  authentication `private_key_jwt` with the realm's own key, so there is no client
  secret; signature checked against the provider's keys; e-mail never trusted, token not
  stored; sync mode FORCE, so every sign-in applies the mapping anew, and a removed group
  is gone at the next sign-in);
- its first sign-in flow `papaia-federation-first-login`: the account is created when no
  account of that name or address exists, otherwise the sign-in fails. An account is
  never linked by name or address, only by the provider's `sub`;
- its post sign-in flow `papaia-federation-check`, fail-closed: no `groups` claim, an
  overage reference (`_claim_names.groups`) or an `acr` outside the accepted values ->
  refused with a fixed text. Three marker roles carry what the mappers saw on the last
  sign-in; papaia-lifecycle reads them to write `idp_group_overflow`;
- one mapper "Advanced Claim to Group" per entry of the group map;
- the default provider of the identity provider redirector of the realm's browser flow:
  the sign-in page leads to the provider without a choice. Local accounts (break-glass,
  service accounts) sign in with `kc_idp_hint` of an unknown alias (docs/federation.md).

`render` writes, for papaia-lifecycle, `security/federation/svc-papaia-status-sync/`:
the key pair of the status sync account (P-256, made once; the provider registers the
public key, no secret) and `status-sync.json` with the directory to read. The override of
`gen_override` gives papaia-lifecycle a way out through papaia-egress, to the host of the
status sync alone, and the mail relay for the warning mail.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

import yaml

from . import common, smtp
from . import realm_sync as rs
from . import service_account_keys as sak

IDP_FILE = Path("security") / "idp.yaml"
MAP_FILE = Path("security") / "idp-group-map.yaml"
IDP_FORMAT = "papaia.idp/1"
MAP_FORMAT = "papaia.idp-group-map/1"
STATUS_FORMAT = "papaia.status-sync/1"
ALIAS = "upstream"
CHECK_FLOW = "papaia-federation-check"
FIRST_FLOW = "papaia-federation-first-login"
REDIRECT_CONFIG = "papaia-federation-redirect"
# Marker roles: set by the mappers on every sign-in (sync mode FORCE), read by the post
# sign-in flow and by papaia-lifecycle. No composite, in no client's token scope.
GROUPS_ROLE = "papaia-idp-groups"
OVERAGE_ROLE = "papaia-idp-group-overage"
ACR_ROLE = "papaia-idp-acr"
MARKER_ROLES = (GROUPS_ROLE, OVERAGE_ROLE, ACR_ROLE)
# The user event of a sign-in the post sign-in flow refused.
REFUSED_EVENT = "IDENTITY_PROVIDER_POST_LOGIN_ERROR"
# The status sync: its key and file in the configuration directory, mounted read-only
# into papaia-lifecycle (src/infra/lifecycle/lifecycle.py reads the same names).
STATUS_KEYS = Path("security") / "federation"
STATUS_ACCOUNT = "svc-papaia-status-sync"
STATUS_FILE = "status-sync.json"
STATUS_KINDS = ("keycloak",)
# The egress source of papaia-lifecycle while the status sync is on.
EGRESS_SOURCE = "lifecycle"
LIFECYCLE_SERVICE = "papaia-lifecycle"
MAIL_RELAY = "smtp-relay"
MAX_MAPPINGS = 500
MAX_ACR = 16
_MAX_FILE_BYTES = 1 << 20
_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_CLIENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_REALM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_ACR_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_MAIL_RE = re.compile(r"[^@\s,;<>\"']{1,64}@[A-Za-z0-9.-]{1,253}")
# The refusal texts (governance GV-33, wording fixed; `{contact}` = the contact point).
OVERFLOW_TEXT = (
    "Anmeldung nicht möglich: Ihr Konto gehört im Firmenverzeichnis zu mehr Gruppen, als die "
    "Anmeldung übermitteln kann. Deshalb lassen sich Ihre Berechtigungen nicht sicher "
    "bestimmen, und Sie werden nicht angemeldet. Wenden Sie sich an {contact}; dort kann die "
    "Gruppenauswahl für papaia eingeschränkt werden."
)
ACR_TEXT = (
    "Anmeldung nicht möglich: Ihre Anmeldung beim Firmenverzeichnis erfüllt nicht die "
    "verlangte Anmeldestärke (zum Beispiel ein zweiter Faktor). Melden Sie sich erneut an "
    "oder wenden Sie sich an {contact}."
)


class FederationError(rs.RealmSyncError):
    """An unusable idp.yaml or group map; nothing is changed."""


@dataclass(frozen=True)
class StatusSync:
    kind: str
    url: str
    realm: str
    client_id: str


@dataclass(frozen=True)
class Federation:
    issuer: str
    authorization_url: str
    token_url: str
    jwks_url: str
    client_id: str
    client_assertion_audience: str
    acr_values: tuple[str, ...]
    contact: str
    status_sync: StatusSync
    groups: tuple[tuple[str, str], ...]  # (upstream group id, realm group name)

    @property
    def upstream_ids(self) -> list[str]:
        return [gid for gid, _ in self.groups]


# ─────────────────────────────────────────────────────────────────────────
# files
# ─────────────────────────────────────────────────────────────────────────


def _url(value: object, label: str, *, path: bool = True) -> str:
    """https to any host, or http to a loopback address only; no user, query or
    fragment."""
    if not isinstance(value, str) or not 0 < len(value) <= 2048 or _CONTROL_RE.search(value):
        raise FederationError(f"{label}: must be a URL")
    parts = urllib.parse.urlsplit(value)
    if parts.username or parts.password or parts.query or parts.fragment or not parts.hostname:
        raise FederationError(f"{label}: must be scheme://host[:port]/path, nothing else")
    if not path and parts.path not in ("", "/"):
        raise FederationError(f"{label}: must be scheme://host[:port] without a path")
    if parts.scheme == "https":
        return value.rstrip("/") if not path else value
    if parts.scheme == "http":
        try:
            if ipaddress.ip_address(parts.hostname).is_loopback:
                return value.rstrip("/") if not path else value
        except ValueError:
            pass
    raise FederationError(f"{label}: must use https (http only on a loopback address)")


def _text(value: object, label: str, limit: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > limit
        or _CONTROL_RE.search(value)
        or rs._LINK_RE.search(value)
        or "{" in value
        or "}" in value
    ):
        raise FederationError(f"{label}: must be plain text of 1 to {limit} characters")
    return value.strip()


def _keys(value: object, required: set[str], optional: set[str], label: str) -> dict:
    if not isinstance(value, dict):
        raise FederationError(f"{label}: must be a mapping")
    unknown = sorted(str(k) for k in set(value) - required - optional)
    if unknown:
        raise FederationError(f"{label}: unknown field {', '.join(unknown)}")
    missing = sorted(required - set(value))
    if missing:
        raise FederationError(f"{label}: missing field {', '.join(missing)}")
    return value


def _read(path: Path) -> object | None:
    """A YAML file that only the user running papaia-ctl may change; None when missing."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise FederationError(f"{path} cannot be opened safely: {exc.strerror}") from None
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise FederationError(f"{path} is not a regular file")
        rs._trusted(st, path, "sign-in and roles")
        rs._trusted(os.stat(path.parent), path.parent, "sign-in and roles")
        raw = fh.read(_MAX_FILE_BYTES + 1)
    if len(raw) > _MAX_FILE_BYTES:
        raise FederationError(f"{path} is larger than {_MAX_FILE_BYTES} bytes")
    try:
        return yaml.safe_load(raw.decode("utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise FederationError(f"{path} is not valid YAML: {exc}") from None


def parse(idp: object, group_map: object) -> Federation:
    doc = _keys(
        idp,
        {"format", "issuer", "authorization_url", "token_url", "jwks_url", "client_id",
         "acr_values", "contact", "status_sync"},
        {"client_assertion_audience"},
        "idp.yaml",
    )
    if doc["format"] != IDP_FORMAT:
        raise FederationError(f"idp.yaml: format must be {IDP_FORMAT}")
    if not isinstance(doc["client_id"], str) or not _CLIENT_RE.fullmatch(doc["client_id"]):
        raise FederationError("idp.yaml: client_id must be a client id")
    acr = doc["acr_values"]
    if (
        not isinstance(acr, list)
        or not 0 < len(acr) <= MAX_ACR
        or len(set(acr)) != len(acr)
        or not all(isinstance(a, str) and _ACR_RE.fullmatch(a) for a in acr)
    ):
        raise FederationError(
            f"idp.yaml: acr_values must list 1 to {MAX_ACR} distinct acr values"
        )
    sync = _keys(doc["status_sync"], {"kind", "url", "realm", "client_id"}, set(),
                 "idp.yaml: status_sync")
    if sync["kind"] not in STATUS_KINDS:
        raise FederationError(
            f"idp.yaml: status_sync.kind must be one of {', '.join(STATUS_KINDS)}"
        )
    if not isinstance(sync["realm"], str) or not _REALM_RE.fullmatch(sync["realm"]):
        raise FederationError("idp.yaml: status_sync.realm must be a realm name")
    if not isinstance(sync["client_id"], str) or not _CLIENT_RE.fullmatch(sync["client_id"]):
        raise FederationError("idp.yaml: status_sync.client_id must be a client id")
    rows = _keys(group_map, {"format", "groups"}, set(), "idp-group-map.yaml")
    if rows["format"] != MAP_FORMAT:
        raise FederationError(f"idp-group-map.yaml: format must be {MAP_FORMAT}")
    if not isinstance(rows["groups"], list) or len(rows["groups"]) > MAX_MAPPINGS:
        raise FederationError(
            f"idp-group-map.yaml: groups must be a list of at most {MAX_MAPPINGS}"
        )
    groups: list[tuple[str, str]] = []
    for index, row in enumerate(rows["groups"]):
        label = f"idp-group-map.yaml: entry {index + 1}"
        row = _keys(row, {"upstream_id", "group"}, set(), label)
        gid, name = row["upstream_id"], row["group"]
        if not isinstance(gid, str) or not _ID_RE.fullmatch(gid):
            raise FederationError(f"{label}: upstream_id must be the immutable group id")
        if not isinstance(name, str) or not _GROUP_RE.fullmatch(name):
            raise FederationError(f"{label}: group must be the name of a group of the realm")
        if any(g == gid for g, _ in groups):
            raise FederationError(f"{label}: {gid} is mapped twice")
        groups.append((gid, name))
    return Federation(
        issuer=_url(doc["issuer"], "idp.yaml: issuer"),
        authorization_url=_url(doc["authorization_url"], "idp.yaml: authorization_url"),
        token_url=_url(doc["token_url"], "idp.yaml: token_url"),
        jwks_url=_url(doc["jwks_url"], "idp.yaml: jwks_url"),
        client_id=doc["client_id"],
        client_assertion_audience=(
            _url(doc["client_assertion_audience"], "idp.yaml: client_assertion_audience")
            if "client_assertion_audience" in doc
            else ""
        ),
        acr_values=tuple(acr),
        contact=_text(doc["contact"], "idp.yaml: contact"),
        status_sync=StatusSync(
            kind=sync["kind"],
            url=_url(sync["url"], "idp.yaml: status_sync.url", path=False),
            realm=sync["realm"],
            client_id=sync["client_id"],
        ),
        groups=tuple(groups),
    )


def check_answer(idp_path: Path) -> Federation:
    """An `idp.yaml` named in the question round of `setup` (BE-03 No. 4), with the
    `idp-group-map.yaml` next to it: both read and checked like the installed files."""
    idp = _read(idp_path)
    if idp is None:
        raise FederationError(f"{idp_path} does not exist")
    group_map = _read(idp_path.parent / MAP_FILE.name)
    if group_map is None:
        raise FederationError(
            f"{idp_path.parent / MAP_FILE.name} is missing (idp.yaml needs it next to it)"
        )
    return parse(idp, group_map)


def load(config_dir: Path) -> Federation | None:
    """The federation of this installation; None without `security/idp.yaml`."""
    idp = _read(config_dir / IDP_FILE)
    if idp is None:
        return None
    group_map = _read(config_dir / MAP_FILE)
    if group_map is None:
        raise FederationError(f"{config_dir / MAP_FILE} is missing (idp.yaml needs it)")
    return parse(idp, group_map)


def status_document(fed: Federation) -> dict:
    """What papaia-lifecycle reads: where the directory is and which groups to compare."""
    return {
        "format": STATUS_FORMAT,
        "alias": ALIAS,
        "kind": fed.status_sync.kind,
        "url": fed.status_sync.url,
        "realm": fed.status_sync.realm,
        "client_id": fed.status_sync.client_id,
        "groups": sorted(fed.upstream_ids),
    }


def operations_mail(config_dir: Path) -> str:
    """`PAPAIA_OPERATIONS_MAIL` of the root `.env`: one address or empty."""
    env = common.parse_env_file(config_dir / ".env")
    mail = env.get("PAPAIA_OPERATIONS_MAIL", "").strip()
    if mail and not _MAIL_RE.fullmatch(mail):
        raise FederationError("PAPAIA_OPERATIONS_MAIL must be one mail address")
    return mail


def status_keys(config_dir: Path) -> sak.KeyStore:
    return sak.KeyStore(config_dir / STATUS_KEYS)


def render(config_dir: Path) -> dict | None:
    """The status sync's key (made once) and file for papaia-lifecycle; removes the file
    without federation (the key stays: the provider may still list it). Returns the
    public JWK to register at the provider, or None."""
    fed = load(config_dir)
    keys = status_keys(config_dir)
    if fed is None:
        folder = keys.folder(STATUS_ACCOUNT)
        if not folder.is_symlink() and folder.is_dir():
            (folder / STATUS_FILE).unlink(missing_ok=True)
        return None
    operations_mail(config_dir)
    jwk = keys.public_jwk(STATUS_ACCOUNT) or keys.generate(STATUS_ACCOUNT)
    data = (json.dumps(status_document(fed), indent=2, sort_keys=True) + "\n").encode()
    if keys.read(STATUS_ACCOUNT, STATUS_FILE) != data:
        keys.write(STATUS_ACCOUNT, STATUS_FILE, data)
    return jwk


# ─────────────────────────────────────────────────────────────────────────
# Compose: papaia-lifecycle's way out, and the egress source
# ─────────────────────────────────────────────────────────────────────────


def egress_source(config_dir: Path) -> dict | None:
    """papaia-lifecycle at papaia-egress while the status sync is on: the host of the
    directory, on its port, nothing else."""
    from . import egress

    fed = load(config_dir)
    if fed is None:
        return None
    parts = urllib.parse.urlsplit(fed.status_sync.url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return {
        "name": EGRESS_SOURCE,
        "alias": egress.alias(EGRESS_SOURCE),
        "allow": [{"host": egress.allowed_host(parts.hostname), "ports": [port]}],
        "internal": [],
    }


def network(env: dict[str, str]) -> str:
    project = env.get("PAPAIA_PROJECT") or env.get("COMPOSE_PROJECT_NAME") or "papaia"
    return f"{project}-{EGRESS_SOURCE}-egress"


def override_path(config_dir: Path) -> Path:
    return config_dir / "overrides" / f"docker-compose.{LIFECYCLE_SERVICE}.federation.override.yml"


def lifecycle_command(base: list[str], mail: str, sender: str) -> list[str]:
    """The service's command of the compose file with the status sync switched on; the
    warning mail needs the mail relay, the operations address and the relay's sender."""
    extra = ["--federation-dir=/run/papaia-lifecycle/federation"]
    if mail and sender:
        extra += [
            f"--mail-relay={MAIL_RELAY}:{smtp.RELAY_PORT}",
            f"--alert-to={mail}",
            f"--alert-from={sender}",
        ]
    return [*base, *extra]


def generate_override(config_dir: Path, repo_root: Path) -> Path | None:
    """With federation and the lifecycle profile: papaia-lifecycle on an internal network
    of its own with papaia-egress as its HTTPS proxy (Keycloak and the mail relay stay
    direct), the status sync folder mounted read-only, and the mail relay on the
    service's network. Removed otherwise."""
    from . import egress

    out = override_path(config_dir)
    env = common.parse_env_file(config_dir / ".env")
    profiles = {p.strip() for p in env.get("COMPOSE_PROFILES", "").split(",")}
    fed = load(config_dir)
    if fed is None or "lifecycle" not in profiles:
        out.unlink(missing_ok=True)
        return None
    compose = yaml.safe_load(
        (repo_root / "src" / "infra" / "lifecycle" / "docker-compose.yml").read_text("utf-8")
    )
    base = compose["services"][LIFECYCLE_SERVICE]["command"]
    mail = operations_mail(config_dir)
    relay = smtp.Settings.load(config_dir) if "smtp" in profiles else None
    sender = relay.from_address if relay is not None and relay.configured else ""
    net = network(env)
    proxy = f"http://{egress.alias(EGRESS_SOURCE)}:{egress.PORT}"
    no_proxy = f"keycloak,{MAIL_RELAY}"
    override = {
        "services": {
            LIFECYCLE_SERVICE: {
                "command": lifecycle_command(base, mail, sender),
                "environment": {
                    "HTTPS_PROXY": proxy,
                    "https_proxy": proxy,
                    "HTTP_PROXY": proxy,
                    "http_proxy": proxy,
                    "NO_PROXY": no_proxy,
                    "no_proxy": no_proxy,
                },
                "volumes": [
                    {
                        "type": "bind",
                        "source": f"${{PAPAIA_CONFIG_DIR}}/{STATUS_KEYS}/{STATUS_ACCOUNT}",
                        "target": "/run/papaia-lifecycle/federation",
                        "read_only": True,
                        "bind": {"create_host_path": False},
                    }
                ],
                "networks": {"papaia-lifecycle-net": {}, net: {}},
            },
            egress.SERVICE: {
                "networks": {
                    egress.EGRESS_NETWORK: {},
                    net: {"aliases": [egress.alias(EGRESS_SOURCE)]},
                }
            },
        },
        "networks": {net: {"name": net, "internal": True}},
    }
    if sender and mail:
        override["services"][MAIL_RELAY] = {
            "networks": {"papaia-net": {}, "papaia-lifecycle-net": {}}
        }
    common.atomic_write(out, yaml.safe_dump(override, sort_keys=False, default_flow_style=False))
    return out


# ─────────────────────────────────────────────────────────────────────────
# realm
# ─────────────────────────────────────────────────────────────────────────


def _change(kind: str, name: str, action: str, operation: str, effect: str = "write"):
    return rs.Change(kind, name, action, f"federation_{operation}", effect=effect)


def _flow_spec(fed: Federation) -> list[tuple]:
    """The post sign-in flow: (sub-flow, condition role, negate, refusal text) rows,
    then `allow-access` (a flow whose conditions all pass has to end in a success)."""
    overflow = OVERFLOW_TEXT.format(contact=fed.contact)
    return [
        ("papaia-federation-no-groups", GROUPS_ROLE, "true", overflow),
        ("papaia-federation-overage", OVERAGE_ROLE, "false", overflow),
        ("papaia-federation-acr", ACR_ROLE, "true", ACR_TEXT.format(contact=fed.contact)),
    ]


def _idp_config(fed: Federation) -> dict:
    config = {
        "issuer": fed.issuer,
        "authorizationUrl": fed.authorization_url,
        "tokenUrl": fed.token_url,
        "jwksUrl": fed.jwks_url,
        "useJwksUrl": "true",
        "validateSignature": "true",
        "clientId": fed.client_id,
        "clientAuthMethod": "private_key_jwt",
        "clientAssertionSigningAlg": "RS256",
        # Entra ID finds the certificate of the assertion by its thumbprint.
        "jwtX509HeadersEnabled": "true",
        "pkceEnabled": "true",
        "pkceMethod": "S256",
        "syncMode": "FORCE",
        "defaultScope": "openid",
        "backchannelSupported": "true",
    }
    if fed.client_assertion_audience:
        config["clientAssertionAudience"] = fed.client_assertion_audience
    return config


def _idp(fed: Federation) -> dict:
    return {
        "alias": ALIAS,
        "displayName": "Firmenanmeldung",
        "providerId": "oidc",
        "enabled": True,
        "trustEmail": False,
        "storeToken": False,
        "addReadTokenRoleOnCreate": False,
        "linkOnly": False,
        "hideOnLogin": True,
        "firstBrokerLoginFlowAlias": FIRST_FLOW,
        "postBrokerLoginFlowAlias": CHECK_FLOW,
        "config": _idp_config(fed),
    }


def _mappers(fed: Federation, paths: dict[str, str]) -> dict[str, dict]:
    def role(name: str, claim: str, value: str, target: str) -> dict:
        return {
            "name": name,
            "identityProviderAlias": ALIAS,
            "identityProviderMapper": "oidc-advanced-role-idp-mapper",
            "config": {
                "syncMode": "FORCE",
                "claims": json.dumps([{"key": claim, "value": value}]),
                "are.claim.values.regex": "true",
                "role": target,
            },
        }

    acr = "^(" + "|".join(re.escape(a) for a in fed.acr_values) + ")$"
    wanted = {
        "papaia groups claim": role("papaia groups claim", "groups", ".+", GROUPS_ROLE),
        "papaia group overage": role(
            "papaia group overage", "_claim_names.groups", ".+", OVERAGE_ROLE
        ),
        "papaia acr": role("papaia acr", "acr", acr, ACR_ROLE),
    }
    for gid, name in fed.groups:
        wanted[f"group {gid}"] = {
            "name": f"group {gid}",
            "identityProviderAlias": ALIAS,
            "identityProviderMapper": "oidc-advanced-group-idp-mapper",
            "config": {
                "syncMode": "FORCE",
                "claims": json.dumps([{"key": "groups", "value": gid}]),
                "are.claim.values.regex": "false",
                "group": paths[name],
            },
        }
    return wanted


class _Align:
    def __init__(self, call, apply: bool, audit) -> None:
        self.call, self.apply = call, apply
        self.act = rs._Actions(call, apply, audit, master=True)

    def _get(self, path: str):
        try:
            return self.call("GET", path)
        except Exception as exc:  # noqa: BLE001 - a missing object is not an error here
            if getattr(exc, "code", None) == 404:
                return None
            raise

    # Lists, not single lookups: an object that is not there is no error to tell apart.
    def _role_names(self) -> set[str]:
        return {r.get("name") for r in self.call("GET", "/roles") or [] if isinstance(r, dict)}

    def _provider(self) -> dict | None:
        rows = self.call("GET", "/identity-provider/instances") or []
        found = [r for r in rows if isinstance(r, dict) and r.get("alias") == ALIAS]
        return found[0] if found else None

    # groups and roles ----------------------------------------------------
    def group_paths(self, fed: Federation) -> dict[str, str]:
        """The realm group of every mapping, found before the first write: a mapping to
        a group that does not exist refuses the whole federation."""
        paths: dict[str, str] = {}
        for _, name in fed.groups:
            if name in paths:
                continue
            query = urllib.parse.urlencode({"search": name, "exact": "true"})
            found = [g for g in self.call("GET", f"/groups?{query}") or [] if g.get("name") == name]
            if not found:
                raise FederationError(
                    f"idp-group-map.yaml: the realm has no group {name!r}"
                )
            paths[name] = found[0].get("path") or f"/{name}"
        return paths

    def roles(self) -> None:
        have = self._role_names()
        for name in MARKER_ROLES:
            if name not in have:
                self.act.do(
                    _change("role", name, "created (marker of the last federated sign-in)", "role"),
                    "POST",
                    "/roles",
                    {"name": name, "description": "papaia federation marker, set at sign-in"},
                )

    # flows ---------------------------------------------------------------
    def _executions(self, alias: str) -> list[dict] | None:
        flows = {f.get("alias"): f for f in self.call("GET", "/authentication/flows") or []}
        if alias not in flows:
            return None
        path = f"/authentication/flows/{urllib.parse.quote(alias)}/executions"
        return self.call("GET", path) or []

    def _shape(self, alias: str) -> list[tuple] | None:
        rows = self._executions(alias)
        if rows is None:
            return None
        shape = []
        for row in rows:
            config = {}
            if row.get("authenticationConfig"):
                found = self._get(f"/authentication/config/{row['authenticationConfig']}") or {}
                config = found.get("config") or {}
            shape.append(
                (
                    row.get("level"),
                    row.get("providerId") or row.get("displayName"),
                    row.get("requirement"),
                    tuple(sorted(config.items())),
                )
            )
        return shape

    @staticmethod
    def _wanted_check_shape(fed: Federation) -> list[tuple]:
        shape = []
        for sub, role, negate, text in _flow_spec(fed):
            shape.append((0, sub, "CONDITIONAL", ()))
            shape.append(
                (1, "conditional-user-role", "REQUIRED",
                 tuple(sorted({"condUserRole": role, "negate": negate}.items())))
            )
            shape.append(
                (1, "deny-access-authenticator", "REQUIRED",
                 tuple(sorted({"denyErrorMessage": text}.items())))
            )
        shape.append((0, "allow-access-authenticator", "REQUIRED", ()))
        return shape

    _FIRST_SHAPE = [(0, "idp-create-user-if-unique", "REQUIRED", ())]

    def _requirement(self, alias: str, wanted: dict[str, str]) -> None:
        for row in self._executions(alias) or []:
            key = row.get("providerId") or row.get("displayName")
            want = wanted.get(key, "REQUIRED")
            if row.get("requirement") != want:
                row["requirement"] = want
                path = f"/authentication/flows/{urllib.parse.quote(alias)}/executions"
                self.call("PUT", path, row)

    def _build(self, alias: str, fed: Federation) -> None:
        """(Re)create a flow: its executions are removed and added anew."""
        q = urllib.parse.quote
        if self._executions(alias) is None:
            self.call(
                "POST",
                "/authentication/flows",
                {"alias": alias, "providerId": "basic-flow", "topLevel": True, "builtIn": False,
                 "description": "papaia federation (managed by papaia-ctl realm sync)"},
            )
        for row in self._executions(alias) or []:
            if row.get("level") == 0:
                self.call("DELETE", f"/authentication/executions/{row['id']}")
        if alias == FIRST_FLOW:
            self.call("POST", f"/authentication/flows/{q(alias)}/executions/execution",
                      {"provider": "idp-create-user-if-unique"})
            self._requirement(alias, {})
            return
        subs = {}
        for sub, role, negate, text in _flow_spec(fed):
            self.call("POST", f"/authentication/flows/{q(alias)}/executions/flow",
                      {"alias": sub, "type": "basic-flow", "provider": "registration-page-form"})
            for provider in ("conditional-user-role", "deny-access-authenticator"):
                self.call("POST", f"/authentication/flows/{q(sub)}/executions/execution",
                          {"provider": provider})
            subs[sub] = (role, negate, text)
        self.call("POST", f"/authentication/flows/{q(alias)}/executions/execution",
                  {"provider": "allow-access-authenticator"})
        self._requirement(alias, {sub: "CONDITIONAL" for sub in subs})
        current = None
        for row in self._executions(alias) or []:
            if row.get("level") == 0:
                current = row.get("displayName")
                continue
            if current not in subs:
                continue
            self.call("PUT", f"/authentication/flows/{q(current)}/executions",
                      dict(row, requirement="REQUIRED"))
            role, negate, text = subs[current]
            if row.get("providerId") == "conditional-user-role":
                body = {"alias": f"{current}-condition",
                        "config": {"condUserRole": role, "negate": negate}}
            else:
                body = {"alias": f"{current}-deny", "config": {"denyErrorMessage": text}}
            self.call("POST", f"/authentication/executions/{row['id']}/config", body)

    def flows(self, fed: Federation) -> None:
        for alias, wanted in (
            (FIRST_FLOW, self._FIRST_SHAPE),
            (CHECK_FLOW, self._wanted_check_shape(fed)),
        ):
            shape = self._shape(alias)
            if shape == wanted:
                continue
            action = "created" if shape is None else "realigned"
            change = _change("flow", alias, action, "flow")
            self.act.changes.append(change)
            print(f"{'  ' if self.apply else 'fail: '}flow {alias}: {action}", flush=True)
            if not self.apply:
                continue
            try:
                self._build(alias, fed)
            except Exception:
                self.act._audit(change, "error", "transport")
                raise
            self.act._audit(change, "allowed")

    # provider and mappers ------------------------------------------------
    def provider(self, fed: Federation) -> None:
        wanted = _idp(fed)
        current = self._provider()
        if current is None:
            self.act.do(_change("identity-provider", ALIAS, "created", "provider"),
                        "POST", "/identity-provider/instances", wanted)
            return
        off = sorted(k for k, v in wanted.items() if k != "config" and current.get(k) != v)
        have = current.get("config") or {}
        off += sorted(f"config.{k}" for k, v in wanted["config"].items() if have.get(k) != v)
        if "clientAssertionAudience" in have and not fed.client_assertion_audience:
            off.append("config.clientAssertionAudience")
        if off:
            config = {k: v for k, v in have.items() if k != "clientAssertionAudience"}
            body = dict(current, **{k: v for k, v in wanted.items() if k != "config"})
            body["config"] = dict(config, **wanted["config"])
            self.act.do(
                _change("identity-provider", ALIAS, f"realigned: {', '.join(off)}", "provider"),
                "PUT", f"/identity-provider/instances/{ALIAS}", body,
            )

    def mappers(self, fed: Federation, paths: dict[str, str]) -> None:
        base = f"/identity-provider/instances/{ALIAS}/mappers"
        wanted = _mappers(fed, paths)
        current = {m.get("name"): m for m in (self._get(base) or []) if isinstance(m, dict)}
        for name, mapper in current.items():
            if name not in wanted:
                self.act.do(_change("idp-mapper", str(name), "removed", "mapper", "delete"),
                            "DELETE", f"{base}/{mapper['id']}")
        for name, mapper in wanted.items():
            have = current.get(name)
            if have is None:
                self.act.do(_change("idp-mapper", name, "created", "mapper"), "POST", base, mapper)
            elif (
                have.get("identityProviderMapper") != mapper["identityProviderMapper"]
                or (have.get("config") or {}) != mapper["config"]
            ):
                self.act.do(_change("idp-mapper", name, "realigned", "mapper"),
                            "PUT", f"{base}/{have['id']}", dict(mapper, id=have["id"]))

    # browser flow --------------------------------------------------------
    def _redirector(self) -> dict | None:
        realm = self.call("GET", "") or {}
        flow = realm.get("browserFlow") or "browser"
        path = f"/authentication/flows/{urllib.parse.quote(flow)}/executions"
        rows = self.call("GET", path) or []
        for row in rows:
            if row.get("providerId") == "identity-provider-redirector":
                return row
        return None

    def redirect(self, on: bool) -> None:
        row = self._redirector()
        if row is None:
            if on:
                raise FederationError(
                    "the browser flow of the realm has no identity provider redirector"
                )
            return
        config = None
        if row.get("authenticationConfig"):
            config = self._get(f"/authentication/config/{row['authenticationConfig']}")
        provider = ((config or {}).get("config") or {}).get("defaultProvider")
        if on and provider != ALIAS:
            if config is None:
                self.act.do(
                    _change("flow", "browser", f"sign-in page leads to {ALIAS}", "redirect"),
                    "POST", f"/authentication/executions/{row['id']}/config",
                    {"alias": REDIRECT_CONFIG, "config": {"defaultProvider": ALIAS}},
                )
            else:
                body = dict(config, config=dict(config.get("config") or {}, defaultProvider=ALIAS))
                self.act.do(
                    _change("flow", "browser", f"sign-in page leads to {ALIAS}", "redirect"),
                    "PUT", f"/authentication/config/{config['id']}", body,
                )
        elif not on and config is not None and config.get("alias") == REDIRECT_CONFIG:
            self.act.do(
                _change("flow", "browser", "redirect to the provider removed", "redirect",
                        "delete"),
                "DELETE", f"/authentication/config/{config['id']}",
            )

    # events ------------------------------------------------------------
    def events(self) -> None:
        """The realm stores refused federated sign-ins (papaia-lifecycle reads them to
        write `idp_group_overflow`); other stored types stay."""
        config = self.call("GET", "/events/config") or {}
        types = list(config.get("enabledEventTypes") or [])
        enabled = config.get("eventsEnabled") is True
        if enabled and (not types or REFUSED_EVENT in types):
            return
        body = dict(config, eventsEnabled=True)
        body["enabledEventTypes"] = sorted(set(types if enabled else []) | {REFUSED_EVENT})
        if not config.get("eventsExpiration"):
            body["eventsExpiration"] = rs.EVENTS_EXPIRATION
        self.act.do(
            _change("realm", "papaia", "refused federated sign-ins stored", "events"),
            "PUT", "/events/config", body,
        )

    # removal -------------------------------------------------------------
    def remove(self) -> None:
        self.redirect(False)
        if self._provider() is not None:
            self.act.do(_change("identity-provider", ALIAS, "removed, no idp.yaml", "provider",
                                "delete"),
                        "DELETE", f"/identity-provider/instances/{ALIAS}")
        flows = {f.get("alias"): f for f in self.call("GET", "/authentication/flows") or []}
        for alias in (CHECK_FLOW, FIRST_FLOW):
            if alias in flows:
                self.act.do(_change("flow", alias, "removed, no idp.yaml", "flow", "delete"),
                            "DELETE", f"/authentication/flows/{flows[alias]['id']}")
        have = self._role_names()
        for name in MARKER_ROLES:
            if name in have:
                self.act.do(_change("role", name, "removed, no idp.yaml", "role", "delete"),
                            "DELETE", f"/roles/{name}")


def align(call, fed: Federation | None, *, apply: bool, audit=None) -> list:
    """Compare (and with `apply` correct) the federation of the `papaia` realm; `call`
    is the master admin's Admin API call of the realm. Returns the deviations."""
    run = _Align(call, apply, audit)
    if fed is None:
        run.remove()
        return run.act.changes
    paths = run.group_paths(fed)
    run.roles()
    run.flows(fed)
    run.provider(fed)
    run.mappers(fed, paths)
    run.redirect(True)
    run.events()
    return run.act.changes
