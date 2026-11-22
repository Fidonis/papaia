"""Hardening of the `papaia` realm: realm settings, sign-in clients and one client policy.

One target for two writers: `render_core.bake_realm_secrets` bakes it into the rendered
realm of a new installation, and `papaia-ctl realm sync` applies it to an existing realm
(Keycloak's `--import-realm` skips a realm that exists).

Realm settings follow the security profile of the installation (security_profile.py, the
one definition of its values):

- `standard` (default): `sslRequired: external`;
- `kritis`: `sslRequired: all`; every configured host must be https.

Offline sessions (the delegations of Flow and the assistant) idle and live as long as the
installation's delegation lifetime says (delegation_lifetime: default 90 / 180 days, up to
365 days each; `kritis` 7 / 30 days at most), with the maximum age always switched on; a
value above the profile's bound is refused. Both profiles: access tokens live 240 s,
refresh tokens are replaced on every use, brute-force protection is on (5 failures, a
wait from 60 s rising to 15 min, no permanent lockout), usernames cannot be changed,
self-registration is off.

Clients (all but the bearer-only ones, which never obtain a token): no password grant, no
implicit flow; a public client with the code flow uses PKCE S256. The redirect URIs, web
origins and post-logout redirects of the realm template's sign-in clients are computed
from their configured hosts (`<public URL>/*`; oauth2-proxy the exact callbacks of the
forward-auth proxy and of the Nginx Proxy Manager's proxy). Another
client keeps only entries that name a full host, with a wildcard at most as the last
character of the path; a relative entry stays when the client has an absolute root URL.
Keycloak's own clients keep their relative URIs.

A public client never carries `standard.token.exchange.enabled` (only confidential
clients exchange tokens).

Client policy `papaia-hardening`: for every client with `papaia.managed=true`, PKCE is
enforced and the password grant and the implicit flow are rejected, whatever a client's
own switches say. Keycloak refuses any update of such a client whose PKCE method is not
S256, so every managed client carries it, also those that never sign anyone in.

Accounts: the realm template ships one account, `admin` (realm role `papaia-admin`),
without a password of its own. The rendered realm gives it `KC_REALM_ADMIN_PASSWORD`
(generated at setup) as a temporary password, to be changed at the first sign-in; without
that value it gets no password at all. No account of the rendered realm has a fixed
password. The 1.9.0 template also shipped `admin`/`admin` and `testuser`/`testuser`;
`known_password` recognises such an account of an existing realm, and realm sync takes
the known password away.
"""

from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass, field

from . import common, security_profile
from . import delegation_lifetime as dl
from .keycloak_role_sync import _compose_value

PROFILE_KEY = security_profile.KEY
# Variables of 1.10.0 pre-releases; the lifetime is the setting of delegation_lifetime.
RETIRED_KEYS = ("KC_OFFLINE_SESSION_IDLE_DAYS", "KC_OFFLINE_SESSION_MAX_DAYS")
DAY = 86400
PKCE = "pkce.code.challenge.method"
MANAGED = "papaia.managed"
SWITCHES = ("directAccessGrantsEnabled", "implicitFlowEnabled")
POST_LOGOUT = "post.logout.redirect.uris"
TOKEN_EXCHANGE = "standard.token.exchange.enabled"
CLIENT_POLICY = "papaia-hardening"
REALM_ADMIN_PASSWORD_KEY = "KC_REALM_ADMIN_PASSWORD"
# A generated value is far longer; this only refuses a hand-typed word.
MIN_PASSWORD = 16
UPDATE_PASSWORD = "UPDATE_PASSWORD"
# The accounts the realm templates up to 1.9.0 created, with their password equal to the
# user name, by user name and e-mail address.
REALM_ADMIN = "admin"
TEMPLATE_USERS = {"admin": "admin@papaia.lan", "testuser": "testuser@papaia.lan"}
# A password credential created within this many milliseconds of its account was stored
# with it (a realm import or a create with credentials) and never changed since.
STORED_WITH_ACCOUNT_MS = 5000

# Keycloak's own clients: their relative URIs resolve against Keycloak's own host.
BUILTIN_CLIENTS = frozenset(
    {
        "account",
        "account-console",
        "admin-cli",
        "broker",
        "realm-management",
        "security-admin-console",
    }
)

# The sign-in clients of the realm template and where their public URL is configured:
# (.env node, key). A client whose URL is not set gets no redirect.
_CLIENT_HOSTS = {
    "librechat": (("ai/librechat", "DOMAIN_CLIENT"), ("ai/librechat", "DOMAIN_SERVER")),
    "litellm": (("", "LITELLM_PUBLIC_URL"),),
    "localai": (("", "LOCALAI_PUBLIC_URL"),),
    "papaia-manager": (("", "MANAGER_PUBLIC_URL"),),
}


class HardeningError(ValueError):
    """A security profile, an offline-session setting or a host that cannot be used."""


@dataclass(frozen=True)
class Settings:
    profile: str = "standard"
    idle_days: int = dl.DEFAULTS["standard"][0]
    max_days: int = dl.DEFAULTS["standard"][1]

    def realm(self) -> dict:
        """The realm settings to enforce (Keycloak's realm representation)."""
        return {
            "sslRequired": security_profile.PROFILES[self.profile].ssl_required,
            "registrationAllowed": False,
            "editUsernameAllowed": False,
            "accessTokenLifespan": 240,
            "revokeRefreshToken": True,
            "refreshTokenMaxReuse": 0,
            "ssoSessionIdleTimeout": 1800,
            "ssoSessionMaxLifespan": 36000,
            "offlineSessionIdleTimeout": self.idle_days * DAY,
            "offlineSessionMaxLifespanEnabled": True,
            "offlineSessionMaxLifespan": self.max_days * DAY,
            "bruteForceProtected": True,
            "permanentLockout": False,
            "failureFactor": 5,
            "waitIncrementSeconds": 60,
            "maxFailureWaitSeconds": 900,
        }


@dataclass(frozen=True)
class ClientUris:
    redirects: tuple[str, ...]
    origins: tuple[str, ...]


@dataclass
class Hardening:
    settings: Settings = field(default_factory=Settings)
    clients: dict[str, ClientUris] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    # KC_REALM_ADMIN_PASSWORD (a secret: never printed, never in an audit row); None when
    # it is not set.
    realm_admin_password: str | None = field(default=None, repr=False)

    @property
    def https_only(self) -> bool:
        return security_profile.PROFILES[self.settings.profile].https_only


def _value(env: dict, key: str) -> str:
    return _compose_value(str(env.get(key) or "")).strip()


def _unset(value: str) -> bool:
    return not value or common.is_placeholder(value) or value.startswith(("CHANGE_ME", "GENERATE_"))


def _base(key: str, raw: str, https_only: bool) -> tuple[str, str]:
    """The origin and the path (without a trailing slash) of a configured public URL."""
    parts = urllib.parse.urlsplit(raw)
    try:
        port = parts.port
    except ValueError:
        port = None
        parts = parts._replace(netloc="*")
    if (
        parts.scheme not in ("http", "https")
        or not parts.hostname
        or "*" in parts.netloc
        or parts.username is not None
        or parts.query
        or parts.fragment
        or "*" in parts.path
    ):
        raise HardeningError(f"{key}={raw!r}: not a URL with a fully named host")
    if https_only and parts.scheme != "https":
        raise HardeningError(f"{key}={raw!r}: the kritis security profile requires https")
    host = parts.hostname if ":" not in parts.hostname else f"[{parts.hostname}]"
    origin = f"{parts.scheme}://{host}" + (f":{port}" if port is not None else "")
    return origin, parts.path.rstrip("/")


def load(
    env: dict, librechat: dict | None = None, *, lifetime: tuple[int, int] | None = None
) -> Hardening:
    """The hardening target from the root `.env` merged with the Keycloak `.env` (`env`),
    LibreChat's `.env` and the stored delegation lifetime (`lifetime`, from
    delegation_lifetime.stored; None: the profile's default). HardeningError for a value
    that cannot be used."""
    try:
        profile = dl.profile_of(env)
        offline = dl.resolve(profile, lifetime)
    except dl.LifetimeError as exc:
        raise HardeningError(str(exc)) from None
    hardening = Hardening(Settings(profile, offline.idle_days, offline.max_days))
    for key in RETIRED_KEYS:
        if _value(env, key):
            hardening.notes.append(
                f"{key} is no longer read; set the delegation lifetime with "
                "'papaia-ctl delegations lifetime'"
            )
    password = _value(env, REALM_ADMIN_PASSWORD_KEY)
    if not _unset(password):
        if len(password) < MIN_PASSWORD or password in TEMPLATE_USERS:
            raise HardeningError(
                f"{REALM_ADMIN_PASSWORD_KEY}: not a generated value (at least {MIN_PASSWORD} "
                "characters; papaia-ctl setup generates one)"
            )
        hardening.realm_admin_password = password
    https_only = hardening.https_only
    nodes = {"": env, "ai/librechat": librechat or {}}

    def add(client_id: str, key: str, raw: str, redirect: str) -> None:
        origin, _ = _base(key, raw, https_only)
        if origin.startswith("http://"):
            hardening.notes.append(
                f"{key}={origin} is plain http: the redirects of {client_id} are not https"
            )
        current = hardening.clients.get(client_id, ClientUris((), ()))
        hardening.clients[client_id] = ClientUris(
            tuple(dict.fromkeys((*current.redirects, redirect))),
            tuple(dict.fromkeys((*current.origins, origin))),
        )

    for client_id, sources in _CLIENT_HOSTS.items():
        for node, key in sources:
            raw = _value(nodes[node], key)
            if not _unset(raw):
                origin, path = _base(key, raw, https_only)
                add(client_id, key, raw, f"{origin}{path}/*")
    # oauth2-proxy signs in on its own port of PAPAIA_HOST and names its exact callback
    # (src/infra/oauth2-proxy/docker-compose.yml: --redirect-url).
    host, port = _value(env, "PAPAIA_HOST"), _value(env, "OAUTH2_PROXY_EXT_PORT")
    if not _unset(host) and not _unset(port):
        _base("PAPAIA_HOST", host, https_only)
        callback = f"{host.rstrip('/')}:{port}/oauth2/callback"
        try:
            origin, _ = _base("OAUTH2_PROXY_EXT_PORT", callback, https_only)
        except HardeningError:
            # PAPAIA_HOST with a port of its own: oauth2-proxy's callback is no URL either.
            hardening.notes.append(f"oauth2-proxy: {callback!r} is no URL; it gets no redirect")
        else:
            add("oauth2-proxy", "PAPAIA_HOST", callback, f"{origin}/oauth2/callback")
    # The forward-auth proxy of the Nginx Proxy Manager signs in with the same client
    # (src/infra/nginx/docker-compose.yml: --redirect-url).
    npm = _value(env, "NPM_ADMIN_HOST")
    if not _unset(npm):
        origin, path = _base("NPM_ADMIN_HOST", npm, https_only)
        add("oauth2-proxy", "NPM_ADMIN_HOST", npm, f"{origin}{path}/oauth2/callback")
    return hardening


# ─────────────────────────────────────────────────────────────────────────
# clients
# ─────────────────────────────────────────────────────────────────────────


def redirect_problem(uri: str, *, https_only: bool) -> str | None:
    """Why `uri` is not acceptable as a redirect URI, or None: an absolute http(s) URL
    with a fully named host, a wildcard at most as the last character of the path."""
    if uri in ("*", "+"):
        return "a wildcard as the whole value"
    parts = urllib.parse.urlsplit(uri)
    if parts.scheme not in ("http", "https") or not uri.startswith(f"{parts.scheme}://"):
        return "not an absolute http(s) URL"
    if not parts.hostname or "*" in parts.netloc:
        return "no fully named host"
    if parts.username is not None or parts.password is not None:
        return "a user name in the URL"
    if "*" in parts.query or "*" in parts.fragment:
        return "a wildcard in the query or fragment"
    if "*" in parts.path[:-1]:
        return "a wildcard before the last character of the path"
    if https_only and parts.scheme != "https":
        return "not https"
    return None


def _origin_problem(origin: str, https_only: bool) -> bool:
    parts = urllib.parse.urlsplit(origin)
    return (
        redirect_problem(origin, https_only=https_only) is not None
        or parts.path not in ("",)
        or "*" in origin
    )


def _absolute_root(client: dict) -> bool:
    root = client.get("rootUrl") or ""
    return redirect_problem(root, https_only=False) is None and "*" not in root


def _kept(uris: list[str], client: dict, https_only: bool) -> list[str]:
    """The entries of a client without a configured host that may stay."""
    kept = []
    for uri in uris:
        if uri.startswith("/") and not uri.startswith("//"):
            if _absolute_root(client) and "*" not in uri[:-1]:
                kept.append(uri)
        elif redirect_problem(uri, https_only=https_only) is None:
            kept.append(uri)
    return kept


def harden_client(
    client: dict, hardening: Hardening, *, uris_only: bool = False
) -> tuple[dict, list[str]]:
    """The fields of `client` to change (a partial client representation; `attributes`
    complete, as Keycloak replaces the map) and the names of the settings that drift.
    `uris_only`: leave the switches to the caller (the managed clients' own target)."""
    if client.get("bearerOnly"):
        return {}, []
    client_id = client.get("clientId", "")
    builtin = client_id in BUILTIN_CLIENTS
    body: dict = {}
    attributes = dict(client.get("attributes") or {})
    wanted_attributes = dict(attributes)
    if not uris_only:
        for key in SWITCHES:
            if client.get(key):
                body[key] = False
    managed = attributes.get(MANAGED) == "true"
    public_sign_in = client.get("publicClient") and client.get("standardFlowEnabled")
    if not uris_only and (managed or public_sign_in):
        wanted_attributes[PKCE] = "S256"
    if client.get("publicClient") and str(attributes.get(TOKEN_EXCHANGE, "")).lower() == "true":
        wanted_attributes[TOKEN_EXCHANGE] = "false"
    if not builtin:
        configured = hardening.clients.get(client_id)
        redirects = list(client.get("redirectUris") or [])
        origins = list(client.get("webOrigins") or [])
        logout = [u for u in (attributes.get(POST_LOGOUT) or "").split("##") if u]
        if configured is not None:
            new_redirects = list(configured.redirects)
            new_origins = list(configured.origins)
        else:
            new_redirects = _kept(redirects, client, hardening.https_only)
            new_origins = [o for o in origins if not _origin_problem(o, hardening.https_only)]
        if sorted(new_redirects) != sorted(redirects):
            body["redirectUris"] = new_redirects
        if sorted(new_origins) != sorted(origins):
            body["webOrigins"] = new_origins
        if configured is not None or any(u in ("+", "*") for u in logout):
            new_logout = new_redirects
        else:
            new_logout = _kept(logout, client, hardening.https_only)
        if sorted(new_logout) != sorted(logout):
            if new_logout:
                wanted_attributes[POST_LOGOUT] = "##".join(new_logout)
            else:
                wanted_attributes.pop(POST_LOGOUT, None)
    drift = [k for k in body]
    drift += sorted(
        k
        for k in set(wanted_attributes) | set(attributes)
        if wanted_attributes.get(k) != attributes.get(k)
    )
    if body or wanted_attributes != attributes:
        # The client policy checks the switches and the PKCE method on every update of a
        # managed client and refuses one that leaves them out (Keycloak 26.7.0: 400, or
        # 500 for a missing switch), so every update names them.
        body.update({key: False for key in SWITCHES})
        if managed:
            wanted_attributes[PKCE] = "S256"
        body["attributes"] = wanted_attributes
    return body, drift


# ─────────────────────────────────────────────────────────────────────────
# client policy
# ─────────────────────────────────────────────────────────────────────────


def client_profile() -> dict:
    return {
        "name": CLIENT_POLICY,
        "description": "papaia: PKCE S256, no password grant, no implicit flow",
        "executors": [
            {"executor": executor, "configuration": {"auto-configure": "false"}}
            for executor in ("pkce-enforcer", "reject-implicit-grant", "reject-ropc-grant")
        ],
    }


def client_policy() -> dict:
    return {
        "name": CLIENT_POLICY,
        "description": "papaia: hardening of every managed client",
        "enabled": True,
        "conditions": [
            {
                "condition": "client-attributes",
                "configuration": {
                    "is-negative-logic": False,
                    "attributes": json.dumps([{"key": "papaia.managed", "value": "true"}]),
                },
            }
        ],
        "profiles": [CLIENT_POLICY],
    }


def _normal(value: object) -> object:
    """A comparable form of a profile or policy (Keycloak echoes configuration values as
    strings or booleans and Map values as JSON text)."""
    if isinstance(value, dict):
        return {k: _normal(v) for k, v in value.items() if k != "description"}
    if isinstance(value, list):
        return [_normal(v) for v in value]
    if isinstance(value, str) and value[:1] in ("[", "{"):
        try:
            return _normal(json.loads(value))
        except ValueError:
            return value
    if isinstance(value, bool):
        return str(value).lower()
    return value


def same(have: dict | None, want: dict) -> bool:
    return have is not None and _normal(have) == _normal(want)


# ─────────────────────────────────────────────────────────────────────────
# rendered realm, report
# ─────────────────────────────────────────────────────────────────────────


def apply_to_realm(realm: dict, hardening: Hardening) -> None:
    """Bake the target into a realm representation (the rendered realm-import file).
    HardeningError when an account of it would have a fixed password."""
    realm.update(hardening.settings.realm())
    for client in realm.get("clients") or []:
        body, _ = harden_client(client, hardening)
        client.update(body)
    for user in realm.get("users") or []:
        if user.get("username") == REALM_ADMIN and hardening.realm_admin_password:
            user["credentials"] = [
                {"type": "password", "value": hardening.realm_admin_password, "temporary": True}
            ]
    problems = user_problems(realm)
    if problems:
        raise HardeningError("; ".join(problems))


def user_problems(realm: dict) -> list[str]:
    """The accounts of a realm representation that would get a fixed password: one that
    is not temporary, is a placeholder or the user name, or lacks the forced change
    (Keycloak's import does not add UPDATE_PASSWORD for a temporary password)."""
    problems = []
    for user in realm.get("users") or []:
        name = user.get("username") or "?"
        for credential in user.get("credentials") or []:
            if credential.get("type") != "password":
                continue
            value = str(credential.get("value") or "")
            if credential.get("temporary") is not True:
                problems.append(f"account {name}: a password that is not temporary")
            elif _unset(value) or "${" in value or value == name or value in TEMPLATE_USERS:
                problems.append(
                    f"account {name}: a password that is its own user name, a placeholder "
                    "or empty"
                )
            elif UPDATE_PASSWORD not in (user.get("requiredActions") or []):
                problems.append(
                    f"account {name}: a password without the required action {UPDATE_PASSWORD}"
                )
    return problems


def known_password(user: dict, credentials: list[dict]) -> bool:
    """Whether `user` (an account of a live realm) is one the 1.9.0 template created and
    can still sign in with its user name as password: the template's name and e-mail
    address, enabled, its password stored with the account and never changed, and no
    forced change pending (a new installation's `admin` has one until its first
    sign-in)."""
    name = user.get("username")
    if name not in TEMPLATE_USERS:
        return False
    if str(user.get("email") or "").lower() != TEMPLATE_USERS[name]:
        return False
    if user.get("enabled") is not True or UPDATE_PASSWORD in (user.get("requiredActions") or []):
        return False
    passwords = [c for c in credentials if c.get("type") == "password"]
    created = user.get("createdTimestamp")
    if not passwords or not isinstance(created, int):
        return False
    return all(
        isinstance(c.get("createdDate"), int)
        and abs(c["createdDate"] - created) <= STORED_WITH_ACCOUNT_MS
        for c in passwords
    )


def offline_limits(realm: dict) -> dict:
    """The current offline-session limits of a realm representation, in days, for the
    permission report (None: no maximum age)."""
    idle = int(realm.get("offlineSessionIdleTimeout") or 0) // DAY
    age = None
    if realm.get("offlineSessionMaxLifespanEnabled"):
        age = int(realm.get("offlineSessionMaxLifespan") or 0) // DAY
    return {"idle_days": idle, "max_age_days": age}


def describe(realm: dict, profile: str) -> str:
    limits = offline_limits(realm)
    age = "none" if limits["max_age_days"] is None else f"{limits['max_age_days']} d"
    return f"offline sessions: idle {limits['idle_days']} d, max age {age} (profile {profile})"
