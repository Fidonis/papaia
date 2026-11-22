"""The security profile of an installation: the one definition (ADR 0022).

`PAPAIA_SECURITY_PROFILE` in the root `.env` takes one of two values. This module is the
only place in the core that names the variable, its values and what each value means;
every other part of papaia-ctl (realm hardening, the delegation lifetime, the platform
PKI, the service catalog) asks it, and modules read the same variable from the root
`.env` instead of carrying a switch of their own.

| Setting                                  | `standard`           | `kritis`              |
|------------------------------------------|----------------------|-----------------------|
| Realm `sslRequired`                      | `external`           | `all`                 |
| Configured public hosts                  | http or https        | https only            |
| Offline sessions: idle / max age (days)  | default 90 / 180, up | default and upper     |
|                                          | to 365 / 365         | bound 7 / 30          |
| TLS between containers                   | ends at the reverse  | same as `standard`;   |
|                                          | proxy; the audit     | links between core    |
|                                          | ingest uses mutual   | containers do not use |
|                                          | TLS with its own CA  | TLS yet               |
| Platform certificates                    | issued for every     | issued for every      |
|                                          | `pki:` request       | `pki:` request        |
| Add-on without a `pki:` request          | allowed              | refused               |

The table says what the core enforces today. Under `kritis` an add-on cannot run without
certificates of the platform PKI; whether it uses them on its links is up to the add-on.

The same table is in docs/configuration.md; `TABLE` below is what both are checked against.
"""

from __future__ import annotations

from dataclasses import dataclass

KEY = "PAPAIA_SECURITY_PROFILE"
DEFAULT = "standard"


@dataclass(frozen=True)
class Profile:
    name: str
    # Keycloak's sslRequired for the papaia realm.
    ssl_required: str
    # Every configured public host must be https.
    https_only: bool
    # Defaults of offline sessions (the delegation lifetime), in days.
    offline_idle_days: int
    offline_max_days: int
    # Upper bounds of the delegation lifetime the administration may set, in days.
    offline_idle_limit: int
    offline_max_limit: int
    # An add-on must declare a `pki:` request to be installed or started.
    addon_pki_required: bool


PROFILES = {
    "standard": Profile(
        name="standard",
        ssl_required="external",
        https_only=False,
        offline_idle_days=90,
        offline_max_days=180,
        offline_idle_limit=365,
        offline_max_limit=365,
        addon_pki_required=False,
    ),
    "kritis": Profile(
        name="kritis",
        ssl_required="all",
        https_only=True,
        offline_idle_days=7,
        offline_max_days=30,
        offline_idle_limit=7,
        offline_max_limit=30,
        addon_pki_required=True,
    ),
}

# Rows of the table in docs/configuration.md: (setting, standard, kritis).
TABLE = (
    ("Realm `sslRequired`", "`external`", "`all`"),
    ("Configured public hosts", "http or https", "https only"),
    (
        "Offline sessions, idle / max age (days)",
        "default 90 / 180, up to 365 / 365",
        "default and upper bound 7 / 30",
    ),
    (
        "TLS between containers",
        "ends at the reverse proxy; the audit ingest uses mutual TLS with its own CA",
        "same as `standard`; links between core containers do not use TLS yet",
    ),
    ("Platform certificates", "issued for every `pki:` request", "issued for every `pki:` request"),
    ("Add-on without a `pki:` request", "allowed", "refused"),
)


class ProfileError(ValueError):
    """`PAPAIA_SECURITY_PROFILE` holds a value that is not a profile."""


def name_of(env: dict) -> str:
    """The profile name in `env` (the root `.env`), validated. Empty means `standard`."""
    raw = str(env.get(KEY) or "").strip().strip("'\"")
    profile = raw or DEFAULT
    if profile not in PROFILES:
        raise ProfileError(f"{KEY}={raw!r}: must be standard or kritis")
    return profile


def load(env: dict) -> Profile:
    """The profile of the installation whose root `.env` is `env`."""
    return PROFILES[name_of(env)]
