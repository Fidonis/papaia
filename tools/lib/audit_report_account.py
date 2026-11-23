"""The report account of papaia-audit, `svc-papaia-audit-report`, the audience
`papaia-audit` and its one exchange right, kept by the realm sync (security 1.16, OPS-19;
docs/audit.md, "Permission report").

While the Compose profile `audit` is active (always, `setup` keeps it), `papaia-ctl realm
sync` makes sure the `papaia` realm holds exactly this (with the master admin, every
change one `papaia.audit/1` row of the sync):

- the client `svc-papaia-audit-report`: client_credentials with `private_key_jwt` (ES256)
  only, the public key of `$PAPAIA_CONFIG_DIR/security/service-accounts/
  svc-papaia-audit-report/private-key.pem`, no sign-in flow, no password grant, no token
  exchange, `fullScopeAllowed: false`;
- its service-account user holds `realm-management` `view-users` and nothing else, also
  in its token scope: no write right, no other client or realm role, no group. Measured
  against Keycloak 26.7.0 (docs/adr/0025): without a role every read of the report is
  refused (403); `query-users` lists no person and reads no role mapping, group or
  offline session; `view-users` reads all of them and is a composite of `query-users`
  and `query-groups`. The client list (`view-clients`) and the realm's offline-session
  limits (`view-realm`; with `view-users` alone the realm answers without them) are not
  read: both come from the inputs file papaia-ctl writes (lib/access_report.py);
- the audience `papaia-audit`: a bearer-only client without secret (part of the plan of
  `realm_sync` while the profile is active, `core_audiences`), persons only;
- one platform pairing `papaia-manager -> papaia-audit` (effect r): standard token
  exchange, one audience, a session required (the person policies of the realm sync).
  `pairings.yaml` cannot name `papaia-audit`; the only other platform pairing is
  `papaia-me -> papaia-audit` (effect x, a person's own read tickets) while the profile
  `me` is on as well (lib/me_area.py).
  The pairing is listed in the permission report's system rows as asked for and
  confirmed by `platform`.

Without the profile the account and its key folder are removed.
"""

from __future__ import annotations

from . import people_account as pa
from . import realm_sync as rs
from . import service_account_keys as sak

CLIENT_ID = "svc-papaia-audit-report"
AUDIENCE = "papaia-audit"
PROFILE = "audit"
REPORT_ROLES = ("view-users",)
EXCHANGE_CLIENT = "papaia-manager"
EXCHANGE_EFFECTS = ("r",)

ACCOUNT = pa.CoreAccount(
    CLIENT_ID,
    PROFILE,
    REPORT_ROLES,
    {"de": "Berechtigungsbericht (nur lesen)", "en": "Permission report (read only)"},
    "audit_report",
)


def enabled(tree: dict) -> bool:
    profiles = tree.get("", {}).get("COMPOSE_PROFILES", "")
    return PROFILE in {p.strip() for p in profiles.split(",")}


def core_audiences(tree: dict) -> frozenset[str]:
    """The audiences the core serves itself under the active profiles."""
    return frozenset({AUDIENCE}) if enabled(tree) else frozenset()


def platform_pairings(tree: dict) -> list[rs.Pairing]:
    """The exchange rights the realm sync sets itself, not an operator."""
    if not enabled(tree):
        return []
    return [
        rs.Pairing(
            EXCHANGE_CLIENT,
            AUDIENCE,
            EXCHANGE_EFFECTS,
            True,
            rs.PLATFORM_PERSON,
            rs.PLATFORM_PERSON,
        )
    ]


def align(call, keys: sak.KeyStore, *, enabled: bool, apply: bool, audit=None) -> list:
    """Compare (and with `apply` correct) the report account; `call` is the master
    admin's Admin API call of the `papaia` realm. Returns the deviations."""
    return pa.align(call, keys, enabled=enabled, apply=apply, audit=audit, account=ACCOUNT)
