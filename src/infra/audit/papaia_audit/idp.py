"""The `papaia` realm's Admin API as `svc-papaia-audit-report`, for the permission report
(report.py; docs/audit.md, "Permission report").

The account signs in with client_credentials and a client assertion (`private_key_jwt`,
ES256 on P-256, RFC 7523); the key is mounted read-only from
`$PAPAIA_CONFIG_DIR/security/service-accounts/svc-papaia-audit-report/` into papaia-audit
alone. It holds `realm-management` `view-users` and nothing else. This client sends GET
requests only, to paths below `/admin/realms/papaia/users`, and reaches Keycloak on
`papaia-audit-idp-net` (internal, shared with Keycloak alone). No token is logged; a
failure names the HTTP status or the kind of error only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import ssl
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from papaia_audit.report import SourceError

CLIENT_ID = "svc-papaia-audit-report"
REALM = "papaia"
KEY_FILE = "private-key.pem"
ASSERTION_SECONDS = 60
TIMEOUT_SECONDS = 10
MAX_RESPONSE_BYTES = 8 << 20
MAX_KEY_BYTES = 16384
# The only Admin API paths the report reads (report.collect).
_PATH_RE = re.compile(
    r"^/users(\?first=[0-9]{1,9}&max=[0-9]{1,4}&briefRepresentation=true"
    r"|/[A-Za-z0-9-]{1,64}/(role-mappings|role-mappings/realm/composite|groups"
    r"|offline-sessions/[A-Za-z0-9-]{1,64}))$"
)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")


class AccountKey:
    """The P-256 key of the account; read on every sign-in, so a rotation applies."""

    def __init__(self, folder: Path) -> None:
        self.path = folder / KEY_FILE

    def _load(self) -> ec.EllipticCurvePrivateKey:
        try:
            st = os.lstat(self.path)
        except FileNotFoundError:
            raise SourceError("the key of the report account is missing") from None
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_size > MAX_KEY_BYTES:
            raise SourceError("the key of the report account must be readable by its owner only")
        try:
            key = serialization.load_pem_private_key(self.path.read_bytes(), password=None)
        except (OSError, ValueError, TypeError):
            raise SourceError("the key of the report account cannot be read") from None
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
            raise SourceError("the key of the report account is not a P-256 key")
        return key

    def assertion(self, audience: str, *, now: float | None = None) -> str:
        key = self._load()
        numbers = key.public_key().public_numbers()
        jwk = {
            "crv": "P-256",
            "kty": "EC",
            "x": _b64(numbers.x.to_bytes(32, "big")),
            "y": _b64(numbers.y.to_bytes(32, "big")),
        }
        # RFC 7638 thumbprint: the key id the realm sync registers (service_account_keys).
        kid = _b64(hashlib.sha256(_canonical(jwk)).digest())
        issued = int(time.time() if now is None else now)
        header = {"alg": "ES256", "kid": kid, "typ": "JWT"}
        claims = {
            "iss": CLIENT_ID,
            "sub": CLIENT_ID,
            "aud": audience,
            "jti": str(uuid.uuid4()),
            "iat": issued,
            "exp": issued + ASSERTION_SECONDS,
        }
        signing_input = ".".join(_b64(_canonical(part)) for part in (header, claims))
        r, s = decode_dss_signature(
            key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
        )
        return f"{signing_input}.{_b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


class AdminReader:
    """GET on the realm's Admin API; `reader(path)` is report.collect's `call`."""

    def __init__(self, base_url: str, context: ssl.SSLContext | None, key: AccountKey) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.path not in (
            "",
            "/",
        ):
            raise ValueError("the Keycloak URL must be scheme://host[:port]")
        self.base_url = base_url.rstrip("/")
        self.context, self.key = context, key
        self._token: str | None = None
        self._until = 0.0
        self._lock = threading.Lock()

    def _open(self, request: urllib.request.Request) -> Any:
        try:
            with urllib.request.urlopen(  # noqa: S310 - fixed scheme checked above
                request, timeout=TIMEOUT_SECONDS, context=self.context
            ) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            error.close()
            if error.code == 401:
                self._token = None
            raise SourceError(f"Keycloak answered HTTP {error.code}") from None
        except (urllib.error.URLError, OSError) as error:
            raise SourceError(f"Keycloak not reachable ({type(error).__name__})") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise SourceError("Keycloak's answer is too large")
        try:
            return json.loads(raw) if raw else None
        except ValueError:
            raise SourceError("Keycloak's answer is not JSON") from None

    def _bearer(self) -> str:
        with self._lock:
            if self._token and time.monotonic() < self._until:
                return self._token
            realm = f"{self.base_url}/realms/{REALM}"
            discovery = self._open(
                urllib.request.Request(f"{realm}/.well-known/openid-configuration")
            )
            issuer = discovery.get("issuer") if isinstance(discovery, dict) else None
            if not isinstance(issuer, str):
                raise SourceError("the discovery document names no issuer")
            form = urllib.parse.urlencode(
                {
                    "grant_type": "client_credentials",
                    "client_id": CLIENT_ID,
                    "client_assertion_type": (
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                    ),
                    "client_assertion": self.key.assertion(issuer),
                }
            ).encode("ascii")
            body = self._open(
                urllib.request.Request(f"{realm}/protocol/openid-connect/token", data=form)
            )
            if not isinstance(body, dict) or not isinstance(body.get("access_token"), str):
                raise SourceError("the token answer holds no access token")
            lifetime = body.get("expires_in")
            lifetime = lifetime if type(lifetime) is int and lifetime > 0 else 60
            self._token = body["access_token"]
            self._until = time.monotonic() + max(5, lifetime - 30)
            return self._token

    def __call__(self, path: str) -> Any:
        if not _PATH_RE.match(path):
            # Only the reads of the report; never a write, never another object.
            raise SourceError("refused an Admin API path outside the report")
        bearer = self._bearer()
        return self._open(
            urllib.request.Request(
                f"{self.base_url}/admin/realms/{REALM}{path}",
                method="GET",
                headers={"Authorization": f"Bearer {bearer}", "Accept": "application/json"},
            )
        )


def from_environment(environ: dict[str, str] | None = None) -> AdminReader:
    """The reader of the running service: Keycloak at PAPAIA_AUDIT_KEYCLOAK_URL (default
    https://keycloak:8443), checked against the copy of the local CA certificate that
    papaia-ctl keeps in the service folder, the key folder mounted at
    PAPAIA_AUDIT_REPORT_ACCOUNT_DIR."""
    env = os.environ if environ is None else environ
    url = env.get("PAPAIA_AUDIT_KEYCLOAK_URL", "https://keycloak:8443")
    ca_file = env.get("PAPAIA_AUDIT_KEYCLOAK_CA", "/etc/papaia-audit/keycloak-ca.crt")
    folder = Path(env.get("PAPAIA_AUDIT_REPORT_ACCOUNT_DIR", "/run/papaia-audit/report-account"))
    context = None
    if url.startswith("https://"):
        context = ssl.create_default_context(cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    return AdminReader(url, context, AccountKey(folder))
