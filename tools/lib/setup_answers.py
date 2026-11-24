"""The question round of a fresh installation (operation BE-03, PLT-32-A1 as Ä-05).

A fresh installation asks at most fifteen inputs. They are the rows of `QUESTIONS`, the
table the README shows; every input of every chapter is one of them (second domain,
registry, pairing confirmation, backup keys), and there is no other.

Counting rule: one question is one input. A compound answer (a URL, a certificate bundle,
an answer file) counts once, because the README shows its format with an example and the
round checks it at once and, on an error, asks only that question again. Every switch on
the command line of `setup` counts as one input as well.

The answers come from the terminal or from an answer file (`setup --answers=FILE`,
format `papaia.setup-answers/1`), which counts the same inputs. A value of the file that
does not pass its check is asked again on a terminal, that question only; without one
the round stops and names every key that failed. Unknown keys are refused.

Rows 14 and 15 are answered after `setup` has written the configuration: the
confirmation of the pairings (`_setup_pairings`, `-y` never confirms them) and the last
eight characters of the generated backup key (`backup keys generate`). They are counted
here, so the total `setup` prints is the whole installation.

Nothing here writes the configuration. `run_round` returns the checked answers; `setup`
measures the host against the chosen size profile before it writes anything, and stores
the record (`setup-answers.yaml`, no secret: paths, names, a mail address) when it is
done.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from . import age, federation, host_size, images, ingress, module_offer, settings, smtp

FORMAT = "papaia.setup-answers/1"
MAX_INPUTS = 15
RECORD_FILE = "setup-answers.yaml"
MAX_FILE_BYTES = 64 * 1024
MAX_BUNDLE_BYTES = 1024 * 1024
INTERNAL_TLS = "internal"
NO_MAIL = "none"
GENERATE_KEY = "generate"
STUDIO = "studio"
NO_MODEL_PROFILE = "small-no-model"
# The contact point setup derives from question 5 (PLT-82, BE-03); doctor contact_point
# warns while it is still this one.
DERIVED_CONTACT_NAME = "Verwaltung von {domain}"
_DIGEST_RE = re.compile(r"^(sha256:)?[0-9a-f]{64}$")
_URL_MAX = 2048


class AnswerError(ValueError):
    """An answer that cannot be used; the message says what to change."""


@dataclass
class Context:
    """What the checks need besides the answer: the modules on offer, whether a
    terminal is there (a generated key is shown on a terminal only), how to run
    openssl."""

    offered_modules: tuple[str, ...] = module_offer.SELECTABLE
    interactive: bool = False
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run
    # True when the answers are read back from the record of a round that already ran:
    # `generate` was accepted on that round's terminal.
    recorded: bool = False


@dataclass(frozen=True)
class Question:
    number: int
    key: str
    title: str
    help: str
    example: str
    check: Callable[[str, dict, Context], Any]
    # Whether the row applies, given the answers before it.
    applies: Callable[[dict], bool] = lambda answers: True
    # The value a missing key of an answer file takes; None: the key is required.
    default: str | None = None
    # False: not asked on a terminal (answered by a later step, or only from a file).
    asked: bool = True
    # True: counted only when the answer file names it (row 13).
    file_only: bool = False
    # When the row is asked, as the README table shows it.
    when: str = "always"


# ── checks ───────────────────────────────────────────────────────────────────


def _has_control(text: str) -> bool:
    return any(unicodedata.category(ch) == "Cc" for ch in text)


def _clean(value: Any) -> str:
    """The answer as text without surrounding blanks; a control character (a line break
    above all: the answers reach the shell as KEY=VALUE lines) is refused."""
    text = str(value)
    if _has_control(text):
        raise AnswerError("the answer holds a control character (a line break, a tab, ...)")
    return text.strip()


def _domain(value: str, label: str) -> str:
    text = _clean(value).lower().rstrip(".")
    if len(text) > 253 or not ingress._DOMAIN_RE.match(text):
        raise AnswerError(f"{label} must be a domain such as example.org (no scheme, no path)")
    if text.endswith(".localhost") or text == "localhost":
        raise AnswerError(f"{label} must be a domain other browsers resolve, not {text}")
    return text


def check_domain(value: str, answers: dict, ctx: Context) -> str:
    return _domain(value, "The base domain")


def check_apps_domain(value: str, answers: dict, ctx: Context) -> str:
    """Empty: the apps live under `apps.<base domain>` (E-20). Otherwise a site of its
    own: not the base domain, not inside it, not above it."""
    if _clean(value) == "":
        return ""
    apps = _domain(value, "The app domain")
    base = answers.get("domain", "")
    if apps == base or apps.endswith(f".{base}") or base.endswith(f".{apps}"):
        raise AnswerError(
            f"The app domain must be a site of its own, not one inside or above {base};"
            " leave it empty for apps under apps." + base
        )
    return apps


def edge_names(answers: dict) -> list[str]:
    """The names a certificate of the edge covers: the base domain with its subdomains,
    and the app domain with its subdomains (`*.apps.<base>` without a second domain)."""
    base = answers["domain"]
    names = [base, f"*.{base}"]
    apps = answers.get("apps_domain", "")
    if apps:
        names += [apps, f"*.{apps}"]
    elif STUDIO in answers.get("modules", []):
        names.append(f"*.{ingress.SINGLE_SITE_APP_LABEL}.{base}")
    return names


def _covers(patterns: list[str], name: str) -> bool:
    for pattern in patterns:
        if pattern == name:
            return True
        if pattern.startswith("*.") and not name.startswith("*."):
            head, _, rest = name.partition(".")
            if head and rest == pattern[2:]:
                return True
    return False


def _read_limited(path: Path, label: str, limit: int, *, private: bool) -> bytes:
    """At most `limit` bytes of a regular file. Opened without blocking, so a FIFO or a
    device is refused instead of waited on or read without end; a private file is not
    followed through a link and must not be readable by group or others."""
    flags = os.O_RDONLY | os.O_NONBLOCK | (os.O_NOFOLLOW if private else 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise AnswerError(f"{label} {path} cannot be opened: {exc.strerror}") from None
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise AnswerError(f"{label} {path} is not a regular file")
        if private and st.st_mode & 0o077:
            raise AnswerError(
                f"{label} {path} is readable by others (mode {stat.S_IMODE(st.st_mode):04o});"
                f" run chmod 600 {path}"
            )
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise AnswerError(f"{label} {path} is larger than {limit} bytes")
    return raw


def _private_file(path: Path, label: str, limit: int) -> bytes:
    return _read_limited(path, label, limit, private=True)


def _openssl(ctx: Context, args: list[str], data: bytes) -> str:
    try:
        done = ctx.run(["openssl", *args], input=data, capture_output=True, check=False,
                       timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AnswerError(f"openssl cannot check the bundle: {exc}") from None
    if done.returncode != 0:
        raise AnswerError("the bundle holds no usable certificate and key in PEM format")
    out = done.stdout
    return out.decode("utf-8", "replace") if isinstance(out, bytes) else out


def check_tls(value: str, answers: dict, ctx: Context) -> str:
    """`internal`, or the path to one PEM file with the certificate (chain) and its key
    for the edge, covering every name of `edge_names`."""
    text = _clean(value)
    if text.lower() == INTERNAL_TLS:
        return INTERNAL_TLS
    if not text:
        raise AnswerError("Answer internal, or name the PEM file of the certificate bundle")
    path = Path(text).expanduser()
    if not path.is_absolute():
        raise AnswerError("The certificate bundle must be named with an absolute path")
    raw = _private_file(path, "The certificate bundle", MAX_BUNDLE_BYTES)
    if b"-----BEGIN CERTIFICATE-----" not in raw or b"PRIVATE KEY-----" not in raw:
        raise AnswerError(
            "The certificate bundle must hold the certificate (chain) and its private key"
        )
    san = _openssl(ctx, ["x509", "-noout", "-ext", "subjectAltName"], raw)
    names = [part.strip()[4:].lower() for part in san.replace("\n", ",").split(",")
             if part.strip().startswith("DNS:")]
    missing = [name for name in edge_names(answers) if not _covers(names, name)]
    if missing:
        raise AnswerError(f"The certificate does not cover {', '.join(missing)}")
    cert_key = _openssl(ctx, ["x509", "-noout", "-pubkey"], raw)
    own_key = _openssl(ctx, ["pkey", "-pubout"], raw)
    if cert_key.strip() != own_key.strip():
        raise AnswerError("The private key in the bundle does not belong to its certificate")
    return str(path)


def check_upstream_idp(value: str, answers: dict, ctx: Context) -> str:
    text = _clean(value)
    if not text:
        return ""
    path = Path(text).expanduser()
    if not path.is_absolute() or path.name != federation.IDP_FILE.name:
        raise AnswerError(
            "Name the absolute path of an idp.yaml (with idp-group-map.yaml next to it),"
            " or leave it empty"
        )
    try:
        federation.check_answer(path)
    except federation.FederationError as exc:
        raise AnswerError(str(exc)) from None
    return str(path)


def check_admin_mail(value: str, answers: dict, ctx: Context) -> str:
    text = _clean(value)
    if len(text) > settings.MAIL_MAX or not settings.MAIL_RE.fullmatch(text):
        raise AnswerError("The mail address must look like it@example.org")
    return text


def check_modules(value: str, answers: dict, ctx: Context) -> list[str]:
    raw = value if isinstance(value, list) else _clean(value).split(",")
    chosen = [_clean(item).lower() for item in raw if _clean(item)]
    if not chosen or chosen == ["none"]:
        return []
    unknown = [m for m in chosen if m not in module_offer.SELECTABLE]
    if unknown:
        raise AnswerError(
            f"Unknown module(s) {', '.join(unknown)}; choose from"
            f" {', '.join(module_offer.SELECTABLE)}, or none"
        )
    withheld = [m for m in chosen if m not in ctx.offered_modules]
    if withheld:
        raise AnswerError(f"This release does not offer {', '.join(withheld)}")
    if len(set(chosen)) != len(chosen):
        raise AnswerError("A module is named twice")
    return [m for m in module_offer.SELECTABLE if m in chosen]


def check_size_profile(value: str, answers: dict, ctx: Context) -> str:
    text = _clean(value).lower()
    if text not in host_size.PROFILES:
        raise AnswerError(f"The size profile must be one of {', '.join(host_size.PROFILES)}")
    return text


def check_model_source(value: str, answers: dict, ctx: Context) -> str:
    text = _clean(value)
    try:
        parts = urlsplit(text)
        parts.port  # noqa: B018 - raises for a port that is not a number
    except ValueError:
        parts = None
    if (
        parts is None
        or len(text) > _URL_MAX
        or parts.scheme not in ("http", "https")
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or parts.fragment
        or any(ch.isspace() for ch in text)
    ):
        raise AnswerError(
            "The model source must be an http(s) URL of your model server, such as"
            " https://models.example.org/v1 (no user name, no password in it)"
        )
    return text


@dataclass(frozen=True)
class MailFile:
    host: str
    port: int
    security: str
    user: str
    password: str = field(repr=False)
    sender: str


_MAIL_SCHEMES = {"smtp+starttls": "starttls", "smtps": "tls", "smtp": "none"}
_MAIL_KEYS = {"SMTP_URL", "SMTP_PASSWORD", "SMTP_FROM"}


def read_mail_file(path: Path, base_domain: str) -> MailFile:
    """The mail answer file `smtp.env` (BE-03 No. 9): `SMTP_URL`, `SMTP_PASSWORD`,
    optionally `SMTP_FROM` (default `papaia@<base domain>`). Readable by its owner only."""
    raw = _private_file(path, "The mail answer file", MAX_FILE_BYTES)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise AnswerError("The mail answer file is not UTF-8 text") from None
    values: dict[str, str] = {}
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, sep, rest = line.partition("=")
        key = key.strip()
        if not sep or key not in _MAIL_KEYS:
            raise AnswerError(
                f"The mail answer file, line {number}: expected one of"
                f" {', '.join(sorted(_MAIL_KEYS))} as KEY=VALUE"
            )
        if key in values:
            raise AnswerError(f"The mail answer file names {key} twice")
        values[key] = rest
    if "SMTP_URL" not in values:
        raise AnswerError("The mail answer file has no SMTP_URL")
    url = values["SMTP_URL"].strip()
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise AnswerError("SMTP_URL is not a URL") from None
    security = _MAIL_SCHEMES.get(parts.scheme)
    if security is None or not parts.hostname or parts.path not in ("", "/") or parts.query:
        raise AnswerError(
            "SMTP_URL must look like smtp+starttls://user@mail.example.org:587"
            " (smtps:// for TLS from the first byte, smtp:// without encryption)"
        )
    if parts.password is not None:
        raise AnswerError("SMTP_URL must not carry the password; put it in SMTP_PASSWORD")
    user = parts.username or ""
    password = values.get("SMTP_PASSWORD", "")
    try:
        host = smtp.validate_host(parts.hostname)
        port = smtp.validate_port(port or {"starttls": 587, "tls": 465, "none": 25}[security])
        if user:
            user = smtp.validate_user(user)
            if security == "none":
                raise AnswerError("A login over smtp:// would travel unencrypted; use smtps://"
                                  " or smtp+starttls://")
            password = smtp.validate_password(password)
        elif password:
            raise AnswerError("SMTP_PASSWORD needs a user name in SMTP_URL")
        sender = smtp.validate_address(values.get("SMTP_FROM", "").strip()
                                       or f"papaia@{base_domain}")
    except smtp.SmtpConfigError as exc:
        raise AnswerError(str(exc)) from None
    return MailFile(host, port, security, user, password, sender)


def check_mail(value: str, answers: dict, ctx: Context) -> str:
    text = _clean(value)
    if text.lower() == NO_MAIL:
        return NO_MAIL
    path = Path(text).expanduser()
    if not text or not path.is_absolute():
        raise AnswerError("Name the absolute path of the mail answer file smtp.env, or none")
    read_mail_file(path, answers.get("domain", "example.org"))
    return str(path)


def check_backup_target(value: str, answers: dict, ctx: Context) -> str:
    text = _clean(value)
    path = Path(text).expanduser()
    if not text or not path.is_absolute():
        raise AnswerError("The backup target must be an absolute path to a directory")
    if not path.is_dir():
        raise AnswerError(f"{path} is not a directory (mount the share first)")
    if not os.access(path, os.W_OK | os.X_OK):
        raise AnswerError(f"{path} is not writable for this user")
    return str(path)


_RECIPIENT_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")


def check_backup_key(value: str, answers: dict, ctx: Context) -> str:
    """`generate` (two key pairs, shown once on the terminal), or one or two public keys
    as `NAME:age1...` separated by commas."""
    text = _clean(value)
    if text.lower() == GENERATE_KEY:
        if not (ctx.interactive or ctx.recorded):
            raise AnswerError(
                "generate shows the private keys on a terminal only; name public keys"
                " (NAME:age1...) in the answer file instead"
            )
        return GENERATE_KEY
    entries = [item.strip() for item in text.split(",") if item.strip()]
    if not 1 <= len(entries) <= 2:
        raise AnswerError("Answer generate, or name one or two keys as NAME:age1...")
    names: set[str] = set()
    for entry in entries:
        name, sep, key = entry.partition(":")
        if not sep or not _RECIPIENT_NAME_RE.match(name) or name in names:
            raise AnswerError(f"{entry!r}: expected NAME:age1... with a short lowercase name")
        try:
            age.parse_recipient(key)
        except age.AgeError as exc:
            raise AnswerError(f"{name}: {exc}") from None
        names.add(name)
    return ",".join(entries)


def check_registry(value: str, answers: dict, ctx: Context) -> str:
    try:
        return images.validate_mirror(_clean(value))
    except images.ImageError as exc:
        raise AnswerError(str(exc)) from None


def check_pairings(value: str, answers: dict, ctx: Context) -> str:
    text = _clean(value)
    if text and not _DIGEST_RE.match(text):
        raise AnswerError(
            "approve_pairings must be the sha256 setup shows for the pairing list, or empty"
        )
    return text


def _never(value: str, answers: dict, ctx: Context) -> str:
    raise AnswerError("this row is answered on the terminal after setup, not in a file")


def _with_studio(answers: dict) -> bool:
    return STUDIO in answers.get("modules", [])


def _no_model(answers: dict) -> bool:
    """Every profile without a local model names the model server (small-no-model, large)."""
    profile = answers.get("size_profile")
    return profile in host_size.PROFILES and not host_size.profile(profile).local_model


def _generated(answers: dict) -> bool:
    return answers.get("backup_key") == GENERATE_KEY


QUESTIONS: tuple[Question, ...] = (
    Question(1, "domain", "Base domain",
             "The domain whose names point at this host: auth.<domain>, chat.<domain>, ...",
             "example.org", check_domain),
    Question(2, "apps_domain", "Domain for Studio apps",
             "A second, registrable domain for the apps (recommended). Empty: apps under"
             " apps.<base domain>, with a lasting warning in Studio.",
             "example-apps.org", check_apps_domain, applies=_with_studio, default="",
             when="only with Studio; empty: apps under apps.<base domain>"),
    Question(3, "tls", "TLS certificate",
             "internal: the platform CA issues it (distribute its root certificate). Or the"
             " absolute path of a PEM file with certificate chain and key for both domains.",
             "internal", check_tls),
    Question(4, "upstream_idp", "Upstream identity provider",
             "Empty: none. Or the absolute path of idp.yaml (idp-group-map.yaml next to it).",
             "/root/papaia-answers/idp.yaml", check_upstream_idp, default=""),
    Question(5, "admin_mail", "Mail address of the first administrator",
             "Also the address of operation warnings and the contact point people see.",
             "it@example.org", check_admin_mail),
    Question(6, "modules", "Modules",
             "Comma-separated, or none. Paperless only when this release offers its gate.",
             "studio,data,flow,assist,paperless", check_modules),
    Question(7, "size_profile", "Size profile",
             "small-no-model (8 cores, 32 GB, 200 GB), small (8 cores, 64 GB or 32 GB and a"
             " 16 GB GPU, 300 GB, local default model), large (16 cores, 64 GB, 500 GB, your own"
             " model server).",
             "small", check_size_profile),
    Question(8, "model_source", "Model source",
             "URL of the API of your model server.",
             "https://models.example.org/v1", check_model_source, applies=_no_model,
             when="only with a size profile without a local model (small-no-model, large)"),
    Question(9, "mail", "Mail answer file",
             "Absolute path of smtp.env (SMTP_URL, SMTP_PASSWORD, mode 0600), or none.",
             "/root/papaia-answers/smtp.env", check_mail),
    Question(11, "backup_target", "Backup target",
             "A directory on another disk or a mounted share; there is no default.",
             "/mnt/papaia-backup", check_backup_target),
    Question(12, "backup_key", "Backup key",
             "generate: two key pairs, shown once here. Or public keys NAME:age1...,NAME:age1...",
             "generate", check_backup_key),
    Question(13, "registry", "Registry",
             "Only for images that are not pulled publicly: the registry prefix, ending in /.",
             "registry.example.com/papaia/", check_registry, default="", asked=False,
             file_only=True, when="only from the answer file, for images not pulled publicly"),
    Question(14, "approve_pairings", "Summary and read pairings",
             "Confirmed after setup on the terminal, or with the sha256 setup shows.",
             "", check_pairings, default="", asked=False,
             when="after setup writes the configuration; never by -y"),
    Question(15, "backup_key_check", "Last eight characters of the backup key",
             "Typed back when the generated key is shown.",
             "", _never, applies=_generated, asked=False,
             when="after setup, only with backup key generate"),
)

# Row 6 decides whether row 2 applies, so it is asked first.
ASK_ORDER = (1, 6, 2, 3, 4, 5, 7, 8, 9, 11, 12, 13, 14, 15)
BY_KEY = {q.key: q for q in QUESTIONS}
BY_NUMBER = {q.number: q for q in QUESTIONS}
FILE_KEYS = {q.key for q in QUESTIONS if q.check is not _never}


@dataclass
class Round:
    answers: dict[str, Any]
    rows: list[int]
    flags: list[str]

    @property
    def total(self) -> int:
        return len(self.rows) + len(self.flags)

    def record(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "answers": dict(self.answers),
            "inputs": {"rows": list(self.rows), "flags": list(self.flags), "total": self.total},
        }


def _counted(question: Question, answers: dict) -> bool:
    if not question.applies(answers):
        return False
    if question.file_only:
        return bool(answers.get(question.key))
    return True


def load_file(path: Path) -> dict[str, Any]:
    """The answers of an answer file, unchecked except for its shape."""
    raw = _read_limited(path, "The answer file", MAX_FILE_BYTES, private=False)
    try:
        doc = yaml.safe_load(raw.decode("utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise AnswerError(f"The answer file {path} is not valid YAML: {exc}") from None
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise AnswerError(f"The answer file {path} must be a mapping with format: {FORMAT}")
    unknown = sorted(str(k) for k in doc if k != "format" and k not in FILE_KEYS)
    if unknown:
        raise AnswerError(
            f"The answer file {path} has unknown key(s) {', '.join(unknown)}; known:"
            f" {', '.join(q.key for q in QUESTIONS if q.key in FILE_KEYS)}"
        )
    values: dict[str, Any] = {}
    for key, value in doc.items():
        if key == "format":
            continue
        if key == "modules" and isinstance(value, list):
            values[key] = [str(item) for item in value]
        elif value is None:
            values[key] = ""
        elif isinstance(value, (str, int)) and not isinstance(value, bool):
            values[key] = str(value)
        else:
            raise AnswerError(f"The answer file {path}: {key} must be a text")
    return values


Ask = Callable[[Question], str | None]
Say = Callable[[str], None]


def _ask_until_valid(question: Question, answers: dict, ctx: Context, ask: Ask, say: Say):
    """The one question, again and again until its answer passes; None at end of input."""
    while True:
        value = ask(question)
        if value is None:
            raise AnswerError(f"No answer for question {question.number} ({question.title})")
        try:
            return question.check(value, answers, ctx)
        except AnswerError as exc:
            say(f"{exc}. Only this question is asked again.")


def run_round(
    provided: dict[str, Any] | None,
    ctx: Context,
    *,
    ask: Ask,
    say: Say,
    flags: list[str] | None = None,
) -> Round:
    """Answers from the file, checked; on a terminal the missing ones and those that did
    not pass are asked (that question only). AnswerError names every key that failed
    when there is no terminal to ask on."""
    provided = dict(provided or {})
    answers: dict[str, Any] = {}
    failures: list[str] = []
    for number in ASK_ORDER:
        question = BY_NUMBER[number]
        if not question.applies(answers):
            if question.key in provided:
                failures.append(f"{question.key}: not asked with these answers (row {number}"
                                " applies only when its condition holds)")
            continue
        if question.key in provided:
            try:
                answers[question.key] = question.check(provided[question.key], answers, ctx)
                continue
            except AnswerError as exc:
                if not ctx.interactive:
                    failures.append(f"{question.key}: {exc}")
                    continue
                say(f"Answer file, {question.key}: {exc}. Only this question is asked again.")
                answers[question.key] = _ask_until_valid(question, answers, ctx, ask, say)
                continue
        if question.check is _never:
            continue
        if question.asked and ctx.interactive:
            answers[question.key] = _ask_until_valid(question, answers, ctx, ask, say)
        elif question.default is not None:
            answers[question.key] = question.check(question.default, answers, ctx)
        else:
            failures.append(f"{question.key}: missing (row {number}, {question.title})")
    if failures:
        raise AnswerError("The answers cannot be used:\n  " + "\n  ".join(failures))
    rows = [q.number for q in QUESTIONS if _counted(q, answers)]
    return Round(answers, rows, list(flags or []))


def count_line(found: Round) -> str:
    line = (
        f"Inputs: {found.total} of at most {MAX_INPUTS}"
        f" (questions {', '.join(str(r) for r in found.rows)}"
    )
    if found.flags:
        line += f"; switches {', '.join(found.flags)}"
    return line + ")"


# ── what the answers mean for setup ──────────────────────────────────────────


def app_host(answers: dict) -> str:
    return f"https://{answers['domain']}"


def root_env(answers: dict) -> dict[str, str]:
    """The root .env keys the answers decide."""
    profile = host_size.profile(answers["size_profile"])
    values = {
        host_size.ENV_KEY: profile.name,
        ingress.APP_DOMAIN_KEY: answers.get("apps_domain", ""),
        ingress.APP_SINGLE_SITE_KEY: "true"
        if _with_studio(answers) and not answers.get("apps_domain") else "false",
    }
    if answers.get("registry"):
        values[images.MIRROR_VAR] = answers["registry"]
    return values


def shell_values(found: Round) -> dict[str, str]:
    """KEY=VALUE lines for the shell part of setup (no secret among them)."""
    answers = found.answers
    profile = host_size.profile(answers["size_profile"])
    values = {
        "ROUND_APP_HOST": app_host(answers),
        "ROUND_SIZE_PROFILE": profile.name,
        "ROUND_LOCAL_AI": "true" if profile.local_model else "false",
        "ROUND_BACKUP_DIR": answers["backup_target"],
        "ROUND_BACKUP_KEY": answers["backup_key"],
        "ROUND_APPROVE_PAIRINGS": answers.get("approve_pairings", ""),
        "ROUND_MAIL": "false" if answers["mail"] == NO_MAIL else "true",
        "ROUND_TLS": answers["tls"],
        "ROUND_INPUTS": str(found.total),
    }
    bad = sorted(key for key, value in values.items() if _has_control(value))
    if bad:
        raise AnswerError(f"{', '.join(bad)} would hold a control character")
    return values


# Rows that name a file. Reading a record checks their form only (keyword or absolute path,
# no control character); setup reads the files again where it uses them: the mail answer
# file (`setup_overrides`), the provider files (`finish_setup`), the backup target
# (`backup target init`). The certificate bundle is recorded only.
_FILE_ROWS = {
    "tls": (INTERNAL_TLS,),
    "upstream_idp": ("",),
    "mail": (NO_MAIL,),
    "backup_target": (),
}


def _recorded_path(key: str, value: Any) -> str:
    if not isinstance(value, str):
        raise AnswerError("must be a text")
    text = _clean(value)
    if text in _FILE_ROWS[key] or (text and Path(text).is_absolute()):
        return text
    raise AnswerError("must be an absolute path")


def _recheck(answers: dict[str, Any]) -> dict[str, Any]:
    """Every answer of a record through the check of its row again, without a terminal
    and in the order of the round (row 2 needs rows 1 and 6)."""
    ctx = Context(recorded=True)
    checked: dict[str, Any] = {}
    failures: list[str] = []
    for number in ASK_ORDER:
        question = BY_NUMBER[number]
        if question.key not in answers:
            continue
        value = answers[question.key]
        try:
            if question.key in _FILE_ROWS:
                checked[question.key] = _recorded_path(question.key, value)
            elif not isinstance(value, str) and not (
                question.key == "modules" and isinstance(value, list)
            ):
                raise AnswerError("must be a text")
            else:
                checked[question.key] = question.check(value, checked, ctx)
        except AnswerError as exc:
            failures.append(f"{question.key}: {exc}")
    if failures:
        raise AnswerError("; ".join(failures))
    return checked


def load_record(path: Path) -> dict[str, Any]:
    """A record written by `setup-round`, read back through the check of every row again
    (it travels through a file); rows naming a file are checked for their form."""
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError, UnicodeDecodeError) as exc:
        raise AnswerError(f"The record {path} cannot be read: {exc}") from None
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise AnswerError(f"The record {path} is not a {FORMAT} record")
    answers = doc.get("answers")
    inputs = doc.get("inputs")
    if not isinstance(answers, dict) or not isinstance(inputs, dict):
        raise AnswerError(f"The record {path} has no answers")
    unknown = sorted(k for k in answers if k not in BY_KEY)
    if unknown:
        raise AnswerError(f"The record {path} has unknown key(s) {', '.join(unknown)}")
    for key in ("domain", "size_profile", "backup_target", "backup_key", "mail", "tls"):
        if not isinstance(answers.get(key), str) or not answers[key]:
            raise AnswerError(f"The record {path} has no {key}")
    try:
        doc["answers"] = _recheck(answers)
    except AnswerError as exc:
        raise AnswerError(f"The record {path} cannot be used: {exc}") from None
    return doc


def found_from_record(doc: dict[str, Any]) -> Round:
    inputs = doc["inputs"]
    return Round(dict(doc["answers"]), list(inputs.get("rows") or []),
                 list(inputs.get("flags") or []))


def derived_contact(config_dir: Path) -> str | None:
    """The contact name setup derived, while the record of the round is there."""
    path = config_dir / RECORD_FILE
    if not path.is_file():
        return None
    try:
        domain = load_record(path)["answers"]["domain"]
    except (AnswerError, KeyError):
        return None
    return DERIVED_CONTACT_NAME.format(domain=domain)


def store_record(config_dir: Path, doc: dict[str, Any]) -> Path:
    from . import common

    path = config_dir / RECORD_FILE
    common.atomic_write_private(path, yaml.safe_dump(doc, sort_keys=False))
    return path


def table_markdown() -> str:
    """The question table as the README shows it."""
    lines = ["| # | Key | Input | Asked | Example |", "|---|---|---|---|---|"]
    for q in QUESTIONS:
        example = f"`{q.example}`" if q.example else "-"
        lines.append(f"| {q.number} | `{q.key}` | {q.title} | {q.when} | {example} |")
    return "\n".join(lines)
