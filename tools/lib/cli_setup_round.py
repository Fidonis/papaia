"""Commands of the question round of a fresh installation (lib/setup_answers.py), the
size check before `setup` writes anything (lib/host_size.py) and `hostnames`, the list
of DNS names to create before the installation (operation BE-03, command 2)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

from . import (
    catalog,
    common,
    doctor,
    envtree,
    federation,
    ingress,
    module_offer,
    settings,
    setup_answers,
)
from .setup_answers import AnswerError, Question


def _say(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def _ask(question: Question) -> str | None:
    _say(f"\n{question.number:>2}) {question.title}")
    _say(f"    {question.help}")
    if question.example:
        _say(f"    Example: {question.example}")
    print("    > ", end="", file=sys.stderr, flush=True)
    line = sys.stdin.readline()
    if line == "":
        return None
    return line.rstrip("\r\n")


def _offered(repo_root: Path) -> tuple[str, ...]:
    return module_offer.offer(module_offer.load(repo_root)).offered


def cmd_setup_round(args: argparse.Namespace) -> int:
    """Ask (or read) the answers, check them, write the record to --record-out."""
    repo_root = Path(args.repo_root)
    try:
        offered = _offered(repo_root)
    except module_offer.OfferError as exc:
        print(f"ERROR: {exc}. Nothing was changed.", file=sys.stderr)
        return 2
    ctx = setup_answers.Context(offered_modules=offered, interactive=args.interactive)
    flags = [f for f in (args.flags or "").split(",") if f]
    try:
        provided = setup_answers.load_file(Path(args.answers)) if args.answers else None
        if args.interactive:
            _say("papAIa setup: at most fifteen inputs (README, 'Question round').")
        found = setup_answers.run_round(provided, ctx, ask=_ask, say=_say, flags=flags)
    except AnswerError as exc:
        print(f"ERROR: {exc}\nNothing was changed.", file=sys.stderr)
        return 2
    common.atomic_write_private(
        Path(args.record_out),
        yaml.safe_dump(found.record(), sort_keys=False),
    )
    _say(setup_answers.count_line(found))
    if found.total > setup_answers.MAX_INPUTS:
        _say(f"WARNING: more than {setup_answers.MAX_INPUTS} inputs; every switch counts.")
    if found.answers.get("modules") and setup_answers.STUDIO in found.answers["modules"] \
            and not found.answers.get("apps_domain"):
        _say(
            "WARNING: without a second domain the Studio apps live under apps."
            f"{found.answers['domain']}; Studio shows a lasting warning (README,"
            " 'Question round', row 2)."
        )
    return 0


def cmd_setup_round_values(args: argparse.Namespace) -> int:
    try:
        found = setup_answers.found_from_record(setup_answers.load_record(Path(args.record)))
    except AnswerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    for key, value in setup_answers.shell_values(found).items():
        print(f"{key}={value}")
    return 0


def cmd_size_check(args: argparse.Namespace) -> int:
    """Exit 0 when the host fits the profile, 3 (nothing changed) when it does not."""
    result = doctor.check_size(Path(args.config_dir), Path(args.repo_root), args.profile)
    if result.status == doctor.FAIL:
        print(f"ERROR: {result.summary}. Nothing was changed.", file=sys.stderr)
        return 3
    if result.status == doctor.WARN:
        print(f"WARNING: {result.summary}", file=sys.stderr)
    else:
        print(result.summary)
    return 0


def cmd_mail_file_notice(args: argparse.Namespace) -> int:
    """At the end of setup: the request to delete the mail answer file of row 9 while it
    still exists. A request, not a question: it adds no input to the count."""
    try:
        path = setup_answers.recorded_mail_file(Path(args.config_dir))
    except AnswerError as exc:
        print(f"WARNING: {exc}", file=sys.stderr)
        return 0
    if path is None:
        return 0
    notice = setup_answers.mail_file_notice(path, setup_answers.mail_file_exists(path))
    if notice:
        print(f"WARNING: {notice}", file=sys.stderr)
    return 0


# ── setup with a record ──────────────────────────────────────────────────────


def setup_overrides(doc: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    """SetupArgs fields the record decides. A switch that names one of them must say the
    same as the record (the shell refuses such switches beside an answer file); otherwise
    the domain of the record and PAPAIA_HOST would part. The mail password is read from
    the mail answer file here, never handed through the shell."""
    answers = doc["answers"]
    profile = setup_answers.host_size.profile(answers["size_profile"])
    mail_on = answers["mail"] != setup_answers.NO_MAIL
    decided = {
        "app_host": setup_answers.app_host(answers),
        "reverse_proxy_provider": "internal_nginx",
        "enable_local_ai": profile.local_model,
        "enable_smtp": mail_on,
    }
    contradicted = [
        f"{key} ({getattr(args, key)!r}, the round decided {value!r})"
        for key, value in decided.items()
        if getattr(args, key) not in (None, "") and getattr(args, key) != value
    ]
    if contradicted:
        raise AnswerError(
            "switches contradict the question round: " + ", ".join(contradicted)
        )
    values: dict[str, Any] = dict(decided)
    if mail_on:
        mail = setup_answers.read_mail_file(Path(answers["mail"]), answers["domain"])
        values.update(
            smtp_host=mail.host,
            smtp_port=str(mail.port),
            smtp_security=mail.security,
            smtp_user=mail.user or None,
            smtp_no_auth=not mail.user,
            smtp_from=mail.sender,
            smtp_password=mail.password or None,
        )
    for key in decided:
        if getattr(args, key) not in (None, ""):
            values.pop(key)
    return values


def finish_setup(config_dir: Path, repo_root: Path, doc: dict[str, Any]) -> None:
    """After the configuration is written: the upstream provider's files, the contact
    point from question 5 (audited by lib/settings.py), and the record itself."""
    answers = doc["answers"]
    idp = answers.get("upstream_idp", "")
    if idp:
        source = Path(idp)
        target = config_dir / federation.IDP_FILE
        federation.check_answer(source)
        for name in (federation.IDP_FILE.name, federation.MAP_FILE.name):
            common.atomic_write_private(
                target.parent / name, (source.parent / name).read_text(encoding="utf-8")
            )
    try:
        has_contact = bool(catalog.current_branding(config_dir).get("contact"))
    except catalog.CatalogError:
        has_contact = True
    if not has_contact:
        settings.set_value(config_dir, repo_root, "contact.name",
                           setup_answers.DERIVED_CONTACT_NAME.format(domain=answers["domain"]))
        settings.set_value(config_dir, repo_root, "contact.mail", answers["admin_mail"])
    setup_answers.store_record(config_dir, doc)


# ── hostnames ────────────────────────────────────────────────────────────────


def hostname_patterns() -> list[str]:
    return [
        "<base domain>",
        "*.<base domain>         (auth., chat., me., manager., the modules, apps.)",
        "<app domain>            (only with Studio and a second domain)",
        "*.<app domain>          (only with Studio and a second domain)",
        "*.apps.<base domain>    (only with Studio without a second domain)",
    ]


def concrete_hostnames(config_dir: Path, repo_root: Path) -> list[str]:
    tree = envtree.load_config_dir_tree(config_dir, repo_root)
    root = tree.get("", {})
    names: list[str] = []
    for route in ingress.routes(tree, config_dir, repo_root):
        names.extend(route.hostnames)
    scheme = ingress.host_scheme(root)
    record = config_dir / setup_answers.RECORD_FILE
    studio = False
    if record.is_file():
        try:
            studio = setup_answers.STUDIO in setup_answers.load_record(record)["answers"].get(
                "modules", [])
        except AnswerError:
            studio = False
    if scheme.app_domain and (studio or root.get(ingress.APP_DOMAIN_KEY)):
        names += [scheme.app_domain, f"*.{scheme.app_domain}"]
    return sorted(dict.fromkeys(names))


def cmd_hostnames(args: argparse.Namespace) -> int:
    config_dir, repo_root = Path(args.config_dir), Path(args.repo_root)
    if not (config_dir / ".env").is_file():
        print("Before setup: the DNS names to create, as patterns (all pointing at this host).")
        print("After setup this command prints the names themselves.")
        for line in hostname_patterns():
            print(f"  {line}")
        return 0
    try:
        names = concrete_hostnames(config_dir, repo_root)
    except ingress.IngressError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if not names:
        print("No host names: this installation is reached on ports (no proxy).")
        return 0
    print("DNS names of this installation (all pointing at this host):")
    for name in names:
        print(f"  {name}")
    return 0


def add_parsers(sub) -> None:
    p = sub.add_parser("setup-round")
    p.add_argument("--answers", default=None)
    p.add_argument("--record-out", required=True)
    p.add_argument("--interactive", action="store_true")
    p.add_argument("--flags", default="")
    p.set_defaults(func=cmd_setup_round)

    p = sub.add_parser("setup-round-values")
    p.add_argument("--record", required=True)
    p.set_defaults(func=cmd_setup_round_values)

    p = sub.add_parser("setup-mail-file-notice")
    p.set_defaults(func=cmd_mail_file_notice)

    p = sub.add_parser("size-check")
    p.add_argument("--profile", required=True)
    p.set_defaults(func=cmd_size_check)

    p = sub.add_parser("hostnames")
    p.set_defaults(func=cmd_hostnames)

