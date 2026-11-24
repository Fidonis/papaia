"""The question round of a fresh installation (lib/setup_answers.py, BE-03, Ä-05).

At most fifteen counted inputs: the table has at most fifteen rows, an answer file counts
the same inputs as the terminal, every switch counts, and a compound answer that fails its
check is asked again on its own, nothing else.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from lib import age, cli_setup_round, ingress, module_offer, setup_answers, smtp
from lib.setup_answers import AnswerError, Context

TOOLS = Path(__file__).resolve().parents[1]
REPO = TOOLS.parent
ALL_MODULES = list(module_offer.SELECTABLE)
# A checkout without a signed bill of materials offers no Paperless (lib/module_offer.py).
CHECKOUT_MODULES = "studio,data,flow,assist"
RECIPIENT = age.generate_identity()[1]


class Prompter:
    """Answers questions from a dict of queues and records which were asked."""

    def __init__(self, replies: dict[str, list[str]] | None = None):
        self.replies = {k: list(v) for k, v in (replies or {}).items()}
        self.asked: list[str] = []
        self.said: list[str] = []

    def ask(self, question) -> str | None:
        self.asked.append(question.key)
        queue = self.replies.get(question.key) or []
        return queue.pop(0) if queue else None

    def say(self, text: str) -> None:
        self.said.append(text)


@pytest.fixture
def target(tmp_path: Path) -> Path:
    path = tmp_path / "backup"
    path.mkdir()
    return path


def typical(target: Path, **overrides) -> dict:
    """The typical installation of BE-03: all modules, internal TLS, no upstream provider,
    profile with model, public images, generated key."""
    values = {
        "domain": "example.org",
        "apps_domain": "example-apps.org",
        "tls": "internal",
        "upstream_idp": "",
        "admin_mail": "it@example.org",
        "modules": ",".join(ALL_MODULES),
        "size_profile": "small",
        "mail": "none",
        "backup_target": str(target),
        "backup_key": "generate",
    }
    for key, value in overrides.items():
        if value is None:
            values.pop(key, None)
        else:
            values[key] = value
    return values


class Probe:
    """Stands in for the handshake with the mail server; answers from a queue (ok when
    empty) and records every call."""

    def __init__(self, *results: smtp.ProbeResult):
        self.results = list(results)
        self.calls: list[tuple] = []

    def __call__(self, host, port, security, user, password, check_login=True):
        self.calls.append((host, port, security, user, password, check_login))
        if self.results:
            return self.results.pop(0)
        return smtp.ProbeResult(True, "ok", login="ok" if user else "not needed")


def run(provided, *, interactive=True, replies=None, flags=None, offered=None, probe=None):
    prompter = Prompter(replies)
    ctx = Context(
        offered_modules=tuple(offered or module_offer.SELECTABLE), interactive=interactive,
        mail_probe=probe or Probe(),
    )
    found = setup_answers.run_round(
        provided, ctx, ask=prompter.ask, say=prompter.say, flags=flags
    )
    return found, prompter


# ── the table ────────────────────────────────────────────────────────────────


def test_the_table_has_at_most_fifteen_rows_and_names_every_chapter():
    numbers = [q.number for q in setup_answers.QUESTIONS]
    assert len(numbers) <= setup_answers.MAX_INPUTS == 15
    assert numbers == sorted(set(numbers)) and max(numbers) <= 15
    keys = {q.key for q in setup_answers.QUESTIONS}
    # Inputs of every chapter count (Ä-05): second domain, registry, pairings, backup keys.
    assert {"apps_domain", "registry", "approve_pairings", "backup_key"} <= keys
    assert sorted(setup_answers.ASK_ORDER) == numbers


def test_the_readme_shows_the_table_and_an_example_answer_file():
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    assert setup_answers.table_markdown() in readme
    assert f"format: {setup_answers.FORMAT}" in readme
    for q in setup_answers.QUESTIONS:
        if q.key in setup_answers.FILE_KEYS:
            assert f"\n{q.key}:" in readme or f"\n# {q.key}:" in readme, q.key


# ── counting ─────────────────────────────────────────────────────────────────


def test_the_typical_installation_counts_twelve_inputs(target):
    found, prompter = run(typical(target))

    assert found.rows == [1, 2, 3, 4, 5, 6, 7, 9, 11, 12, 14, 15]
    assert found.total == 12
    assert prompter.asked == []


def test_without_studio_the_app_domain_is_not_asked_and_not_counted(target):
    modules = ",".join(m for m in ALL_MODULES if m != "studio")
    found, _ = run(typical(target, modules=modules, apps_domain=None))
    assert 2 not in found.rows
    assert found.total == 11


def test_without_studio_an_app_domain_in_the_file_is_refused(target):
    modules = ",".join(m for m in ALL_MODULES if m != "studio")
    with pytest.raises(AnswerError, match="apps_domain"):
        run(typical(target, modules=modules), interactive=False)


def test_the_largest_case_counts_fourteen_and_every_switch_counts(target):
    found, _ = run(
        typical(
            target,
            size_profile="small-no-model",
            model_source="https://models.example.org/v1",
            registry="registry.example.com/papaia/",
        )
    )
    assert found.rows == [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15]
    assert found.total == 14

    flagged, _ = run(typical(target), flags=["--voice", "--config-dir"])
    assert flagged.total == 14
    assert "switches --voice, --config-dir" in setup_answers.count_line(flagged)


def test_an_answer_file_counts_the_same_inputs_as_the_terminal(target):
    answers = typical(target)
    from_file, _ = run(answers)
    replies = {key: [value] for key, value in answers.items()}
    asked, prompter = run(None, replies=replies)

    assert asked.total == from_file.total == 12
    assert asked.answers == from_file.answers
    # Rows 13 to 15 are no questions of the round: registry only from a file, pairings and
    # the key check after setup.
    assert "registry" not in prompter.asked and "approve_pairings" not in prompter.asked


# ── checked at once, only that question again ───────────────────────────────


def test_an_invalid_url_in_the_answer_file_re_asks_that_question_only(target):
    answers = typical(target, size_profile="small-no-model", model_source="ftp:/models")
    found, prompter = run(answers, replies={"model_source": ["https://models.example.org/v1"]})

    assert prompter.asked == ["model_source"]
    assert found.answers["model_source"] == "https://models.example.org/v1"
    assert any("model_source" in line and "only this question" in line.lower()
               for line in prompter.said)
    # The repeated question is still one input.
    assert found.total == 13


def test_a_wrong_answer_on_the_terminal_repeats_that_question_only(target):
    answers = typical(target)
    del answers["admin_mail"]
    found, prompter = run(answers, replies={"admin_mail": ["not a mail", "it@example.org"]})

    assert prompter.asked == ["admin_mail", "admin_mail"]
    assert found.answers["admin_mail"] == "it@example.org"
    assert found.total == 12


def test_without_a_terminal_every_failed_key_is_named_and_nothing_is_asked(target):
    answers = typical(target, domain="https://example.org", admin_mail="x")
    with pytest.raises(AnswerError) as caught:
        run(answers, interactive=False)

    assert "domain:" in str(caught.value) and "admin_mail:" in str(caught.value)


def test_a_missing_required_key_without_a_terminal_is_named(target):
    answers = typical(target)
    del answers["size_profile"]
    with pytest.raises(AnswerError, match="size_profile: missing"):
        run(answers, interactive=False)


# ── the checks ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value", ["example.org/x", "localhost", "a.localhost", "-x.org", "org", "x .org"]
)
def test_unusable_base_domains_are_refused(value, target):
    with pytest.raises(AnswerError, match="domain"):
        run(typical(target, domain=value), interactive=False)


def test_an_empty_app_domain_puts_the_apps_below_the_base_domain(target):
    found, _ = run(typical(target, apps_domain=""))
    env = setup_answers.root_env(found.answers)
    assert env[ingress.APP_SINGLE_SITE_KEY] == "true"
    assert env[ingress.APP_DOMAIN_KEY] == ""
    assert "*.apps.example.org" in setup_answers.edge_names(found.answers)


@pytest.mark.parametrize("value", ["example.org", "apps.example.org", "org"])
def test_an_app_domain_inside_or_above_the_base_domain_is_refused(value, target):
    with pytest.raises(AnswerError, match="apps_domain"):
        run(typical(target, apps_domain=value), interactive=False)


def test_modules_are_checked_against_the_offer(target):
    with pytest.raises(AnswerError, match="does not offer paperless"):
        run(typical(target), interactive=False,
            offered=[m for m in ALL_MODULES if m != "paperless"])
    with pytest.raises(AnswerError, match="Unknown module"):
        run(typical(target, modules="studio,crm"), interactive=False)
    found, _ = run(typical(target, modules="none", apps_domain=None))
    assert found.answers["modules"] == []


def test_the_model_source_is_asked_only_without_a_local_model(target):
    with pytest.raises(AnswerError, match="model_source"):
        run(typical(target, model_source="https://models.example.org/v1"), interactive=False)


@pytest.mark.parametrize("profile", ["small-no-model", "large"])
def test_every_profile_without_a_local_model_asks_for_the_model_source(profile, target):
    found, _ = run(typical(target, size_profile=profile,
                           model_source="https://models.example.org/v1"))
    assert 8 in found.rows and found.total == 13
    assert setup_answers.shell_values(found)["ROUND_LOCAL_AI"] == "false"
    with pytest.raises(AnswerError, match="model_source: missing"):
        run(typical(target, size_profile=profile, backup_key=f"betrieb:{RECIPIENT}"),
            interactive=False)


@pytest.mark.parametrize(
    "value",
    ["ftp://models.example.org", "https://user:pw@models.example.org", "models.example.org",
     "https://", "https://models.example.org:99999/v1", "https://a b.org"],
)
def test_unusable_model_sources_are_refused(value, target):
    with pytest.raises(AnswerError, match="model_source"):
        run(typical(target, size_profile="small-no-model", model_source=value),
            interactive=False)


def test_generated_backup_keys_need_a_terminal(target):
    with pytest.raises(AnswerError, match="backup_key"):
        run(typical(target), interactive=False)
    found, _ = run(typical(target, backup_key=f"betrieb:{RECIPIENT}"), interactive=False)
    assert found.answers["backup_key"] == f"betrieb:{RECIPIENT}"
    assert 15 not in found.rows


@pytest.mark.parametrize(
    "value", ["age1nothing", f"{RECIPIENT}", f"a:{RECIPIENT},a:{RECIPIENT}", "BIG:" + RECIPIENT]
)
def test_unusable_backup_keys_are_refused(value, target):
    with pytest.raises(AnswerError, match="backup_key"):
        run(typical(target, backup_key=value), interactive=False)


def test_the_backup_target_must_be_an_existing_directory(tmp_path, target):
    with pytest.raises(AnswerError, match="backup_target"):
        run(typical(target, backup_target=str(tmp_path / "absent")), interactive=False)
    with pytest.raises(AnswerError, match="backup_target"):
        run(typical(target, backup_target="relative/dir"), interactive=False)


def test_the_registry_is_a_prefix_and_counts_only_when_given(target):
    with pytest.raises(AnswerError, match="registry"):
        run(typical(target, registry="registry.example.com/papaia"), interactive=False)


def test_the_pairing_digest_must_be_a_sha256(target):
    with pytest.raises(AnswerError, match="approve_pairings"):
        run(typical(target, approve_pairings="yes"), interactive=False)
    found, _ = run(typical(target, approve_pairings="sha256:" + "a" * 64))
    assert found.answers["approve_pairings"] == "sha256:" + "a" * 64


# ── the mail answer file ─────────────────────────────────────────────────────


def _mail(tmp_path: Path, text: str, mode: int = 0o600) -> Path:
    path = tmp_path / "smtp.env"
    path.write_text(text, encoding="utf-8")
    os.chmod(path, mode)
    return path


def test_the_mail_answer_file_is_read_with_its_password(tmp_path, target):
    path = _mail(tmp_path, "SMTP_URL=smtp+starttls://relay@mail.example.org:587\n"
                           "SMTP_PASSWORD=test-only-value\n")
    found, _ = run(typical(target, mail=str(path)))
    mail = setup_answers.read_mail_file(Path(found.answers["mail"]), "example.org")

    assert (mail.host, mail.port, mail.security, mail.user) == (
        "mail.example.org", 587, "starttls", "relay")
    assert mail.sender == "papaia@example.org"
    assert "test-only-value" not in repr(mail)


def test_a_mail_answer_file_readable_by_others_is_refused(tmp_path, target):
    path = _mail(tmp_path, "SMTP_URL=smtps://mail.example.org\n", mode=0o644)
    with pytest.raises(AnswerError, match="chmod 600"):
        run(typical(target, mail=str(path)), interactive=False)


@pytest.mark.parametrize(
    "text",
    [
        "SMTP_URL=http://mail.example.org\n",
        "SMTP_URL=smtps://u:pw@mail.example.org\n",
        "SMTP_URL=smtp://u@mail.example.org\nSMTP_PASSWORD=x1\n",
        "SMTP_URL=smtps://mail.example.org\nOTHER=1\n",
        "SMTP_PASSWORD=x1\n",
    ],
)
def test_unusable_mail_answer_files_are_refused(text, tmp_path, target):
    path = _mail(tmp_path, text)
    with pytest.raises(AnswerError, match="mail"):
        run(typical(target, mail=str(path)), interactive=False)


_LOGIN_FILE = "SMTP_URL=smtps://relay@mail.example.org\nSMTP_PASSWORD=pw-test-1\n"


def test_a_mail_answer_file_with_a_wrong_mode_re_asks_only_this_question(tmp_path, target):
    loose = _mail(tmp_path, _LOGIN_FILE, mode=0o640)
    good = tmp_path / "private" / "smtp.env"
    good.parent.mkdir()
    good.write_text(_LOGIN_FILE, encoding="utf-8")
    os.chmod(good, 0o600)

    found, prompter = run(typical(target, mail=str(loose)), replies={"mail": [str(good)]})

    assert prompter.asked == ["mail"]
    assert any("chmod 600" in line and "Only this question" in line for line in prompter.said)
    assert found.answers["mail"] == str(good)


def test_an_invalid_mail_url_re_asks_only_this_question(tmp_path, target):
    bad = _mail(tmp_path, "SMTP_URL=http://mail.example.org\n")
    good = tmp_path / "good.env"
    good.write_text(_LOGIN_FILE, encoding="utf-8")
    os.chmod(good, 0o600)

    found, prompter = run(typical(target, mail=str(bad)), replies={"mail": [str(good)]})

    assert prompter.asked == ["mail"]
    assert any("SMTP_URL must look like" in line for line in prompter.said)
    assert found.answers["mail"] == str(good)


def test_the_mail_server_is_asked_at_once_and_a_refused_login_re_asks_only_this_question(
    tmp_path, target
):
    path = _mail(tmp_path, _LOGIN_FILE)
    probe = Probe(smtp.ProbeResult(False, "auth", "login refused: (535, b'5.7.8 rejected')"))

    found, prompter = run(typical(target, mail=str(path)), replies={"mail": [str(path)]},
                          probe=probe)

    assert probe.calls[0] == ("mail.example.org", 465, "tls", "relay", "pw-test-1", True)
    assert len(probe.calls) == 2
    assert prompter.asked == ["mail"]
    said = "\n".join(prompter.said)
    assert "mail.example.org:465" in said and "login refused" in said
    assert "pw-test-1" not in said
    assert found.answers["mail"] == str(path)


def test_a_mail_server_that_does_not_answer_stops_a_round_without_a_terminal(tmp_path, target):
    path = _mail(tmp_path, _LOGIN_FILE)
    probe = Probe(smtp.ProbeResult(False, "connect", "timed out"))

    with pytest.raises(AnswerError) as caught:
        run(typical(target, mail=str(path)), interactive=False, probe=probe)

    assert "mail:" in str(caught.value) and "timed out" in str(caught.value)
    assert "pw-test-1" not in str(caught.value)


def test_a_mail_server_without_a_login_is_asked_without_one(tmp_path, target):
    path = _mail(tmp_path, "SMTP_URL=smtp+starttls://mail.example.org\n")
    probe = Probe()

    run(typical(target, mail=str(path)), probe=probe)

    assert probe.calls == [("mail.example.org", 587, "starttls", "", "", False)]


def test_the_mail_password_never_leaves_the_mail_answer_file(tmp_path, target):
    path = _mail(tmp_path, _LOGIN_FILE)
    found, prompter = run(typical(target, mail=str(path)))
    config = tmp_path / "papaia-config"
    config.mkdir()
    stored = setup_answers.store_record(config, found.record())

    assert "pw-test-1" not in stored.read_text(encoding="utf-8")
    assert "pw-test-1" not in "\n".join(setup_answers.shell_values(found).values())
    assert "pw-test-1" not in "\n".join(prompter.said)


def _installed(tmp_path: Path, target: Path, mail: str) -> Path:
    config = tmp_path / "papaia-config"
    config.mkdir()
    (config / ".env").write_text("")
    (config / "deployment.yaml").write_text("addons: []\n")
    found, _ = run(typical(target, mail=mail))
    setup_answers.store_record(config, found.record())
    return config


def _doctor_ctx(config: Path, *, in_container: bool = False):
    from datetime import datetime, timezone

    from lib import doctor

    return doctor.Context(config, REPO, run=lambda a, t: None,
                          probes=doctor.Probes(in_container=lambda: in_container),
                          now=datetime.now(timezone.utc))


def test_doctor_warns_while_the_mail_answer_file_exists(tmp_path, target):
    from lib import doctor

    path = _mail(tmp_path, _LOGIN_FILE)
    config = _installed(tmp_path, target, str(path))

    result = doctor.check_mail_answer_file(_doctor_ctx(config))
    assert result.status == doctor.WARN
    assert str(path) in result.summary and "rm " in result.summary
    assert "pw-test-1" not in result.summary + repr(result.details)

    path.unlink()
    assert doctor.check_mail_answer_file(_doctor_ctx(config)).status == doctor.PASS


def test_doctor_skips_the_mail_answer_file_where_there_is_none_to_delete(tmp_path, target):
    from lib import doctor

    path = _mail(tmp_path, _LOGIN_FILE)
    config = _installed(tmp_path, target, "none")
    assert doctor.check_mail_answer_file(_doctor_ctx(config)).status == doctor.SKIP

    (config / setup_answers.RECORD_FILE).unlink()
    assert doctor.check_mail_answer_file(_doctor_ctx(config)).status == doctor.SKIP

    other = tmp_path / "other"
    other.mkdir()
    config = _installed(other, target, str(path))
    in_container = doctor.check_mail_answer_file(_doctor_ctx(config, in_container=True))
    assert in_container.status == doctor.SKIP, "a container does not see the host's files"


def test_setup_asks_to_delete_the_mail_answer_file_until_it_is_gone(tmp_path, target, capsys):
    path = _mail(tmp_path, _LOGIN_FILE)
    config = _installed(tmp_path, target, str(path))
    args = type("Args", (), {"config_dir": str(config), "repo_root": str(REPO)})()

    assert cli_setup_round.cmd_mail_file_notice(args) == 0
    shown = capsys.readouterr()
    assert f"rm {path}" in shown.err and "Delete" in shown.err
    assert "pw-test-1" not in shown.out + shown.err

    path.unlink()
    assert cli_setup_round.cmd_mail_file_notice(args) == 0
    shown = capsys.readouterr()
    assert shown.out + shown.err == ""


def test_the_readme_shows_the_mail_answer_file_and_its_removal():
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    section = readme[readme.index("The mail answer file `smtp.env`"):]
    section = section[:section.index("### Size profiles")]
    assert "SMTP_URL=smtp+starttls://" in section and "SMTP_PASSWORD=" in section
    assert "rm " in section and "doctor mail_answer_file" in section
    assert "| `mail_answer_file` |" in readme
    german = (REPO / "docs" / "de" / "betrieb" / "mail-antwortdatei.md").read_text(
        encoding="utf-8")
    assert "SMTP_URL=" in german and "mail_answer_file" in german


# ── the certificate bundle ───────────────────────────────────────────────────


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is not available")
def test_a_certificate_bundle_must_cover_both_domains(tmp_path, target):
    def bundle(names: str) -> Path:
        key, cert = tmp_path / "k.pem", tmp_path / "c.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
             "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "2",
             "-subj", "/CN=test", "-addext", f"subjectAltName={names}"],
            check=True, capture_output=True,
        )
        path = tmp_path / "bundle.pem"
        path.write_bytes(cert.read_bytes() + key.read_bytes())
        os.chmod(path, 0o600)
        return path

    good = bundle("DNS:example.org,DNS:*.example.org,DNS:example-apps.org,DNS:*.example-apps.org")
    found, _ = run(typical(target, tls=str(good)))
    assert found.answers["tls"] == str(good)

    short = bundle("DNS:example.org,DNS:*.example.org")
    with pytest.raises(AnswerError, match=r"does not cover example-apps\.org"):
        run(typical(target, tls=str(short)), interactive=False)


def test_a_bundle_without_a_key_or_readable_by_others_is_refused(tmp_path, target):
    path = tmp_path / "bundle.pem"
    path.write_text("-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n")
    os.chmod(path, 0o600)
    with pytest.raises(AnswerError, match="private key"):
        run(typical(target, tls=str(path)), interactive=False)
    os.chmod(path, 0o640)
    with pytest.raises(AnswerError, match="chmod 600"):
        run(typical(target, tls=str(path)), interactive=False)


# ── the answer file ──────────────────────────────────────────────────────────


def _file(tmp_path: Path, doc) -> Path:
    path = tmp_path / "answers.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


def test_unknown_keys_and_a_wrong_format_are_refused(tmp_path, target):
    with pytest.raises(AnswerError, match="unknown key"):
        setup_answers.load_file(_file(tmp_path, {"format": setup_answers.FORMAT, "domian": "x"}))
    with pytest.raises(AnswerError, match="format"):
        setup_answers.load_file(_file(tmp_path, {"format": "papaia.setup-answers/2"}))
    with pytest.raises(AnswerError, match="unknown key"):
        setup_answers.load_file(
            _file(tmp_path, {"format": setup_answers.FORMAT, "backup_key_check": "abcdefgh"})
        )


def test_modules_may_be_a_list_in_the_file(tmp_path, target):
    doc = {"format": setup_answers.FORMAT, **typical(target, apps_domain=None),
           "modules": ["flow", "data"]}
    found, _ = run(setup_answers.load_file(_file(tmp_path, doc)))
    assert found.answers["modules"] == ["data", "flow"]


def _cli(*args: str, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "lib.cli", "--repo-root", str(REPO), "--config-dir",
         "/nonexistent-papaia-config", *args],
        cwd=TOOLS, input=stdin, capture_output=True, text=True, check=False,
        env={**os.environ, "PYTHONPATH": str(TOOLS)},
    )


def test_install_from_an_answer_file_counts_its_inputs(tmp_path, target):
    doc = {"format": setup_answers.FORMAT,
           **typical(target, backup_key=f"betrieb:{RECIPIENT}", modules=CHECKOUT_MODULES)}
    answers, record = _file(tmp_path, doc), tmp_path / "record.yaml"

    done = _cli("setup-round", f"--answers={answers}", f"--record-out={record}",
                "--flags=-y")

    assert done.returncode == 0, done.stderr
    assert "Inputs: 12 of at most 15" in done.stderr
    assert "switches -y" in done.stderr
    assert (record.stat().st_mode & 0o077) == 0
    stored = setup_answers.load_record(record)
    assert stored["inputs"]["total"] == 12
    values = _cli("setup-round-values", f"--record={record}")
    assert values.returncode == 0, values.stderr
    lines = dict(line.split("=", 1) for line in values.stdout.splitlines())
    assert lines["ROUND_APP_HOST"] == "https://example.org"
    assert lines["ROUND_LOCAL_AI"] == "true"
    assert lines["ROUND_INPUTS"] == "12"


def test_the_cli_re_asks_only_the_invalid_url_on_a_terminal(tmp_path, target):
    doc = {"format": setup_answers.FORMAT,
           **typical(target, size_profile="small-no-model", model_source="not a url",
                     backup_key=f"betrieb:{RECIPIENT}", modules=CHECKOUT_MODULES)}
    answers, record = _file(tmp_path, doc), tmp_path / "record.yaml"

    done = _cli("setup-round", f"--answers={answers}", f"--record-out={record}",
                "--interactive", stdin="https://models.example.org/v1\n")

    assert done.returncode == 0, done.stderr
    assert done.stderr.count(") Model source") == 1
    asked = re.findall(r"^\s*\d+\) (.+)$", done.stderr, re.MULTILINE)
    assert asked == ["Model source"], "no other question was asked"
    assert setup_answers.load_record(record)["answers"]["model_source"] == (
        "https://models.example.org/v1")


def test_the_cli_without_a_terminal_changes_nothing_on_a_bad_answer(tmp_path, target):
    doc = {"format": setup_answers.FORMAT, **typical(target, domain="bad domain")}
    answers, record = _file(tmp_path, doc), tmp_path / "record.yaml"
    record.write_text("")

    done = _cli("setup-round", f"--answers={answers}", f"--record-out={record}")

    assert done.returncode == 2
    assert "domain:" in done.stderr and "Nothing was changed" in done.stderr
    assert record.read_text() == ""


# ── what setup does with the record ──────────────────────────────────────────


def test_the_record_decides_host_profile_mail_and_backup(tmp_path, target):
    path = _mail(tmp_path, "SMTP_URL=smtps://relay@mail.example.org\nSMTP_PASSWORD=pw-test-1\n")
    found, _ = run(typical(target, mail=str(path)))

    class Args:
        app_host = None
        reverse_proxy_provider = None
        enable_local_ai = None
        enable_smtp = None

    values = cli_setup_round.setup_overrides(found.record(), Args())
    assert values["app_host"] == "https://example.org"
    assert values["reverse_proxy_provider"] == "internal_nginx"
    assert values["enable_local_ai"] is True
    assert values["smtp_security"] == "tls" and values["smtp_port"] == "465"
    assert values["smtp_password"] == "pw-test-1"
    assert setup_answers.root_env(found.answers)["PAPAIA_SIZE_PROFILE"] == "small"

    class Same(Args):
        app_host = "https://example.org"
        reverse_proxy_provider = "internal_nginx"
        enable_local_ai = True
        enable_smtp = True

    same = cli_setup_round.setup_overrides(found.record(), Same())
    assert "app_host" not in same and same["smtp_password"] == "pw-test-1"


@pytest.mark.parametrize(
    "switch",
    [{"app_host": "https://other.example.org"}, {"reverse_proxy_provider": "no_proxy"},
     {"enable_local_ai": False}, {"enable_smtp": False}],
)
def test_a_switch_that_contradicts_the_record_is_refused(switch, tmp_path, target):
    path = _mail(tmp_path, "SMTP_URL=smtps://relay@mail.example.org\nSMTP_PASSWORD=pw-test-1\n")
    found, _ = run(typical(target, mail=str(path)))
    args = {"app_host": None, "reverse_proxy_provider": None, "enable_local_ai": None,
            "enable_smtp": None, **switch}

    with pytest.raises(AnswerError, match="question round"):
        cli_setup_round.setup_overrides(found.record(), type("Args", (), args)())


def test_doctor_warns_while_the_contact_point_is_the_derived_one(tmp_path, target, monkeypatch):
    from datetime import datetime, timezone

    from lib import catalog, doctor

    config = tmp_path / "papaia-config"
    config.mkdir()
    (config / ".env").write_text("")
    (config / "deployment.yaml").write_text("addons: []\n")
    found, _ = run(typical(target))
    setup_answers.store_record(config, found.record())
    assert (config / setup_answers.RECORD_FILE).stat().st_mode & 0o077 == 0
    contact = {"name": "Verwaltung von example.org", "mail": "it@example.org"}
    monkeypatch.setattr(catalog, "current_branding", lambda c: {"contact": contact})
    ctx = doctor.Context(config, REPO, run=lambda a, t: None, probes=doctor.Probes(),
                         now=datetime.now(timezone.utc))

    assert doctor.check_contact_point(ctx).status == doctor.WARN
    contact["name"] = "IT-Service"
    assert doctor.check_contact_point(ctx).status == doctor.PASS


# ── control characters, the record, the size of the answer file ─────────────


@pytest.mark.parametrize("key", ["tls", "upstream_idp", "mail", "backup_target"])
def test_a_path_with_a_line_break_is_refused(key, tmp_path, target):
    odd = tmp_path / "a\nROUND_TLS=x"
    odd.mkdir()
    with pytest.raises(AnswerError, match=f"{key}: .*control character"):
        run(typical(target, **{key: str(odd)}), interactive=False)


@pytest.mark.parametrize(
    "key, value",
    [("domain", "example.org\r"), ("admin_mail", "it@example.org\n"),
     ("model_source", "https://models.example.org/v1\x00"),
     ("backup_key", f"betrieb:{RECIPIENT}\nX=1"), ("registry", "registry.example.com/\t/")],
)
def test_every_answer_with_a_control_character_is_refused(key, value, target):
    answers = typical(target, size_profile="small-no-model", **{key: value})
    answers.setdefault("model_source", "https://models.example.org/v1")
    with pytest.raises(AnswerError, match=key):
        run(answers, interactive=False)


def test_shell_values_never_carry_a_line_break(target):
    found, _ = run(typical(target))
    found.answers["backup_target"] = "/mnt/x\nROUND_TLS=/etc/shadow"
    with pytest.raises(AnswerError, match="control character"):
        setup_answers.shell_values(found)


def _record(tmp_path: Path, target: Path, **answers) -> Path:
    found, _ = run(typical(target))
    doc = found.record()
    doc["answers"].update(answers)
    path = tmp_path / "record.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


def test_the_record_is_checked_row_by_row_when_it_is_read(tmp_path, target):
    stored = setup_answers.load_record(_record(tmp_path, target))
    assert stored["answers"]["backup_key"] == "generate", "generate came from the terminal"

    for key, value in [("domain", "bad domain"), ("admin_mail", "x"),
                       ("size_profile", "huge"), ("modules", ["crm"]),
                       ("backup_target", "relative/dir"), ("tls", "/x\ny"),
                       ("backup_key_check", "abcdefgh")]:
        with pytest.raises(AnswerError, match=key):
            setup_answers.load_record(_record(tmp_path, target, **{key: value}))


def test_the_answer_file_is_read_only_up_to_its_limit(tmp_path):
    big = tmp_path / "big.yaml"
    big.write_bytes(b"#" * (setup_answers.MAX_FILE_BYTES + 10))
    with pytest.raises(AnswerError, match="larger than"):
        setup_answers.load_file(big)
    fifo = tmp_path / "answers.fifo"
    os.mkfifo(fifo)
    with pytest.raises(AnswerError, match="not a regular file"):
        setup_answers.load_file(fifo)
    if Path("/dev/zero").exists():
        with pytest.raises(AnswerError, match="not a regular file"):
            setup_answers.load_file(Path("/dev/zero"))
