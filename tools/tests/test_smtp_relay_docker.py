"""The mail relay with real containers: whatever a module puts into From, the mail leaves
the relay with the one sender of the installation; subjects, text and link pass
unchanged; a mail with an attachment is refused (PLT-78 with Ä-32, ASS-42-A6, KE-25).

The relay is the module's own compose file with its pinned image. Its upstream is a
small capture server on the same network (security `none`, no login), so every mail the
relay delivers can be read back as it arrived. The recipient domain is a network alias of
that server, so the relay's recipient-domain check passes without public DNS. A sender
container plays two modules: a task from Flow and a reminder from the assistant, each
with its own From and a Sender header, as a module that ignores the rule would send them.

Needs Docker; skipped without it. The Compose project and the address range can be set
with PAPAIA_SMTP_TEST_PROJECT and PAPAIA_SMTP_TEST_SUBNET (a /24) so the test does not
collide with other stacks on the same host.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
from email import message_from_bytes, policy
from pathlib import Path

import pytest
import yaml

from lib import smtp

REPO = Path(__file__).resolve().parents[2]
COMPOSE = REPO / "src" / "infra" / "smtp-relay" / "docker-compose.yml"
PROJECT = os.environ.get("PAPAIA_SMTP_TEST_PROJECT", "papaia-smtp-test")
SUBNET = ipaddress.ip_network(os.environ.get("PAPAIA_SMTP_TEST_SUBNET", "10.250.83.0/24"))
# The pinned base of the core's own images (src/infra/egress/Dockerfile).
IMAGE = (
    "python:3.12.16-slim-trixie"
    "@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
)
INSTALLATION = "Café Müller"
SENDER = "noreply@example.org"


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

# The upstream: accepts every mail and keeps it as /captured/<n>.eml.
_CAPTURE = r"""
import asyncio, itertools
count = itertools.count(1)

async def session(reader, writer):
    def say(line):
        writer.write(line.encode() + b"\r\n")
    say("220 capture")
    while True:
        line = await reader.readline()
        if not line:
            break
        verb = line[:4].upper()
        if verb == b"DATA":
            say("354 go ahead")
            lines = []
            while True:
                part = await reader.readline()
                if part in (b".\r\n", b".\n", b""):
                    break
                lines.append(part[1:] if part.startswith(b"..") else part)
            with open(f"/captured/{next(count)}.eml", "wb") as handle:
                handle.write(b"".join(lines))
            say("250 queued")
        elif verb == b"QUIT":
            say("221 bye")
            await writer.drain()
            break
        else:
            say("250 capture")
        await writer.drain()
    writer.close()

async def main():
    server = await asyncio.start_server(session, "0.0.0.0", 25)
    await server.serve_forever()

asyncio.run(main())
"""

# Runs in the sender container; prints one JSON object with the outcome of each mail.
_SEND = r"""
import json, smtplib
from email.message import EmailMessage

def notification(module, sender, subject, link):
    mail = EmailMessage()
    mail["From"] = f"{module} <{sender}>"
    mail["Sender"] = f"{module} Service <{sender}>"
    mail["To"] = "anna@recipients.test"
    mail["Subject"] = subject
    mail.set_content(f"Aus {module}\n\n{subject.split(': ', 1)[1]}\n\nÖffnen: {link}\n")
    mail.add_alternative(f'<p>Aus {module}</p><p><a href="{link}">Öffnen</a></p>', subtype="html")
    return mail

results = {}
with smtplib.SMTP("smtp-relay", 587, timeout=30) as relay:
    task = notification("Flow", "flow@example.org", "Aufgabe: Urlaubsantrag Cem",
                        "https://flow.papaia.example.org/tasks/42")
    relay.send_message(task)
    results["task"] = "sent"
    reminder = notification("Assistent", "assist@example.org", "Erinnerung: Rechnung Y prüfen",
                            "https://assist.papaia.example.org/reminders/7")
    relay.send_message(reminder)
    results["reminder"] = "sent"
    attached = notification("Flow", "flow@example.org", "Aufgabe: Bericht", "https://x.example.org/")
    attached.add_attachment(b"%PDF-1.4", maintype="application", subtype="pdf", filename="r.pdf")
    try:
        relay.send_message(attached)
        results["attachment"] = "sent"
    except smtplib.SMTPDataError as exc:
        results["attachment"] = [exc.smtp_code, exc.smtp_error.decode()]
print(json.dumps(results))
"""

_READ = r"""
import json, pathlib, sys, time
deadline = time.time() + float(sys.argv[1])
while time.time() < deadline and len(list(pathlib.Path("/captured").glob("*.eml"))) < 2:
    time.sleep(1)
time.sleep(3)
print(json.dumps({p.name: p.read_text(errors="replace")
                  for p in sorted(pathlib.Path("/captured").glob("*.eml"))}))
"""


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=300, check=check)


@pytest.fixture(scope="module")
def relay(tmp_path_factory):
    work = tmp_path_factory.mktemp("smtp-relay")
    secret = work / smtp.MODULE_DIR / smtp.PASSWORD_FILE
    secret.parent.mkdir(parents=True)
    secret.write_text("", encoding="utf-8")  # the capture server needs no login
    values = {
        "PAPAIA_CONFIG_DIR": str(work),
        smtp.KEY_HOST: "capture",
        smtp.KEY_PORT: "25",
        smtp.KEY_FROM: SENDER,
        smtp.KEY_FROM_NAME: INSTALLATION,
        **smtp.derived_keys("none", SENDER, INSTALLATION),
    }
    env_file = work / "test.env"
    env_file.write_text("".join(f"{k}={v}\n" for k, v in values.items()), encoding="utf-8")
    sleeper = {"image": IMAGE, "init": True, "networks": ["papaia-net"]}
    override = {
        "services": {
            "capture": {
                **sleeper,
                "command": ["python", "-c", _CAPTURE],
                "tmpfs": ["/captured"],
                # The relay refuses recipient domains that do not resolve; this name
                # resolves on the test network only, so nothing depends on public DNS.
                "networks": {"papaia-net": {"aliases": ["recipients.test"]}},
            },
            "sender": {**sleeper, "command": ["sleep", "infinity"]},
            "smtp-relay": {"depends_on": ["capture"]},
        },
        "networks": {
            "papaia-net": {
                "name": f"{PROJECT}-net",
                "ipam": {"config": [{"subnet": str(SUBNET)}]},
            }
        },
    }
    override_file = work / "override.yml"
    override_file.write_text(yaml.safe_dump(override, sort_keys=False), encoding="utf-8")
    base = ("docker", "compose", "-p", PROJECT, "--env-file", str(env_file),
            "--profile", smtp.PROFILE, "-f", str(COMPOSE), "-f", str(override_file))
    try:
        up = _run(*base, "up", "-d", "--wait", "--wait-timeout", "180", check=False)
        assert up.returncode == 0, up.stderr
        yield base
    finally:
        _run(*base, "down", "-v", "--remove-orphans", "--timeout", "5", check=False)


def _exec(base: tuple[str, ...], service: str, script: str, *args: str) -> dict:
    out = _run(*base, "exec", "-T", service, "python", "-c", script, *args, check=False)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


@pytest.fixture(scope="module")
def captured(relay):
    sent = _exec(relay, "sender", _SEND)
    mails = _exec(relay, "capture", _READ, "90")
    parsed = [message_from_bytes(m.encode(), policy=policy.default) for m in mails.values()]
    return sent, {str(m["Subject"]).split(":", 1)[0]: m for m in parsed}


def test_task_and_reminder_leave_with_the_same_sender_of_the_installation(captured):
    _, mails = captured

    assert set(mails) == {"Aufgabe", "Erinnerung"}
    task, reminder = mails["Aufgabe"], mails["Erinnerung"]
    assert task["From"].addresses[0].display_name == INSTALLATION
    assert task["From"].addresses[0].addr_spec == SENDER
    assert str(task["From"]) == str(reminder["From"])
    assert "Sender" not in task and "Sender" not in reminder


def test_subjects_text_and_link_pass_unchanged(captured):
    _, mails = captured

    assert str(mails["Aufgabe"]["Subject"]) == "Aufgabe: Urlaubsantrag Cem"
    assert str(mails["Erinnerung"]["Subject"]) == "Erinnerung: Rechnung Y prüfen"
    text = mails["Aufgabe"].get_body(preferencelist=("plain",)).get_content()
    assert text.startswith("Aus Flow\n")
    assert "https://flow.papaia.example.org/tasks/42" in text


def test_a_mail_with_an_attachment_is_refused_and_never_delivered(captured):
    sent, mails = captured

    assert sent["task"] == sent["reminder"] == "sent"
    code, reason = sent["attachment"]
    assert code == 550 and reason.startswith("5.7.1 Notifications carry text and a link only")
    assert "Bericht" not in " ".join(str(m["Subject"]) for m in mails.values())
