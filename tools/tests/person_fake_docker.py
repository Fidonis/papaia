"""A stand-in for `docker` in the subprocess tests of `papaia-ctl person`
(test_person.py): `docker ps` names one container, `docker exec … papaia_audit person`
answers through the real request routes (person_requests.PersonRequestApi) over a store
kept in a JSON file, and `docker exec … lifecycle.py find` runs the real `find` of
papaia-lifecycle on a key folder. The file, the folder and the clock of the test come
from the environment (PERSON_FAKE_AUDIT_STORE, PERSON_FAKE_LIFECYCLE_KEYS,
PERSON_FAKE_NOW)."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict, replace
from datetime import datetime
from pathlib import Path

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS.parent))
sys.path.insert(0, str(TESTS.parents[1] / "src" / "infra" / "audit"))
sys.path.insert(0, str(TESTS))

from papaia_audit import core  # noqa: E402
from papaia_audit import person_requests as pr  # noqa: E402

_TIMES = ("requested_at", "decided_at", "changed_at")


class FileRequestStore:
    """Requests and keys of papaia-audit in one JSON file; events are only checked."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.requests: dict[str, pr.PersonRequest] = {}
        self.keys: dict[str, bytes] = {}
        self.check = core.SubmissionCheck()
        self.seq = 0
        if path.exists():
            doc = json.loads(path.read_text(encoding="utf-8"))
            for rid, item in doc["requests"].items():
                for name in _TIMES:
                    if item[name] is not None:
                        item[name] = datetime.fromisoformat(item[name])
                self.requests[rid] = pr.PersonRequest(**item)
            self.keys = {rid: bytes.fromhex(k) for rid, k in doc["keys"].items()}
            self.seq = doc["seq"]

    def _save(self) -> None:
        requests = {}
        for rid, item in self.requests.items():
            data = asdict(item)
            for name in _TIMES:
                if data[name] is not None:
                    data[name] = data[name].isoformat()
            requests[rid] = data
        self.path.write_text(json.dumps({
            "requests": requests, "keys": {r: k.hex() for r, k in self.keys.items()},
            "seq": self.seq,
        }), encoding="utf-8")

    def _event(self, build) -> None:
        self.seq += 1
        self.check.check(build(self.seq).encode("utf-8"), "papaia-audit")

    def append_own(self, build) -> int:
        self._event(build)
        self._save()
        return self.seq

    def add_person_request(self, request, build) -> None:
        self._event(build)
        self.requests[request.id] = replace(request)
        self._save()

    def get_person_request(self, request_id):
        found = self.requests.get(request_id)
        return None if found is None else replace(found)

    def person_requests_of(self, sub, since):
        return [replace(r) for r in self.requests.values()
                if sub in (r.requested_by, r.confirmed_by) and r.requested_at > since]

    def decide_person_request(self, request_id, state, by, at, key, build) -> bool:
        item = self.requests[request_id]
        if item.state != "open":
            return False
        assert state != "confirmed" or (by == item.confirmed_by and by != item.requested_by)
        self._event(build)
        if key is not None:
            self.keys[request_id] = key
        item.state, item.decided_by, item.decided_at = state, by, at
        self._save()
        return True

    def advance_person_request(self, request_id, from_state, to_state, at, build) -> bool:
        item = self.requests[request_id]
        if item.state != from_state:
            return False
        self._event(build)
        item.state, item.changed_at = to_state, at
        if to_state in ("done", "partial"):
            self.keys.pop(request_id, None)
        self._save()
        return True

    def take_person_request_key(self, request_id, build):
        if self.requests[request_id].state != "running" or request_id not in self.keys:
            return None
        self._event(build)
        key = self.keys.pop(request_id)
        self._save()
        return key


def _audit_person(stdin: str) -> int:
    store = FileRequestStore(Path(os.environ["PERSON_FAKE_AUDIT_STORE"]))
    now = float(os.environ["PERSON_FAKE_NOW"])
    api = pr.PersonRequestApi(store, lambda: None, b"k" * 32, core.SubmissionCheck(),
                              clock=lambda: now)
    request = pr.host_request(stdin)
    if request is None:
        print(json.dumps({"status": 400, "body": {"code": "AUDIT-HOST-400"}}))
        return 0
    response = api.host(request)
    print(json.dumps({"status": response.status, "body": json.loads(response.body)}))
    return 0


def _lifecycle_find(args: list[str]) -> int:
    from test_lifecycle import lc

    keys = os.environ["PERSON_FAKE_LIFECYCLE_KEYS"]
    args = [a for a in args if not a.startswith("--key-dir=")]
    return lc.main(["find", f"--key-dir={keys}", *args])


def main(argv: list[str]) -> int:
    if argv[:1] == ["ps"]:
        service = next((a.split("=", 1)[1] for a in argv if "compose.service=" in a), "")
        print(f"itk-{service}-1")
        return 0
    if argv[:1] == ["exec"]:
        rest = [a for a in argv[1:] if a != "-i"][1:]
        if rest[-3:] == ["-m", "papaia_audit", "person"]:
            return _audit_person(sys.stdin.read())
        if "/opt/papaia-lifecycle/lifecycle.py" in rest:
            return _lifecycle_find(rest[rest.index("find") + 1:])
    print(f"fake docker: unexpected {argv}", file=sys.stderr)
    return 125


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
