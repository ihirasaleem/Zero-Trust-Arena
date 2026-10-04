
"""Tamper-evident audit log.

Every entry stores the hash of the previous entry. Editing or deleting any
entry in the middle breaks the chain, and verify() reports where.

Verify a saved log from the command line:
    python audit.py audit_log.jsonl
"""

import hashlib
import json
import os
import sys
import threading
import time

GENESIS = "0" * 64
_FIELDS = ("seq", "ts", "kind", "detail", "prev")


def entry_hash(ev: dict) -> str:
    payload = json.dumps(
        {k: ev[k] for k in _FIELDS},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def verify_events(events: list):
    """Return (ok, broken_index). broken_index is the first bad entry, or None."""
    prev = GENESIS

    for i, ev in enumerate(events):
        try:
            good = (
                ev["seq"] == i
                and ev["prev"] == prev
                and ev["hash"] == entry_hash(ev)
            )
        except (KeyError, TypeError):
            good = False

        if not good:
            return False, i

        prev = ev["hash"]

    return True, None


def load_file(path: str) -> list:
    events = []

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))

    return events


def verify_file(path: str):
    """Return (ok, broken_index). broken_index is -1 if the file is unreadable."""
    try:
        events = load_file(path)
    except (OSError, ValueError):
        return False, -1

    return verify_events(events)


class AuditLog:
    def __init__(self, path: str = None):
        self.events = []
        self._lock = threading.Lock()

        # Vercel's project directory is read-only.
        # Use temporary storage when running on Vercel.
        if path and os.environ.get("VERCEL"):
            path = os.path.join("/tmp", os.path.basename(path))

        self.path = path

        if self.path:
            open(self.path, "w", encoding="utf-8").close()

    def append(self, kind: str, **detail) -> dict:
        with self._lock:
            prev = self.events[-1]["hash"] if self.events else GENESIS

            ev = {
                "seq": len(self.events),
                "ts": round(time.time(), 3),
                "kind": kind,
                "detail": detail,
                "prev": prev,
            }

            ev["hash"] = entry_hash(ev)
            self.events.append(ev)

            if self.path:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(ev, sort_keys=True) + "\n")

            return ev

    def since(self, seq: int) -> list:
        return [e for e in self.events if e["seq"] > seq]

    def verify(self):
        return verify_events(self.events)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "audit_log.jsonl"

    ok, bad = verify_file(path)

    if ok:
        print(f"AUDIT OK: hash chain intact ({path})")
    elif bad == -1:
        print(f"TAMPERING DETECTED: {path} is unreadable or has a damaged line")
        sys.exit(1)
    else:
        print(f"TAMPERING DETECTED: chain broken at entry {bad} ({path})")
        sys.exit(1)
