"""Attack detection over proxy log entries.

Specific signatures and counters decide on their own. Only vague signals
(a stray quote, a semicolon) can be sent to an optional LLM for a second
opinion, and the LLM may only answer from a fixed set of choices. So the LLM
advises, but fixed rules decide what the rest of the system does.
"""
import re
import time
from collections import defaultdict, deque
from urllib.parse import unquote_plus

WINDOW = 30.0          # seconds
BRUTE_THRESHOLD = 5    # failed logins from one IP inside WINDOW
SCAN_THRESHOLD = 15    # distinct 404 paths from one IP inside WINDOW
COOLDOWN = 60.0        # do not re-alert the same (ip, kind) inside this time
KINDS = ("sqli", "xss", "traversal")  # what the LLM is allowed to answer

_STRONG = {
    "sqli": [
        r"['\"]\s*or\s+['\"\d]",
        r"\bor\s+\d+\s*=\s*\d+",
        r"union\s+(all\s+)?select",
        r"sleep\s*\(\s*\d",
        r";\s*drop\s+table",
        r"['\"]\s*--",
    ],
    "xss": [
        r"<\s*script",
        r"\bon(error|load|click|mouseover)\s*=",
        r"javascript\s*:",
        r"<\s*iframe",
    ],
    "traversal": [r"\.\./", r"\.\.\\", r"/etc/passwd"],
}
STRONG = {k: [re.compile(p, re.I) for p in v] for k, v in _STRONG.items()}
WEAK = re.compile(r"""['"`;|\x00]|\$\(|\{\{""")


def _req_text(path: str, query: str, body: str) -> str:
    # decode twice so double-encoded payloads are still caught
    return unquote_plus(unquote_plus(f"{path}?{query} {body}"))


class Detector:
    def __init__(self, triage=None):
        """triage: optional callable(entry) -> dict | None, used for vague signals only."""
        self.triage = triage
        self._fails = defaultdict(deque)    # ip -> times of failed logins
        self._missing = defaultdict(dict)   # ip -> {path: time} of 404s
        self._last_alert = {}               # (ip, kind) -> time

    def analyze(self, entries: list) -> list:
        alerts = []
        for e in entries:
            try:
                alerts.extend(self._one(e))
            except (KeyError, TypeError, ValueError, AttributeError):
                continue  # malformed entry: skip it
        for ip in [ip for ip, q in self._fails.items() if not q]:
            del self._fails[ip]
        for ip in [ip for ip, m in self._missing.items() if not m]:
            del self._missing[ip]
        return alerts

    def _one(self, e: dict) -> list:
        if e.get("blocked"):
            return []  # already blocked by the proxy, nothing new to learn
        ip = e["ip"]
        if not isinstance(ip, str):
            return []
        ts = float(e["ts"])
        method = str(e.get("method", ""))
        path = str(e.get("path", ""))
        query = str(e.get("query", ""))
        status = e.get("status")
        line = f"{method} {path}" + (f"?{query}" if query else "")
        out = []

        text = _req_text(path, query, str(e.get("body_head", "")))
        strong = next((k for k, pats in STRONG.items() if any(p.search(text) for p in pats)), None)
        if strong:
            self._add(out, strong, "high", ip, ts, e, f"{strong} signature in request", [line])
        elif self.triage and WEAK.search(_req_text(path, query, "")):
            verdict = self._ask(e)
            if verdict:
                kind, reason = verdict
                self._add(out, kind, "medium", ip, ts, e, reason or "LLM judged the request malicious", [line], source="llm")

        if path == "/rest/user/login" and method == "POST" and status == 401:
            q = self._fails[ip]
            q.append(ts)
            while q and ts - q[0] > WINDOW:
                q.popleft()
            if len(q) >= BRUTE_THRESHOLD:
                self._add(out, "brute_force", "high", ip, ts, e,
                          f"{len(q)} failed logins in {int(WINDOW)}s", [line], count=len(q))

        if status == 404:
            m = self._missing[ip]
            m[path] = ts
            for p in [p for p, t in m.items() if ts - t > WINDOW]:
                del m[p]
            if len(m) >= SCAN_THRESHOLD:
                self._add(out, "recon_scan", "high", ip, ts, e,
                          f"{len(m)} distinct missing paths in {int(WINDOW)}s", [line], count=len(m))
        return out

    def _ask(self, e: dict):
        try:
            res = self.triage(e)
        except Exception:
            return None
        if not isinstance(res, dict):
            return None
        if res.get("verdict") != "attack" or res.get("kind") not in KINDS:
            return None
        reason = "".join(ch for ch in str(res.get("reason", ""))[:80] if ch.isprintable())
        return res["kind"], reason

    def _add(self, out, kind, severity, ip, ts, e, reason, evidence, source="rule", count=1):
        last = self._last_alert.get((ip, kind))
        if last is not None and ts - last < COOLDOWN:
            return
        self._last_alert[(ip, kind)] = ts
        out.append({
            "kind": kind,
            "severity": severity,
            "ip": ip,
            "reason": reason[:120],
            "source": source,
            "count": count,
            "evidence": [x[:160] for x in evidence],
            "entry_n": e.get("n"),
            "event_ts": ts,
            "detected_ts": round(time.time(), 3),
        })
