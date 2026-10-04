"""Tests for the Red Team: target restriction, catalog safety, and the full
Recon -> Analyst -> Planner chain against the hub and proxy.

Offline checks run on their own. The integration part needs the hub and
proxy running (same as test_blue.py) and starts the Red agents itself:

  1. python run_hub.py
  2. python proxy.py
  Then:  python test_red.py
"""
import os
import subprocess
import sys
import time
import uuid

import requests

import red_agents as R
from zt_client import HubClient
from zt_crypto import Identity

total = 0
fails = 0


def check(name: str, ok: bool, extra: str = "") -> None:
    global total, fails
    total += 1
    if not ok:
        fails += 1
    print(("PASS" if ok else "FAIL"), "-", name, extra, flush=True)


# ---- offline: target restriction
for bad in ("http://8.8.8.8:80", "http://1.1.1.1:8080", "http://example.com:8080"):
    try:
        R.ensure_target_allowed(bad)
        check(f"1 refuses public target {bad}", False)
    except R.TargetNotAllowed:
        check(f"1 refuses public target {bad}", True)

for good in ("http://127.0.0.1:8080", "http://192.168.56.10:8080", "http://10.0.0.5:8080", "http://localhost:8080"):
    try:
        R.ensure_target_allowed(good)
        check(f"2 allows lab target {good}", True)
    except R.TargetNotAllowed as e:
        check(f"2 allows lab target {good}", False, str(e))

# ---- offline: catalog is closed and every entry has a known kind
check("3a catalog is non-empty", len(R.CATALOG) >= 4)
check("3b every catalog kind is one of the fixed set", set(R.KINDS) <= {
      "sqli", "xss", "traversal", "brute_force", "recon_scan"})
check("3c catalog ids are unique", len(R.CATALOG_BY_ID) == len(R.CATALOG))

# ---- offline: the LLM can only pick an id that is already in the catalog
planner = R.PlannerAgent(client=None, proxy="http://127.0.0.1:1", analyst_id="x",
                          ask=lambda s, u: {"next": "drop-all-tables", "reason": "nope"})
planner._queue = list(R.CATALOG)
chosen = planner._pick_next()
check("4a an invented id from the LLM is ignored", chosen["id"] in R.CATALOG_BY_ID, chosen["id"])

planner2 = R.PlannerAgent(client=None, proxy="http://127.0.0.1:1", analyst_id="x", ask=lambda s, u: None)
planner2._queue = list(R.CATALOG)
chosen2 = planner2._pick_next()
check("4b no LLM answer still returns a valid catalog probe", chosen2["id"] in R.CATALOG_BY_ID)

planner3 = R.PlannerAgent(client=None, proxy="http://127.0.0.1:1", analyst_id="x",
                           ask=lambda s, u: {"next": "sqli_login"})
planner3._queue = list(R.CATALOG)
chosen3 = planner3._pick_next()
check("4c a valid LLM choice is honoured", chosen3["id"] == "sqli_login")

# ---- offline: fire() itself refuses a non-lab target before sending anything
try:
    R.fire("http://8.8.8.8", R.CATALOG_BY_ID["xss_search"])
    check("5 fire() refuses a public target", False)
except R.TargetNotAllowed:
    check("5 fire() refuses a public target", True)

print()
if "--offline-only" in sys.argv:
    print(f"{total - fails}/{total} offline checks passed")
    sys.exit(1 if fails else 0)


# ---- integration: full Red chain through the hub + proxy
def _read_port(path: str, default: int) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f"http://127.0.0.1:{f.read().strip()}"
    except OSError:
        return f"http://127.0.0.1:{default}"


HUB = os.environ.get("ZT_HUB") or _read_port("hub_port.txt", 9000)
PROXY = os.environ.get("ZT_PROXY") or _read_port("proxy_port.txt", 8080)
TOKEN = os.environ.get("ZT_ENROLL_TOKEN", "zt-arena-demo-token")
ADMIN = {"X-ZT-Admin": os.environ.get("ZT_PROXY_ADMIN", "zt-proxy-admin-demo")}
RED_LOG = "red_test.log"


def need(ok: bool, msg: str) -> None:
    if not ok:
        print(msg)
        sys.exit(2)


def wait_for(fn, timeout: float = 25.0, step: float = 0.5) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if fn():
                return True
        except requests.RequestException:
            pass
        time.sleep(step)
    return False


try:
    need(requests.get(f"{HUB}/health", timeout=5).json().get("ok"), "Hub is not healthy.")
except (requests.RequestException, ValueError):
    need(False, f"Cannot reach the hub at {HUB}. Start it with: python run_hub.py")
try:
    r = requests.get(PROXY + "/", timeout=15)
except requests.RequestException:
    need(False, f"Cannot reach the proxy at {PROXY}. Start it with: python proxy.py")
need(r.status_code != 502, "The proxy is up but its upstream is not. Start Juice Shop (or the stand-in).")
requests.post(f"{PROXY}/_zt/reset", headers=ADMIN, timeout=10)

tag = uuid.uuid4().hex[:6]
judge_id = f"judge-{tag}"
judge = HubClient(HUB, Identity(judge_id, "judge"), TOKEN)
judge.register()

log_file = open(RED_LOG, "w", encoding="utf-8")
red = subprocess.Popen(
    [sys.executable, "run_red.py", "--tag", tag, "--hub", HUB, "--proxy", PROXY,
     "--report-to", judge_id, "--rounds", "2"],
    stdout=log_file, stderr=subprocess.STDOUT,
)
try:
    def team_ready() -> bool:
        reg = requests.get(f"{HUB}/registry", timeout=5).json()
        return all(f"red-{x}-{tag}" in reg for x in ("recon", "analyst", "planner"))

    need(wait_for(team_ready, 25), f"The Red agents did not register in time. See {RED_LOG}")
    check("6 three Red agents registered with the hub", True)

    got_events = []

    def poll_judge() -> bool:
        got_events.extend(judge.poll())
        return len(got_events) >= 2

    need(wait_for(poll_judge, 40), f"The Planner never reported attack_event. See {RED_LOG}")
    ok_events = [m for m in got_events if m.get("ok")]
    check("7 attack_event messages arrived at the Judge", len(ok_events) >= 2, f"count={len(ok_events)}")
    check("8 every attack_event kind is from the fixed catalog",
          all(m["body"].get("kind") in R.KINDS for m in ok_events))
    check("9 every attack_event stayed inside the lab proxy's own logs",
          all(isinstance(m["body"].get("results"), list) and m["body"]["results"] for m in ok_events))

    events = requests.get(f"{HUB}/events?since=-1", timeout=10).json()["events"]

    def accepted(prefix: str, mtype: str) -> bool:
        return any(ev["kind"] == "MSG_ACCEPTED" and ev["detail"]["sender"].startswith(prefix)
                   and ev["detail"]["type"] == mtype for ev in events)

    check("10 the whole chain went through the hub (recon_report, findings, attack_event)",
          accepted(f"red-recon-{tag}", "recon_report") and
          accepted(f"red-analyst-{tag}", "findings") and
          accepted(f"red-planner-{tag}", "attack_event"))

    # ---- role policy: a Blue-role agent cannot send attack_event
    imposter = HubClient(HUB, Identity(f"blue-imposter-{tag}", "blue_detector"), TOKEN)
    imposter.register()
    status, resp = imposter.send(judge_id, "attack_event", {"id": "sqli_login", "kind": "sqli", "results": []})
    check("11 a Blue-role agent cannot send attack_event (role policy)",
          status == 403 and resp.get("reason") == "NOT_AUTHORIZED", str(resp.get("reason")))
finally:
    requests.post(f"{PROXY}/_zt/reset", headers=ADMIN, timeout=10)
    red.terminate()
    try:
        red.wait(timeout=10)
    except subprocess.TimeoutExpired:
        red.kill()
    log_file.close()

print(f"\n{total - fails}/{total} checks passed   (Red agent output is in {RED_LOG})")
sys.exit(1 if fails else 0)
