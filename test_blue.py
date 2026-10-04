"""End-to-end test of the Blue Team (Monitor -> Detector -> Patch) with the hub and proxy.

Start these first, each in its own PowerShell window:
  1. Juice Shop          (npm start, in its own folder)
  2. python run_hub.py
  3. python proxy.py
Then run:  python test_blue.py
The test starts the Blue agents itself and stops them at the end.
It sends fake failed logins and probe strings to your own lab proxy only.
"""
import os
import subprocess
import sys
import time
import uuid

import requests

from zt_client import HubClient
from zt_crypto import Identity, seal


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
BLUE_LOG = "blue_test.log"

total = 0
fails = 0


def check(name: str, ok: bool, extra: str = "") -> None:
    global total, fails
    total += 1
    if not ok:
        fails += 1
    print(("PASS" if ok else "FAIL"), "-", name, extra, flush=True)


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


def rules() -> list:
    return requests.get(f"{PROXY}/_zt/rules", headers=ADMIN, timeout=10).json()["rules"]


def has_rule(kind: str, value: str) -> bool:
    return any(r["kind"] == kind and r["value"] == value for r in rules())


def reset() -> None:
    requests.post(f"{PROXY}/_zt/reset", headers=ADMIN, timeout=10)


# ---- preflight
try:
    need(requests.get(f"{HUB}/health", timeout=5).json().get("ok"), "Hub is not healthy.")
except (requests.RequestException, ValueError):
    need(False, f"Cannot reach the hub at {HUB}. Start it with: python run_hub.py")
try:
    r = requests.get(PROXY + "/", timeout=15)
except requests.RequestException:
    need(False, f"Cannot reach the proxy at {PROXY}. Start it with: python proxy.py")
need(r.status_code != 502, "The proxy is up but Juice Shop is not. Start it with: npm start")
reset()
logs = requests.get(f"{PROXY}/_zt/logs", headers=ADMIN, timeout=10).json()["logs"]
my_ip = logs[-1]["ip"] if logs else "127.0.0.1"

# ---- start the Blue Team
tag = uuid.uuid4().hex[:6]
log_file = open(BLUE_LOG, "w", encoding="utf-8")
blue = subprocess.Popen(
    [sys.executable, "run_blue.py", "--tag", tag, "--hub", HUB, "--proxy", PROXY],
    stdout=log_file, stderr=subprocess.STDOUT,
)
try:
    def team_ready() -> bool:
        reg = requests.get(f"{HUB}/registry", timeout=5).json()
        return all(f"blue-{x}-{tag}" in reg for x in ("monitor", "detector", "patch"))

    need(wait_for(team_ready, 25), f"The Blue agents did not register in time. See {BLUE_LOG}")
    time.sleep(3)  # let the Monitor reach "now" in the proxy log
    check("1 three Blue agents registered with the hub", True)

    # ---- scenario A: brute force
    for i in range(6):
        requests.post(f"{PROXY}/rest/user/login",
                      json={"email": "zt-probe@test.local", "password": f"wrong-{i}"}, timeout=15)
    got = wait_for(lambda: has_rule("ip", my_ip))
    check("2 brute force detected and the attacker IP is blocked", got, f"ip={my_ip}")
    blocked = requests.get(PROXY + "/", timeout=15)
    check("3 the blocked IP now gets 403 from the proxy", blocked.status_code == 403, f"status={blocked.status_code}")

    events = requests.get(f"{HUB}/events?since=-1", timeout=10).json()["events"]

    def accepted(prefix: str, mtype: str) -> bool:
        return any(ev["kind"] == "MSG_ACCEPTED" and ev["detail"]["sender"].startswith(prefix)
                   and ev["detail"]["type"] == mtype for ev in events)

    check("4 the whole chain went through the hub (log_batch, alert)",
          accepted(f"blue-monitor-{tag}", "log_batch") and accepted(f"blue-detector-{tag}", "alert"))

    # ---- scenario B: XSS probe becomes a virtual patch
    reset()
    requests.get(f"{PROXY}/rest/products/search", params={"q": "<script>alert(1)</script>"}, timeout=15)
    got = wait_for(lambda: has_rule("contains", "<script"))
    check("5 xss probe detected and a signature rule is added", got)
    check("6 high-severity alert also blocked the attacker IP", has_rule("ip", my_ip))
    reset()

    # ---- scenario C: attacks on the Blue agents themselves
    me = HubClient(HUB, Identity(f"probe-{tag}", "red_recon"), TOKEN)
    me.register()
    victim = "10.9.8.7"  # an innocent address the forged alerts try to get blocked
    fake_alert = {"kind": "brute_force", "severity": "high", "ip": victim, "reason": "forged",
                  "source": "rule", "count": 9, "evidence": [], "event_ts": time.time(), "detected_ts": time.time()}

    status, resp = me.send(f"blue-patch-{tag}", "alert", fake_alert)
    check("7 a Red-role agent cannot send alerts (role policy)", status == 403 and resp.get("reason") == "NOT_AUTHORIZED", str(resp.get("reason")))

    me.refresh_registry()
    imposter = Identity(f"blue-detector-{tag}", "blue_detector")  # same id, different keys
    env = seal(imposter, me.registry[f"blue-patch-{tag}"], "alert", fake_alert)
    r = requests.post(f"{HUB}/send", json=env, timeout=10)
    check("8 impersonating the Detector fails (bad signature)", r.status_code == 403 and r.json().get("reason") == "BAD_SIGNATURE", r.text[:80])

    evil = HubClient(HUB, Identity(f"evil-detector-{tag}", "blue_detector"), TOKEN)
    evil.register()
    status, resp = evil.send(f"blue-patch-{tag}", "alert", fake_alert)
    time.sleep(4)
    log_text = open(BLUE_LOG, encoding="utf-8").read()
    check("9 an enrolled but unpinned Detector is ignored by Patch",
          status == 200 and not has_rule("ip", victim) and "UNPINNED_SENDER" in log_text,
          f"hub_status={status}")
    check("10 the innocent address was never blocked", not has_rule("ip", victim))
finally:
    reset()
    blue.terminate()
    try:
        blue.wait(timeout=10)
    except subprocess.TimeoutExpired:
        blue.kill()
    log_file.close()

print(f"\n{total - fails}/{total} checks passed   (Blue agent output is in {BLUE_LOG})")
sys.exit(1 if fails else 0)
