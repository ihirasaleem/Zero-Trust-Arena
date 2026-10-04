"""End-to-end test for the hub. Start the hub first:

    python run_hub.py

then run:  python test_hub.py
(The test reads the port from hub_port.txt. Set ZT_HUB to override it.)
"""
import os
import sys
import time
import uuid

import requests

import audit
from zt_client import HubClient
from zt_crypto import Identity, b64e, seal


def _default_hub() -> str:
    try:
        with open("hub_port.txt", encoding="utf-8") as f:
            return f"http://127.0.0.1:{f.read().strip()}"
    except OSError:
        return "http://127.0.0.1:9000"


HUB = os.environ.get("ZT_HUB") or _default_hub()
TOKEN = os.environ.get("ZT_ENROLL_TOKEN", "zt-arena-demo-token")
AUDIT_FILE = os.environ.get("ZT_AUDIT", "audit_log.jsonl")

total = 0
fails = 0


def check(name: str, ok: bool, extra: str = "") -> None:
    global total, fails
    total += 1
    if not ok:
        fails += 1
    print(("PASS" if ok else "FAIL"), "-", name, extra)


def post(env: dict):
    r = requests.post(f"{HUB}/send", json=env, timeout=10)
    return r.status_code, r.json()


run = uuid.uuid4().hex[:6]  # unique ids, so the test can be re-run without restarting the hub
recon_id, analyst_id, patch_id = f"recon-{run}", f"analyst-{run}", f"patch-{run}"

recon = HubClient(HUB, Identity(recon_id, "red_recon"), TOKEN)
analyst = HubClient(HUB, Identity(analyst_id, "red_analyst"), TOKEN)
patch = HubClient(HUB, Identity(patch_id, "blue_patch"), TOKEN)
for c in (recon, analyst, patch):
    c.register()
for c in (recon, analyst, patch):
    c.refresh_registry()

# 1. Enrollment needs the right token
try:
    HubClient(HUB, Identity(f"x-{run}", "red_recon"), "wrong-token").register()
    check("1 wrong enrollment token refused", False)
except RuntimeError as e:
    check("1 wrong enrollment token refused", "BAD_ENROLL_TOKEN" in str(e))

# 2. Normal message: sent, delivered, decrypted
status, _ = recon.send(analyst_id, "recon_report", {"open": [3000, 8080]})
msgs = analyst.poll()
check(
    "2 valid message delivered and decrypted",
    status == 200 and len(msgs) == 1 and msgs[0]["ok"] and msgs[0]["body"] == {"open": [3000, 8080]},
)

# 3. Replay: same envelope posted twice
env = seal(recon.me, recon.registry[analyst_id], "recon_report", {"n": 1})
s1, _ = post(env)
s2, r2 = post(env)
check("3 replayed message blocked", s1 == 200 and s2 == 403 and r2["reason"] == "REPLAY_DETECTED", r2.get("reason", ""))
analyst.poll()  # drain

# 4. Unregistered rogue agent
rogue = Identity(f"evil-{run}", "red_recon")
s, r = post(seal(rogue, recon.registry[analyst_id], "recon_report", {}))
check("4 unregistered rogue agent blocked", s == 403 and r["reason"] == "UNKNOWN_AGENT", r.get("reason", ""))

# 5. Impersonation: rogue claims to be recon but has different keys
fake_recon = Identity(recon_id, "red_recon")
s, r = post(seal(fake_recon, recon.registry[analyst_id], "recon_report", {}))
check("5 impersonation blocked", s == 403 and r["reason"] == "BAD_SIGNATURE", r.get("reason", ""))

# 6. Privilege abuse: a Red agent tries to send a Blue-only command
s, r = recon.send(patch_id, "block_rule", {"ip": "10.0.0.1"})
trust = requests.get(f"{HUB}/events", timeout=10).json()["trust"]
check("6 role violation blocked", s == 403 and r["reason"] == "NOT_AUTHORIZED", r.get("reason", ""))
check("7 violating agent loses trust (100 -> 70)", trust.get(recon_id) == 70, f"trust={trust.get(recon_id)}")

# 8. Cannot re-register an id that already exists
try:
    HubClient(HUB, Identity(recon_id, "red_recon"), TOKEN).register()
    check("8 duplicate agent id refused", False)
except RuntimeError as e:
    check("8 duplicate agent id refused", "DUPLICATE_AGENT" in str(e))

# 9. Nobody else can drain an agent's inbox
ts = str(time.time())
bad_sig = b64e(rogue.sign_key.sign(f"inbox|{analyst_id}|{ts}".encode()))
r = requests.get(f"{HUB}/inbox/{analyst_id}", params={"ts": ts, "sig": bad_sig}, timeout=10)
check("9 forged inbox request refused", r.status_code == 403, r.json().get("reason", ""))

# 10. Audit chain is intact, and editing the saved log is detected
v = requests.get(f"{HUB}/audit/verify", timeout=10).json()
check("10 audit chain intact on the hub", v["ok"], f"entries={v['entries']}")

if os.path.exists(AUDIT_FILE):
    ok_file, _ = audit.verify_file(AUDIT_FILE)
    check("11 saved log file verifies", ok_file)
    with open(AUDIT_FILE, encoding="utf-8") as f:
        lines = f.read().splitlines()
    idx = next((i for i, ln in enumerate(lines) if '"MSG_BLOCKED"' in ln), None)
    if idx is not None:
        lines[idx] = lines[idx].replace('"MSG_BLOCKED"', '"MSG_ACCEPTED"')
        with open("audit_tampered.jsonl", "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        ok_t, bad_at = audit.verify_file("audit_tampered.jsonl")
        check("12 edited log is detected", (not ok_t) and bad_at == idx, f"broken at entry {bad_at}")
        os.remove("audit_tampered.jsonl")
else:
    print(f"SKIP - {AUDIT_FILE} not in this folder (run the test from the hub's folder for checks 11-12)")

print(f"\n{total - fails}/{total} checks passed")
sys.exit(1 if fails else 0)
