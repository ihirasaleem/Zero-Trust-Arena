"""Test for the lab proxy.

Needs two things running first:
  1. Juice Shop        (npm start, in its own folder)
  2. python proxy.py   (in this folder)

Then run:  python test_proxy.py
"""
import os
import socket
import sys
from urllib.parse import urlparse

import requests

from proxy import check_upstream


def _default_base() -> str:
    try:
        with open("proxy_port.txt", encoding="utf-8") as f:
            return f"http://127.0.0.1:{f.read().strip()}"
    except OSError:
        return "http://127.0.0.1:8080"


BASE = os.environ.get("ZT_PROXY") or _default_base()
ADMIN = {"X-ZT-Admin": os.environ.get("ZT_PROXY_ADMIN", "zt-proxy-admin-demo")}

total = 0
fails = 0


def check(name: str, ok: bool, extra: str = "") -> None:
    global total, fails
    total += 1
    if not ok:
        fails += 1
    print(("PASS" if ok else "FAIL"), "-", name, extra)


def get_logs() -> list:
    return requests.get(f"{BASE}/_zt/logs", headers=ADMIN, timeout=10).json()["logs"]


try:
    r = requests.get(BASE + "/", timeout=15)
except requests.RequestException as e:
    print(f"Cannot reach the proxy at {BASE}. Is `python proxy.py` running?\n{e}")
    sys.exit(2)
if r.status_code == 502:
    print("The proxy is running but Juice Shop is not. Start it with `npm start` and retry.")
    sys.exit(2)

# 1. The lab app loads through the proxy
check("1 page loads through the proxy", r.status_code == 200 and len(r.content) > 0, f"status={r.status_code}")

# 2. The request was logged
entries = get_logs()
home = [e for e in entries if e["path"] == "/" and e["status"] == 200]
check("2 request appears in the access log", bool(home))
my_ip = home[-1]["ip"] if home else "127.0.0.1"

# 3. Control endpoints stay hidden without the right token
no_tok = requests.get(f"{BASE}/_zt/logs", timeout=10)
bad_tok = requests.get(f"{BASE}/_zt/logs", headers={"X-ZT-Admin": "wrong"}, timeout=10)
check("3 admin endpoints hidden without the token", no_tok.status_code == 404 and bad_tok.status_code == 404)

# 4. A 'contains' rule blocks the probe, but normal traffic still works
rr = requests.post(
    f"{BASE}/_zt/rules",
    json={"kind": "contains", "value": "<script", "reason": "xss probe"},
    headers=ADMIN, timeout=10,
)
rid = rr.json().get("id")
bad = requests.get(f"{BASE}/rest/products/search", params={"q": "<script>alert(1)</script>"}, timeout=15)
good = requests.get(f"{BASE}/rest/products/search", params={"q": "apple"}, timeout=15)
check(
    "4 contains-rule blocks the probe, normal search still works",
    rr.status_code == 200 and bad.status_code == 403 and good.status_code < 400,
    f"probe={bad.status_code} normal={good.status_code}",
)

# 5. The block is recorded in the log with the rule id
blocked = [e for e in get_logs() if e["blocked"] and e["rule"] == rid]
check("5 blocked request is logged with its rule id", bool(blocked))

# 6. An IP rule blocks that client; admin still works; deleting the rule restores access
ip_rule = requests.post(
    f"{BASE}/_zt/rules", json={"kind": "ip", "value": my_ip, "reason": "test"},
    headers=ADMIN, timeout=10,
).json()["id"]
blocked_home = requests.get(BASE + "/", timeout=15)
admin_ok = requests.get(f"{BASE}/_zt/rules", headers=ADMIN, timeout=10)
requests.delete(f"{BASE}/_zt/rules/{ip_rule}", headers=ADMIN, timeout=10)
restored = requests.get(BASE + "/", timeout=15)
check(
    "6 ip-rule blocks a client, admin unaffected, delete restores access",
    blocked_home.status_code == 403 and admin_ok.status_code == 200 and restored.status_code == 200,
    f"blocked={blocked_home.status_code} admin={admin_ok.status_code} restored={restored.status_code}",
)

# 7. Bad rules are refused
codes = [
    requests.post(f"{BASE}/_zt/rules", json=body, headers=ADMIN, timeout=10).status_code
    for body in (
        {"kind": "ip", "value": "not-an-ip"},
        {"kind": "contains", "value": "a"},
        {"kind": "nonsense", "value": "whatever"},
    )
]
check("7 invalid rules are refused", codes == [400, 400, 400], f"codes={codes}")

# 8. Passwords never reach the log
requests.post(
    f"{BASE}/rest/user/login",
    json={"email": "zt@test.local", "password": "hunter2-zt"},
    timeout=15,
)
login = [e for e in get_logs() if e["path"] == "/rest/user/login"]
head = login[-1]["body_head"] if login else ""
check("8 passwords are redacted in the log", bool(login) and "***" in head and "hunter2-zt" not in head, head)

# 9. The proxy refuses non-lab targets
check(
    "9 non-lab upstreams are refused",
    check_upstream("http://127.0.0.1:3000") is None
    and check_upstream("http://192.168.1.20:3000") is None
    and check_upstream("http://8.8.8.8:3000") is not None
    and check_upstream("ftp://127.0.0.1") is not None,
)

# 10. Admin endpoints refuse callers that are not on this PC (needs --host 0.0.0.0)
try:
    lan = socket.gethostbyname(socket.gethostname())
except OSError:
    lan = "127.0.0.1"
if lan.startswith("127."):
    print("SKIP - 10 could not find a LAN address for this PC")
else:
    try:
        port = urlparse(BASE).port
        rem = requests.get(f"http://{lan}:{port}/_zt/logs", headers=ADMIN, timeout=5)
        check("10 admin endpoints refuse non-local callers", rem.status_code == 404, f"status={rem.status_code}")
    except requests.RequestException:
        print("SKIP - 10 proxy is not listening on the LAN address (start it with --host 0.0.0.0 to run this check)")

requests.post(f"{BASE}/_zt/reset", headers=ADMIN, timeout=10)  # leave no rules behind
print(f"\n{total - fails}/{total} checks passed")
sys.exit(1 if fails else 0)
