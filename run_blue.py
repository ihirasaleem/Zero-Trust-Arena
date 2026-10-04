"""Start the three Blue Team agents (Monitor, Detector, Patch).

    python run_blue.py
    python run_blue.py --protect 192.168.56.1   # addresses Patch must never block
    python run_blue.py --report-to judge-1      # send patch reports to a Judge agent

The hub and the proxy must already be running. Press Ctrl+C to stop.
"""
import argparse
import os
import sys
import threading
import uuid

import requests

import llm_client
from blue_agents import DetectorAgent, MonitorAgent, PatchAgent, make_triage, say
from zt_client import HubClient
from zt_crypto import Identity


def _url(arg, env_name, port_file, fallback_port):
    if arg:
        return arg
    if os.environ.get(env_name):
        return os.environ[env_name]
    try:
        with open(port_file, encoding="utf-8") as f:
            return f"http://127.0.0.1:{f.read().strip()}"
    except OSError:
        return f"http://127.0.0.1:{fallback_port}"


def main() -> None:
    ap = argparse.ArgumentParser(description="ZeroTrust Arena Blue Team")
    ap.add_argument("--tag", default=uuid.uuid4().hex[:6], help="suffix that makes agent ids unique per run")
    ap.add_argument("--hub", default="")
    ap.add_argument("--proxy", default="")
    ap.add_argument("--protect", default="", help="comma-separated IPs that must never be blocked")
    ap.add_argument("--report-to", default="", help="agent id that receives patch reports")
    ap.add_argument("--keep-history", action="store_true", help="also analyse log entries from before start")
    args = ap.parse_args()

    hub = _url(args.hub, "ZT_HUB", "hub_port.txt", 9000)
    proxy = _url(args.proxy, "ZT_PROXY", "proxy_port.txt", 8080)
    token = os.environ.get("ZT_ENROLL_TOKEN", "zt-arena-demo-token")
    admin = os.environ.get("ZT_PROXY_ADMIN", "zt-proxy-admin-demo")
    protect = [p.strip() for p in args.protect.split(",") if p.strip()]

    ids = {r: f"blue-{r}-{args.tag}" for r in ("monitor", "detector", "patch")}
    clients = {
        "monitor": HubClient(hub, Identity(ids["monitor"], "blue_monitor"), token),
        "detector": HubClient(hub, Identity(ids["detector"], "blue_detector"), token),
        "patch": HubClient(hub, Identity(ids["patch"], "blue_patch"), token),
    }
    try:
        for c in clients.values():
            c.register()
    except (RuntimeError, requests.RequestException) as e:
        print(f"Could not register with the hub at {hub}: {e}")
        print("Is the hub running?  python run_hub.py")
        sys.exit(1)

    triage = make_triage() if llm_client.available() else None
    agents = [
        MonitorAgent(clients["monitor"], proxy, admin, ids["detector"], skip_history=not args.keep_history),
        DetectorAgent(clients["detector"], ids["monitor"], ids["patch"], triage=triage),
        PatchAgent(clients["patch"], proxy, admin, ids["detector"],
                   protected=protect, report_to=args.report_to or None),
    ]

    say("blue", f"READY - hub {hub}, proxy {proxy}, tag {args.tag}")
    names = llm_client.configured()
    say("blue", "LLM second opinion: " + (f"ON ({', '.join(names)})" if names else "OFF (no API key set, rules only)"))
    if protect:
        say("blue", f"protected addresses: {', '.join(protect)}")

    stop = threading.Event()
    threads = [threading.Thread(target=a.run, args=(stop,), daemon=True) for a in agents]
    for t in threads:
        t.start()
    try:
        while True:
            stop.wait(1)
    except KeyboardInterrupt:
        stop.set()
        say("blue", "stopping")


if __name__ == "__main__":
    main()
