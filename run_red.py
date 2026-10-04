"""Start the three Red Team agents (Recon, Analyst, Planner).

    python run_red.py
    python run_red.py --report-to judge-1     # send attack_event to a Judge agent
    python run_red.py --llm                   # let the LLM choose the probe order

This only ever attacks the lab proxy, and refuses to run if that proxy is
not on a loopback or private address (see ensure_target_allowed in
red_agents.py). The hub and the proxy must already be running.
Press Ctrl+C to stop.
"""
import argparse
import os
import sys
import threading
import uuid

import requests

import llm_client
from red_agents import AnalystAgent, PlannerAgent, ReconAgent, TargetNotAllowed, ensure_target_allowed, say
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
    ap = argparse.ArgumentParser(description="ZeroTrust Arena Red Team (lab-only)")
    ap.add_argument("--tag", default=uuid.uuid4().hex[:6], help="suffix that makes agent ids unique per run")
    ap.add_argument("--hub", default="")
    ap.add_argument("--proxy", default="")
    ap.add_argument("--report-to", default="", help="agent id (e.g. a Judge) that receives attack_event")
    ap.add_argument("--rounds", type=int, default=None, help="how many catalog probes to fire (default: all)")
    ap.add_argument("--llm", action="store_true", help="let the LLM choose which catalog probe is next")
    args = ap.parse_args()

    hub = _url(args.hub, "ZT_HUB", "hub_port.txt", 9000)
    proxy = _url(args.proxy, "ZT_PROXY", "proxy_port.txt", 8080)
    token = os.environ.get("ZT_ENROLL_TOKEN", "zt-arena-demo-token")

    try:
        ensure_target_allowed(proxy)
    except TargetNotAllowed as e:
        print(f"Refusing to start: {e}")
        sys.exit(1)

    ids = {r: f"red-{r}-{args.tag}" for r in ("recon", "analyst", "planner")}
    clients = {
        "recon": HubClient(hub, Identity(ids["recon"], "red_recon"), token),
        "analyst": HubClient(hub, Identity(ids["analyst"], "red_analyst"), token),
        "planner": HubClient(hub, Identity(ids["planner"], "red_planner"), token),
    }
    try:
        for c in clients.values():
            c.register()
    except (RuntimeError, requests.RequestException) as e:
        print(f"Could not register with the hub at {hub}: {e}")
        print("Is the hub running?  python run_hub.py")
        sys.exit(1)

    ask = llm_client.ask_json if (args.llm and llm_client.available()) else None
    agents = [
        ReconAgent(clients["recon"], proxy, ids["analyst"]),
        AnalystAgent(clients["analyst"], ids["planner"], ids["recon"]),
        PlannerAgent(clients["planner"], proxy, ids["analyst"],
                     report_to=args.report_to or None, ask=ask, rounds=args.rounds),
    ]

    say("red", f"READY - hub {hub}, proxy {proxy}, tag {args.tag}, target checked as lab-only")
    say("red", "LLM probe ordering: " + ("ON" if ask else "OFF (fixed catalog order)"))
    if args.report_to:
        say("red", f"reporting attack_event to {args.report_to}")

    stop = threading.Event()
    threads = [threading.Thread(target=a.run, args=(stop,), daemon=True) for a in agents]
    for t in threads:
        t.start()
    try:
        while True:
            stop.wait(1)
    except KeyboardInterrupt:
        stop.set()
        say("red", "stopping")


if __name__ == "__main__":
    main()
