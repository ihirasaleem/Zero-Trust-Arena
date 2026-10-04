"""Start the AI Judge.

    python run_judge.py

Hub and proxy must already be running.
"""
import argparse
import os
import sys
import threading
import uuid

import requests

from judge_agent import JudgeAgent, say
from zt_client import HubClient
from zt_crypto import Identity
import llm_client


def _url(arg, env_name, port_file, fallback):
    if arg:
        return arg
    if os.environ.get(env_name):
        return os.environ[env_name]
    try:
        with open(port_file, encoding="utf-8") as f:
            return f"http://127.0.0.1:{f.read().strip()}"
    except OSError:
        return f"http://127.0.0.1:{fallback}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default=uuid.uuid4().hex[:6])
    ap.add_argument("--hub", default="")
    ap.add_argument("--proxy", default="")
    args = ap.parse_args()

    hub = _url(args.hub, "ZT_HUB", "hub_port.txt", 9000)
    proxy = _url(args.proxy, "ZT_PROXY", "proxy_port.txt", 8080)
    token = os.environ.get("ZT_ENROLL_TOKEN", "zt-arena-demo-token")
    admin = os.environ.get("ZT_PROXY_ADMIN", "zt-proxy-admin-demo")

    client = HubClient(hub, Identity(f"judge-{args.tag}", "judge"), token)
    try:
        client.register()
    except Exception as e:
        print(f"Could not register Judge: {e}")
        sys.exit(1)

    judge = JudgeAgent(client, proxy, admin)

    stop = threading.Event()
    t = threading.Thread(target=judge.run, args=(stop,), daemon=True)
    t.start()
    try:
        while True:
            stop.wait(1)
    except KeyboardInterrupt:
        stop.set()
        say("stopping")


if __name__ == "__main__":
    main()