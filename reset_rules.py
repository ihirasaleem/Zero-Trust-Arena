"""Show the proxy's block rules and clear them (use between demo runs).

    python reset_rules.py
"""
import os
import sys

import requests


def main() -> None:
    base = os.environ.get("ZT_PROXY")
    if not base:
        try:
            with open("proxy_port.txt", encoding="utf-8") as f:
                base = f"http://127.0.0.1:{f.read().strip()}"
        except OSError:
            base = "http://127.0.0.1:8080"
    admin = {"X-ZT-Admin": os.environ.get("ZT_PROXY_ADMIN", "zt-proxy-admin-demo")}
    try:
        rules = requests.get(f"{base}/_zt/rules", headers=admin, timeout=10).json()["rules"]
        print(f"{len(rules)} rule(s) were active:")
        for r in rules:
            print(f"  #{r['id']} {r['kind']} = {r['value']!r}  ({r['reason']})")
        requests.post(f"{base}/_zt/reset", headers=admin, timeout=10)
        print("All rules cleared.")
    except (requests.RequestException, KeyError, ValueError) as e:
        print(f"Could not reach the proxy at {base}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
