"""Start the hub on a port that this PC actually allows, and remember it.

    python run_hub.py                   # this PC only (127.0.0.1)
    python run_hub.py --host 0.0.0.0    # also reachable from the Kali VM
    python run_hub.py --port 8123       # force one specific port

The chosen port is printed and saved to hub_port.txt (test_hub.py reads it).
"""
import argparse
import socket
import sys

import uvicorn

# Stable ports tried first, spread across different ranges.
PREFERRED = [
    9000, 8765, 8900, 7000, 5050, 8123, 9100, 9500, 6060,
    4040, 7777, 5555, 8088, 8181, 3100, 4000, 5100,
]


def can_bind(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def ephemeral_port(host: str):
    """Ask the OS for any port it will allow right now (port 0 = OS chooses)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, 0))
        return s.getsockname()[1]
    except OSError:
        return None
    finally:
        s.close()


def pick_port(host: str, forced: int):
    if forced:
        return (forced if can_bind(host, forced) else None), []
    skipped = []
    for p in PREFERRED:
        if can_bind(host, p):
            return p, skipped
        skipped.append(p)
    return ephemeral_port(host), skipped


def main() -> None:
    ap = argparse.ArgumentParser(description="Start the ZeroTrust hub")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    args = ap.parse_args()

    port, skipped = pick_port(args.host, args.port)
    if port is None:
        if args.port:
            print(f"Port {args.port} is not available on this PC. Run without --port to auto-pick one.")
        else:
            print("This PC refused every port, including one the OS chose itself.")
            print("Try, in this order:")
            print("  1) Open PowerShell as Administrator and run this again")
            print("  2) Pause antivirus / endpoint security for a minute, then retry")
            print("  3) Send me the output of: netsh interface ipv4 show excludedportrange protocol=tcp")
        sys.exit(1)

    if skipped:
        print(f"Skipped unavailable ports: {skipped}")
    with open("hub_port.txt", "w", encoding="utf-8") as f:
        f.write(str(port))
    print(f"\n=== ZeroTrust hub on http://{args.host}:{port}  (saved to hub_port.txt) ===\n", flush=True)

    from hub import app  # imported late, so a failed port search never touches the audit log

    uvicorn.run(app, host=args.host, port=port, log_level="info")


if __name__ == "__main__":
    main()
