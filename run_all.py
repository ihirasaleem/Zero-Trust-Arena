"""One command that starts the whole ZeroTrust Arena exercise: hub, proxy,
Judge, Blue Team, and Red Team - in the right order, with the right delays,
and (optionally) your Groq/Gemini/OpenRouter key passed to every agent that
can use it.

    python run_all.py --groq-key gsk_xxx
    python run_all.py --groq-key gsk_xxx --juice-shop "C:\\path\\to\\juice-shop_20.2.0"
    python run_all.py                       # if Juice Shop is already running on :3000

Juice Shop itself is NOT started unless you pass --juice-shop (it lives in a
different folder with its own "npm start" - this script will cd there and
start it for you if you give the path). Everything else - hub, proxy,
Judge, Blue, Red - is started by this one script.

Press Ctrl+C once to stop everything this script started, in the right order.
"""
import argparse
import os
import subprocess
import sys
import time
import uuid
import webbrowser

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
children = []  # (name, Popen, logfile) - stopped in reverse order on exit


def say(msg: str) -> None:
    print(f"[run_all] {msg}", flush=True)


def spawn(name: str, args: list, cwd: str = None, shell: bool = False) -> subprocess.Popen:
    log = open(os.path.join(HERE, f"{name}.log"), "w", encoding="utf-8")
    p = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, cwd=cwd or HERE, shell=shell)
    children.append((name, p, log))
    say(f"started {name} (pid {p.pid}) - output in {name}.log")
    return p


def wait_for(fn, timeout: float, what: str) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if fn():
                return
        except requests.RequestException:
            pass
        time.sleep(0.4)
    say(f"WARNING: timed out waiting for {what} - check its .log file")


def read_port(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read().strip()


def stop_all() -> None:
    say("stopping everything...")
    for name, p, log in reversed(children):
        try:
            p.terminate()
        except OSError:
            pass
    for name, p, log in reversed(children):
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
        log.close()
    say("all stopped.")


def main() -> None:
    ap = argparse.ArgumentParser(description="Start the whole ZeroTrust Arena exercise with one command")
    ap.add_argument("--groq-key", default=os.environ.get("GROQ_API_KEY", ""))
    ap.add_argument("--gemini-key", default=os.environ.get("GEMINI_API_KEY", ""))
    ap.add_argument("--openrouter-key", default=os.environ.get("OPENROUTER_API_KEY", ""))
    ap.add_argument("--juice-shop", default="", help="path to the extracted Juice Shop folder (starts it with npm start)")
    ap.add_argument("--upstream", default="", help="override the proxy's upstream URL (default http://127.0.0.1:3000)")
    ap.add_argument("--tag", default=uuid.uuid4().hex[:6])
    ap.add_argument("--rounds", type=int, default=None, help="how many Red probes to fire (default: all 5)")
    ap.add_argument("--no-browser", action="store_true", help="do not auto-open the dashboard")
    args = ap.parse_args()

    if args.groq_key:
        os.environ["GROQ_API_KEY"] = args.groq_key
    if args.gemini_key:
        os.environ["GEMINI_API_KEY"] = args.gemini_key
    if args.openrouter_key:
        os.environ["OPENROUTER_API_KEY"] = args.openrouter_key
    ai_on = bool(args.groq_key or args.gemini_key or args.openrouter_key)

    for leftover in ("hub_port.txt", "proxy_port.txt"):
        path = os.path.join(HERE, leftover)
        if os.path.exists(path):
            os.remove(path)  # make sure we wait for THIS run's hub/proxy, not a stale file

    try:
        if args.juice_shop:
            say(f"starting Juice Shop in {args.juice_shop} ...")
            npm = "npm.cmd" if os.name == "nt" else "npm"
            spawn("juice_shop", [npm, "start"], cwd=args.juice_shop, shell=(os.name == "nt"))
            wait_for(lambda: requests.get("http://127.0.0.1:3000", timeout=3).status_code < 500,
                     60, "Juice Shop on :3000")
        else:
            say("not starting Juice Shop (no --juice-shop given) - assuming it is already running")

        say("starting the hub...")
        spawn("hub", [sys.executable, "run_hub.py"])
        wait_for(lambda: os.path.exists(os.path.join(HERE, "hub_port.txt")), 15, "hub_port.txt")
        hub_port = read_port(os.path.join(HERE, "hub_port.txt"))
        hub_url = f"http://127.0.0.1:{hub_port}"
        wait_for(lambda: requests.get(f"{hub_url}/health", timeout=3).ok, 15, "the hub to answer /health")
        say(f"hub is up on {hub_url}")

        say("starting the proxy...")
        proxy_args = [sys.executable, "proxy.py"]
        if args.upstream:
            proxy_args += ["--upstream", args.upstream]
        spawn("proxy", proxy_args)
        wait_for(lambda: os.path.exists(os.path.join(HERE, "proxy_port.txt")), 15, "proxy_port.txt")
        proxy_port = read_port(os.path.join(HERE, "proxy_port.txt"))
        proxy_url = f"http://127.0.0.1:{proxy_port}"
        wait_for(lambda: requests.get(proxy_url + "/", timeout=5).status_code != 502,
                 30, "the proxy's upstream (Juice Shop) to answer")
        say(f"proxy is up on {proxy_url}")

        admin_token = os.environ.get("ZT_PROXY_ADMIN", "zt-proxy-admin-demo")
        judge_id = f"judge-{args.tag}"

        say(f"starting the Judge (AI {'ON' if ai_on else 'OFF - rule-based score'}) ...")
        spawn("judge", [sys.executable, "run_judge.py", "--tag", args.tag, "--hub", hub_url, "--proxy", proxy_url])
        time.sleep(2)

        say(f"starting the Blue Team (AI {'ON' if ai_on else 'OFF - rules only'}) ...")
        spawn("blue", [sys.executable, "run_blue.py", "--tag", args.tag, "--hub", hub_url, "--proxy", proxy_url,
                       "--report-to", judge_id])
        time.sleep(3)

        say("starting the Red Team ...")
        red_args = [sys.executable, "run_red.py", "--tag", f"{args.tag}-r", "--hub", hub_url, "--proxy", proxy_url,
                    "--report-to", judge_id]
        if args.rounds is not None:
            red_args += ["--rounds", str(args.rounds)]
        spawn("red", red_args)

        dash = f"{hub_url}/dashboard?proxy={proxy_url}&token={admin_token}"
        say("=" * 70)
        say("EVERYTHING IS RUNNING. Dashboard:")
        say(dash)
        say("=" * 70)
        if not args.no_browser:
            try:
                webbrowser.open(dash)
            except Exception:
                pass
        say("Press Ctrl+C to stop everything.")

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        stop_all()


if __name__ == "__main__":
    main()