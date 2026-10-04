"""Logging reverse proxy for the lab target (Juice Shop).

Red agents attack THIS proxy, not Juice Shop directly. The proxy
  * forwards every request to the lab app,
  * logs it, so the Blue Monitor agent can read the log,
  * blocks requests that match rules added by the Blue Patch agent.

Control endpoints live under /_zt/ and only answer callers that are on this
PC (loopback) AND send the admin token. Everyone else gets a plain 404.

    python proxy.py                        # listen on 127.0.0.1 only
    python proxy.py --host 0.0.0.0         # let the Kali VM reach it
    python proxy.py --upstream http://127.0.0.1:3000

The lab target must be a loopback or private address. The proxy refuses to
start otherwise, so it can never be pointed at a real public site.
"""
import argparse
import hmac
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
from collections import deque
from urllib.parse import unquote_plus, urlparse

import requests
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from run_hub import can_bind, ephemeral_port

UPSTREAM = os.environ.get("ZT_UPSTREAM", "http://127.0.0.1:3000")
ADMIN_TOKEN = os.environ.get("ZT_PROXY_ADMIN", "zt-proxy-admin-demo")
LOG_PATH = "access_log.jsonl"
PREFERRED_PORTS = [8080, 8081, 8888, 8000, 8008, 5000, 5001, 6001, 7001, 4001, 8082, 8090]
MAX_BODY = 5 * 1024 * 1024
BODY_HEAD = 200
MAX_RULES = 200

HOP_REQ = {
    "host", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length", "accept-encoding",
}
DROP_RESP = {"content-encoding", "content-length", "transfer-encoding", "connection", "keep-alive"}
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
state_lock = threading.Lock()
rules = {}                      # id -> {"id", "kind", "value", "reason", "ts"}
_next_rule = 1
logs = deque(maxlen=5000)
_seq = 0

_JSON_PASS = re.compile(r'(?i)("[a-z_]*pass[a-z_]*"\s*:\s*")[^"]*')
_FORM_PASS = re.compile(r"(?i)(pass[a-z_]*=)[^&\s]*")


def check_upstream(url: str):
    """Return an error message if the target is not a lab address, else None."""
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return "upstream must look like http://127.0.0.1:3000"
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(p.hostname))
    except (OSError, ValueError):
        return f"cannot resolve upstream host {p.hostname}"
    if not (ip.is_loopback or ip.is_private):
        return f"refusing {ip}: the lab target must be a loopback or private address"
    return None


def _body_head(method: str, body: bytes) -> str:
    if method not in ("POST", "PUT", "PATCH") or not body:
        return ""
    text = body[:BODY_HEAD].decode("utf-8", "replace")
    text = _JSON_PASS.sub(r"\1***", text)
    return _FORM_PASS.sub(r"\1***", text)


def _match(ip: str, haystack: str):
    for r in rules.values():
        if r["kind"] == "ip" and r["value"] == ip:
            return r
        if r["kind"] == "contains" and r["value"] in haystack:
            return r
    return None


def _log(ip, method, path, query, status, request, body_head, rule) -> None:
    global _seq
    with state_lock:
        entry = {
            "n": _seq,
            "ts": round(time.time(), 3),
            "ip": ip,
            "method": method,
            "path": path[:300],
            "query": unquote_plus(query)[:300],
            "status": status,
            "ua": request.headers.get("user-agent", "")[:120],
            "body_head": body_head,
            "blocked": rule is not None,
            "rule": rule["id"] if rule else None,
        }
        _seq += 1
        logs.append(entry)
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass


# ---------------------------------------------------------------- admin API
def require_admin(request: Request) -> None:
    local = request.client is not None and request.client.host in ("127.0.0.1", "::1")
    token = request.headers.get("x-zt-admin", "")
    if not (local and hmac.compare_digest(token.encode(), ADMIN_TOKEN.encode())):
        raise HTTPException(status_code=404, detail="Not Found")


class RuleReq(BaseModel):
    kind: str
    value: str
    reason: str = ""


@app.get("/_zt/logs")
def get_logs(request: Request, since: int = -1, limit: int = 500):
    require_admin(request)
    limit = max(1, min(limit, 2000))
    with state_lock:
        items = [e for e in logs if e["n"] > since][:limit]
    return {"logs": items, "last": items[-1]["n"] if items else since}


@app.options("/_zt/rules")
def rules_options() -> Response:
    # Lets the dashboard (served from the hub's own origin) read this endpoint.
    # Still gated by require_admin on the real GET - a bare OPTIONS gives no data.
    return Response(status_code=204, headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "X-ZT-Admin, Content-Type",
        "Access-Control-Allow-Methods": "GET",
    })


@app.get("/_zt/rules")
def get_rules(request: Request, response: Response):
    require_admin(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    with state_lock:
        return {"rules": list(rules.values())}


@app.post("/_zt/rules")
def add_rule(req: RuleReq, request: Request):
    global _next_rule
    require_admin(request)
    value = req.value.strip()
    if req.kind == "ip":
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            raise HTTPException(status_code=400, detail="not a valid IP address")
    elif req.kind == "contains":
        value = value.lower()
        if not 3 <= len(value) <= 100:
            raise HTTPException(status_code=400, detail="a 'contains' rule must be 3-100 characters")
    else:
        raise HTTPException(status_code=400, detail="kind must be 'ip' or 'contains'")
    with state_lock:
        for r in rules.values():
            if r["kind"] == req.kind and r["value"] == value:
                return {"id": r["id"], "duplicate": True}
        if len(rules) >= MAX_RULES:
            raise HTTPException(status_code=400, detail="too many rules")
        rid = _next_rule
        _next_rule += 1
        rules[rid] = {
            "id": rid, "kind": req.kind, "value": value,
            "reason": req.reason[:200], "ts": round(time.time(), 3),
        }
    return {"id": rid}


@app.delete("/_zt/rules/{rule_id}")
def delete_rule(rule_id: int, request: Request):
    require_admin(request)
    with state_lock:
        if rule_id not in rules:
            raise HTTPException(status_code=404, detail="no such rule")
        del rules[rule_id]
    return {"deleted": rule_id}


@app.post("/_zt/reset")
def reset_rules(request: Request):
    require_admin(request)
    with state_lock:
        rules.clear()
    return {"rules": 0}


# ------------------------------------------------------------------- proxy
def _forward(method: str, url: str, headers: dict, body: bytes):
    return requests.request(
        method, url, headers=headers, data=body, allow_redirects=False, timeout=15
    )


@app.api_route("/{full_path:path}", methods=METHODS)
async def proxy(full_path: str, request: Request):
    ip = request.client.host if request.client else "?"
    method = request.method
    path = request.url.path
    raw_query = request.scope.get("query_string", b"").decode("latin-1")
    raw_path = request.scope.get("raw_path", path.encode()).decode("latin-1")

    cl = request.headers.get("content-length", "")
    if cl.isdigit() and int(cl) > MAX_BODY:
        return Response("Body too large", status_code=413, media_type="text/plain")
    body = await request.body()
    head = _body_head(method, body)

    decoded = unquote_plus(unquote_plus(path + ("?" + raw_query if raw_query else "")))
    haystack = (decoded + " " + head).lower()
    with state_lock:
        rule = _match(ip, haystack)
    if rule:
        _log(ip, method, path, raw_query, 403, request, head, rule)
        return Response(
            f"Blocked by ZeroTrust Arena (rule {rule['id']})",
            status_code=403,
            media_type="text/plain",
        )

    headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_REQ}
    headers["X-Forwarded-For"] = ip
    url = UPSTREAM.rstrip("/") + raw_path + ("?" + raw_query if raw_query else "")
    try:
        r = await run_in_threadpool(_forward, method, url, headers, body)
    except requests.RequestException:
        _log(ip, method, path, raw_query, 502, request, head, None)
        return Response(
            "Bad gateway: the lab app is not reachable. Is Juice Shop running?",
            status_code=502,
            media_type="text/plain",
        )

    _log(ip, method, path, raw_query, r.status_code, request, head, None)
    out_headers = {
        k: v for k, v in r.headers.items()
        if k.lower() not in DROP_RESP and k.lower() != "set-cookie"
    }
    out = Response(content=r.content, status_code=r.status_code, headers=out_headers)
    for cookie in r.raw.headers.getlist("Set-Cookie"):  # keep each cookie as its own header
        out.raw_headers.append((b"set-cookie", cookie.encode("latin-1")))
    return out


# --------------------------------------------------------------------- main
def _pick_port(host: str, forced: int):
    if forced:
        return forced if can_bind(host, forced) else None
    for p in PREFERRED_PORTS:
        if can_bind(host, p):
            return p
    return ephemeral_port(host)


def main() -> None:
    global UPSTREAM
    ap = argparse.ArgumentParser(description="ZeroTrust Arena lab proxy")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--upstream", default=UPSTREAM)
    args = ap.parse_args()

    problem = check_upstream(args.upstream)
    if problem:
        print("Not starting:", problem)
        sys.exit(1)
    UPSTREAM = args.upstream.rstrip("/")

    port = _pick_port(args.host, args.port)
    if port is None:
        print("This PC refused the port. Run without --port to auto-pick one.")
        sys.exit(1)

    open(LOG_PATH, "w", encoding="utf-8").close()  # fresh access log each run
    with open("proxy_port.txt", "w", encoding="utf-8") as f:
        f.write(str(port))

    print(f"\n=== Lab proxy on http://{args.host}:{port}  ->  {UPSTREAM} ===")
    print("    (port saved to proxy_port.txt)")
    try:
        requests.get(UPSTREAM, timeout=3)
        print("    Lab app reachable: yes")
    except requests.RequestException:
        print("    Lab app reachable: NO - start Juice Shop first (npm start)")
    if ADMIN_TOKEN == "zt-proxy-admin-demo":
        print("    Note: default admin token in use. Set $env:ZT_PROXY_ADMIN before the real demo.")
    print()

    uvicorn.run(app, host=args.host, port=port, log_level="info")


if __name__ == "__main__":
    main()