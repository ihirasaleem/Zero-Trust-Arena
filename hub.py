"""ZeroTrust Arena hub: Trust Authority + message bus + audit log.

The hub only ever sees encrypted envelopes. It checks the outer layer
(identity, signature, freshness, replay, role policy) and drops anything that
fails. Recipients repeat every check themselves, so even a compromised hub
cannot read or forge messages.

Run:  uvicorn hub:app --host 127.0.0.1 --port 9000
(Use --host 0.0.0.0 later, when the Kali machine needs to reach it.)
"""
import hmac
import json
import math
import os
import re
import threading
import time
from collections import defaultdict, deque

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Body, FastAPI, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from fastapi.responses import HTMLResponse

from audit import AuditLog
from zt_crypto import MAX_AGE, POLICY, ZTError, b64d, verify_signature

# Root of trust: only holders of this token can enroll agents.
ENROLL_TOKEN = os.environ.get("ZT_ENROLL_TOKEN", "zt-arena-demo-token")
MAX_ENV_CHARS = 64 * 1024
AGENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
STR_FIELDS = ("sender", "recipient", "msg_id", "type", "eph_pub", "nonce", "ct", "sig")

app = FastAPI(title="ZeroTrust Arena Hub")
state_lock = threading.Lock()
registry = {}                                         # agent_id -> public card
inboxes = defaultdict(lambda: deque(maxlen=1000))     # agent_id -> envelopes
seen = {}                                             # msg_id / poll signature -> first seen
trust = {}                                            # registered agent -> score 0..100
unverified = {}                                       # id claimed by a sender that failed identity checks -> attempts
audit = AuditLog("audit_log.jsonl")
judge_report = {}                                     # latest Judge verdict, for the dashboard only


DASHBOARD_HTML = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>ZeroTrust Arena</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{--bg:#0b0f17;--panel:#11182a;--border:#1f2a44;--text:#e6ebf5;--dim:#7c8aad;
--blue:#3b82f6;--red:#ef4444;--green:#22c55e;--gold:#f5c542;--judge:#a855f7}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font-family:'Segoe UI',system-ui,-apple-system,sans-serif}
header{padding:18px 24px;border-bottom:1px solid var(--border);
display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}
header h1{margin:0;font-size:20px;letter-spacing:.5px}
header h1 span{color:var(--blue)}header h1 b{color:var(--red)}
#chain{font-size:13px;padding:5px 12px;border-radius:20px;font-weight:600}
#chain.ok{background:rgba(34,197,94,.15);color:var(--green)}
#chain.bad{background:rgba(239,68,68,.15);color:var(--red)}
main{display:grid;grid-template-columns:1.1fr 1fr;gap:18px;padding:20px;max-width:1300px;margin:0 auto}
@media (max-width:900px){main{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:18px}
.card h2{margin:0 0 14px;font-size:14px;letter-spacing:.8px;color:var(--dim);
text-transform:uppercase;font-weight:700}
#feed{height:420px;overflow-y:auto;display:flex;flex-direction:column-reverse;gap:6px;font-size:13px}
.ev{padding:8px 10px;border-radius:8px;border-left:3px solid var(--border);
background:rgba(255,255,255,.02);display:flex;justify-content:space-between;gap:8px}
.ev.ok{border-left-color:var(--green)}
.ev.blocked{border-left-color:var(--red)}
.ev .tag{font-weight:700;font-size:11px;padding:2px 7px;border-radius:5px;white-space:nowrap}
.ev.ok .tag{background:rgba(34,197,94,.15);color:var(--green)}
.ev.blocked .tag{background:rgba(239,68,68,.15);color:var(--red)}
.ev .meta{color:var(--dim);font-size:11px}
.agent{display:flex;align-items:center;gap:10px;margin-bottom:10px;font-size:13px}
.agent .name{width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar{flex:1;height:8px;background:rgba(255,255,255,.07);border-radius:5px;overflow:hidden}
.bar i{display:block;height:100%;border-radius:5px}
.role-red i{background:var(--red)} .role-blue i{background:var(--blue)}
.role-judge i{background:var(--judge)} .role-other i{background:var(--dim)}
.score{width:34px;text-align:right;color:var(--dim);font-size:12px}
.verdict{display:flex;gap:18px;margin-bottom:14px}
.vbox{flex:1;text-align:center;padding:14px;border-radius:10px;background:rgba(255,255,255,.03)}
.vbox .n{font-size:30px;font-weight:800}
.vbox.blue .n{color:var(--blue)} .vbox.red .n{color:var(--red)}
.vbox .l{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
#winner{text-align:center;font-size:13px;color:var(--gold);margin-bottom:10px;font-weight:700}
#summary{font-size:13px;color:var(--text);line-height:1.5;margin-bottom:10px}
#highlights{font-size:12px;color:var(--dim);padding-left:18px;margin:0}
.empty{color:var(--dim);font-size:13px;text-align:center;padding:30px 0}
#src{font-size:11px;color:var(--dim);text-align:right}
.rules{font-size:12px;display:flex;flex-direction:column;gap:6px;max-height:160px;overflow-y:auto}
.rule{padding:6px 10px;border-radius:7px;background:rgba(239,68,68,.08);
border-left:3px solid var(--red);display:flex;justify-content:space-between;gap:8px}
.rule .k{color:var(--dim)}
</style></head>
<body>
<header>
  <h1>Zero<span>Trust</span> <b>Arena</b></h1>
  <div id="chain" class="ok">checking audit chain...</div>
</header>
<main>
  <div class="card">
    <h2>Live message feed (hub-verified)</h2>
    <div id="feed"><div class="empty">Waiting for traffic...</div></div>
  </div>
  <div style="display:flex;flex-direction:column;gap:18px">
    <div class="card">
      <h2>Judge verdict</h2>
      <div id="judge"><div class="empty">No Judge report yet. Start run_judge.py.</div></div>
    </div>
    <div class="card">
      <h2>Agent trust scores</h2>
      <div id="trust"><div class="empty">No agents registered yet.</div></div>
    </div>
    <div class="card">
      <h2>Active block rules (proxy)</h2>
      <div id="rules" class="rules"><div class="empty">None active.</div></div>
    </div>
  </div>
</main>
<script>
const $=s=>document.querySelector(s);
let sinceSeq=-1, proxyBase=null;

function roleClass(id){
  if(id.startsWith('red-')||id.startsWith('mallory')||id.startsWith('stranger')) return 'role-red';
  if(id.startsWith('blue-')) return 'role-blue';
  if(id.startsWith('judge')) return 'role-judge';
  return 'role-other';
}

async function pollEvents(){
  try{
    const r = await fetch('/events?since='+sinceSeq);
    const d = await r.json();
    const feed = $('#feed');
    if(d.events.length && feed.querySelector('.empty')) feed.innerHTML='';
    for(const ev of d.events){
      sinceSeq = Math.max(sinceSeq, ev.seq);
      const det = ev.detail||{};
      const blocked = ev.kind === 'MSG_BLOCKED' || (det.reason && ev.kind.endsWith('DENIED'));
      const row = document.createElement('div');
      row.className = 'ev ' + (blocked ? 'blocked' : 'ok');
      const tag = blocked ? (det.reason||ev.kind) : ev.kind;
      const who = det.sender || det.agent || '?';
      row.innerHTML = `<div><b>${who}</b> <span class="meta">${det.type||''}</span></div>
                       <span class="tag">${tag}</span>`;
      feed.insertBefore(row, feed.firstChild);
      while(feed.children.length>80) feed.removeChild(feed.lastChild);
    }
    renderTrust(d.trust||{});
    const chain = await (await fetch('/audit/verify')).json();
    const c = $('#chain');
    c.className = chain.ok ? 'ok' : 'bad';
    c.textContent = chain.ok ? `audit chain OK (${chain.entries} entries)` : `TAMPERING DETECTED at #${chain.broken_at}`;
  }catch(e){}
}

function renderTrust(trust){
  const box = $('#trust');
  const ids = Object.keys(trust);
  if(!ids.length){ box.innerHTML = '<div class="empty">No agents registered yet.</div>'; return; }
  box.innerHTML = ids.sort().map(id=>{
    const score = trust[id];
    return `<div class="agent ${roleClass(id)}"><span class="name">${id}</span>
      <span class="bar"><i style="width:${score}%"></i></span>
      <span class="score">${score}</span></div>`;
  }).join('');
}

async function pollJudge(){
  try{
    const r = await fetch('/judge/report');
    const d = await r.json();
    const box = $('#judge');
    if(!d || d.source==='none'){ box.innerHTML = '<div class="empty">No Judge report yet. Start run_judge.py.</div>'; return; }
    const hi = (d.ai_highlights||[]).map(h=>`<li>${h}</li>`).join('');
    box.innerHTML = `
      <div class="verdict">
        <div class="vbox blue"><div class="n">${d.blue_score}</div><div class="l">Blue</div></div>
        <div class="vbox red"><div class="n">${d.red_score}</div><div class="l">Red</div></div>
      </div>
      <div id="winner">Winner: ${d.winner}</div>
      <div id="summary">${d.summary||''}</div>
      <ul id="highlights">${hi}</ul>
      <div id="src">source: ${d.source}</div>`;
  }catch(e){}
}

async function pollRules(){
  if(!proxyBase){ try{ proxyBase = (new URLSearchParams(location.search)).get('proxy'); }catch(e){} }
  const box = $('#rules');
  if(!proxyBase){ box.innerHTML = '<div class="empty">Add ?proxy=http://127.0.0.1:PORT&token=... to the dashboard URL to show rules.</div>'; return; }
  const token = (new URLSearchParams(location.search)).get('token') || 'zt-proxy-admin-demo';
  try{
    const r = await fetch(proxyBase + '/_zt/rules', {headers:{'X-ZT-Admin':token}});
    const d = await r.json();
    if(!d.rules || !d.rules.length){ box.innerHTML = '<div class="empty">None active.</div>'; return; }
    box.innerHTML = d.rules.map(x=>`<div class="rule"><span>${x.kind}=${x.value}</span>
      <span class="k">${x.reason||''}</span></div>`).join('');
  }catch(e){ box.innerHTML = '<div class="empty">Could not reach the proxy (CORS or it is not running).</div>'; }
}

setInterval(pollEvents, 1500);
setInterval(pollJudge, 3000);
setInterval(pollRules, 3000);
pollEvents(); pollJudge(); pollRules();
</script>
</body></html>
"""


def _prune(now: float) -> None:
    for k in [k for k, t in seen.items() if now - t > MAX_AGE * 2]:
        del seen[k]


def _validate_card(card: dict):
    for k in ("agent_id", "role", "sign_pub", "enc_pub"):
        if not isinstance(card.get(k), str):
            return "MALFORMED_CARD"
    if not AGENT_ID_RE.match(card["agent_id"]):
        return "BAD_AGENT_ID"
    if card["role"] not in POLICY:
        return "UNKNOWN_ROLE"
    try:
        if len(b64d(card["sign_pub"])) != 32 or len(b64d(card["enc_pub"])) != 32:
            return "BAD_KEY"
    except Exception:
        return "BAD_KEY"
    return None


def _check(env: dict) -> None:
    """Outer-layer Zero Trust checks. Raises ZTError(reason) on failure."""
    if not all(k in env for k in STR_FIELDS + ("ts",)):
        raise ZTError("MALFORMED")
    if not all(isinstance(env[k], str) for k in STR_FIELDS):
        raise ZTError("MALFORMED")
    ts = env["ts"]
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not math.isfinite(ts):
        raise ZTError("MALFORMED")
    if len(json.dumps(env)) > MAX_ENV_CHARS:
        raise ZTError("TOO_LARGE")

    card = registry.get(env["sender"])
    if not card:
        raise ZTError("UNKNOWN_AGENT")
    verify_signature(env, card)  # raises BAD_SIGNATURE

    now = time.time()
    if abs(now - ts) > MAX_AGE:
        raise ZTError("STALE_MESSAGE")
    _prune(now)
    if env["msg_id"] in seen:
        raise ZTError("REPLAY_DETECTED")
    if env["type"] not in POLICY.get(card["role"], set()):
        raise ZTError("NOT_AUTHORIZED")
    if env["recipient"] not in registry:
        raise ZTError("UNKNOWN_RECIPIENT")


def _record_block(env: dict, reason: str) -> None:
    sender = str(env.get("sender", "?"))[:40]
    if reason == "NOT_AUTHORIZED" and sender in trust:
        # A registered agent tried something its role forbids.
        trust[sender] = max(0, trust[sender] - 30)
    elif reason in ("UNKNOWN_AGENT", "BAD_SIGNATURE"):
        # Someone failed identity checks while claiming this id.
        if sender in unverified or len(unverified) < 500:
            unverified[sender] = unverified.get(sender, 0) + 1
    audit.append(
        "MSG_BLOCKED",
        sender=sender,
        recipient=str(env.get("recipient", "?"))[:40],
        type=str(env.get("type", "?"))[:40],
        reason=reason,
    )


class RegisterReq(BaseModel):
    token: str
    card: dict


@app.post("/register")
def register(req: RegisterReq):
    card = req.card
    aid = str(card.get("agent_id", ""))[:40]
    with state_lock:
        if not hmac.compare_digest(req.token.encode(), ENROLL_TOKEN.encode()):
            audit.append("REGISTER_DENIED", agent=aid, reason="BAD_ENROLL_TOKEN")
            return JSONResponse(status_code=403, content={"status": "denied", "reason": "BAD_ENROLL_TOKEN"})
        problem = _validate_card(card)
        if problem:
            audit.append("REGISTER_DENIED", agent=aid, reason=problem)
            return JSONResponse(status_code=400, content={"status": "denied", "reason": problem})
        if aid in registry:
            audit.append("REGISTER_DENIED", agent=aid, reason="DUPLICATE_AGENT")
            return JSONResponse(status_code=409, content={"status": "denied", "reason": "DUPLICATE_AGENT"})
        registry[aid] = {k: card[k] for k in ("agent_id", "role", "sign_pub", "enc_pub")}
        trust[aid] = 100
        audit.append("REGISTER_OK", agent=aid, role=card["role"])
    return {"status": "registered", "agent_id": aid}


@app.get("/registry")
def get_registry():
    with state_lock:
        return dict(registry)


@app.post("/send")
def send(env: dict = Body(...)):
    with state_lock:
        try:
            _check(env)
        except ZTError as e:
            reason = str(e)
            _record_block(env, reason)
            return JSONResponse(status_code=403, content={"status": "blocked", "reason": reason})
        seen[env["msg_id"]] = time.time()
        inboxes[env["recipient"]].append(env)
        audit.append(
            "MSG_ACCEPTED",
            sender=env["sender"],
            recipient=env["recipient"],
            type=env["type"],
            msg_id=env["msg_id"],
        )
    return {"status": "accepted", "msg_id": env["msg_id"]}


@app.get("/inbox/{agent_id}")
def inbox(agent_id: str, ts: str = Query(...), sig: str = Query(...)):
    """Agents prove who they are before draining their own inbox."""
    def deny(reason: str):
        audit.append("INBOX_DENIED", agent=agent_id[:40], reason=reason)
        return JSONResponse(status_code=403, content={"status": "denied", "reason": reason})

    with state_lock:
        card = registry.get(agent_id)
        if not card:
            return deny("UNKNOWN_AGENT")
        now = time.time()
        try:
            tsf = float(ts)
        except ValueError:
            return deny("MALFORMED")
        if not math.isfinite(tsf) or abs(now - tsf) > MAX_AGE:
            return deny("STALE_REQUEST")
        try:
            Ed25519PublicKey.from_public_bytes(b64d(card["sign_pub"])).verify(
                b64d(sig), f"inbox|{agent_id}|{ts}".encode()
            )
        except Exception:
            return deny("BAD_SIGNATURE")
        _prune(now)
        key = "poll:" + sig
        if key in seen:
            return deny("REPLAY_DETECTED")
        seen[key] = now
        msgs = list(inboxes[agent_id])
        inboxes[agent_id].clear()
        if msgs:
            audit.append("INBOX_DELIVERED", agent=agent_id, count=len(msgs))
    return {"messages": msgs}


@app.get("/events")
def events(since: int = -1):
    """Feed for the dashboard: new audit entries plus current trust scores."""
    with state_lock:
        return {
            "events": audit.since(since),
            "trust": dict(trust),
            "unverified": dict(unverified),
        }


@app.get("/audit/verify")
def audit_verify():
    with state_lock:
        ok, bad = audit.verify()
        return {"ok": ok, "broken_at": bad, "entries": len(audit.events)}


@app.post("/judge/report")
def post_judge_report(report: dict = Body(...)):
    """Display-only side channel: the Judge's latest validated score, for the
    dashboard. This never affects any Zero Trust check above - the hub still
    never decrypts anything, and nothing here can block or allow a message."""
    global judge_report
    if not isinstance(report, dict):
        return JSONResponse(status_code=400, content={"status": "denied"})
    with state_lock:
        judge_report = {
            "blue_score": report.get("blue_score"),
            "red_score": report.get("red_score"),
            "winner": str(report.get("winner", ""))[:20],
            "summary": str(report.get("summary", ""))[:400],
            "ai_highlights": [str(h)[:100] for h in report.get("ai_highlights", [])][:5],
            "source": str(report.get("source", ""))[:20],
            "ts": time.time(),
        }
    return {"status": "ok"}


@app.get("/judge/report")
def get_judge_report():
    with state_lock:
        return judge_report or {"source": "none", "summary": "No Judge report yet."}


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD_HTML


@app.get("/health")
def health():
    with state_lock:
        return {"ok": True, "agents": len(registry)}