"""ZeroTrust Arena -- the Zero-Trust Proof demo.

Run this ONE command in front of judges:

    python zero_trust_proof.py

It needs nothing else running - it starts its own throw-away hub, proves
every claim with a live result, then shuts the hub down again. Nothing here
is a description; every line below is something that just happened on this
machine, with the hub's and the crypto layer's own numbers printed as proof.

What it proves, in order:
  PART A - the signing and encryption code itself (zt_crypto.py), with no
           hub involved at all: a real Ed25519 signature, a real AES-GCM
           ciphertext that hides the plaintext, and both primitives
           rejecting a single flipped bit.
  PART B - the running hub rejecting forged traffic LIVE over HTTP:
           an unregistered agent, a forged signature, and a replayed
           message - none of these are role-policy checks, they are the
           identity/signature/freshness layer that runs before role policy
           is ever consulted.
  PART C - the audit log: every rejection above is on disk, and the
           hash chain that makes the log tamper-evident still verifies.
"""
import inspect
import os
import subprocess
import sys
import tempfile
import time

import requests

import zt_crypto
from audit import AuditLog
from zt_crypto import Identity, ZTError, b64d, open_msg, seal

PROOF_LOG = "zero_trust_proof.log"
total = 0
fails = 0


def check(name: str, ok: bool, extra: str = "") -> None:
    global total, fails
    total += 1
    if not ok:
        fails += 1
    print(("PASS" if ok else "FAIL"), "-", name, extra, flush=True)


def heading(title: str) -> None:
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def code(fn, name: str) -> None:
    src = inspect.getsource(fn)
    print(f"\n--- zt_crypto.py : {name}() ---")
    print(src.rstrip())


# =====================================================================
# PART A - the crypto layer, directly, no hub, no network
# =====================================================================
heading("PART A - signing and encryption, proved in code (no hub involved)")
code(seal, "seal")
code(open_msg, "open_msg")

alice = Identity("alice-proof", "judge")
bob = Identity("bob-proof", "blue_patch")
registry = {a.agent_id: a.card() for a in (alice, bob)}

secret_body = {"order": "transfer $1,000,000 to attacker", "note": "this must stay unreadable on the wire"}
env = seal(alice, bob.card(), "score_update", secret_body)

print(f"\nReal signature on the wire (Ed25519, 64 bytes): {env['sig'][:44]}...")
print(f"Real ciphertext on the wire (AES-GCM):            {env['ct'][:44]}...")
check("A1 the signature is real bytes, not a placeholder",
      len(b64d(env["sig"])) == 64)
check("A2 the wire body is ciphertext, not the plaintext",
      "1,000,000" not in str(env) and "attacker" not in str(env))

opened = open_msg(bob, env, registry)
check("A3 the legitimate recipient decrypts it back correctly", opened == secret_body)

tampered_sig = dict(env)
sig_bytes = bytearray(b64d(tampered_sig["sig"]))
sig_bytes[0] ^= 0x01
tampered_sig["sig"] = zt_crypto.b64e(bytes(sig_bytes))
try:
    open_msg(bob, tampered_sig, registry)
    check("A4 a single flipped bit in the signature is rejected", False)
except ZTError as e:
    check("A4 a single flipped bit in the signature is rejected", str(e) == "BAD_SIGNATURE", str(e))

tampered_ct = dict(env)
tampered_ct["msg_id"] = "ct-tamper-" + tampered_ct["msg_id"]  # fresh id: must not be read as a replay
ct_bytes = bytearray(b64d(tampered_ct["ct"]))
ct_bytes[0] ^= 0x01
tampered_ct["ct"] = zt_crypto.b64e(bytes(ct_bytes))
tampered_ct["sig"] = zt_crypto.b64e(alice.sign_key.sign(zt_crypto._canon(
    {k: v for k, v in tampered_ct.items() if k != "sig"})))
try:
    open_msg(bob, tampered_ct, registry)
    check("A5 a single flipped bit in the ciphertext is rejected (AES-GCM auth tag)", False)
except ZTError as e:
    check("A5 a single flipped bit in the ciphertext is rejected (AES-GCM auth tag)",
          str(e) == "DECRYPT_FAILED", str(e))

wrong_key_sender = Identity("mallory-proof", "judge")
forged = seal(wrong_key_sender, bob.card(), "score_update", {"fake": "data"})
forged["sender"] = "alice-proof"  # claims to be Alice, but signed with a different key
forged["sig"] = zt_crypto.b64e(wrong_key_sender.sign_key.sign(
    zt_crypto._canon({k: v for k, v in forged.items() if k != "sig"})))
try:
    open_msg(bob, forged, registry)
    check("A6 impersonation (wrong signing key for the claimed sender) is rejected", False)
except ZTError as e:
    check("A6 impersonation (wrong signing key for the claimed sender) is rejected",
          str(e) == "BAD_SIGNATURE", str(e))

print(f"\nPart A result: the encryption layer hid the plaintext, and both the "
      f"signature and the AES-GCM ciphertext independently detect a single "
      f"flipped bit, with no role check involved anywhere above.")


# =====================================================================
# PART B - the live hub, over real HTTP, rejecting forged traffic
# =====================================================================
heading("PART B - the live hub rejecting forged traffic over HTTP")

TOKEN = os.environ.get("ZT_ENROLL_TOKEN", "zt-arena-demo-token")
# Run the demo hub in its own throw-away folder, so it never touches whatever
# hub_port.txt / audit_log.jsonl you already have from a real session.
demo_dir = tempfile.mkdtemp(prefix="zt_proof_")
run_hub_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "run_hub.py")
log_file = open(PROOF_LOG, "w", encoding="utf-8")
hub_proc = subprocess.Popen([sys.executable, run_hub_path, "--port", "0"],
                            stdout=log_file, stderr=subprocess.STDOUT, cwd=demo_dir)
try:
    port_file = os.path.join(demo_dir, "hub_port.txt")
    deadline = time.time() + 15
    base = None
    while time.time() < deadline:
        try:
            with open(port_file, encoding="utf-8") as f:
                p = f.read().strip()
            base = f"http://127.0.0.1:{p}"
            if requests.get(f"{base}/health", timeout=2).ok:
                break
        except (OSError, requests.RequestException):
            pass
        time.sleep(0.3)
    if not base:
        print(f"Could not start the demo hub. See {PROOF_LOG}")
        sys.exit(2)
    print(f"Fresh demo hub started on {base}\n")

    def register(ident: Identity) -> None:
        r = requests.post(f"{base}/register", json={"token": TOKEN, "card": ident.card()}, timeout=10)
        r.raise_for_status()

    carol = Identity("carol-live", "judge")
    dave = Identity("dave-live", "blue_patch")
    register(carol)
    register(dave)
    live_registry = requests.get(f"{base}/registry", timeout=10).json()

    # B1: a normal, legitimate message is accepted
    good_env = seal(carol, live_registry["dave-live"], "score_update", {"score": 90})
    r = requests.post(f"{base}/send", json=good_env, timeout=10)
    check("B1 a legitimate signed message is ACCEPTED", r.status_code == 200, r.text[:80])

    # B2: an unregistered agent is rejected before anything else is checked
    stranger = Identity("stranger-live", "judge")
    stranger_env = seal(stranger, live_registry["dave-live"], "score_update", {"score": 1})
    r = requests.post(f"{base}/send", json=stranger_env, timeout=10)
    check("B2 an UNREGISTERED agent is rejected",
          r.status_code == 403 and r.json().get("reason") == "UNKNOWN_AGENT", r.text[:100])

    # B3: a forged signature (ciphertext/header unchanged, signature bit-flipped) is rejected
    forged_env = dict(good_env)
    forged_env["msg_id"] = "forged-" + forged_env["msg_id"]  # new id so this is not read as a replay
    fb = bytearray(b64d(forged_env["sig"]))
    fb[0] ^= 0x01
    forged_env["sig"] = zt_crypto.b64e(bytes(fb))
    r = requests.post(f"{base}/send", json=forged_env, timeout=10)
    check("B3 a FORGED signature is rejected",
          r.status_code == 403 and r.json().get("reason") == "BAD_SIGNATURE", r.text[:100])

    # B4: replaying the exact same, already-accepted envelope is rejected
    r = requests.post(f"{base}/send", json=good_env, timeout=10)
    check("B4 REPLAYING the same accepted message is rejected",
          r.status_code == 403 and r.json().get("reason") == "REPLAY_DETECTED", r.text[:100])

    # B5: role policy is a SEPARATE, later check - a legitimately signed message
    # of a type the sender's role may not send is rejected for a different reason
    bad_type_env = seal(carol, live_registry["dave-live"], "attack_event", {"x": 1})
    r = requests.post(f"{base}/send", json=bad_type_env, timeout=10)
    check("B5 (contrast) a valid signature but wrong ROLE fails differently (NOT_AUTHORIZED)",
          r.status_code == 403 and r.json().get("reason") == "NOT_AUTHORIZED", r.text[:100])

    print(f"\nPart B result: UNKNOWN_AGENT, BAD_SIGNATURE and REPLAY_DETECTED all "
          f"fired on a sender whose ROLE was perfectly fine - these are identity "
          f"and cryptography checks, not the role check, which is B5 and only B5.")

    # =================================================================
    # PART C - the tamper-evident audit log
    # =================================================================
    heading("PART C - every rejection above is on disk, and the chain still verifies")
    av = requests.get(f"{base}/audit/verify", timeout=10).json()
    check("C1 the audit hash chain verifies (no tampering)", av.get("ok") is True, str(av))

    events = requests.get(f"{base}/events?since=-1", timeout=10).json()["events"]
    blocked_reasons = [e["detail"]["reason"] for e in events if e["kind"] == "MSG_BLOCKED"]
    for reason in ("UNKNOWN_AGENT", "BAD_SIGNATURE", "REPLAY_DETECTED", "NOT_AUTHORIZED"):
        check(f"C2 {reason} is permanently recorded in audit_log.jsonl", reason in blocked_reasons)

    print(f"\nFull audit trail for this run ({len(events)} entries):")
    for e in events:
        d = e["detail"]
        print(f"  [{d.get('reason') or d.get('type') or '?'}] {e['kind']}  sender={d.get('sender', d.get('agent', '?'))}")
finally:
    hub_proc.terminate()
    try:
        hub_proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        hub_proc.kill()
    log_file.close()
    import shutil
    shutil.rmtree(demo_dir, ignore_errors=True)

heading("RESULT")
print(f"{total - fails}/{total} checks passed")
if fails:
    print("Something above did not hold - fix it before the demo. See the FAIL lines.")
else:
    print("Zero Trust is a demonstrated property of this system, not a claim:")
    print("  - signing and AES-GCM encryption are implemented in zt_crypto.py (Part A);")
    print("  - the live hub rejects forged/replayed/unregistered traffic over real HTTP (Part B);")
    print("  - that rejection is permanently and verifiably logged (Part C).")
sys.exit(1 if fails else 0)