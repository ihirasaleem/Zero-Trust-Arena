"""ZeroTrust Arena - crypto layer.

Every message is: signed (Ed25519), encrypted (X25519 + AES-GCM),
time-stamped with a unique id (replay protection), and checked against
a role policy (authorization).
"""
import os
import time
import json
import uuid
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

RAW = dict(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


MAX_AGE = 30  # seconds a message stays valid

# Which role may send which message type (Zero Trust authorization)
POLICY = {
    "red_recon": {"recon_report"},
    "red_analyst": {"findings"},
    "red_planner": {"attack_event"},
    "blue_monitor": {"log_batch"},
    "blue_detector": {"alert"},
    "blue_patch": {"block_rule", "patch_report"},
    "judge": {"score_update"},
}


class ZTError(Exception):
    """Raised when a Zero Trust check fails."""


class Identity:
    def __init__(self, agent_id: str, role: str):
        self.agent_id = agent_id
        self.role = role
        self.sign_key = Ed25519PrivateKey.generate()
        self.enc_key = X25519PrivateKey.generate()
        self.seen = {}  # msg_id -> time first seen (replay cache)

    def card(self) -> dict:
        """Public info registered with the Trust Authority."""
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "sign_pub": b64e(self.sign_key.public_key().public_bytes(**RAW)),
            "enc_pub": b64e(self.enc_key.public_key().public_bytes(**RAW)),
        }


def _canon(d: dict) -> bytes:
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def _derive(shared: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"zt-arena-v1",
    ).derive(shared)


def seal(me: Identity, recipient_card: dict, msg_type: str, body: dict) -> dict:
    """Encrypt body for the recipient and sign the whole envelope."""
    eph = X25519PrivateKey.generate()
    pub = X25519PublicKey.from_public_bytes(b64d(recipient_card["enc_pub"]))
    key = _derive(eph.exchange(pub))
    env = {
        "sender": me.agent_id,
        "recipient": recipient_card["agent_id"],
        "ts": time.time(),
        "msg_id": str(uuid.uuid4()),
        "type": msg_type,
        "eph_pub": b64e(eph.public_key().public_bytes(**RAW)),
        "nonce": b64e(os.urandom(12)),
    }
    # The header is bound to the ciphertext as AES-GCM associated data.
    env["ct"] = b64e(
        AESGCM(key).encrypt(b64d(env["nonce"]), _canon(body), _canon(env))
    )
    env["sig"] = b64e(me.sign_key.sign(_canon(env)))
    return env


def verify_signature(env: dict, sender_card: dict) -> None:
    unsigned = {k: v for k, v in env.items() if k != "sig"}
    try:
        Ed25519PublicKey.from_public_bytes(b64d(sender_card["sign_pub"])).verify(
            b64d(env["sig"]), _canon(unsigned)
        )
    except Exception:
        raise ZTError("BAD_SIGNATURE")


def open_msg(me: Identity, env: dict, registry: dict) -> dict:
    """Run every Zero Trust check, then decrypt. Raises ZTError on failure."""
    card = registry.get(env.get("sender"))
    if not card:
        raise ZTError("UNKNOWN_AGENT")
    if env.get("recipient") != me.agent_id:
        raise ZTError("WRONG_RECIPIENT")
    verify_signature(env, card)

    now = time.time()
    if abs(now - env["ts"]) > MAX_AGE:
        raise ZTError("STALE_MESSAGE")
    if env["msg_id"] in me.seen:
        raise ZTError("REPLAY_DETECTED")
    if env["type"] not in POLICY.get(card["role"], set()):
        raise ZTError("NOT_AUTHORIZED")

    header = {k: v for k, v in env.items() if k not in ("ct", "sig")}
    key = _derive(
        me.enc_key.exchange(
            X25519PublicKey.from_public_bytes(b64d(env["eph_pub"]))
        )
    )
    try:
        pt = AESGCM(key).decrypt(b64d(env["nonce"]), b64d(env["ct"]), _canon(header))
    except Exception:
        raise ZTError("DECRYPT_FAILED")

    me.seen[env["msg_id"]] = now
    me.seen = {k: v for k, v in me.seen.items() if now - v <= MAX_AGE * 2}
    return json.loads(pt)
