"""Small client that every agent uses to talk to the hub."""
import time

import requests

from zt_crypto import Identity, ZTError, b64e, open_msg, seal


def _reason(r) -> str:
    try:
        return str(r.json().get("reason", r.text))
    except ValueError:
        return r.text


class HubClient:
    def __init__(self, hub_url: str, identity: Identity, enroll_token: str):
        self.hub = hub_url.rstrip("/")
        self.me = identity
        self.token = enroll_token
        self.registry = {}

    def register(self) -> None:
        r = requests.post(
            f"{self.hub}/register",
            json={"token": self.token, "card": self.me.card()},
            timeout=10,
        )
        if r.status_code != 200:
            raise RuntimeError(f"registration refused: {_reason(r)}")
        self.refresh_registry()

    def refresh_registry(self) -> None:
        r = requests.get(f"{self.hub}/registry", timeout=10)
        r.raise_for_status()
        self.registry = r.json()

    def send(self, recipient_id: str, msg_type: str, body: dict):
        """Returns (http_status, json). 200 = accepted, 403 = blocked by the hub."""
        if recipient_id not in self.registry:
            self.refresh_registry()
        if recipient_id not in self.registry:
            raise RuntimeError(f"unknown recipient {recipient_id}")
        env = seal(self.me, self.registry[recipient_id], msg_type, body)
        r = requests.post(f"{self.hub}/send", json=env, timeout=10)
        return r.status_code, r.json()

    def poll(self) -> list:
        """Fetch our inbox. Each message is fully verified and decrypted here."""
        ts = str(time.time())
        sig = b64e(self.me.sign_key.sign(f"inbox|{self.me.agent_id}|{ts}".encode()))
        r = requests.get(
            f"{self.hub}/inbox/{self.me.agent_id}",
            params={"ts": ts, "sig": sig},
            timeout=10,
        )
        if r.status_code != 200:
            raise RuntimeError(f"inbox refused: {_reason(r)}")
        envs = r.json()["messages"]
        if envs:
            self.refresh_registry()
        out = []
        for env in envs:
            try:
                body = open_msg(self.me, env, self.registry)
                out.append({"ok": True, "sender": env["sender"], "type": env["type"], "body": body})
            except ZTError as e:
                out.append({"ok": False, "sender": env.get("sender"), "error": str(e)})
        return out
