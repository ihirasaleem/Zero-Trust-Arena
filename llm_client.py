"""Tiny LLM client with automatic fallback between free providers.

Order: Groq -> Gemini -> OpenRouter -> Ollama (local, only if ZT_USE_OLLAMA=1).
A provider is used only if its API key is set in the environment:
    GROQ_API_KEY, GEMINI_API_KEY, OPENROUTER_API_KEY

Model names change often, so this client is forgiving:
  * if the default model is rejected ("model not found"), it asks the provider
    for its model list and picks a working chat model by itself;
  * reasoning models (gpt-oss) get a larger token budget and low reasoning effort,
    so the answer is not eaten by hidden thinking;
  * set GROQ_MODEL, GEMINI_MODEL, OPENROUTER_MODEL or OLLAMA_MODEL to force a model.

Only send fake lab data here, never real passwords, keys or personal data.
"""
import json
import os
import time

import requests

PROVIDERS = [
    {"name": "groq", "base": "https://api.groq.com/openai/v1",
     "key": "GROQ_API_KEY", "model_env": "GROQ_MODEL", "model": "openai/gpt-oss-20b",
     "prefer": ["openai/gpt-oss-20b", "openai/gpt-oss-120b", "llama-3.3-70b", "llama-3.1-8b", "llama"]},
    {"name": "gemini", "base": "https://generativelanguage.googleapis.com/v1beta/openai",
     "key": "GEMINI_API_KEY", "model_env": "GEMINI_MODEL", "model": "gemini-2.0-flash",
     "prefer": ["gemini-2.5-flash", "gemini-2.0-flash", "flash"]},
    {"name": "openrouter", "base": "https://openrouter.ai/api/v1",
     "key": "OPENROUTER_API_KEY", "model_env": "OPENROUTER_MODEL",
     "model": "meta-llama/llama-3.3-70b-instruct:free", "free_only": True,
     "prefer": ["llama-3.3-70b", "gpt-oss", "llama", "qwen", "gemma"]},
    {"name": "ollama", "base": "http://127.0.0.1:11434/v1",
     "key": None, "model_env": "OLLAMA_MODEL", "model": "llama3.2",
     "prefer": ["llama3.2", "llama3", "llama", "qwen", "gemma"]},
]

_cooldown = {}     # provider name -> time before which it is skipped
_model_cache = {}  # provider name -> model id found by auto-discovery
last_error = {}    # provider name -> short text about the last failure (never contains keys)

_SKIP_WORDS = ("whisper", "tts", "guard", "embed", "vision", "image", "audio", "orpheus",
               "playai", "transcribe", "moderation", "safeguard")


def configured() -> list:
    names = [p["name"] for p in PROVIDERS if p["key"] and os.environ.get(p["key"])]
    if os.environ.get("ZT_USE_OLLAMA") == "1":
        names.append("ollama")
    return names


def available() -> bool:
    return bool(configured())


def _extract_json(text):
    if not isinstance(text, str):
        return None
    a, b = text.find("{"), text.rfind("}")
    if a == -1 or b <= a:
        return None
    try:
        data = json.loads(text[a:b + 1])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def _headers(p) -> dict:
    h = {"Content-Type": "application/json"}
    if p["key"]:
        h["Authorization"] = "Bearer " + os.environ[p["key"]]
    return h


def _explicit_model(p):
    return os.environ.get(p["model_env"]) or None


def _model_for(p) -> str:
    return _explicit_model(p) or _model_cache.get(p["name"]) or p["model"]


def _pick_model(ids, prefer=(), free_only=False):
    """Choose a chat model from a provider's model list."""
    ids = [i for i in ids if isinstance(i, str)]
    ids = [i.split("/", 1)[1] if i.startswith("models/") else i for i in ids]
    ids = [i for i in ids if not any(w in i.lower() for w in _SKIP_WORDS)]
    if free_only:
        ids = [i for i in ids if i.endswith(":free")]
    for want in prefer:
        for i in ids:
            if want.lower() in i.lower():
                return i
    return ids[0] if ids else None


def _discover(p, timeout: float):
    try:
        r = requests.get(p["base"] + "/models", headers=_headers(p), timeout=timeout)
        if r.status_code != 200:
            return None
        items = r.json().get("data", [])
        ids = [m.get("id") for m in items if isinstance(m, dict)]
    except (requests.RequestException, ValueError, AttributeError):
        return None
    return _pick_model(ids, p.get("prefer", ()), p.get("free_only", False))


def _body_text(r) -> str:
    try:
        return str(getattr(r, "text", "") or "")[:300]
    except Exception:  # noqa: BLE001
        return ""


def _call(p, system: str, user: str, timeout: float, _retry: bool = True):
    """One request to one provider. Returns (parsed_dict_or_None, error_text_or_None)."""
    model = _model_for(p)
    payload = {
        "model": model,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        "temperature": 0,
        "max_tokens": 1000,
    }
    if "gpt-oss" in model:
        payload["reasoning_effort"] = "low"
    try:
        r = requests.post(p["base"] + "/chat/completions", headers=_headers(p), json=payload, timeout=timeout)
    except requests.RequestException as e:
        _cooldown[p["name"]] = time.time() + 30
        return None, f"network error: {type(e).__name__}"

    code = r.status_code
    if code in (400, 404) and _retry and not _explicit_model(p) and "model" in _body_text(r).lower():
        found = _discover(p, timeout)
        if found and found != model:
            _model_cache[p["name"]] = found
            return _call(p, system, user, timeout, _retry=False)
    if code == 429 or code >= 500:
        _cooldown[p["name"]] = time.time() + 60
        return None, f"HTTP {code} (rate limited or provider down)"
    if code != 200:
        _cooldown[p["name"]] = time.time() + 300
        return None, f"HTTP {code} model={model} {_body_text(r)[:120]}".strip()
    try:
        choice = r.json()["choices"][0]
        text = choice["message"].get("content")
        finish = choice.get("finish_reason")
    except (KeyError, IndexError, ValueError, AttributeError, TypeError):
        return None, "unexpected response shape"
    if not text or not str(text).strip():
        return None, f"empty answer (finish_reason={finish}, model={model})"
    data = _extract_json(text)
    if data is None:
        return None, f"answer was not JSON (model={model})"
    return data, None


def ask_json(system: str, user: str, timeout: float = 12.0):
    """Ask the first working provider. Returns a dict, or None if all fail."""
    names = set(configured())
    for p in PROVIDERS:
        if p["name"] not in names or time.time() < _cooldown.get(p["name"], 0):
            continue
        data, err = _call(p, system, user, timeout)
        if data is not None:
            last_error.pop(p["name"], None)
            return data
        if err:
            last_error[p["name"]] = err
    return None


def diagnose(timeout: float = 15.0) -> list:
    """Live self-test of every configured provider. Returns printable lines (no keys)."""
    lines = []
    names = configured()
    if not names:
        return ["No provider is configured. Set GROQ_API_KEY (and/or GEMINI_API_KEY, OPENROUTER_API_KEY)."]
    for p in PROVIDERS:
        if p["name"] not in names:
            continue
        data, err = _call(p, 'Reply with only this JSON: {"ok": true}', "ping", timeout)
        model = _model_for(p)
        if data is not None:
            lines.append(f"OK    {p['name']:<10} model={model}")
        else:
            lines.append(f"FAIL  {p['name']:<10} model={model}  {err}")
    return lines
