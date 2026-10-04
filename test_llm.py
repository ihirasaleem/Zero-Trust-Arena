"""Offline tests for llm_client.py (fake HTTP, no internet, no real keys):  python test_llm.py"""
import os
import sys

import llm_client as L

total = 0
fails = 0


def check(name, ok, extra=""):
    global total, fails
    total += 1
    if not ok:
        fails += 1
    print(("PASS" if ok else "FAIL"), "-", name, extra)


class R:
    def __init__(self, code, content=None, text="", models=None, finish="stop"):
        self.status_code = code
        self.text = text
        self._c, self._m, self._f = content, models, finish

    def json(self):
        if self._m is not None:
            return {"data": [{"id": m} for m in self._m]}
        return {"choices": [{"message": {"content": self._c}, "finish_reason": self._f}]}


def reset():
    L._cooldown.clear()
    L._model_cache.clear()
    L.last_error.clear()
    for k in ("GROQ_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY", "ZT_USE_OLLAMA",
              "GROQ_MODEL", "GEMINI_MODEL", "OPENROUTER_MODEL", "OLLAMA_MODEL"):
        os.environ.pop(k, None)
    os.environ["GROQ_API_KEY"] = "fake-key-for-tests"


real_post, real_get = L.requests.post, L.requests.get
GOOD = '{"ok": true}'

# 1. model_not_found -> discovery -> retry with a working model
reset()
posted = []


def post1(url, **kw):
    m = kw["json"]["model"]
    posted.append(m)
    if m == "openai/gpt-oss-20b":
        return R(404, text='{"error":{"message":"The model `openai/gpt-oss-20b` does not exist","code":"model_not_found"}}')
    return R(200, GOOD)


def get1(url, **kw):
    return R(200, models=["whisper-large-v3", "llama-guard-4", "llama-3.1-8b-instant", "playai-tts"])


L.requests.post, L.requests.get = post1, get1
try:
    res = L.ask_json("s", "u")
finally:
    L.requests.post, L.requests.get = real_post, real_get
check("1 model_not_found -> finds another model and succeeds",
      res == {"ok": True} and posted == ["openai/gpt-oss-20b", "llama-3.1-8b-instant"], str(posted))
check("1b discovered model is remembered", L._model_cache.get("groq") == "llama-3.1-8b-instant")

# 2. explicit model is never replaced
reset()
os.environ["GROQ_MODEL"] = "my-model"
posted.clear()
L.requests.post, L.requests.get = (lambda u, **kw: (posted.append(kw["json"]["model"]) or R(404, text="model not found"))), get1
try:
    res = L.ask_json("s", "u")
finally:
    L.requests.post, L.requests.get = real_post, real_get
check("2 explicit GROQ_MODEL is respected (no silent swap)", res is None and posted == ["my-model"], str(posted))

# 3. reasoning model: big budget + low effort
reset()
seen = {}


def post3(url, **kw):
    seen.update(kw["json"])
    return R(200, GOOD)


L.requests.post = post3
try:
    L.ask_json("s", "u")
finally:
    L.requests.post = real_post
check("3 gpt-oss gets max_tokens>=800 and reasoning_effort=low",
      seen.get("max_tokens", 0) >= 800 and seen.get("reasoning_effort") == "low", str(seen.get("max_tokens")))

# 4. empty content is a failure and is reported
reset()
L.requests.post = lambda u, **kw: R(200, "", finish="length")
try:
    res = L.ask_json("s", "u")
finally:
    L.requests.post = real_post
check("4 empty answer -> None with a clear reason", res is None and "empty" in L.last_error.get("groq", ""), L.last_error.get("groq", ""))

# 5. bad key -> long cooldown, not retried
reset()
n = []
L.requests.post = lambda u, **kw: (n.append(1) or R(401, text="invalid api key"))
try:
    L.ask_json("s", "u")
    L.ask_json("s", "u")
finally:
    L.requests.post = real_post
check("5 401 puts the provider on cooldown (one call only)", len(n) == 1 and "401" in L.last_error.get("groq", ""))

# 6. fallback to second provider on 429
reset()
os.environ["GEMINI_API_KEY"] = "fake2"
urls = []


def post6(url, **kw):
    urls.append(url)
    return R(429) if "groq" in url else R(200, 'x {"ok": true} y')


L.requests.post = post6
try:
    res = L.ask_json("s", "u")
finally:
    L.requests.post = real_post
check("6 429 on Groq falls back to Gemini", res == {"ok": True} and len(urls) == 2 and "generativelanguage" in urls[1])

# 7. network error -> None, no crash
reset()


def post7(url, **kw):
    raise L.requests.ConnectionError("down")


L.requests.post = post7
try:
    res = L.ask_json("s", "u")
finally:
    L.requests.post = real_post
check("7 network error is handled", res is None)

# 8. _pick_model rules
check("8a skips audio/guard models", L._pick_model(["whisper-large-v3", "llama-guard-4", "llama-3.1-8b-instant"], ["llama"]) == "llama-3.1-8b-instant")
check("8b free_only keeps only :free", L._pick_model(["a/b", "c/d:free"], [], True) == "c/d:free")
check("8c strips 'models/' prefix", L._pick_model(["models/gemini-2.5-flash"], ["flash"]) == "gemini-2.5-flash")
check("8d nothing usable -> None", L._pick_model(["whisper-1"], []) is None)

# 9. diagnose never prints the key
reset()
L.requests.post = lambda u, **kw: R(401, text="bad key fake-key-for-tests")
try:
    out = "\n".join(L.diagnose())
finally:
    L.requests.post = real_post
check("9 diagnose reports FAIL for a bad key", out.startswith("FAIL") and "401" in out)

reset()
print(f"\n{total - fails}/{total} checks passed")
sys.exit(1 if fails else 0)
