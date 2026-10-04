"""Check which free LLM providers work with your keys.

PowerShell (keys come from environment variables, never paste them in a chat):
    $env:GROQ_API_KEY = "paste-your-NEW-key-here"
    python check_llm.py
"""
import sys

import llm_client

print("Providers with a key:", ", ".join(llm_client.configured()) or "none")
lines = llm_client.diagnose()
for line in lines:
    print(line)
if not any(line.startswith("OK") for line in lines):
    print("\nNo provider answered. The Blue Team still works with rules only (no LLM).")
    sys.exit(1)
print("\nAt least one provider works. The LLM second opinion will be used.")
