import llm_client

system = '''You are the official Judge of a ZeroTrust Arena cyber exercise.
Reply with ONLY valid JSON in this exact format:
{"blue_score": 50, "red_score": 40, "winner": "Blue", "summary": "test summary", "ai_highlights": ["point1"]}'''

user = 'Here is a simple test state: {"active_block_rules": [], "recent_events": []}'
print(llm_client.ask_json(system, user))
