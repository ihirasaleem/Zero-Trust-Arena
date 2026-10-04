import copy
from zt_crypto import Identity, seal, open_msg, ZTError

recon = Identity("recon-1", "red_recon")
analyst = Identity("analyst-1", "red_analyst")
registry = {a.agent_id: a.card() for a in (recon, analyst)}

# 1. A valid message
env = seal(recon, registry["analyst-1"], "recon_report", {"open": [3000, 8080]})
print("1 valid      :", open_msg(analyst, env, registry))


def attempt(name, fn):
    try:
        fn()
        print(name, "-> NOT BLOCKED (this is a bug)")
    except ZTError as e:
        print(name, "-> blocked:", e)


# 2. Same message sent again
attempt("2 replay     ", lambda: open_msg(analyst, env, registry))

# 3. Message changed in transit (type altered)
fresh = seal(recon, registry["analyst-1"], "recon_report", {"open": [3000]})
tampered = copy.deepcopy(fresh)
tampered["type"] = "findings"
attempt("3 tampered   ", lambda: open_msg(analyst, tampered, registry))

# 4. Rogue agent that never registered
rogue = Identity("evil-1", "red_recon")
attempt(
    "4 rogue agent",
    lambda: open_msg(
        analyst, seal(rogue, registry["analyst-1"], "recon_report", {}), registry
    ),
)

# 5. Registered agent sending something its role may not send
attempt(
    "5 no permission",
    lambda: open_msg(
        analyst, seal(recon, registry["analyst-1"], "block_rule", {}), registry
    ),
)

# 6. Message addressed to someone else
other = Identity("planner-1", "red_planner")
registry["planner-1"] = other.card()
for_planner = seal(recon, registry["planner-1"], "recon_report", {})
attempt("6 wrong target ", lambda: open_msg(analyst, for_planner, registry))
