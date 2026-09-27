"""Collector requests for the public configuration import API, not an oracle."""

def document(label, previous, uids, actions=(1, 2), modes=(0, 1)):
    prior = previous.get("configuration", {}).get("rules", [])
    rules = []
    for side in range(2):
        base = prior[side]["definition"].split()[0] if len(prior) == 2 else "0"
        rules.append({"name": f"{label}-{'request' if side == 0 else 'reply'}", "source": "t23-acceptance",
            "definition": f"0 {base} 4294967295 4294967295 4294967295 10 {side} 17 0 {actions[side]} * * 0 65535 0 65535 0e0{side+1}"})
    # Both directions are explicit complete rules. Repeated binding paths
    # intentionally reach the same logical rule without multiplying its hits.
    bindings = []
    for uid in uids:
        for side in range(2):
            for _ in range(2):
                bindings.append([len(bindings)+1, uid, 1, side, modes[side]])
    return {"format": "sakamoto-config-v1", "rules": rules, "groups": [], "edges": [],
            "bindings": bindings, "lists": []}


def empty():
    return {"format": "sakamoto-config-v1", "rules": [], "groups": [], "edges": [], "bindings": [], "lists": []}
