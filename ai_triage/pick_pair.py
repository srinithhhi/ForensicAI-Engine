"""Print one attack + one benign incident_id for smoke-testing predict.py.

Filters to the 39 v0_state.completed bundles — the dev bundles in data/labeled/
(INC-20260523-134301 + INC-WIN-20260523-191951) predate the four-feature
schema bump and crash predict.py.
"""
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
LABELED = ROOT / "data" / "labeled"
V0_STATE = ROOT / "data" / "experiments" / "v0_state.json"


def main() -> None:
    wanted = {
        entry["incident_id"]
        for entry in json.loads(V0_STATE.read_text())["completed"].values()
    }
    benign = attack = None
    for p in sorted(LABELED.glob("*.json")):
        v = json.loads(p.read_text())
        if v["incident_id"] not in wanted:
            continue
        if v["label"]["is_benign"] and benign is None:
            benign = v["incident_id"]
        elif v["label"]["technique_ids"] and attack is None:
            attack = (v["incident_id"], v["label"]["technique_ids"])
        if benign and attack:
            break
    print("attack:", attack)
    print("benign:", benign)


if __name__ == "__main__":
    main()
