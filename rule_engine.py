import json

OPS = {
    ">=": lambda a, b: a >= b,
    "<=": lambda a, b: a <= b,
    ">": lambda a, b: a > b,
    "<": lambda a, b: a < b,
    "==": lambda a, b: a == b,
    "!=": lambda a, b: a != b,
    "in": lambda a, b: a in b,
    "not-in": lambda a, b: a not in b
}

class RuleEngine:
    def __init__(self, config_path="rules.json"):
        self.config_path = config_path
        self.rules = []
        self.load_rules()

    def load_rules(self):
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.rules = json.load(f)
        except Exception as e:
            print(f"[RuleEngine] could not load rules: {e}")
            self.rules = []

    def evaluate_rule(self, rule, event):
        # rule: {"name":..., "field":..., "op":..., "value":..., "weight":...}
        field = rule.get("field")
        op = rule.get("op")
        value = rule.get("value")
        # safe get value from event
        ev = event.get(field)
        # handle missing ops
        func = OPS.get(op)
        if func is None:
            return False, f"unknown op {op}"
        try:
            passed = func(ev, value)
            return bool(passed), None
        except Exception as e:
            return False, str(e)

    def evaluate(self, event: dict):
        results = []
        for r in self.rules:
            passed, err = self.evaluate_rule(r, event)
            rec = {
                "rule": r.get("name"),
                "passed": bool(passed),
                "weight": r.get("weight", 1)
            }
            if err:
                rec["error"] = err
            results.append(rec)
        return results


class ScoringService:
    def __init__(self, thresholds=None):
        self.thresholds = thresholds or {"block": 50, "review": 30}

    def calculate(self, results):
        # accumulate weights of FAILED rules
        score = sum(r.get("weight", 1) for r in results if not r.get("passed"))
        return score

    def decide(self, score):
        if score >= self.thresholds["block"]:
            return "BLOCK"
        if score >= self.thresholds["review"]:
            return "REVIEW"
        return "ALLOW"
