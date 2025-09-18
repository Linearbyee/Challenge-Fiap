import json

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
            print(f"[RuleEngine] Erro ao carregar regras: {e}")
            self.rules = []

    def evaluate(self, event: dict):
        results = []
        for rule in self.rules:
            try:
                passed = eval(rule["condition"], {}, {"event": event})
                results.append({
                    "rule": rule["name"],
                    "passed": bool(passed),
                    "weight": rule.get("weight", 1)
                })
            except Exception as e:
                results.append({
                    "rule": rule["name"],
                    "passed": False,
                    "weight": rule.get("weight", 1),
                    "error": str(e)
                })
        return results


class ScoringService:
    def __init__(self, thresholds=None):
        self.thresholds = thresholds or {"block": 50, "review": 30}

    def calculate(self, results):
        score = sum(r["weight"] for r in results if not r["passed"])
        return score

    def decide(self, score):
        if score >= self.thresholds["block"]:
            return "BLOCK"
        elif score >= self.thresholds["review"]:
            return "REVIEW"
        return "ALLOW"
