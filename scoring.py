class ScoringService:
    def __init__(self):
        # Pesos para as regras
        self.pesos = {
            "ip_abuseipdb": 3,
            "ip_spamhaus": 4,
            "muitas_falhas": 2
        }
        self.limiar_block = 7
        self.limiar_review = 4

    def calculate(self, resultados):
        score = 0
        for regra, passou in resultados.items():
            if not passou:
                score += self.pesos.get(regra, 1)
        return score

    def decide(self, score):
        if score >= self.limiar_block:
            return "BLOCK"
        elif score >= self.limiar_review:
            return "REVIEW"
        return "ALLOW"
