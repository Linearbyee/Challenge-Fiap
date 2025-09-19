class RuleEngine:
    def __init__(self):
        # Aqui você pode configurar regras extras se quiser
        self.regras = {
            "ip_abuseipdb": "Score no AbuseIPDB baixo",
            "ip_spamhaus": "IP listado no Spamhaus",
            "muitas_falhas": "Muitas tentativas de login"
        }

    def evaluate(self, event):
        """
        Recebe um dicionário com as condições
        Retorna dict {regra: True/False}
        """
        resultados = {}
        for regra in self.regras:
            # Se o evento trouxe a condição, usa; senão marca como True (passou)
            resultados[regra] = event.get(regra, True)
        return resultados