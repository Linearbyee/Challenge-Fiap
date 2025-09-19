import requests
import os

ABUSE_API_KEY = os.getenv("ABUSE_API_KEY", "")
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

def check_abuseipdb(ip):
    """Consulta IP no AbuseIPDB e retorna score de confiança"""
    if not ABUSE_API_KEY:
        return 0
    try:
        resp = requests.get(
            ABUSE_URL,
            headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90}
        )
        data = resp.json()
        return data.get("data", {}).get("abuseConfidenceScore", 0)
    except Exception:
        return 0

def ip_in_spamhaus(ip):
    """Simulação de consulta Spamhaus (mock).
       Em produção poderia baixar lista DROP/EDROP e verificar."""
    # ⚠️ Aqui seria feita a checagem real
    return False
