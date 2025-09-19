import requests
import os
import time

ABUSE_API_KEY = os.getenv("ABUSE_API_KEY", "")
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

# Cache simples em memória
_cache = {}
CACHE_TTL = 300  # 5 minutos

def check_abuseipdb(ip):
    """Consulta IP no AbuseIPDB e retorna score de confiança (0-100)."""
    if not ABUSE_API_KEY:
        return 0

    # Verifica cache
    if ip in _cache and (time.time() - _cache[ip]["ts"] < CACHE_TTL):
        return _cache[ip]["score"]

    try:
        resp = requests.get(
            ABUSE_URL,
            headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=5  # garante que não trava
        )
        data = resp.json()
        score = data.get("data", {}).get("abuseConfidenceScore", 0)

        # Salva em cache
        _cache[ip] = {"score": score, "ts": time.time()}
        return score

    except requests.Timeout:
        print(f"⚠️ Timeout ao consultar AbuseIPDB para {ip}")
        return 0
    except Exception as e:
        print(f"⚠️ Erro na API AbuseIPDB: {e}")
        return 0

def ip_in_spamhaus(ip):
    """Simulação de consulta Spamhaus (mock).
       Em produção poderia baixar lista DROP/EDROP e verificar."""
    # ⚠️ Aqui seria feita a checagem real
    return False
