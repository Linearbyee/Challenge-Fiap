import os
import json
import time
import requests
from flask import Flask, request, jsonify, session, redirect, url_for, render_template

from rule_engine import RuleEngine, ScoringService

# =========================
# Configurações
# =========================
app = Flask(__name__)
app.secret_key = "sua_chave_segura"  # Trocar para algo forte em produção
LOG_FILE = "cyberfortress_logs.ndjson"

# AbuseIPDB
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY", "SUA_KEY_AQUI")
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

# Spamhaus (DROP/EDROP lists)
SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"
spamhaus_list = set()
spamhaus_last_update = 0

# Motor de Regras
rule_engine = RuleEngine("rules.json")
scoring_service = ScoringService()


# =========================
# Funções auxiliares
# =========================
def refresh_spamhaus_if_needed(force=False):
    global spamhaus_list, spamhaus_last_update
    if force or (time.time() - spamhaus_last_update > 3600):  # 1h
        drop = requests.get(SPAMHAUS_DROP_URL).text.splitlines()
        edrop = requests.get(SPAMHAUS_EDROP_URL).text.splitlines()
        spamhaus_list = {line.split(";")[0].strip() for line in drop + edrop if line and not line.startswith(";")}
        spamhaus_last_update = time.time()
        print("[+] Spamhaus atualizado, total IPs:", len(spamhaus_list))


def check_abuseipdb(ip):
    try:
        resp = requests.get(
            ABUSE_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": ABUSE_API_KEY, "Accept": "application/json"}
        )
        if resp.status_code == 200:
            data = resp.json()
            return data["data"]["abuseConfidenceScore"]
    except Exception as e:
        print("[!] Erro AbuseIPDB:", e)
    return 0


def ip_in_spamhaus(ip):
    refresh_spamhaus_if_needed()
    return ip in spamhaus_list


def log_event(entry):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def load_logs(limit=50):
    logs = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
            for line in lines:
                logs.append(json.loads(line))
    except FileNotFoundError:
        pass
    return logs


# =========================
# Rotas principais
# =========================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    ip = request.remote_addr

    # Mock de autenticação admin
    if username == "admin" and password == "123":
        session["is_admin"] = True
        session["username"] = username
        return redirect(url_for("admin_panel"))

    # Threat Intel
    abuse_score = check_abuseipdb(ip)
    in_spamhaus = ip_in_spamhaus(ip)
    failed_attempts = 0  # exemplo; ideal seria armazenar em Redis/DB

    # Evento de avaliação
    event = {
        "abuseScore": abuse_score,
        "spamhaus": in_spamhaus,
        "failedAttempts": failed_attempts
    }

    results = rule_engine.evaluate(event)
    score = scoring_service.calculate(results)
    decision = scoring_service.decide(score)

    # Logar evento
    log_entry = {
        "username": username,
        "ip": ip,
        "score": score,
        "decision": decision,
        "rules": results,
        "timestamp": time.time()
    }
    log_event(log_entry)

    # Decisões do motor
    if decision == "BLOCK":
        return render_template("index.html", message="❌ IP bloqueado pelo motor de regras")
    elif decision == "REVIEW":
        return render_template("index.html", message="⚠️ Login precisa de verificação adicional")

    # Se passou
    return render_template("index.html", message="✅ Login permitido (usuário normal)")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# =========================
# Rotas Admin
# =========================
@app.route("/admin")
def admin_panel():
    if not session.get("is_admin"):
        return redirect(url_for("index"))

    logs = load_logs(50)
    return render_template("admin.html", logs=logs)


@app.get("/logs")
def show_logs():
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    return jsonify(load_logs(100))


@app.get("/intel/<ip>")
def intel_lookup(ip):
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    info = {
        "geo": "não implementado aqui",
        "threat_intel": {
            "abuse_score": check_abuseipdb(ip),
            "spamhaus": ip_in_spamhaus(ip)
        }
    }
    return jsonify(info)


@app.post("/intel-refresh")
def intel_refresh():
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    refresh_spamhaus_if_needed(force=True)
    return jsonify({"ok": True, "refreshed_at": time.time()})


# =========================
# Start
# =========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
