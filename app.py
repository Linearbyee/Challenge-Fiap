import os
import time
import json
import bcrypt
from collections import defaultdict
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, abort
from dotenv import load_dotenv
from rule_engine import RuleEngine
from scoring import ScoringService
from threat_intel import check_abuseipdb, ip_in_spamhaus

# Carregar variáveis do .env
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "dev_key")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY", "")
LOG_FILE = os.getenv("LOG_FILE", "cyberfortress_logs.ndjson")
HONEYPOT_LOG = "honeypot_logs.ndjson"
REGRAS_STATS_FILE = "regras_stats.json"

# Inicializar Flask
app = Flask(__name__)
app.secret_key = SECRET_KEY

# Mock de usuários com bcrypt (pode substituir por banco depois)
usuarios = {
    "admin": bcrypt.hashpw("123".encode("utf-8"), bcrypt.gensalt()),
    "user": bcrypt.hashpw("senha123".encode("utf-8"), bcrypt.gensalt())
}

# Serviços
rule_engine = RuleEngine()
scoring_service = ScoringService()

# --- Funções auxiliares ---
def log_event(event, file=LOG_FILE):
    """Salva evento em NDJSON"""
    with open(file, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

def update_rule_stats(resultados):
    """Atualiza estatísticas de regras"""
    try:
        with open(REGRAS_STATS_FILE, "r") as f:
            stats = json.load(f)
    except FileNotFoundError:
        stats = defaultdict(lambda: {"passou": 0, "falhou": 0})

    for regra, passou in resultados.items():
        if passou:
            stats[regra]["passou"] = stats.get(regra, {}).get("passou", 0) + 1
        else:
            stats[regra]["falhou"] = stats.get(regra, {}).get("falhou", 0) + 1

    with open(REGRAS_STATS_FILE, "w") as f:
        json.dump(stats, f, indent=2)

    return stats

# --- Rotas ---
@app.route("/")
def index():
    return render_template("index.html", message=None)

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    ip = request.remote_addr

    # Autenticação
    if username in usuarios and bcrypt.checkpw(password.encode("utf-8"), usuarios[username]):
        if username == "admin":
            session["is_admin"] = True
            session["username"] = username
            return redirect(url_for("admin_panel"))

    # Threat intel
    abuse_score = check_abuseipdb(ip)
    in_spamhaus = ip_in_spamhaus(ip)
    failed_attempts = 0  # mock

    event = {
        "ip_abuseipdb": abuse_score < 50,
        "ip_spamhaus": not in_spamhaus,
        "muitas_falhas": failed_attempts < 10
    }

    results = rule_engine.evaluate(event)
    score = scoring_service.calculate(results)
    decision = scoring_service.decide(score)

    # Atualizar estatísticas
    update_rule_stats(results)

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

    # Respostas
    if decision == "BLOCK":
        return render_template("index.html", message="❌ IP bloqueado pelo motor de regras")
    elif decision == "REVIEW":
        return render_template("index.html", message="⚠️ Login precisa de verificação adicional")
    return render_template("index.html", message="✅ Login permitido (usuário normal)")

# Painel admin
@app.route("/admin")
def admin_panel():
    if not session.get("is_admin"):
        return redirect(url_for("index"))

    logs = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            logs = [json.loads(line) for line in f.readlines()][-50:]
    except FileNotFoundError:
        pass

    stats = {}
    try:
        with open(REGRAS_STATS_FILE, "r") as f:
            stats = json.load(f)
    except FileNotFoundError:
        stats = {}

    return render_template("admin.html", logs=logs, stats=stats)

# Honeypot
@app.route("/admin_secret")
def honeypot():
    ip = request.remote_addr
    log_event({
        "event": "honeypot_triggered",
        "ip": ip,
        "timestamp": time.time()
    }, HONEYPOT_LOG)
    abort(403)

# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# --- Início ---
if __name__ == "__main__":
    app.run(debug=True)
