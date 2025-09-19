import os
import time
import json
import requests
from datetime import datetime, timedelta
from flask import Flask, request, session, redirect, url_for, render_template, jsonify
from dotenv import load_dotenv

from rule_engine import RuleEngine, ScoringService

# load .env
load_dotenv()

# =========================
# Config
# =========================
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-please-change")
LOG_FILE = os.getenv("LOG_FILE", "cyberfortress_logs.ndjson")

ABUSE_API_KEY = os.getenv("ABUSE_API_KEY", "")
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"

SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"

# rule engine
rule_engine = RuleEngine("rules.json")
scoring_service = ScoringService()

# in-memory state (simple; for demo)
spamhaus_list = set()
spamhaus_last_update = 0

failed_state = {}   # ip -> {"count": int, "first_ts": epoch}
BAN_STATE = {}      # ip -> expire_epoch
ABUSE_CACHE = {}    # ip -> (score, expire_ts)

# configuration (tuneable)
FAILED_WINDOW_SECONDS = 15 * 60   # 15 minutes window
FAILED_THRESHOLD = 10             # fails to ban
BAN_SECONDS = 60 * 60             # ban for 1 hour
ABUSE_CACHE_TTL = 60 * 60         # cache abuse scores 1 hour


# =========================
# Helpers
# =========================
def now_ts():
    return int(time.time())

def is_banned(ip: str) -> bool:
    exp = BAN_STATE.get(ip)
    if not exp:
        return False
    if now_ts() >= exp:
        BAN_STATE.pop(ip, None)
        return False
    return True

def ban_ip(ip: str, seconds: int = BAN_SECONDS):
    BAN_STATE[ip] = now_ts() + seconds
    app.logger.info(f"Banned IP {ip} until {datetime.fromtimestamp(BAN_STATE[ip]).isoformat()}")

def incr_failed(ip: str) -> int:
    rec = failed_state.get(ip)
    ts = now_ts()
    if not rec:
        failed_state[ip] = {"count": 1, "first_ts": ts}
        return 1
    # if outside window, reset
    if ts - rec["first_ts"] > FAILED_WINDOW_SECONDS:
        failed_state[ip] = {"count": 1, "first_ts": ts}
        return 1
    rec["count"] += 1
    return rec["count"]

def reset_failed(ip: str):
    failed_state.pop(ip, None)

def refresh_spamhaus_if_needed(force=False):
    global spamhaus_list, spamhaus_last_update
    try:
        if force or (time.time() - spamhaus_last_update > 3600):
            r1 = requests.get(SPAMHAUS_DROP_URL, timeout=10)
            r2 = requests.get(SPAMHAUS_EDROP_URL, timeout=10)
            lines = []
            if r1.status_code == 200:
                lines += r1.text.splitlines()
            if r2.status_code == 200:
                lines += r2.text.splitlines()
            spamhaus_list = {line.split(";")[0].strip() for line in lines if line and not line.startswith(";")}
            spamhaus_last_update = time.time()
            app.logger.info(f"Spamhaus refreshed: {len(spamhaus_list)} entries")
    except Exception as e:
        app.logger.warning("Could not refresh Spamhaus: %s", e)

def ip_in_spamhaus(ip: str) -> bool:
    try:
        refresh_spamhaus_if_needed()
        return ip in spamhaus_list
    except Exception:
        return False

def check_abuseipdb_cached(ip: str) -> int:
    # in-memory cache
    rec = ABUSE_CACHE.get(ip)
    if rec and rec[1] > now_ts():
        return rec[0]
    # query
    try:
        headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"} if ABUSE_API_KEY else {}
        resp = requests.get(ABUSE_URL, params={"ipAddress": ip, "maxAgeInDays": 90}, headers=headers, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            score = int(data.get("data", {}).get("abuseConfidenceScore", 0))
        else:
            score = 0
    except Exception as e:
        app.logger.warning("AbuseIPDB request failed: %s", e)
        score = 0
    ABUSE_CACHE[ip] = (score, now_ts() + ABUSE_CACHE_TTL)
    return score

def log_event(entry: dict):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        app.logger.error("Failed to write log: %s", e)

def load_logs(limit=50):
    logs = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()[-limit:]
            for line in lines:
                try:
                    logs.append(json.loads(line))
                except Exception:
                    continue
    except FileNotFoundError:
        pass
    return list(reversed(logs))  # show newest first


# =========================
# Routes
# =========================
@app.route("/")
def index():
    # show login page
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "") or ""
    password = request.form.get("password", "") or ""
    ip = request.remote_addr or request.environ.get("HTTP_X_FORWARDED_FOR", "unknown")

    # quick banned check
    if is_banned(ip):
        msg = "❌ IP temporariamente banido (rate/segurança)."
        # still log attempt
        entry = {"username": username, "ip": ip, "score": None, "decision": "BANNED", "rules": [], "timestamp": now_ts()}
        log_event(entry)
        return render_template("index.html", message=msg)

    # admin quick auth (demo)
    if username == "admin" and password == "123":
        session["is_admin"] = True
        session["username"] = username
        msg = "✅ Login admin realizado"
        # log admin login as ALLOW with score 0
        entry = {"username": username, "ip": ip, "score": 0, "decision": "ALLOW", "rules": [], "timestamp": now_ts()}
        log_event(entry)
        return redirect(url_for("admin_panel"))

    # check intel
    abuse_score = check_abuseipdb_cached(ip)
    in_spamhaus = ip_in_spamhaus(ip)

    # build event
    # failed_attempts read from in-memory state
    failed_info = failed_state.get(ip, {"count": 0})
    failed_attempts = failed_info.get("count", 0)

    event = {
        "abuseScore": abuse_score,
        "spamhaus": in_spamhaus,
        "failedAttempts": failed_attempts,
        "username": username,
        "ip": ip
    }

    # evaluate rules
    results = rule_engine.evaluate(event)
    score = scoring_service.calculate(results)
    decision = scoring_service.decide(score)

    # if login unsuccessful (simple demo: password isn't '123'), increment failed
    # In real: compare hashed password, etc.
    password_ok = (password == "123")  # demo only
    if not password_ok:
        cnt = incr_failed(ip)
        # if reached threshold, ban
        if cnt >= FAILED_THRESHOLD:
            ban_ip(ip, BAN_SECONDS)
            decision = "BLOCK"  # override
            # append as rule result for traceability (optional)
    else:
        # clear failed attempts on success
        reset_failed(ip)

    # Always log
    entry = {
        "username": username,
        "ip": ip,
        "score": score,
        "decision": decision,
        "rules": results,
        "timestamp": now_ts()
    }
    log_event(entry)

    # respond to user (render index with message; admin sees /admin)
    if decision == "BLOCK":
        return render_template("index.html", message="❌ IP bloqueado pelo motor de regras")
    if decision == "REVIEW":
        return render_template("index.html", message="⚠️ Login precisa de verificação adicional")
    if not password_ok:
        return render_template("index.html", message="❌ Usuário ou senha inválidos")

    return render_template("index.html", message="✅ Login permitido (usuário normal)")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# Admin routes
@app.route("/admin")
def admin_panel():
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    logs = load_logs(50)
    return render_template("admin.html", logs=logs)

@app.route("/admin/unblock", methods=["POST"])
def admin_unblock():
    if not session.get("is_admin"):
        return jsonify({"ok": False, "error": "forbidden"}), 403
    ip = request.form.get("ip")
    if not ip:
        return redirect(url_for("admin_panel"))
    # remove ban and failed counters
    BAN_STATE.pop(ip, None)
    failed_state.pop(ip, None)
    return redirect(url_for("admin_panel"))

@app.route("/intel/<ip>")
def intel_lookup(ip):
    if not session.get("is_admin"):
        return redirect(url_for("index"))
    info = {
        "abuse_score": check_abuseipdb_cached(ip),
        "spamhaus": ip_in_spamhaus(ip),
        "is_banned": is_banned(ip)
    }
    return jsonify(info)

# health
@app.route("/health")
def health():
    return jsonify({"ok": True, "time": now_ts()})

# =========================
# Run
# =========================
if __name__ == "__main__":
    app.run(debug=True)

