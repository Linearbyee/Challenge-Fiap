import os
import json
import time
import datetime
import ipaddress
from pathlib import Path
from functools import wraps

from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, session, abort
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import requests
from dotenv import load_dotenv

# =========================
# Configuração e constantes
# =========================

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")  # carrega .env se existir

SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret")
GEO_API_BASE = os.getenv("GEOLocation_API_BASE", "https://ipapi.co")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
DEBUG = os.getenv("DEBUG", "true").lower() == "true"

# Anti-abuso (configuráveis via .env)
ATTEMPT_WINDOW_MIN = int(os.getenv("ATTEMPT_WINDOW_MIN", "5"))     # janela deslizante (min)
ATTEMPT_MAX_FAILS  = int(os.getenv("ATTEMPT_MAX_FAILS", "10"))     # falhas antes do ban
ATTEMPT_BLOCK_MIN  = int(os.getenv("ATTEMPT_BLOCK_MIN", "60"))     # duração do ban (min)

app = Flask(__name__, template_folder=str(BASE / "templates"))
app.config["SECRET_KEY"] = SECRET_KEY

# rate limit global (10/min) e específico no /login (5/min via decorator)
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["10/minute"])

USERS_FILE = BASE / "users.json"
LOG_FILE   = BASE / "login_logs.ndjson"

# diretórios/cache para Threat Intel e Rate/Ban
INTEL_DIR = BASE / "threatintel"
RATE_DIR  = BASE / "ratelimit"
INTEL_DIR.mkdir(parents=True, exist_ok=True)
RATE_DIR.mkdir(parents=True, exist_ok=True)

SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
SPAMHAUS_EDROP_URL = "https://www.spamhaus.org/drop/edrop.txt"
SPAMHAUS_DROP_FILE  = INTEL_DIR / "drop.txt"
SPAMHAUS_EDROP_FILE = INTEL_DIR / "edrop.txt"

ABUSEIPDB_CACHE_FILE = INTEL_DIR / "abuseipdb_cache.json"
ABUSEIPDB_TTL_SEC    = 60 * 60  # 1 hora

# estado de rate/ban
IP_ATTEMPTS_FILE = RATE_DIR / "ip_attempts.json"
# {
#   "<ip>": {"fail_ts":[...], "block_until": epoch_secs}
# }

# memória (preenchida em runtime) para Spamhaus
_SPAMHAUS_NETWORKS = {"DROP": [], "EDROP": []}
_SPAMHAUS_LOADED_AT = 0.0


# =========================
# Helpers de auth/autz
# =========================
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = session.get("user")
        if not user or "admin" not in user.get("roles", []):
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return wrapper


# =========================
# Usuários
# =========================
def load_users():
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

def bootstrap_password_hashes():
    """
    Gera hash bcrypt para usuários com password_hash==null usando senha demo '123'.
    """
    users = load_users()
    changed = False
    for u in users:
        if not u.get("password_hash"):
            pw = "123".encode("utf-8")  # DEMO — troque em produção
            u["password_hash"] = bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")
            changed = True
    if changed:
        save_users(users)

def verify_user(username: str, password: str) -> bool:
    users = load_users()
    for u in users:
        if u.get("username") == username and u.get("password_hash"):
            try:
                return bcrypt.checkpw(password.encode("utf-8"), u["password_hash"].encode("utf-8"))
            except Exception:
                return False
    return False

def get_user_record(username: str):
    for u in load_users():
        if u.get("username") == username:
            return u
    return None


# =========================
# IP & Geolocalização
# =========================
def is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except Exception:
        return True

def get_client_ip() -> str:
    """
    Preferência:
    1) client_public_ip (form/JSON)
    2) X-Forwarded-For (primeiro IP público)
    3) remote_addr
    """
    data = request.get_json(silent=True) or {}
    pub = (request.form.get("client_public_ip") or data.get("client_public_ip") or "").strip()
    if pub and not is_private_ip(pub):
        return pub

    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        for part in [p.strip() for p in xff.split(",")]:
            if part and not is_private_ip(part):
                return part

    return (request.remote_addr or "").split(",")[0].strip()

def geo_lookup(ip: str) -> dict:
    if is_private_ip(ip):
        return {"city": None, "region": None, "country_name": None, "latitude": None, "longitude": None}
    try:
        r = requests.get(f"{GEO_API_BASE}/{ip}/json", timeout=4)
        if r.ok:
            d = r.json()
            return {
                "city": d.get("city"),
                "region": d.get("region"),
                "country_name": d.get("country_name"),
                "latitude": d.get("latitude"),
                "longitude": d.get("longitude"),
            }
    except Exception:
        pass
    return {"city": None, "region": None, "country_name": None, "latitude": None, "longitude": None}


# =========================
# Spamhaus (DROP/EDROP)
# =========================
def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    r = requests.get(url, timeout=8)
    r.raise_for_status()
    dest.write_bytes(r.content)

def _parse_spamhaus_file(path: Path):
    nets = []
    if not path.exists():
        return nets
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(";") or line.startswith("#"):
                continue
            # formato: 1.2.3.0/24 ; motivo
            cidr = line.split(";", 1)[0].strip()
            try:
                nets.append(ipaddress.ip_network(cidr, strict=False))
            except Exception:
                continue
    return nets

def refresh_spamhaus_if_needed(force: bool = False):
    global _SPAMHAUS_LOADED_AT, _SPAMHAUS_NETWORKS
    now = time.time()
    # atualiza a cada 24h ou sob demanda
    if force or (now - _SPAMHAUS_LOADED_AT) > 24 * 3600 or not _SPAMHAUS_NETWORKS["DROP"]:
        try:
            _download(SPAMHAUS_DROP_URL, SPAMHAUS_DROP_FILE)
            _download(SPAMHAUS_EDROP_URL, SPAMHAUS_EDROP_FILE)
        except Exception:
            # se falhar download, usa o que tiver no disco (se existir)
            pass
        _SPAMHAUS_NETWORKS["DROP"]  = _parse_spamhaus_file(SPAMHAUS_DROP_FILE)
        _SPAMHAUS_NETWORKS["EDROP"] = _parse_spamhaus_file(SPAMHAUS_EDROP_FILE)
        _SPAMHAUS_LOADED_AT = now

def check_spamhaus(ip: str) -> dict:
    """
    Retorna {"listed": True/False, "list": "DROP|EDROP", "cidr": "..."} se pertencer.
    """
    refresh_spamhaus_if_needed()
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return {"listed": False}
    for lst in ("DROP", "EDROP"):
        for net in _SPAMHAUS_NETWORKS[lst]:
            if ip_obj in net:
                return {"listed": True, "list": lst, "cidr": str(net)}
    return {"listed": False}


# =========================
# AbuseIPDB (com cache disco)
# =========================
def _load_abuseipdb_cache() -> dict:
    if ABUSEIPDB_CACHE_FILE.exists():
        try:
            return json.loads(ABUSEIPDB_CACHE_FILE.read_text("utf-8"))
        except Exception:
            return {}
    return {}

def _save_abuseipdb_cache(cache: dict) -> None:
    ABUSEIPDB_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    ABUSEIPDB_CACHE_FILE.write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")

def check_abuseipdb(ip: str) -> dict:
    """
    Retorna dados principais do AbuseIPDB. Usa cache disco (TTL 1h).
    """
    if not ABUSEIPDB_API_KEY or is_private_ip(ip):
        return {}

    cache = _load_abuseipdb_cache()
    rec = cache.get(ip)
    now = time.time()
    if rec and (now - rec.get("ts", 0)) < ABUSEIPDB_TTL_SEC:
        return rec.get("data", {})

    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=6,
        )
        if r.ok:
            data = r.json().get("data", {})
            filtered = {
                "abuseConfidenceScore": data.get("abuseConfidenceScore"),
                "totalReports": data.get("totalReports"),
                "lastReportedAt": data.get("lastReportedAt"),
                "isPublic": data.get("isPublic"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "usageType": data.get("usageType"),
                "countryCode": data.get("countryCode"),
            }
            cache[ip] = {"ts": now, "data": filtered}
            _save_abuseipdb_cache(cache)
            return filtered
    except Exception:
        pass

    return {}

def enrich_threat_intel(ip: str) -> dict:
    """
    Combina Spamhaus + AbuseIPDB. Só faz sentido para IP público.
    """
    if is_private_ip(ip):
        return {"private": True}
    spamhaus = check_spamhaus(ip)
    abuse    = check_abuseipdb(ip)
    return {"private": False, "spamhaus": spamhaus, "abuseipdb": abuse}


# =========================
# Rate limiting por IP (ban por 1h após N falhas)
# =========================
def _load_ip_state() -> dict:
    if IP_ATTEMPTS_FILE.exists():
        try:
            return json.loads(IP_ATTEMPTS_FILE.read_text("utf-8"))
        except Exception:
            return {}
    return {}

def _save_ip_state(state: dict) -> None:
    IP_ATTEMPTS_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

def is_ip_blocked(ip: str) -> bool:
    state = _load_ip_state()
    entry = state.get(ip, {})
    block_until = entry.get("block_until", 0)
    return time.time() < block_until

def register_fail_and_maybe_block(ip: str) -> dict:
    """
    Registra falha, pruneia por janela e, se ultrapassar ATTEMPT_MAX_FAILS, aplica ban.
    """
    now = time.time()
    window_sec = ATTEMPT_WINDOW_MIN * 60
    block_sec  = ATTEMPT_BLOCK_MIN * 60

    state = _load_ip_state()
    entry = state.get(ip, {"fail_ts": [], "block_until": 0})

    # remove falhas fora da janela
    entry["fail_ts"] = [ts for ts in entry.get("fail_ts", []) if now - ts <= window_sec]
    # adiciona falha atual
    entry["fail_ts"].append(now)

    blocked = False
    if len(entry["fail_ts"]) > ATTEMPT_MAX_FAILS:
        entry["block_until"] = now + block_sec
        blocked = True

    state[ip] = entry
    _save_ip_state(state)

    return {"blocked": blocked, "fails_in_window": len(entry["fail_ts"]), "block_until": entry.get("block_until", 0)}

def clear_fail_history_on_success(ip: str) -> None:
    """Limpa histórico de falhas no sucesso (opcional)."""
    state = _load_ip_state()
    entry = state.get(ip)
    if entry:
        entry["fail_ts"] = []
        state[ip] = entry
        _save_ip_state(state)


# =========================
# Helpers adicionais (admin)
# =========================
def _read_raw_ip_state() -> dict:
    if IP_ATTEMPTS_FILE.exists():
        try:
            return json.loads(IP_ATTEMPTS_FILE.read_text("utf-8"))
        except Exception:
            return {}
    return {}

def _write_raw_ip_state(state: dict) -> None:
    IP_ATTEMPTS_FILE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")

def _ratelimit_snapshot():
    now = time.time()
    window_sec = ATTEMPT_WINDOW_MIN * 60
    state = _read_raw_ip_state()
    out = {}
    for ip, entry in state.items():
        fail_ts = [ts for ts in entry.get("fail_ts", []) if now - ts <= window_sec]
        block_until = entry.get("block_until", 0)
        out[ip] = {
            "fails_in_window": len(fail_ts),
            "block_until": block_until,
            "blocked": now < block_until
        }
    return out

def _read_recent_logs(limit=50):
    items = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                items.append(json.loads(line))
    except FileNotFoundError:
        pass
    return items[-limit:][::-1]  # últimos primeiro


# =========================
# Logging
# =========================
def write_log(entry: dict) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# =========================
# Rotas
# =========================
@app.get("/")
def index():
    return render_template("login.html", message=None)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5/minute")
def login():
    if request.method == "GET":
        return redirect(url_for("index"))

    data = request.get_json(silent=True) or {}
    username = request.form.get("username") or data.get("username")
    password = request.form.get("password") or data.get("password")

    client_ip = get_client_ip()
    ua = request.headers.get("User-Agent", "")
    geo = geo_lookup(client_ip)

    # 🔒 checagem de ban antes de qualquer coisa
    if is_ip_blocked(client_ip):
        intel = enrich_threat_intel(client_ip)  # ainda logamos contexto
        status = "BLOQUEADO"
        ok = False
        write_log({
            "username": username,
            "status": status,
            "ip": client_ip,
            "user_agent": ua,
            "geo": geo,
            "threat_intel": intel,
            "ts": datetime.datetime.utcnow().isoformat() + "Z",
            "reason": "ip_banned_window"
        })
        # 429 Too Many Requests é semântico para ban/limite
        wants_json = (request.mimetype == "application/json") or request.headers.get("Accept", "").startswith("application/json")
        body = {"status": status, "reason": "ip_banned_window"}
        return (jsonify(body), 429) if wants_json else (render_template("login.html", message="Login bloqueado por segurança"), 429)

    # segue o fluxo normal
    intel = enrich_threat_intel(client_ip)

    ok = verify_user(username or "", password or "")
    status = "SUCESSO" if ok else "FALHA"

    # 🔴 Bloqueio por inteligência (AbuseIPDB / Spamhaus)
    abuse = intel.get("abuseipdb") or {}
    score = abuse.get("abuseConfidenceScore") or 0
    if score >= 50:
        status = "FALHA"
        ok = False

    spamhaus = intel.get("spamhaus") or {}
    if spamhaus.get("listed"):
        status = "FALHA"
        ok = False
    # 🔴 fim do bloqueio

    # 📊 registra tentativa falha e aplica ban se exceder a janela
    ban_info = None
    if not ok:
        ban_info = register_fail_and_maybe_block(client_ip)

    # ✅ sucesso limpa histórico (opcional) e cria sessão
    if ok:
        clear_fail_history_on_success(client_ip)
        u = get_user_record(username)
        if u:
            session["user"] = {"username": u["username"], "roles": u.get("roles", [])}

    log_entry = {
        "username": username,
        "status": status,
        "ip": client_ip,
        "user_agent": ua,
        "geo": geo,
        "threat_intel": intel,
        "ts": datetime.datetime.utcnow().isoformat() + "Z"
    }
    if ban_info:
        log_entry["ban"] = ban_info

    write_log(log_entry)

    wants_json = (request.mimetype == "application/json") or request.headers.get("Accept", "").startswith("application/json")
    if wants_json:
        body = {"status": status, "geo": geo, "threat_intel": intel}
        if ban_info:
            body["ban"] = ban_info
        return jsonify(body), (200 if ok else (429 if ban_info and ban_info.get("blocked") else 401))

    return render_template("login.html", message=f"Login {status.lower()}")


# ======== Logout (POST e GET) ========
@app.post("/logout")
def logout_post():
    """Logout seguro via POST: limpa a sessão e volta ao login."""
    session.clear()
    return redirect(url_for("index"))

@app.get("/logout")
def logout_get():
    """Logout também por GET (atalho)."""
    session.clear()
    return redirect(url_for("index"))


# ======== Auxiliares ========
@app.get("/me")
def me():
    return jsonify(session.get("user") or {})

@app.get("/health")
def health():
    return jsonify({"ok": True, "time": datetime.datetime.utcnow().isoformat() + "Z"})


# ======== Logs (admin) ========
@app.get("/logs")
@admin_required
def show_logs():
    """Mostra até 100 últimas linhas do NDJSON (útil pro pitch)."""
    items = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i >= 100:
                    break
                items.append(json.loads(line))
    except FileNotFoundError:
        pass
    return jsonify(items)


# ======== Threat Intel (admin) ========
@app.get("/intel/<ip>")
@admin_required
def intel_lookup(ip):
    """Consulta manual de inteligência para um IP específico."""
    info = {"geo": geo_lookup(ip), "threat_intel": enrich_threat_intel(ip)}
    return jsonify(info)

@app.post("/intel-refresh")
@admin_required
def intel_refresh():
    """Força update das listas Spamhaus (útil em demo)."""
    refresh_spamhaus_if_needed(force=True)
    return jsonify({"ok": True, "refreshed_at": time.time()})


# ======== Rate-limit Admin ========
@app.get("/ratelimit/state")
@admin_required
def ratelimit_state():
    """
    Retorna o estado atual de tentativas/bloqueios por IP.
    """
    now = time.time()
    window_sec = ATTEMPT_WINDOW_MIN * 60

    state = _read_raw_ip_state()
    out = {}
    for ip, entry in state.items():
        fail_ts = [ts for ts in entry.get("fail_ts", []) if now - ts <= window_sec]
        block_until = entry.get("block_until", 0)
        out[ip] = {
            "fail_ts": fail_ts,
            "fails_in_window": len(fail_ts),
            "block_until": block_until,
            "blocked": now < block_until
        }
    return jsonify({
        "window_min": ATTEMPT_WINDOW_MIN,
        "max_fails": ATTEMPT_MAX_FAILS,
        "block_min": ATTEMPT_BLOCK_MIN,
        "ips": out
    })

@app.post("/ratelimit/unblock")
@admin_required
def ratelimit_unblock():
    """
    Body JSON: { "ip": "x.x.x.x" }
    """
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"ok": False, "error": "ip_required"}), 400

    state = _read_raw_ip_state()
    entry = state.get(ip)
    if not entry:
        return jsonify({"ok": False, "error": "ip_not_found"}), 404

    entry["block_until"] = 0
    entry["fail_ts"] = []  # limpa histórico
    state[ip] = entry
    _write_raw_ip_state(state)
    return jsonify({"ok": True, "ip": ip})

@app.post("/ratelimit/clear")
@admin_required
def ratelimit_clear():
    """
    Limpa TODO o estado de tentativas/bloqueios.
    """
    _write_raw_ip_state({})
    return jsonify({"ok": True})


# ======== Painel Admin (HTML) ========
@app.get("/admin")
@admin_required
def admin_dashboard():
    # snapshot para renderização server-side
    rl = _ratelimit_snapshot()
    logs = _read_recent_logs(limit=50)

    # info extra p/ cabeçalho
    spamhaus_age = max(0, int(time.time() - _SPAMHAUS_LOADED_AT))
    return render_template(
        "admin.html",
        cfg={
            "window_min": ATTEMPT_WINDOW_MIN,
            "max_fails": ATTEMPT_MAX_FAILS,
            "block_min": ATTEMPT_BLOCK_MIN,
        },
        spamhaus={"loaded_ago_sec": spamhaus_age},
        rl=rl,
        logs=logs
    )


# =========================
# Bootstrap
# =========================
if __name__ == "__main__":
    bootstrap_password_hashes()
    refresh_spamhaus_if_needed(force=True)
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=DEBUG)
