import os
import json
import datetime
import ipaddress
from pathlib import Path

from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bcrypt
import requests
from dotenv import load_dotenv

# === Configuração básica ===
BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")  # carrega .env se existir

SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-secret")
GEO_API_BASE = os.getenv("GEOLocation_API_BASE", "https://ipapi.co")
DEBUG = os.getenv("DEBUG", "true").lower() == "true"

app = Flask(__name__, template_folder=str(BASE / "templates"))
app.config["SECRET_KEY"] = SECRET_KEY

# rate limit global (10/min) e específico no /login (5/min via decorator)
limiter = Limiter(get_remote_address, app=app, default_limits=["10/minute"])

USERS_FILE = BASE / "users.json"
LOG_FILE = BASE / "login_logs.ndjson"


# ---------- utilidades ----------
def load_users():
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)


def bootstrap_password_hashes():
    """
    No primeiro run, gera hash bcrypt para usuários cujo password_hash é null.
    Senha DEMO: '123' (troque em produção).
    """
    users = load_users()
    changed = False
    for u in users:
        if not u.get("password_hash"):
            pw = "123".encode("utf-8")
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


def is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except Exception:
        return True


def get_client_ip() -> str:
    """
    Ordem de preferência:
    1) client_public_ip enviado pelo front (se válido e público)
    2) X-Forwarded-For (primeiro IP público)
    3) request.remote_addr (pode ser local)
    """
    data = request.get_json(silent=True) or {}

    # 1) IP público do front-end
    pub = (request.form.get("client_public_ip") or data.get("client_public_ip") or "").strip()
    if pub and not is_private_ip(pub):
        return pub

    # 2) X-Forwarded-For (se houver proxy)
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        for part in [p.strip() for p in xff.split(",")]:
            if part and not is_private_ip(part):
                return part

    # 3) Fallback
    return (request.remote_addr or "").split(",")[0].strip()


def geo_lookup(ip: str) -> dict:
    # em dev/local, IP privado não tem geo pública
    if is_private_ip(ip):
        # acadêmico: retorna vazio (para não “inventar” dados)
        return {
            "city": None, "region": None, "country_name": None,
            "latitude": None, "longitude": None
        }

    try:
        r = requests.get(f"{GEO_API_BASE}/{ip}/json", timeout=3)
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


def write_log(entry: dict) -> None:
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


# ---------- rotas ----------
@app.get("/")
def index():
    return render_template("login.html", message=None)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5/minute")
def login():
    if request.method == "GET":
        # Navegou direto para /login? Manda para a página de formulário.
        return redirect(url_for("index"))

    # --- POST (form ou JSON) ---
    data = request.get_json(silent=True) or {}

    username = request.form.get("username") or data.get("username")
    password = request.form.get("password") or data.get("password")

    client_ip = get_client_ip()
    ua = request.headers.get("User-Agent", "")
    geo = geo_lookup(client_ip)

    ok = verify_user(username or "", password or "")
    status = "SUCESSO" if ok else "FALHA"

    write_log({
        "username": username,
        "status": status,
        "ip": client_ip,
        "user_agent": ua,
        "geo": geo,
        "ts": datetime.datetime.utcnow().isoformat() + "Z"
    })

    # prefere JSON se o cliente pedir JSON
    wants_json = (request.mimetype == "application/json") or \
                 request.headers.get("Accept", "").startswith("application/json")
    if wants_json:
        return jsonify({"status": status, "geo": geo}), (200 if ok else 401)

    return render_template("login.html", message=f"Login {status.lower()}")


@app.get("/health")
def health():
    return jsonify({"ok": True, "time": datetime.datetime.utcnow().isoformat() + "Z"})


@app.get("/logs")
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


if __name__ == "__main__":
    bootstrap_password_hashes()
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=DEBUG)
