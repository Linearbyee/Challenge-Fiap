# seed_users.py
import bcrypt
import json

USERS_FILE = "users.json"

# Usuários iniciais (senha em texto só para geração do hash)
seed_users = {
    "admin": "123",
    "alice": "123",
    "pedro": "1234"
}

users = {}
for u, p in seed_users.items():
    hashed = bcrypt.hashpw(p.encode(), bcrypt.gensalt()).decode()
    users[u] = {"password": hashed, "roles": ["admin"] if u == "admin" else ["user"]}

# Salvar no users.json
with open(USERS_FILE, "w", encoding="utf-8") as f:
    json.dump(users, f, indent=2)

print("Arquivo users.json gerado com sucesso!")
