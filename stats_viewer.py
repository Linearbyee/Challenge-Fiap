import json
import os

REGRAS_STATS_FILE = "regras_stats.json"

def load_stats():
    if not os.path.exists(REGRAS_STATS_FILE):
        print("❌ Nenhum dado de estatísticas encontrado ainda.")
        return {}

    with open(REGRAS_STATS_FILE, "r") as f:
        return json.load(f)

def print_table(stats):
    print("\n📊 Estatísticas das Regras de Segurança\n")
    print(f"{'Regra':<20}{'Passou':<10}{'Falhou':<10}")
    print("-" * 40)
    for regra, valores in stats.items():
        passou = valores.get("passou", 0)
        falhou = valores.get("falhou", 0)
        print(f"{regra:<20}{passou:<10}{falhou:<10}")

def print_graph(stats):
    print("\n📈 Gráfico de Falhas por Regra\n")
    for regra, valores in stats.items():
        falhou = valores.get("falhou", 0)
        barra = "█" * min(falhou, 50)  # limita no terminal
        print(f"{regra:<20} {barra} ({falhou})")

if __name__ == "__main__":
    stats = load_stats()
    if stats:
        print_table(stats)
        print_graph(stats)
