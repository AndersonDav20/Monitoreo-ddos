#!/bin/bash
# Escaneo de puertos (nmap) contra el servicio academico del laboratorio.
# Se corre DENTRO del contenedor "atacante":
#   docker compose exec atacante bash /attack/portscan.sh
set -e

OBJETIVO_IP="${OBJETIVO_IP:-172.28.0.10}"
GRAFANA_URL="${GRAFANA_URL:-http://grafana:3000}"
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASSWORD="${GRAFANA_PASSWORD:-admin123}"

if ! command -v nmap >/dev/null 2>&1; then
  echo "[portscan] instalando nmap..."
  apt-get update -qq && apt-get install -y -qq nmap curl >/dev/null
fi

INICIO="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
echo "[portscan] inicio del ataque: $INICIO"

# Marca el inicio del ataque como anotacion en Grafana (panel "Alertas en el
# tiempo"), asi queda visible junto a la alerta real que genere Suricata.
curl -s -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" -X POST \
  -H "Content-Type: application/json" \
  -d "{\"text\":\"Inicio escaneo de puertos (nmap) contra ${OBJETIVO_IP}\",\"tags\":[\"ataque\",\"portscan\"]}" \
  "${GRAFANA_URL}/api/annotations" >/dev/null || echo "[portscan] aviso: no se pudo anotar en Grafana"

echo "[portscan] lanzando nmap contra ${OBJETIVO_IP}..."
nmap -sS -p 1-1000 -T4 "${OBJETIVO_IP}"

echo "[portscan] ataque finalizado. Revisa el dashboard de Grafana (http://localhost:3000)."
