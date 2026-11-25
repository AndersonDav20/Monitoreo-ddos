#!/bin/bash
# Verificacion rapida de que los 4 servicios principales estan arriba.
# Correr desde la VM Ubuntu, en la carpeta del repo:
#   bash scripts/verify-stack.sh
set -e

echo "== docker compose ps =="
docker compose ps

echo
echo "== Loki /ready =="
curl -s http://localhost:3100/ready || echo "Loki no responde"

echo
echo "== Grafana /api/health =="
curl -s http://localhost:3000/api/health || echo "Grafana no responde"

echo
echo "== eve.json (ultimas 5 lineas, dentro del contenedor suricata) =="
docker compose exec suricata tail -n 5 /var/log/suricata/eve.json || echo "Suricata aun no genero eve.json"

echo
echo "== interfaz labnet0 vista por Suricata =="
docker compose exec suricata ip link show labnet0 || echo "labnet0 no aparece (revisar driver_opts del docker-compose)"
