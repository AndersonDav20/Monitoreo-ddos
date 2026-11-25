# Monitoreo de ataques DoS, escaneos y accesos no autorizados

Código del prototipo del proyecto de investigación **"Influencia de un stack de observabilidad en la
detección automática de ataques en la red inteligente de un campus universitario simulada, Lima 2026"**
(Equipo 1, Seguridad en Redes y Sistemas de Información, UNFV, 2026-2).

El stack detecta cuatro tipos de ataque y los muestra en Grafana en tiempo real:

| Ataque | Dónde ocurre | Quién lo detecta |
|---|---|---|
| Escaneo de puertos (nmap) | Laboratorio Docker | Suricata |
| Denegación de servicio, SYN flood (hping3) | Laboratorio Docker | Suricata |
| Acceso no autorizado entre VLANs | Cisco Packet Tracer (ACL del router) | pt-agent |
| Dispositivo no autorizado | Cisco Packet Tracer (Port Security del switch) | pt-agent |

## Arquitectura

```
 Laboratorio Docker                                 Cisco Packet Tracer (campus de 4 pabellones)
 atacante (172.28.0.20) ──┐                         Router-Core (ACL 110/120/150)
                          ├─ red lab-net (labnet0)  SW-PabC / SW-PabD (Port Security)
 servicio-academico (.10)─┘        │                         │
                                   ▼                         ▼ puente MCP (API de PT)
                          Suricata (IDS, eve.json)     pt-agent (sondeo cada 3 s)
                                   │                         │
                                   ▼                         │
                               Promtail ──────► Loki ◄───────┘
                                                 │
                    exporter-objetivo ─► Prometheus
                                                 ▼
                                              Grafana (4 tableros + alertas)
```

- **Suricata** escucha la interfaz `labnet0` (bridge de la red `lab-net`, con nombre fijo) en
  `network_mode: host`, así ve el tráfico real entre el atacante y el servidor objetivo.
  Usa el ruleset de Emerging Threats más tres reglas propias de umbral (`config/suricata/update-rules.sh`).
- **Promtail** lee `eve.json`, se queda con los eventos `alert` y los envía a **Loki**.
- **pt-agent** consulta `show access-lists` y `show port-security` en Packet Tracer y, cuando un
  contador sube, envía la alerta a Loki con las mismas etiquetas que Suricata (`job="packet-tracer"`).
- **Prometheus** guarda las métricas de red del servidor víctima (node-exporter que comparte su pila de red).
- **Grafana** muestra todo en un solo lugar. Los scripts de ataque marcan su inicio con una
  anotación, así el tiempo de detección es `primera alerta − inicio del ataque`.

## Estructura del repositorio

```
├── docker-compose.yml          # todos los servicios del laboratorio
├── .env.example                # usuario y contraseña de Grafana
├── docker/
│   ├── atacante/               # imagen Kali con nmap, hping3 y curl
│   └── servicio-academico/     # servidor objetivo (nginx)
├── config/
│   ├── suricata/               # suricata.yaml + reglas propias (update-rules.sh)
│   ├── promtail/               # lectura de eve.json y envío a Loki
│   ├── loki/
│   └── prometheus/
├── grafana/
│   ├── generar_dashboards.py   # genera los 4 tableros (no editar los JSON a mano)
│   └── provisioning/           # datasources y tableros que Grafana carga al iniciar
├── pt-agent/                   # recolector de eventos de Packet Tracer hacia Loki
│   ├── mcp-client.ts           # cliente HTTP del puente MCP de Packet Tracer
│   ├── pt-agent.ts             # agente: ACL y Port Security -> Loki
│   └── pt-ataque.ts            # lanza los ataques dentro de Packet Tracer
├── scripts/
│   ├── attack/portscan.sh      # escaneo de puertos (nmap)
│   ├── attack/dos.sh           # SYN flood (hping3)
│   └── verify-stack.sh         # comprobación rápida del stack
└── medicion/
    ├── medir.py                # medición formal: 10 repeticiones x 4 ataques x 2 condiciones
    └── figuras.py              # gráficos de resultados
```

## Tableros de Grafana

| Tablero | Qué muestra |
|---|---|
| 1. Centro de detección de ataques | Alertas por tipo, línea de tiempo con el inicio de cada ataque, alertas por fuente y últimas alertas |
| 2. Impacto en el servidor objetivo | Paquetes, bytes, CPU, memoria y segmentos TCP del servidor víctima (Prometheus) |
| 3. Red del campus (Packet Tracer) | Accesos entre VLANs bloqueados (origen → destino) e intrusos por Port Security con su MAC |
| 4. Explorador de alertas | Filtros por fuente, categoría y origen; alertas por firma |

## Requisitos

- Docker Desktop (WSL2) o Docker Engine con el plugin Compose. Probado en Docker Desktop sobre Windows 11.
- Internet la primera vez, para que `suricata-update` descargue las reglas de Emerging Threats.
- Para la parte de Packet Tracer: Cisco Packet Tracer 9 con la topología del campus abierta,
  el puente MCP [`packet-tracer-mcp`](https://github.com/jcorderop02/packet-tracer-mcp) (proyecto
  externo, licencia MIT, no incluido aquí) corriendo en el puerto 39011, y [Bun](https://bun.sh).
- Para la medición: Python 3 con `openpyxl` (y `matplotlib` y `numpy` para `figuras.py`).

## Cómo ejecutarlo

```bash
docker compose up -d --build
bash scripts/verify-stack.sh
```

Grafana queda en `http://localhost:3000` (usuario `admin`, contraseña `admin123`; para cambiarlos,
copiar `.env.example` como `.env`). Los tableros están en la carpeta "Deteccion de Ataques".
Loki en `http://localhost:3100` y Prometheus en `http://localhost:9090`.

### Ataques en el laboratorio Docker

```bash
docker compose exec atacante bash /attack/portscan.sh     # escaneo de puertos
docker compose exec atacante bash /attack/dos.sh          # SYN flood de 15 s
docker compose exec atacante bash /attack/dos.sh 30       # SYN flood de 30 s
```

En Git Bash (Windows) anteponer `MSYS_NO_PATHCONV=1` a estos comandos.

### Ataques en Packet Tracer

```bash
cd pt-agent
bun run pt-agent.ts              # deja el agente corriendo
bun run pt-ataque.ts vlan        # PC-Invitados1 intenta llegar a la VLAN Académica
bun run pt-ataque.ts intruso     # conecta una laptop no autorizada en Fa0/11 de SW-PabD
bun run pt-ataque.ts restaurar   # retira al intruso y reactiva el puerto
```

Variables opcionales de `pt-agent`: `PT_MCP_URL` (por defecto `http://127.0.0.1:39011/mcp`),
`LOKI_URL` (`http://127.0.0.1:3100`), `PT_ROUTER` (`Router-Core`), `PT_SWITCHES` (`SW-PabC,SW-PabD`),
`PT_ACLS` (`110,120,150`) y `POLL_MS` (`3000`).

La consola de Packet Tracer 9 a veces se reinicia y devuelve una salida vacía; el agente descarta
esas lecturas para no generar alertas duplicadas y espera al siguiente sondeo.

### Medición formal

```bash
python medicion/medir.py --reps 1 --nombre prueba    # prueba piloto
python medicion/medir.py --reps 10                   # medición completa (~45 min)
python medicion/figuras.py resultados/medicion-formal-2026-11-13
```

`medir.py` ejecuta los 4 ataques en la condición **sin stack** (Suricata, Promtail y pt-agent
apagados) y luego **con stack**, clasifica las alertas de Loki (verdadero positivo, secundaria,
falso positivo, falso negativo) y guarda `ataques.csv`, `alertas.csv` y `resultados.xlsx` en
`medicion/resultados/<nombre>/`. Los datos de la medición del informe no están en este repositorio:
se entregan aparte junto con las evidencias.

Resultados de la sesión del 13/11/2026 (80 ataques): sin stack 0 de 40 detectados; con stack
40 de 40, sin falsos positivos. Tiempo medio de detección: escaneo 0,387 s, DoS 0,190 s,
acceso entre VLANs 4,728 s y dispositivo no autorizado 3,540 s.

## Detener

```bash
docker compose down        # agregar -v para borrar también los datos de Loki, Grafana y Suricata
```
