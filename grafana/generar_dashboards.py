"""
Genera los 4 dashboards de Grafana del laboratorio (carpeta "Deteccion de Ataques").

  1. Centro de deteccion de ataques       -> resumen general (Loki)
  2. Impacto en el servidor objetivo     -> metricas del servidor (Prometheus) + alertas
  3. Red del campus (Packet Tracer)       -> ACL entre VLANs y Port Security (Loki, job=packet-tracer)
  4. Explorador de alertas                -> filtros por fuente / categoria / origen (Loki)

Uso:  python grafana/generar_dashboards.py
Escribe los JSON en grafana/provisioning/dashboards/json/ (Grafana los recarga en ~30 s).
"""
import json
import os

OUT = os.path.join(os.path.dirname(__file__), "provisioning", "dashboards", "json")
LOKI = {"type": "loki", "uid": "loki"}
PROM = {"type": "prometheus", "uid": "prometheus"}
ALERTA = '{event_type="alert"}'

# Firmas de cada tipo de ataque (reglas LAB de Suricata y eventos de pt-agent)
TIPOS = [
    ("Escaneo de puertos", ".*Escaneo de puertos.*", "blue"),
    ("Denegacion de servicio", ".*denegacion de servicio.*", "yellow"),
    ("Acceso entre VLANs", ".*Acceso no autorizado entre VLANs.*", "green"),
    ("Dispositivo no autorizado", ".*Dispositivo no autorizado.*", "orange"),
]

ANOTACIONES = {"list": [{
    "name": "Inicio de ataque", "datasource": {"type": "grafana", "uid": "-- Grafana --"},
    "enable": True, "iconColor": "red", "type": "tags", "tags": ["ataque"],
    "matchAny": True, "limit": 100,
}]}

_id = 0


def pid():
    global _id
    _id += 1
    return _id


def grid(x, y, w, h):
    return {"x": x, "y": y, "w": w, "h": h}


def loki(expr, legend=None, instant=False, ref="A"):
    t = {"refId": ref, "expr": expr, "datasource": LOKI}
    if legend:
        t["legendFormat"] = legend
    if instant:
        t["queryType"] = "instant"
    return t


def prom(expr, legend=None, ref="A"):
    t = {"refId": ref, "expr": expr, "datasource": PROM}
    if legend:
        t["legendFormat"] = legend
    return t


def texto(gp, md):
    return {"id": pid(), "type": "text", "title": "", "gridPos": gp,
            "options": {"mode": "markdown", "content": md}}


def fila(titulo, y):
    return {"id": pid(), "type": "row", "title": titulo, "collapsed": False,
            "gridPos": grid(0, y, 24, 1), "panels": []}


def stat(titulo, gp, target, color="green", unidad="none", desc=""):
    return {
        "id": pid(), "type": "stat", "title": titulo, "description": desc, "gridPos": gp,
        "datasource": target["datasource"], "targets": [target],
        "fieldConfig": {"defaults": {
            "unit": unidad, "noValue": "0", "decimals": 0 if unidad == "none" else 1,
            "color": {"mode": "fixed", "fixedColor": color},
        }, "overrides": []},
        "options": {"reduceOptions": {"values": False, "calcs": ["lastNotNull"], "fields": ""},
                    "colorMode": "background", "graphMode": "none", "textMode": "value",
                    "justifyMode": "center"},
    }


def serie(titulo, gp, targets, unidad="none", barras=False, apilado=False, desc="", min0=True):
    custom = {"drawStyle": "bars" if barras else "line", "lineWidth": 2,
              "fillOpacity": 60 if barras else 15, "showPoints": "never",
              "stacking": {"mode": "normal" if apilado else "none"}}
    d = {"unit": unidad, "custom": custom}
    if min0:
        d["min"] = 0
    return {
        "id": pid(), "type": "timeseries", "title": titulo, "description": desc, "gridPos": gp,
        "datasource": targets[0]["datasource"] if len({t["datasource"]["uid"] for t in targets}) == 1
        else {"type": "datasource", "uid": "-- Mixed --"},
        "targets": targets,
        "fieldConfig": {"defaults": d, "overrides": []},
        "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
    }


COLORES_CATEGORIA = [
    ("Attempted Information Leak", "blue"),        # escaneo de puertos (classtype attempted-recon)
    ("Attempted Denial of Service", "yellow"),     # DoS
    ("Acceso no autorizado entre VLANs", "green"),
    ("Dispositivo no autorizado", "orange"),
]
OVERRIDES_CATEGORIA = [
    {"matcher": {"id": "byName", "options": n},
     "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]} for n, c in COLORES_CATEGORIA]


def torta(titulo, gp, target):
    return {
        "id": pid(), "type": "piechart", "title": titulo, "gridPos": gp,
        "datasource": target["datasource"], "targets": [target],
        "fieldConfig": {"defaults": {"noValue": "0"},
                        "overrides": OVERRIDES_CATEGORIA},
        "options": {"reduceOptions": {"values": True, "calcs": ["lastNotNull"], "fields": "/^Value/"},
                    "pieType": "donut", "displayLabels": ["value"],
                    "legend": {"displayMode": "table", "placement": "right", "showLegend": True,
                               "values": ["value", "percent"]}},
    }


def barras(titulo, gp, target, orientacion="horizontal"):
    return {
        "id": pid(), "type": "bargauge", "title": titulo, "gridPos": gp,
        "datasource": target["datasource"], "targets": [target],
        "fieldConfig": {"defaults": {"noValue": "0", "min": 0, "color": {"mode": "palette-classic"}},
                        "overrides": []},
        "options": {"reduceOptions": {"values": True, "calcs": ["lastNotNull"], "fields": "/^Value/"},
                    "orientation": orientacion, "displayMode": "gradient", "showUnfilled": True,
                    "namePlacement": "top", "sizing": "auto"},
    }


def tabla(titulo, gp, target, renombrar):
    return {
        "id": pid(), "type": "table", "title": titulo, "gridPos": gp,
        "datasource": target["datasource"], "targets": [target],
        "transformations": [
            {"id": "organize", "options": {"excludeByName": {"Time": True}, "renameByName": renombrar}},
            {"id": "sortBy", "options": {"sort": [{"field": list(renombrar.values())[-1], "desc": True}]}},
        ],
        "fieldConfig": {"defaults": {"custom": {"align": "left"}}, "overrides": []},
        "options": {"showHeader": True, "cellHeight": "sm"},
    }


def registro(titulo, gp, expr):
    return {
        "id": pid(), "type": "logs", "title": titulo, "gridPos": gp, "datasource": LOKI,
        "targets": [loki(expr)],
        "options": {"showTime": True, "showLabels": False, "wrapLogMessage": True,
                    "sortOrder": "Descending", "enableLogDetails": True, "dedupStrategy": "none"},
    }


def lista_anotaciones(titulo, gp):
    return {
        "id": pid(), "type": "annolist", "title": titulo, "gridPos": gp,
        "options": {"onlyFromThisDashboard": False, "onlyInTimeRange": True, "tags": ["ataque"],
                    "limit": 20, "showUser": False, "showTime": True, "showTags": True,
                    "navigateToPanel": False, "navigateBefore": "10m", "navigateAfter": "10m"},
    }


def dashboard(uid, titulo, paneles, desc, variables=None, tags=None):
    return {
        "uid": uid, "title": titulo, "description": desc, "tags": tags or ["ids", "laboratorio"],
        "schemaVersion": 39, "version": 1, "editable": True, "timezone": "browser",
        "time": {"from": "now-30m", "to": "now"}, "refresh": "10s",
        "annotations": ANOTACIONES, "templating": {"list": variables or []},
        "links": [{"title": "Otros dashboards", "type": "dashboards", "tags": ["ids"],
                   "asDropdown": True, "includeVars": False, "keepTime": True}],
        "panels": paneles,
    }


LINE = ('{event_type="alert"} | line_format "{{.job}} | sev {{.alert_severity}} | '
        '{{.alert_signature}} | {{.src_ip}} -> {{.dest_ip}}"')

# ------------------------------------------------------------------ 1. Centro de deteccion
def d1():
    p = [texto(grid(0, 0, 24, 2),
               "**Centro de deteccion de ataques**: alertas de **Suricata** (escaneo de puertos y DoS en el "
               "laboratorio Docker) y de **pt-agent** (ACL y Port Security en Cisco Packet Tracer), centralizadas en Loki. "
               "Las lineas rojas punteadas marcan el **inicio real** de cada ataque; la distancia hasta la barra es el "
               "**tiempo de deteccion**.")]
    p.append(stat("Alertas totales", grid(0, 2, 4, 4),
                  loki(f"sum(count_over_time({ALERTA}[$__range]))", "Total", True), "purple"))
    x = 4
    for nombre, rx, color in TIPOS:
        p.append(stat(nombre, grid(x, 2, 5, 4),
                      loki(f'sum(count_over_time({{event_type="alert", alert_signature=~"{rx}"}}[$__range]))',
                           nombre, True), color))
        x += 5
    tl = serie("Alertas en el tiempo por tipo de ataque", grid(0, 6, 16, 9),
               [loki(f'sum(count_over_time({{event_type="alert", alert_signature=~"{rx}"}}[$__interval]))',
                     n, ref=chr(65 + i)) for i, (n, rx, _) in enumerate(TIPOS)],
               barras=True, apilado=True)
    tl["fieldConfig"]["overrides"] = [
        {"matcher": {"id": "byName", "options": n},
         "properties": [{"id": "color", "value": {"mode": "fixed", "fixedColor": c}}]} for n, _, c in TIPOS]
    tl["interval"] = "15s"
    p.append(tl)
    p.append(lista_anotaciones("Ataques lanzados (inicio)", grid(16, 6, 8, 9)))
    p.append(torta("Alertas por categoria", grid(0, 15, 8, 8),
                   loki(f"sum by (alert_category) (count_over_time({ALERTA}[$__range]))",
                        "{{alert_category}}", True)))
    p.append(barras("Alertas por fuente", grid(8, 15, 6, 8),
                    loki(f"sum by (job) (count_over_time({ALERTA}[$__range]))", "{{job}}", True)))
    p.append(serie("Paquetes/s recibidos por el servidor objetivo (Prometheus)", grid(14, 15, 10, 8),
                   [prom('rate(node_network_receive_packets_total{device="eth0"}[10s])', "paquetes/s")],
                   unidad="pps", desc="Metrica del servidor victima: un DoS se ve como un pico aqui."))
    p.append(registro("Ultimas alertas (Suricata + Packet Tracer)", grid(0, 23, 24, 10), LINE))
    return dashboard("ids-deteccion-ataques", "1. Centro de deteccion de ataques", p,
                     "Resumen general de alertas de todas las fuentes")


# ------------------------------------------------------------------ 2. Impacto en el servidor
def d2():
    p = [texto(grid(0, 0, 24, 2),
               "**Impacto en el servidor objetivo** (`servicio-academico`, 172.28.0.10). Metricas recogidas por "
               "**Prometheus** desde un node-exporter que comparte la red del servidor: muestran *que le pasa* a la "
               "victima durante el ataque, mientras Loki muestra *que se detecto*.")]
    p.append(stat("Paquetes/s recibidos (ahora)", grid(0, 2, 6, 4),
                  prom('rate(node_network_receive_packets_total{device="eth0"}[10s])'), "blue", "suffix: paq/s"))
    p.append(stat("Pico de paquetes/s (rango)", grid(6, 2, 6, 4),
                  prom('max_over_time(rate(node_network_receive_packets_total{device="eth0"}[10s])[$__range:5s])'),
                  "red", "suffix: paq/s"))
    p.append(stat("CPU del entorno (ahora)", grid(12, 2, 6, 4),
                  prom('clamp_min(100 * (1 - avg(rate(node_cpu_seconds_total{mode="idle"}[10s]))), 0)'), "orange", "percent"))
    p.append(stat("Alertas en el rango", grid(18, 2, 6, 4),
                  loki(f"sum(count_over_time({ALERTA}[$__range]))", "Alertas", True), "purple"))
    p.append(serie("Trafico de red del servidor (paquetes/s)", grid(0, 6, 12, 9), [
        prom('rate(node_network_receive_packets_total{device="eth0"}[10s])', "recibidos", "A"),
        prom('rate(node_network_transmit_packets_total{device="eth0"}[10s])', "enviados", "B"),
    ], unidad="pps"))
    p.append(serie("Trafico de red del servidor (bytes/s)", grid(12, 6, 12, 9), [
        prom('rate(node_network_receive_bytes_total{device="eth0"}[10s])', "recibidos", "A"),
        prom('rate(node_network_transmit_bytes_total{device="eth0"}[10s])', "enviados", "B"),
    ], unidad="Bps"))
    p.append(serie("Uso de CPU del entorno (%)", grid(0, 15, 8, 8), [
        prom('clamp_min(100 * (1 - avg(rate(node_cpu_seconds_total{mode="idle"}[10s]))), 0)', "CPU %"),
    ], unidad="percent"))
    p.append(serie("Memoria usada del entorno (%)", grid(8, 15, 8, 8), [
        prom("100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)", "Memoria %"),
    ], unidad="percent"))
    p.append(serie("Respuesta TCP del servidor", grid(16, 15, 8, 8), [
        prom("rate(node_netstat_Tcp_InSegs[10s])", "segmentos TCP recibidos/s", "A"),
        prom("rate(node_netstat_Tcp_OutRsts[10s])", "RST enviados/s (puertos cerrados)", "B"),
    ], unidad="pps", desc="Durante un escaneo el servidor responde RST a cada puerto cerrado (eje derecho); "
                          "durante un SYN flood se disparan los segmentos recibidos (eje izquierdo)."))
    p[-1]["fieldConfig"]["overrides"] = [{
        "matcher": {"id": "byName", "options": "RST enviados/s (puertos cerrados)"},
        "properties": [{"id": "custom.axisPlacement", "value": "right"},
                       {"id": "color", "value": {"mode": "fixed", "fixedColor": "red"}}]}]
    p.append(serie("Alertas detectadas en el mismo periodo (Loki)", grid(0, 23, 24, 7), [
        loki(f"sum by (alert_category) (count_over_time({ALERTA}[$__interval]))", "{{alert_category}}"),
    ], barras=True, apilado=True))
    p[-1]["interval"] = "15s"
    return dashboard("ids-impacto-servidor", "2. Impacto en el servidor objetivo (Prometheus)", p,
                     "Metricas del servidor victima durante los ataques")


# ------------------------------------------------------------------ 3. Red del campus (Packet Tracer)
PT = '{job="packet-tracer", event_type="alert"}'


def d3():
    p = [texto(grid(0, 0, 24, 3),
               "**Red del campus en Cisco Packet Tracer**: sede de 4 pabellones (A Administracion, B Aulas, C Laboratorios, D Biblioteca) y un centro de datos, con Router-Core (router-on-a-stick, NAT y DHCP relay), Switch-Core y un switch "
               "de acceso por pabellon. VLAN **10 Academica**, **20 Administrativa**, **30 Invitados**, **40 Servidores**, "
               "**50 Laboratorios** y 99 Gestion (192.168.X.0/24). Las **ACL 110/120/150** bloquean Invitados, Academica y "
               "Laboratorios hacia las zonas no permitidas; **Port Security** protege los puertos de Laboratorios (SW-PabC) "
               "e Invitados (SW-PabD). `pt-agent` consulta los contadores cada 3 s y envia cada evento a Loki.")]
    p.append(stat("Accesos entre VLANs bloqueados", grid(0, 3, 8, 4),
                  loki(f'sum(count_over_time({{job="packet-tracer", alert_category="Acceso no autorizado entre VLANs"}}[$__range]))',
                       "Eventos", True), "green"))
    p.append(stat("Dispositivos no autorizados", grid(8, 3, 8, 4),
                  loki(f'sum(count_over_time({{job="packet-tracer", alert_category="Dispositivo no autorizado"}}[$__range]))',
                       "Eventos", True), "orange"))
    p.append(stat("Equipos con eventos", grid(16, 3, 8, 4),
                  loki(f"count(sum by (device) (count_over_time({PT}[$__range])))", "Equipos", True), "blue"))
    p.append(tabla("Intentos bloqueados por origen -> destino", grid(0, 7, 12, 8),
                   loki(f'sum by (src_ip, dest_ip) (count_over_time({{job="packet-tracer", '
                        f'alert_category="Acceso no autorizado entre VLANs"}}[$__range]))', None, True),
                   {"src_ip": "Red de origen", "dest_ip": "Red de destino", "Value #A": "Eventos de bloqueo"}))
    p.append(barras("Eventos por equipo de red", grid(12, 7, 12, 8),
                    loki(f"sum by (device) (count_over_time({PT}[$__range]))", "{{device}}", True)))
    tl = serie("Eventos de la red del campus en el tiempo", grid(0, 15, 24, 8), [
        loki(f"sum by (alert_category) (count_over_time({PT}[$__interval]))", "{{alert_category}}"),
    ], barras=True, apilado=True)
    tl["interval"] = "15s"
    p.append(tl)
    p.append(registro("Detalle de eventos (incluye MAC del intruso y ACL/linea que bloqueo)", grid(0, 23, 24, 10),
                      f'{PT} | json | line_format "{{{{.device}}}} | {{{{.alert_signature}}}} | {{{{.detalle}}}}"'))
    return dashboard("ids-red-campus", "3. Red del campus (Packet Tracer)", p,
                     "Seguridad de la topologia VLAN simulada en Packet Tracer")


# ------------------------------------------------------------------ 4. Explorador
def var(nombre, etiqueta, label):
    return {
        "name": nombre, "label": etiqueta, "type": "query", "datasource": LOKI,
        "query": {"label": label, "stream": ALERTA, "type": 1, "refId": "LokiVariableQueryEditor-VariableQuery"},
        "definition": f"label_values({ALERTA}, {label})",
        "refresh": 2, "includeAll": True, "multi": True, "allValue": ".+",
        "current": {"selected": True, "text": ["All"], "value": ["$__all"]}, "sort": 1,
    }


def d4():
    sel = '{event_type="alert", job=~"$fuente", alert_category=~"$categoria", src_ip=~"$origen"}'
    p = [texto(grid(0, 0, 24, 2),
               "**Explorador de alertas**: usa los selectores de arriba (fuente, categoria, origen) para filtrar. "
               "Equivale al dashboard \"Logs por contenedor\" del proyecto UNFV, pero sobre alertas de seguridad.")]
    p.append(stat("Alertas filtradas", grid(0, 2, 6, 4),
                  loki(f"sum(count_over_time({sel}[$__range]))", "Alertas", True), "purple"))
    p.append(stat("Firmas distintas", grid(6, 2, 6, 4),
                  loki(f"count(sum by (alert_signature) (count_over_time({sel}[$__range])))", "Firmas", True), "blue"))
    p.append(stat("Origenes distintos", grid(12, 2, 6, 4),
                  loki(f"count(sum by (src_ip) (count_over_time({sel}[$__range])))", "Origenes", True), "orange"))
    p.append(stat("Destinos distintos", grid(18, 2, 6, 4),
                  loki(f"count(sum by (dest_ip) (count_over_time({sel}[$__range])))", "Destinos", True), "green"))
    p.append(barras("Alertas por firma", grid(0, 6, 12, 9),
                    loki(f"sum by (alert_signature) (count_over_time({sel}[$__range]))", "{{alert_signature}}", True)))
    p.append(barras("Principales origenes", grid(12, 6, 12, 9),
                    loki(f"topk(10, sum by (src_ip) (count_over_time({sel}[$__range])))", "{{src_ip}}", True)))
    tl = serie("Alertas filtradas en el tiempo", grid(0, 15, 24, 7), [
        loki(f"sum by (alert_signature) (count_over_time({sel}[$__interval]))", "{{alert_signature}}"),
    ], barras=True, apilado=True)
    tl["interval"] = "15s"
    p.append(tl)
    p.append(registro("Registro filtrado", grid(0, 22, 24, 12),
                      sel + ' | line_format "{{.job}} | sev {{.alert_severity}} | {{.alert_category}} | '
                            '{{.alert_signature}} | {{.src_ip}} -> {{.dest_ip}}"'))
    variables = [var("fuente", "Fuente", "job"), var("categoria", "Categoria", "alert_category"),
                 var("origen", "Origen", "src_ip")]
    return dashboard("ids-explorador", "4. Explorador de alertas", p,
                     "Filtros por fuente, categoria y origen", variables)


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    viejo = os.path.join(OUT, "ids-dashboard.json")
    if os.path.exists(viejo):
        os.remove(viejo)
    for nombre, fn in [("01-centro-deteccion.json", d1), ("02-impacto-servidor.json", d2),
                       ("03-red-campus-packet-tracer.json", d3), ("04-explorador-alertas.json", d4)]:
        with open(os.path.join(OUT, nombre), "w", encoding="utf-8") as f:
            json.dump(fn(), f, ensure_ascii=False, indent=2)
        print("escrito", nombre)
