"""
Medicion formal del estudio (diseno pre-experimental: sin stack vs con stack).

Para cada condicion y cada repeticion lanza los 4 ataques simulados:
  escaneo  -> nmap -sS -p 1-1000 contra servicio-academico   (laboratorio Docker)
  dos      -> hping3 -S --flood -p 80 durante 15 s            (laboratorio Docker)
  vlan     -> ping PC-Invitados1 -> 192.168.10.10             (Packet Tracer, ACL 110)
  intruso  -> Laptop-Intruso en el puerto Fa0/11 de Invitados (Packet Tracer, Port Security)

Condiciones:
  sin_stack: sensores apagados (Suricata, Promtail y pt-agent). Loki/Grafana/Prometheus
             siguen encendidos solo como instrumento de verificacion.
  con_stack: stack completo encendido.

Cada ataque queda marcado con una anotacion en Grafana (tags: ataque, tipo, condicion, repN)
cuya hora es el inicio real del ataque (T0). Al final se leen TODAS las alertas de Loki de
la sesion y se clasifican:
  - verdadero positivo: alerta del tipo correcto dentro de la ventana del ataque
    (la primera define el tiempo de deteccion = alerta - T0)
  - falso positivo: alerta de otro tipo dentro de una ventana, o alerta fuera de toda ventana
  - falso negativo: ataque sin ninguna alerta de su tipo en su ventana ("No detectado")

Uso:
  python medicion/medir.py --reps 10                 # medicion completa
  python medicion/medir.py --reps 1 --nombre prueba  # prueba rapida
Salida: medicion/resultados/<nombre>/ (ataques.csv, alertas.csv, resultados.xlsx, log.txt)
"""
import argparse
import base64
import csv
import json
import math
import os
import re
import statistics
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

STACK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PT_AGENT_DIR = os.path.join(STACK, "pt-agent")
BUN = os.path.expanduser(r"~\.bun\bin\bun.exe") if os.name == "nt" else "bun"
LOKI = "http://127.0.0.1:3100"
GRAFANA = "http://127.0.0.1:3000"
PROM = "http://127.0.0.1:9090"
AUTH = "Basic " + base64.b64encode(b"admin:admin123").decode()
OBJETIVO = "172.28.0.10"

# tipo -> (nombre legible, regex de firma, ventana de observacion en s)
TIPOS = {
    "escaneo": ("Escaneo de puertos", r"Escaneo de puertos", 20),
    "dos": ("Denegacion de servicio", r"denegacion de servicio", 30),
    "vlan": ("Acceso no autorizado entre VLANs", r"Acceso no autorizado entre VLANs", 20),
    "intruso": ("Dispositivo no autorizado", r"Dispositivo no autorizado", 20),
}
ENTORNO = {"escaneo": "Docker / Suricata", "dos": "Docker / Suricata",
           "vlan": "Packet Tracer / pt-agent", "intruso": "Packet Tracer / pt-agent"}

LOG = None


def log(*a):
    linea = datetime.now().strftime("%H:%M:%S") + " " + " ".join(str(x) for x in a)
    print(linea, flush=True)
    if LOG:
        LOG.write(linea + "\n")
        LOG.flush()


def sh(cmd, timeout=180, cwd=STACK, env=None):
    e = dict(os.environ, MSYS_NO_PATHCONV="1")
    if env:
        e.update(env)
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=timeout, env=e)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def http(url, data=None, headers=None):
    req = urllib.request.Request(url, data=json.dumps(data).encode() if data is not None else None,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def anotar(t0_ms, texto, tags):
    http(f"{GRAFANA}/api/annotations", {"time": t0_ms, "text": texto, "tags": tags},
         {"Authorization": AUTH})


# ------------------------------------------------------------------ control del stack
def sensores(encender):
    accion = "start" if encender else "stop"
    log(f"sensores Suricata/Promtail -> {accion}")
    sh(["docker", "compose", accion, "suricata", "promtail"], timeout=120)
    if encender:
        # esperar el "Engine started" del arranque ACTUAL del contenedor (si ya estaba
        # encendido, ese mensaje ya existe) y dar margen de calentamiento: con ~53 mil
        # reglas Suricata tarda en procesar a ritmo normal
        _, desde = sh(["docker", "inspect", "-f", "{{.State.StartedAt}}", "suricata"], timeout=30)
        desde = desde.strip()
        listo = False
        for _ in range(80):
            _, out = sh(["docker", "logs", "--since", desde, "suricata"], timeout=30)
            if "Engine started" in out:
                listo = True
                break
            time.sleep(3)
        log(f"  Suricata {'listo' if listo else 'NO confirmo arranque'}; calentamiento 20 s")
        time.sleep(20)


def iniciar_pt_agent(carpeta):
    out = open(os.path.join(carpeta, "pt-agent.log"), "w", encoding="utf-8")
    p = subprocess.Popen([BUN, "run", "pt-agent.ts"], cwd=PT_AGENT_DIR, stdout=out, stderr=subprocess.STDOUT)
    time.sleep(10)  # primer sondeo = linea base de contadores
    log(f"pt-agent iniciado (pid {p.pid})")
    return p


# ------------------------------------------------------------------ ataques
def ataque_docker(tipo, tags):
    if tipo == "escaneo":
        cmd = f"nmap -sS -p 1-1000 -T4 {OBJETIVO}"
    else:
        cmd = f"timeout 15 hping3 -S --flood -p 80 {OBJETIVO} 2>&1; true"
    # T0 se toma DENTRO del contenedor: mismo reloj (VM Linux de Docker) que Suricata
    _, out = sh(["docker", "compose", "exec", "-T", "atacante", "bash", "-c",
                 f"echo T0_MS=$(date +%s%3N); {cmd}"], timeout=120)
    m = re.search(r"T0_MS=(\d+)", out)
    t0 = int(m.group(1))
    anotar(t0, f"[{tags[2]}] Inicio {TIPOS[tipo][0]} ({tags[3]})", tags)
    if tipo == "escaneo":
        abiertos = re.findall(r"^(\d+)/tcp\s+open", out, re.M)
        cerrados = re.search(r"Not shown: (\d+) closed", out)
        evid = f"nmap: {cerrados.group(1) if cerrados else '?'} cerrados, abiertos {','.join(abiertos) or '-'}"
    else:
        pk = re.search(r"(\d+) packets transmitted", out)
        evid = f"hping3: {pk.group(1) if pk else '?'} paquetes SYN en 15 s"
    return t0, evid


def ataque_pt(tipo, tags):
    env = {"PT_TAGS": ",".join(tags[1:])}
    accion = "vlan" if tipo == "vlan" else "intruso"
    _, out = sh([BUN, "run", "pt-ataque.ts", accion], cwd=PT_AGENT_DIR, env=env, timeout=150)
    m = re.search(r"T0_MS=(\d+)", out)
    if not m:
        raise RuntimeError("pt-ataque no devolvio T0:\n" + out[-800:])
    t0 = int(m.group(1))
    if tipo == "vlan":
        n = out.count("Destination host unreachable")
        evid = f"ping Invitados->Academica: {n} respuesta(s) 'Destination host unreachable' (bloqueado)"
    else:
        r = re.search(r"(\d+)/(\d+) replies", out)
        evid = f"ping del intruso al gateway: {r.group(1)}/{r.group(2)} respuestas" if r else "ping del intruso: ?"
    return t0, evid


def restaurar_pt():
    _, out = sh([BUN, "run", "pt-ataque.ts", "restaurar"], cwd=PT_AGENT_DIR, timeout=150)
    ok = "4/4 replies" in out or "3/4 replies" in out
    log(f"  red PT restaurada ({'ping OK' if ok else 'REVISAR: ' + out[-200:]})")


def pico_paquetes(t0_ms, ventana):
    q = f'max_over_time(rate(node_network_receive_packets_total{{device="eth0"}}[10s])[{ventana}s:2s])'
    t = t0_ms / 1000 + ventana
    try:
        r = http(f"{PROM}/api/v1/query?" + urllib.parse.urlencode({"query": q, "time": t}))
        v = r["data"]["result"]
        return round(float(v[0]["value"][1]), 1) if v else None
    except Exception:
        return None


# ------------------------------------------------------------------ analisis
def leer_alertas(desde_ms, hasta_ms):
    params = {"query": '{event_type="alert"}', "start": str(desde_ms * 1_000_000),
              "end": str(hasta_ms * 1_000_000), "limit": "5000", "direction": "forward"}
    r = http(f"{LOKI}/loki/api/v1/query_range?" + urllib.parse.urlencode(params))
    alertas = []
    for s in r["data"]["result"]:
        lb = s["stream"]
        for ts, _linea in s["values"]:
            alertas.append({"ts_ms": int(ts) / 1e6, "fuente": lb.get("job"),
                            "firma": lb.get("alert_signature", ""), "categoria": lb.get("alert_category", ""),
                            "origen": lb.get("src_ip", ""), "destino": lb.get("dest_ip", "")})
    return sorted(alertas, key=lambda a: a["ts_ms"])


def tipo_de_alerta(firma):
    for k, (_, rx, _) in TIPOS.items():
        if re.search(rx, firma, re.I):
            return k
    return "otra"


# IPs que participan en cada tipo de ataque (para reconocer alertas secundarias del mismo ataque)
IPS_ATAQUE = {"escaneo": {"172.28.0.20", "172.28.0.10"}, "dos": {"172.28.0.20", "172.28.0.10"},
              "vlan": {"192.168.30.0/24", "192.168.10.0/24"}, "intruso": set()}


def clasificar(ataques, alertas):
    for a in ataques:
        a.update(alertas_tipo=0, alertas_secundarias=0, alertas_otro_tipo=0, primera_alerta_ms=None)
    for al in alertas:
        al["tipo_alerta"] = tipo_de_alerta(al["firma"])
        al["ataque"] = None
        for a in ataques:
            if a["t0_ms"] - 1000 <= al["ts_ms"] <= a["t0_ms"] + a["ventana_s"] * 1000:
                al["ataque"] = a["id"]
                if al["tipo_alerta"] == a["tipo"]:
                    al["clase"] = "VP"
                    a["alertas_tipo"] += 1
                    if a["primera_alerta_ms"] is None:
                        a["primera_alerta_ms"] = al["ts_ms"]
                elif al["origen"] in IPS_ATAQUE[a["tipo"]] and al["destino"] in IPS_ATAQUE[a["tipo"]]:
                    # otra firma, pero sobre el mismo trafico atacante<->victima: no es falsa alarma
                    al["clase"] = "Secundaria (mismo ataque)"
                    a["alertas_secundarias"] += 1
                else:
                    al["clase"] = "FP (otro tipo)"
                    a["alertas_otro_tipo"] += 1
                break
        else:
            al["clase"] = "FP (fuera de ventana)"
    for a in ataques:
        a["detectado"] = "Si" if a["primera_alerta_ms"] is not None else "No"
        a["tiempo_deteccion_s"] = (round((a["primera_alerta_ms"] - a["t0_ms"]) / 1000, 3)
                                   if a["primera_alerta_ms"] is not None else None)


def fisher_2x2(a, b, c, d):
    """p bilateral de la prueba exacta de Fisher para [[a,b],[c,d]]."""
    n1, n2, k, n = a + b, c + d, a + c, a + b + c + d

    def p(x):
        return math.comb(n1, x) * math.comb(n2, k - x) / math.comb(n, k)
    obs = p(a)
    return min(1.0, sum(p(x) for x in range(max(0, k - n2), min(k, n1) + 1) if p(x) <= obs * (1 + 1e-9)))


# ------------------------------------------------------------------ Excel
def excel(carpeta, ataques, alertas, meta):
    from openpyxl import Workbook
    from openpyxl.chart import BarChart, Reference
    from openpyxl.styles import Alignment, Font, PatternFill

    wb = Workbook()
    neg = Font(bold=True)
    cab = PatternFill("solid", fgColor="D9E2F3")

    def hoja(ws, filas, anchos=None):
        for i, f in enumerate(filas):
            ws.append(f)
            if i == 0:
                for c in ws[1]:
                    c.font, c.fill = neg, cab
                    c.alignment = Alignment(wrap_text=True, vertical="center")
        for i, w in enumerate(anchos or []):
            ws.column_dimensions[chr(65 + i)].width = w

    # Resumen
    ws = wb.active
    ws.title = "Resumen"
    filas = [["Condicion", "Tipo de ataque", "Entorno", "Ataques", "Detectados", "Tasa de deteccion (%)",
              "Media (s)", "Mediana (s)", "Desv. estandar (s)", "Minimo (s)", "Maximo (s)",
              "Alertas del tipo (VP)", "Alertas secundarias (mismo ataque)", "Falsos positivos (FP)"]]
    resumen = {}
    for cond in ["sin_stack", "con_stack"]:
        for tipo in TIPOS:
            g = [a for a in ataques if a["condicion"] == cond and a["tipo"] == tipo]
            if not g:
                continue
            t = [a["tiempo_deteccion_s"] for a in g if a["tiempo_deteccion_s"] is not None]
            det = len(t)
            resumen[(cond, tipo)] = (det, len(g))
            filas.append([cond, TIPOS[tipo][0], ENTORNO[tipo], len(g), det, round(100 * det / len(g), 1),
                          round(statistics.mean(t), 3) if t else None,
                          round(statistics.median(t), 3) if t else None,
                          round(statistics.stdev(t), 3) if len(t) > 1 else None,
                          min(t) if t else None, max(t) if t else None,
                          sum(a["alertas_tipo"] for a in g), sum(a["alertas_secundarias"] for a in g),
                          sum(a["alertas_otro_tipo"] for a in g)])
    hoja(ws, filas, [12, 30, 24, 9, 11, 12, 10, 11, 12, 10, 10, 12, 14, 12])
    fila_fisher = ws.max_row + 2
    ws.cell(fila_fisher, 1, "Prueba exacta de Fisher (detectado si/no): sin_stack vs con_stack").font = neg
    r = fila_fisher + 1
    for tipo in TIPOS:
        if ("sin_stack", tipo) in resumen and ("con_stack", tipo) in resumen:
            ds, ns = resumen[("sin_stack", tipo)]
            dc, nc = resumen[("con_stack", tipo)]
            pval = fisher_2x2(dc, nc - dc, ds, ns - ds)
            ws.cell(r, 1, TIPOS[tipo][0])
            ws.cell(r, 2, f"con: {dc}/{nc}  sin: {ds}/{ns}")
            ws.cell(r, 3, f"p = {pval:.2e}")
            r += 1
    vp = sum(1 for a in alertas if a["clase"] == "VP")
    sec = sum(1 for a in alertas if a["clase"].startswith("Secundaria"))
    fp = sum(1 for a in alertas if a["clase"].startswith("FP"))
    fn = sum(1 for a in ataques if a["condicion"] == "con_stack" and a["detectado"] == "No")
    r += 1
    ws.cell(r, 1, "Con stack: alertas VP / secundarias / FP / ataques no detectados (FN)").font = neg
    ws.cell(r + 1, 1, (f"VP = {vp}   Secundarias = {sec}   FP = {fp}   FN = {fn}   "
                       f"Precision VP/(VP+FP) = {vp / (vp + fp):.3f}   "
                       f"Exhaustividad = {(len([a for a in ataques if a['condicion'] == 'con_stack']) - fn) / max(1, len([a for a in ataques if a['condicion'] == 'con_stack'])):.3f}")
                      if vp + fp else "sin alertas")

    # grafico: tiempo medio de deteccion con stack
    filas_con = [i for i, f in enumerate(filas) if f[0] == "con_stack"]
    if filas_con:
        ch = BarChart()
        ch.title = "Tiempo medio de deteccion por tipo de ataque (con stack)"
        ch.y_axis.title = "segundos"
        ch.add_data(Reference(ws, min_col=7, min_row=filas_con[0] + 1, max_row=filas_con[-1] + 1), titles_from_data=False)
        ch.set_categories(Reference(ws, min_col=2, min_row=filas_con[0] + 1, max_row=filas_con[-1] + 1))
        ch.legend = None
        ch.width, ch.height = 18, 8
        ws.add_chart(ch, f"A{r + 4}")

    # Ataques (ficha de extraccion por ataque)
    ws = wb.create_sheet("Ataques")
    filas = [["ID", "Condicion", "Repeticion", "Tipo de ataque", "Entorno", "Inicio (T0, UTC)",
              "Primera alerta (UTC)", "Tiempo de deteccion (s)", "Detectado", "Alertas del tipo",
              "Alertas secundarias", "Falsos positivos", "Pico paquetes/s en el servidor",
              "Evidencia de que el ataque ocurrio"]]
    iso = lambda ms: datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if ms else None
    for a in ataques:
        filas.append([a["id"], a["condicion"], a["rep"], TIPOS[a["tipo"]][0], ENTORNO[a["tipo"]], iso(a["t0_ms"]),
                      iso(a["primera_alerta_ms"]), a["tiempo_deteccion_s"], a["detectado"], a["alertas_tipo"],
                      a["alertas_secundarias"], a["alertas_otro_tipo"], a["pico_pps"], a["evidencia"]])
    hoja(ws, filas, [22, 11, 10, 30, 22, 24, 24, 12, 10, 10, 10, 10, 14, 70])

    # Contingencia (tipo simulado x primera clasificacion del sistema), solo con stack
    ws = wb.create_sheet("Contingencia")
    cols = [TIPOS[t][0] for t in TIPOS] + ["No detectado"]
    filas = [["Tipo simulado \\ Clasificacion del sistema (con stack)"] + cols]
    for tipo in TIPOS:
        g = [a for a in ataques if a["condicion"] == "con_stack" and a["tipo"] == tipo]
        cuenta = {c: 0 for c in cols}
        for a in g:
            if a["detectado"] == "Si":
                cuenta[TIPOS[tipo][0]] += 1
            elif a["alertas_otro_tipo"]:
                otras = [al for al in alertas if al["ataque"] == a["id"] and al["clase"].startswith("FP")]
                cuenta[TIPOS.get(otras[0]["tipo_alerta"], ("No detectado",))[0]] += 1
            else:
                cuenta["No detectado"] += 1
        filas.append([TIPOS[tipo][0]] + [cuenta[c] for c in cols])
    hoja(ws, filas, [34, 18, 22, 30, 24, 14])

    # Alertas crudas
    ws = wb.create_sheet("Alertas")
    filas = [["Hora (UTC)", "Fuente", "Firma", "Categoria", "Origen", "Destino", "Tipo segun firma",
              "Ataque asociado", "Clasificacion"]]
    for al in alertas:
        filas.append([iso(al["ts_ms"]), al["fuente"], al["firma"], al["categoria"], al["origen"], al["destino"],
                      al["tipo_alerta"], al["ataque"], al["clase"]])
    hoja(ws, filas, [24, 14, 60, 30, 22, 26, 14, 22, 20])

    # Metodo
    ws = wb.create_sheet("Metodo")
    for k, v in meta.items():
        ws.append([k, v])
    ws.column_dimensions["A"].width = 34
    ws.column_dimensions["B"].width = 110
    for c in ws["A"]:
        c.font = neg

    ruta = os.path.join(carpeta, "resultados.xlsx")
    wb.save(ruta)
    return ruta


def guardar_csv(ruta, filas):
    if not filas:
        return
    with open(ruta, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0].keys()))
        w.writeheader()
        w.writerows(filas)


# ------------------------------------------------------------------ principal
def main():
    global LOG
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--nombre", default=datetime.now().strftime("medicion-%Y%m%d-%H%M"))
    ap.add_argument("--condiciones", default="sin_stack,con_stack")
    ap.add_argument("--pausa", type=int, default=5, help="segundos extra entre ataques")
    args = ap.parse_args()

    carpeta = os.path.join(STACK, "medicion", "resultados", args.nombre)
    os.makedirs(carpeta, exist_ok=True)
    LOG = open(os.path.join(carpeta, "log.txt"), "w", encoding="utf-8")
    inicio_ms = int(time.time() * 1000)
    _, reloj = sh(["docker", "compose", "exec", "-T", "atacante", "date", "+%s%3N"])
    desfase = int(re.search(r"\d{13}", reloj).group()) - int(time.time() * 1000)
    log(f"Sesion {args.nombre}: {args.reps} repeticion(es), condiciones {args.condiciones}; "
        f"desfase reloj Docker-Windows ~{desfase} ms")

    ataques, agente = [], None
    try:
        for cond in args.condiciones.split(","):
            log(f"===== CONDICION {cond} =====")
            if cond == "sin_stack":
                sensores(False)
            else:
                sensores(True)
                agente = iniciar_pt_agent(carpeta)
            for rep in range(1, args.reps + 1):
                for tipo in TIPOS:
                    tags = ["ataque", tipo, cond, f"rep{rep}"]
                    aid = f"{cond}/{tipo}/{rep:02d}"
                    try:
                        if tipo in ("escaneo", "dos"):
                            t0, evid = ataque_docker(tipo, tags)
                        else:
                            t0, evid = ataque_pt(tipo, tags)
                    except Exception as e:
                        log(f"  {aid}: ERROR al lanzar el ataque: {e}")
                        if tipo == "intruso":
                            restaurar_pt()
                        continue
                    ventana = TIPOS[tipo][2]
                    log(f"  {aid}: T0 {datetime.fromtimestamp(t0 / 1000).strftime('%H:%M:%S.%f')[:-3]} | {evid}")
                    espera = t0 / 1000 + ventana + args.pausa - time.time() - (desfase / 1000 if tipo in ("escaneo", "dos") else 0)
                    if espera > 0:
                        time.sleep(espera)
                    ataques.append({"id": aid, "condicion": cond, "rep": rep, "tipo": tipo, "t0_ms": t0,
                                    "ventana_s": ventana, "evidencia": evid,
                                    "pico_pps": pico_paquetes(t0, ventana) if tipo in ("escaneo", "dos") else None})
                    if tipo == "intruso":
                        restaurar_pt()
                        time.sleep(args.pausa)
            if agente:
                agente.terminate()
                agente = None
                log("pt-agent detenido")
    finally:
        if agente:
            agente.terminate()
        sensores(True)  # dejar el stack completo encendido al terminar

    time.sleep(10)  # margen para que las ultimas alertas lleguen a Loki
    alertas = leer_alertas(inicio_ms - 5000, int(time.time() * 1000))
    clasificar(ataques, alertas)
    guardar_csv(os.path.join(carpeta, "ataques.csv"), ataques)
    guardar_csv(os.path.join(carpeta, "alertas.csv"), alertas)
    meta = {
        "Sesion": args.nombre,
        "Inicio (UTC)": datetime.fromtimestamp(inicio_ms / 1000, timezone.utc).isoformat(timespec="seconds"),
        "Repeticiones por tipo y condicion": args.reps,
        "Condiciones": "sin_stack = Suricata, Promtail y pt-agent apagados; con_stack = stack completo",
        "Ataques": "escaneo nmap -sS -p 1-1000 -T4; DoS hping3 -S --flood -p 80 (15 s); "
                   "VLAN: ping Invitados->Academica en PT; intruso: laptop no registrada en Fa0/11 (Invitados)",
        "Inicio del ataque (T0)": "Docker: reloj del contenedor atacante (mismo reloj que Suricata); "
                                  "Packet Tracer: reloj del equipo anfitrion (mismo reloj que pt-agent)",
        "Desfase reloj Docker - Windows (ms)": desfase,
        "Ventanas de observacion (s)": ", ".join(f"{k}={v[2]}" for k, v in TIPOS.items()),
        "Regla de clasificacion": "VP: alerta del tipo correcto en la ventana del ataque (la primera define el "
                                  "tiempo de deteccion); Secundaria: alerta de otra firma en la ventana pero sobre "
                                  "el mismo trafico atacante-victima (no es falsa alarma); FP: alerta no relacionada "
                                  "con el ataque o fuera de toda ventana; FN: ataque sin alerta de su tipo",
        "Intervalo de sondeo de pt-agent": "3 s (el tiempo de deteccion en PT incluye esta espera)",
        "Topologia Packet Tracer": "Red-Campus-4-Pabellones.pkt: 4 pabellones (A Administracion, B Aulas, C Laboratorios, D Biblioteca), centro de datos, VLAN 10/20/30/40/50/99, ACL 110/120/150, Port Security en SW-PabC y SW-PabD",
    }
    ruta = excel(carpeta, ataques, alertas, meta)
    det = sum(1 for a in ataques if a["condicion"] == "con_stack" and a["detectado"] == "Si")
    tot = sum(1 for a in ataques if a["condicion"] == "con_stack")
    log(f"FIN. Ataques: {len(ataques)} | con stack detectados {det}/{tot} | alertas en Loki: {len(alertas)}")
    log(f"Excel: {ruta}")


if __name__ == "__main__":
    main()
