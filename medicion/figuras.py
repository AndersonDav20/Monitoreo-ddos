"""
Genera las figuras del capitulo de resultados y de aspectos administrativos a partir
de los datos de la medicion formal (ataques.csv). Salida: medicion/figuras/*.png

Uso: python medicion/figuras.py resultados/medicion-formal-2026-11-12
"""
import csv
import os
import statistics
import sys
from datetime import date, timedelta

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

def coma(v, dec=2):
    """Formato decimal en espanol (coma)."""
    return f"{v:.{dec}f}".replace(".", ",")


AQUI = os.path.dirname(os.path.abspath(__file__))
SESION = os.path.join(AQUI, sys.argv[1] if len(sys.argv) > 1 else "resultados/medicion-formal-2026-11-13")
OUT = os.path.join(AQUI, "figuras")
os.makedirs(OUT, exist_ok=True)

plt.rcParams.update({"font.family": "Times New Roman", "font.size": 11, "axes.spines.top": False,
                     "axes.spines.right": False, "savefig.dpi": 200, "savefig.bbox": "tight"})

TIPOS = [("escaneo", "Escaneo\nde puertos"), ("dos", "Denegación\nde servicio"),
         ("vlan", "Acceso no autorizado\nentre VLANs"), ("intruso", "Dispositivo\nno autorizado")]
COLOR = {"escaneo": "#2F5597", "dos": "#C9A227", "vlan": "#548235", "intruso": "#C55A11"}

filas = list(csv.DictReader(open(os.path.join(SESION, "ataques.csv"), encoding="utf-8-sig")))


def tiempos(tipo, cond="con_stack"):
    """Tiempos validos (>= 0); un negativo es un ajuste de reloj de la VM y se excluye (la deteccion cuenta igual)."""
    return [float(f["tiempo_deteccion_s"]) for f in filas
            if f["tipo"] == tipo and f["condicion"] == cond and f["tiempo_deteccion_s"] and float(f["tiempo_deteccion_s"]) >= 0]


def detectados(tipo, cond):
    return sum(1 for f in filas if f["tipo"] == tipo and f["condicion"] == cond and f["detectado"] == "Si")


def guardar(nombre):
    plt.savefig(os.path.join(OUT, nombre))
    plt.close()
    print("figura", nombre)


# 1. Tasa de deteccion sin vs con stack ---------------------------------------
fig, ax = plt.subplots(figsize=(7.5, 3.8))
x = range(len(TIPOS))
sin = [100 * detectados(t, "sin_stack") / 10 for t, _ in TIPOS]
con = [100 * detectados(t, "con_stack") / 10 for t, _ in TIPOS]
ax.bar([i - 0.2 for i in x], sin, 0.4, label="Sin stack de observabilidad", color="#A6A6A6")
b = ax.bar([i + 0.2 for i in x], con, 0.4, label="Con stack de observabilidad", color="#2F5597")
for i, v in enumerate(sin):
    ax.text(i - 0.2, v + 2, f"{v:.0f} %", ha="center", fontsize=10)
for r in b:
    ax.text(r.get_x() + r.get_width() / 2, r.get_height() + 2, f"{r.get_height():.0f} %", ha="center", fontsize=10)
ax.set_xticks(list(x), [n for _, n in TIPOS])
ax.set_ylabel("Ataques detectados (%)")
ax.set_ylim(0, 115)
ax.legend(frameon=False, loc="upper center", ncol=2, bbox_to_anchor=(0.5, 1.12))
guardar("fig-tasa-deteccion.png")

# 2. Distribucion del tiempo de deteccion (con stack) --------------------------
fig, ax = plt.subplots(figsize=(7.5, 4))
datos = [tiempos(t) for t, _ in TIPOS]
bp = ax.boxplot(datos, widths=0.45, patch_artist=True, medianprops={"color": "black"})
for caja, (t, _) in zip(bp["boxes"], TIPOS):
    caja.set_facecolor(COLOR[t]); caja.set_alpha(0.35)
for i, (t, _) in enumerate(TIPOS, start=1):
    v = tiempos(t)
    ax.scatter([i + (k - 4.5) * 0.025 for k in range(len(v))], v, s=16, color=COLOR[t], zorder=3)
    ax.text(i, max(v) + 0.2, f"media {coma(statistics.mean(v))} s", ha="center", fontsize=9)
ax.set_xticks(range(1, 5), [n for _, n in TIPOS])
ax.set_ylabel("Tiempo de detección (s)")
ax.axvline(2.5, color="#BFBFBF", lw=0.8, ls="--")
TOPE = max(max(v) for v in datos) + 1.3  # escala segun los datos (los tiempos de PT dependen del ciclo del agente)
ax.set_ylim(-0.2, TOPE)
ax.text(1.5, TOPE - 0.3, "Laboratorio Docker (Suricata)", ha="center", fontsize=9, color="#595959")
ax.text(3.5, TOPE - 0.3, "Packet Tracer (pt-agent, sondeo 3 s)", ha="center", fontsize=9, color="#595959")
guardar("fig-tiempo-deteccion.png")

# 3. Tiempo de deteccion por repeticion ---------------------------------------
fig, ax = plt.subplots(figsize=(7.5, 3.8))
for t, n in TIPOS:
    reps = sorted((int(f["rep"]), float(f["tiempo_deteccion_s"])) for f in filas
                  if f["tipo"] == t and f["condicion"] == "con_stack" and f["tiempo_deteccion_s"] and float(f["tiempo_deteccion_s"]) >= 0)
    ax.plot([r for r, _ in reps], [v for _, v in reps], marker="o", ms=4, color=COLOR[t], label=n.replace("\n", " "))
ax.axhline(3, color="#7F7F7F", lw=0.8, ls=":")
ax.text(10.2, 3.05, "intervalo de\nsondeo (3 s)", fontsize=8, color="#595959", va="bottom")
ax.set_xticks(range(1, 11))
ax.set_xlabel("Repetición")
ax.set_ylabel("Tiempo de detección (s)")
ax.legend(frameon=False, fontsize=9, ncol=2, loc="upper center", bbox_to_anchor=(0.5, 1.18))
guardar("fig-tiempo-por-repeticion.png")

# 4. Impacto en el servidor: pico de paquetes/s (Prometheus) -------------------
fig, ax = plt.subplots(figsize=(6.5, 3.6))
grupos = []
for cond, etiqueta, color in [("sin_stack", "Sin stack", "#A6A6A6"), ("con_stack", "Con stack", "#2F5597")]:
    v = [float(f["pico_pps"]) / 1000 for f in filas if f["tipo"] == "dos" and f["condicion"] == cond and f["pico_pps"]]
    grupos.append((etiqueta, v, color))
for i, (etq, v, color) in enumerate(grupos):
    ax.bar(i, statistics.mean(v), 0.5, color=color, yerr=statistics.stdev(v), capsize=6)
    ax.scatter([i + (k - 4.5) * 0.03 for k in range(len(v))], v, s=12, color="black", zorder=3)
    ax.text(i, max(max(v), statistics.mean(v) + statistics.stdev(v)) + 5, f"media {coma(statistics.mean(v), 1)} mil paq/s", ha="center", fontsize=10)
ax.set_xticks([0, 1], [g[0] for g in grupos])
ax.set_ylabel("Pico de paquetes recibidos (miles/s)")
ax.set_ylim(0, max(max(g[1]) for g in grupos) * 1.25)
guardar("fig-impacto-dos.png")

# 5. Cronograma (Gantt) ---------------------------------------------------------
INICIO = date(2026, 9, 27)
SEMANAS = [(INICIO + timedelta(days=7 * i), INICIO + timedelta(days=7 * i + 6)) for i in range(7)]
ACTIVIDADES = [  # (actividad, semana inicial, semana final) en base 1
    ("Definición del tema y revisión del informe inicial", 1, 1),
    ("Revisión bibliográfica y búsqueda de literatura", 1, 3),
    ("Planteamiento del problema (primera entrega)", 1, 2),
    ("Marco teórico", 2, 3),
    ("Hipótesis, variables y marco metodológico (segunda entrega)", 3, 3),
    ("Construcción del stack de observabilidad (Docker)", 4, 6),
    ("Diseño y simulación de la red en Packet Tracer (4 pabellones)", 5, 7),
    ("Integración de Packet Tracer (pt-agent) y tableros", 6, 7),
    ("Prueba piloto y medición formal", 7, 7),
    ("Análisis de datos y redacción de resultados", 7, 7),
    ("Entrega final", 7, 7),
]
fig, ax = plt.subplots(figsize=(8, 4.6))
for i, (act, s1, s2) in enumerate(ACTIVIDADES):
    ax.barh(i, s2 - s1 + 1, left=s1 - 0.5, height=0.6, color="#2F5597" if s1 < 4 else "#548235")
ax.set_yticks(range(len(ACTIVIDADES)), [a for a, _, _ in ACTIVIDADES], fontsize=9)
ax.invert_yaxis()
ax.set_xticks(range(1, 8), [f"S{i}\n{a.day}/{a.month}–{b.day}/{b.month}" for i, (a, b) in enumerate(SEMANAS, 1)], fontsize=8)
ax.set_xlim(0.5, 7.5)
ax.grid(axis="x", color="#D9D9D9", lw=0.6)
ax.set_axisbelow(True)
guardar("fig-cronograma.png")

# 6. Arquitectura del sistema ---------------------------------------------------
fig, ax = plt.subplots(figsize=(9, 5.2))
ax.set_xlim(0, 100); ax.set_ylim(0, 60); ax.axis("off")


def caja(x, y, w, h, texto, color, fs=9):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.2",
                                fc=color, ec="#404040", lw=0.8))
    ax.text(x + w / 2, y + h / 2, texto, ha="center", va="center", fontsize=fs)


def flecha(x1, y1, x2, y2, texto=""):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops={"arrowstyle": "->", "color": "#404040", "lw": 1})
    if texto:
        ax.text((x1 + x2) / 2, (y1 + y2) / 2 + 1, texto, ha="center", fontsize=7.5, color="#404040")


ax.text(22, 57, "Laboratorio Docker (red lab-net 172.28.0.0/24)", ha="center", fontsize=9.5, weight="bold")
ax.text(22, 25, "Cisco Packet Tracer 9.0 (sede de 4 pabellones, VLAN 10 a 50)", ha="center", fontsize=9.5, weight="bold")
ax.text(78, 57, "Stack de observabilidad", ha="center", fontsize=9.5, weight="bold")
caja(2, 44, 16, 8, "Atacante (Kali)\nnmap / hping3", "#F8CBAD")
caja(25, 44, 18, 8, "servicio-academico\n(nginx, 172.28.0.10)", "#DEEBF7")
caja(48, 44, 15, 8, "node-exporter\n(comparte su red)", "#FFF2CC")
caja(14, 30, 18, 7, "Suricata (IDS)\neve.json", "#FFF2CC")
caja(2, 4, 18, 13, "Router-Core 2911\nACL 110 / 120 / 150\n\nSW-PabC y SW-PabD\nPort Security", "#E2EFDA", 8.5)
caja(26, 7, 16, 8, "Puente MCP\n(API de scripting)", "#EDEDED")
caja(50, 30, 14, 7, "Promtail", "#D9E2F3")
caja(50, 8, 14, 7, "pt-agent\n(sondeo 3 s)", "#D9E2F3")
caja(72, 42, 14, 8, "Prometheus\n(métricas)", "#BDD7EE")
caja(72, 24, 14, 9, "Loki\n(logs y alertas)", "#BDD7EE")
caja(74, 2, 22, 10, "Grafana\n4 tableros y anotación\nde inicio del ataque", "#9DC3E6")
flecha(18, 48, 25, 48, "ataque real")
ax.plot([43.4, 47.6], [48, 48], ls="--", color="#7F7F7F", lw=0.9)
flecha(30, 43.6, 24, 37.4, "captura (labnet0)")
flecha(32.4, 33.5, 49.6, 33.5, "alertas")
flecha(63.4, 48, 71.6, 46, "")
flecha(64.4, 33.5, 71.6, 29.5, "")
flecha(20.4, 11, 25.6, 11, "")
flecha(42.4, 11, 49.6, 11.5, "contadores")
flecha(64.4, 11.5, 71.6, 26, "alertas")
flecha(79, 23.6, 80, 12.4, "")
flecha(86.4, 44, 93, 12.4, "")
guardar("fig-arquitectura.png")
print("listo:", OUT)
