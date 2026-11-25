/**
 * pt-agent: agente recolector para Cisco Packet Tracer.
 *
 * Packet Tracer es un simulador cerrado: sus routers/switches no pueden enviar
 * Syslog a una red real. Este agente hace lo mismo que haria un sistema de
 * monitoreo por sondeo (tipo SNMP polling): cada N segundos CONSULTA el estado
 * de los equipos simulados a traves del puente MCP (packet-tracer-mcp, que usa
 * la API de scripting/IPC de PT) y, cuando un contador de seguridad aumenta,
 * genera un evento de alerta y lo envia a Loki por su API HTTP de ingesta.
 *
 * Eventos que detecta:
 *   - Acceso no autorizado entre VLANs: aumento de "N match(es)" en una linea
 *     "deny" de las ACL extendidas del router (show access-lists).
 *   - Dispositivo no autorizado: aumento de "SecurityViolation" en Port
 *     Security del switch (show port-security) + MAC del intruso.
 *
 * Uso (en el equipo anfitrion, con Packet Tracer abierto y el puente activo):
 *   bun run pt-agent.ts
 * Variables de entorno opcionales:
 *   PT_MCP_URL   (default http://127.0.0.1:39011/mcp)
 *   LOKI_URL     (default http://127.0.0.1:3100)
 *   PT_ROUTER    (default Router-Core)
 *   PT_SWITCHES  (default SW-PabC,SW-PabD: switches de acceso con Port Security)
 *   PT_ACLS      (default 110,120,150: ACL del router, se consultan por separado
 *                 para que la salida no se corte con --More--)
 *   POLL_MS      (default 3000)
 */

import { MCP_URL, cli, marcarDesconectado } from "./mcp-client";

const LOKI_URL = process.env.LOKI_URL ?? "http://127.0.0.1:3100";
const ROUTER = process.env.PT_ROUTER ?? "Router-Core";
const SWITCHES = (process.env.PT_SWITCHES ?? "SW-PabC,SW-PabD").split(",").map((x) => x.trim()).filter(Boolean);
const ACLS = (process.env.PT_ACLS ?? "110,120,150").split(",").map((x) => x.trim()).filter(Boolean);
const POLL_MS = Number(process.env.POLL_MS ?? 3000);

// Nombres de VLAN para que las alertas se lean en lenguaje del campus.
const REDES: Record<string, string> = {
  "192.168.10.0": "VLAN 10 Academica",
  "192.168.20.0": "VLAN 20 Administrativa",
  "192.168.30.0": "VLAN 30 Invitados",
  "192.168.40.0": "VLAN 40 Servidores",
  "192.168.50.0": "VLAN 50 Laboratorios",
};

const log = (...a: unknown[]) => console.log(new Date().toISOString(), "[pt-agent]", ...a);

// ---------------------------------------------------------------- envio a Loki
type Alerta = {
  signature: string;
  category: string;
  severity: number;
  src: string;
  dest: string;
  device: string;
  detalle: string;
};

async function enviarLoki(a: Alerta) {
  const ts = (BigInt(Date.now()) * 1_000_000n).toString();
  const stream = {
    job: "packet-tracer",
    fuente: "Packet Tracer",
    event_type: "alert",
    alert_signature: a.signature,
    alert_category: a.category,
    alert_severity: String(a.severity),
    src_ip: a.src,
    dest_ip: a.dest,
    device: a.device,
  };
  const linea = JSON.stringify({ timestamp: new Date().toISOString(), event_type: "alert", ...stream, detalle: a.detalle });
  const res = await fetch(`${LOKI_URL}/loki/api/v1/push`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ streams: [{ stream, values: [[ts, linea]] }] }),
  });
  if (!res.ok) throw new Error(`Loki HTTP ${res.status}: ${await res.text()}`);
  log("ALERTA ->", a.signature, "|", a.src, "->", a.dest, "|", a.detalle);
}

// ---------------------------------------------------------------- parsers
/** Devuelve { "110/192.168.30.0>192.168.10.0": {matches, src, dst, seq} } para cada linea deny. */
function parseAcl(out: string) {
  const res: Record<string, { matches: number; src: string; dst: string; acl: string; seq: string }> = {};
  let acl = "";
  let n = 0; // posicion de la linea dentro de la ACL (PT9 no siempre imprime el numero de secuencia)
  for (const l of out.split(/\r?\n/)) {
    const h = l.match(/IP access list (\S+)/);
    if (h) { acl = h[1]; n = 0; continue; }
    if (!acl || !/^\s+(\d+\s+)?(permit|deny)\s/.test(l)) continue;
    n++;
    const m = l.match(/^\s*(?:(\d+)\s+)?deny\s+\S+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:.*\((\d+) match)?/);
    if (m) {
      const seq = m[1] ?? String(n * 10);
      res[`${acl}/${m[2]}>${m[4]}`] = { acl, seq, src: m[2], dst: m[4], matches: m[6] ? Number(m[6]) : 0 };
    }
  }
  return res;
}

/** Devuelve { "Fa0/11": violaciones } a partir de 'show port-security'. */
function parsePortSec(out: string) {
  const res: Record<string, number> = {};
  for (const l of out.split(/\r?\n/)) {
    const m = l.match(/^\s*(\S+\d+\/\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\S+/);
    if (m) res[m[1]] = Number(m[4]);
  }
  return res;
}

const red = (ip: string) => REDES[ip] ? `${ip}/24 (${REDES[ip]})` : ip;

// ---------------------------------------------------------------- bucle
let prevAcl: ReturnType<typeof parseAcl> | null = null;
let prevPs: Record<string, number> | null = null;

async function sondeo() {
  // 1) ACLs del router: accesos bloqueados entre VLANs
  // Ojo: la consola de PT9 se "resetea" a veces y devuelve salida vacia o
  // cortada. Una lectura sin lineas deny se descarta (no es un contador en 0).
  const acl = parseAcl(await cli(ROUTER, ACLS.map((n) => `show access-lists ${n}`)));
  if (Object.keys(acl).length === 0) { log("lectura de ACL vacia (reseteo de consola PT), se ignora"); }
  else if (prevAcl) {
    for (const [k, v] of Object.entries(acl)) {
      const antes = prevAcl[k]?.matches ?? 0;
      if (v.matches > antes) {
        await enviarLoki({
          signature: `PT Acceso no autorizado entre VLANs bloqueado (ACL ${v.acl})`,
          category: "Acceso no autorizado entre VLANs",
          severity: 2,
          src: `${v.src}/24`,
          dest: `${v.dst}/24`,
          device: ROUTER,
          detalle: `ACL ${v.acl} linea ${v.seq} deny: ${v.matches - antes} paquete(s) bloqueado(s) de ${red(v.src)} hacia ${red(v.dst)} (total ${v.matches})`,
        });
      }
    }
  }
  // Los contadores de ACL solo crecen (se reinician al recargar la red), asi que
  // una linea leida "cortada" (sin el "(N match(es))") no debe bajar la base.
  for (const [k, v] of Object.entries(acl)) {
    prevAcl ??= {};
    prevAcl[k] = { ...v, matches: Math.max(v.matches, prevAcl[k]?.matches ?? 0) };
  }

  // 2) Port Security de los switches de acceso: dispositivos no autorizados
  for (const SWITCH of SWITCHES) {
    const ps = parsePortSec(await cli(SWITCH, ["show port-security"]));
    if (Object.keys(ps).length === 0) { log(`lectura de Port Security vacia en ${SWITCH} (reseteo de consola PT), se ignora`); continue; }
    for (const [puerto, viol] of Object.entries(ps)) {
      const clave = `${SWITCH}|${puerto}`;
      if (prevPs && clave in prevPs && viol > prevPs[clave]) {
        const det = await cli(SWITCH, [`show port-security interface ${puerto}`]);
        const mac = det.match(/Last Source Address:Vlan\s*:\s*([0-9A-Fa-f.]+):(\d+)/);
        const estado = det.match(/Port Status\s*:\s*(\S+)/)?.[1] ?? "?";
        await enviarLoki({
          signature: "PT Dispositivo no autorizado detectado (Port Security)",
          category: "Dispositivo no autorizado",
          severity: 1,
          src: mac ? `MAC ${mac[1]}` : "MAC desconocida",
          dest: `${SWITCH} ${puerto}${mac ? ` (VLAN ${mac[2]})` : ""}`,
          device: SWITCH,
          detalle: `Violacion de Port Security en ${SWITCH} ${puerto}: estado ${estado}, violaciones ${viol}`,
        });
      }
      prevPs ??= {};
      prevPs[clave] = viol;
    }
  }
}

async function main() {
  log(`MCP=${MCP_URL} Loki=${LOKI_URL} router=${ROUTER} (ACL ${ACLS.join(",")}) switches=${SWITCHES.join(",")} cada ${POLL_MS} ms`);
  for (;;) {
    try {
      await sondeo();
    } catch (e) {
      log("error:", (e as Error).message);
      marcarDesconectado(); // reconecta en el siguiente ciclo
    }
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
}

main();
