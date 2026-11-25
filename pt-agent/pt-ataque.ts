/**
 * pt-ataque: lanza los ataques simulados dentro de Packet Tracer y marca su
 * inicio en Grafana (anotacion con tag "ataque"), igual que portscan.sh y
 * dos.sh en el laboratorio Docker. Asi el tiempo de deteccion se mide del
 * mismo modo para los 4 tipos de ataque: alerta - inicio.
 *
 * Uso:
 *   bun run pt-ataque.ts vlan        # PC-Invitados1 intenta llegar a la VLAN Academica
 *   bun run pt-ataque.ts intruso     # conecta Laptop-Intruso en el puerto de Invitados
 *   bun run pt-ataque.ts restaurar   # retira al intruso y reactiva el puerto
 */
import { cli, tool } from "./mcp-client";

const GRAFANA_URL = process.env.GRAFANA_URL ?? "http://127.0.0.1:3000";
const GRAFANA_AUTH = "Basic " + btoa(`${process.env.GRAFANA_USER ?? "admin"}:${process.env.GRAFANA_PASSWORD ?? "admin123"}`);
const SWITCH = process.env.PT_SWITCH ?? "SW-PabD"; // Pabellon D: biblioteca e invitados
const PUERTO = "FastEthernet0/11";
const PC_INVITADOS = "PC-Invitados1";
const INTRUSO = "Laptop-Intruso";

// Etiquetas extra opcionales (las usa el script de medicion: condicion, repeticion)
const TAGS_EXTRA = (process.env.PT_TAGS ?? "").split(",").map((t) => t.trim()).filter(Boolean);

async function anotar(texto: string, tag: string) {
  const t0 = Date.now();
  const res = await fetch(`${GRAFANA_URL}/api/annotations`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: GRAFANA_AUTH },
    body: JSON.stringify({ time: t0, text: texto, tags: ["ataque", tag, ...TAGS_EXTRA] }),
  });
  if (!res.ok) console.warn("[pt-ataque] aviso: no se pudo anotar en Grafana:", res.status);
  console.log(`[pt-ataque] inicio del ataque: ${new Date(t0).toISOString()} (${texto})`);
  console.log(`T0_MS=${t0}`); // lo lee el script de medicion
}

async function vlan() {
  await anotar("Inicio acceso no autorizado entre VLANs (Invitados -> Academica) en Packet Tracer", "pt-vlan");
  console.log(await tool("pt_ping", { device: PC_INVITADOS, target: "192.168.10.10", timeout_ms: 30000 }));
}

async function intruso() {
  await tool("pt_delete_link", { device: PC_INVITADOS, port: "FastEthernet0" });
  await tool("pt_add_device", { name: INTRUSO, model: "Laptop-PT", x: 1200, y: 600 });
  await tool("pt_create_link", { device_a: INTRUSO, port_a: "FastEthernet0", device_b: SWITCH, port_b: PUERTO });
  await tool("pt_set_pc", { device: INTRUSO, mode: "static", ip: "192.168.30.66", mask: "255.255.255.0", gateway: "192.168.30.1" });
  await anotar("Inicio dispositivo no autorizado en puerto de Invitados (Packet Tracer)", "pt-intruso");
  console.log(await tool("pt_ping", { device: INTRUSO, target: "192.168.30.1", timeout_ms: 30000 }));
  console.log("[pt-ataque] para dejar la red como antes: bun run pt-ataque.ts restaurar");
}

async function restaurar() {
  try { await tool("pt_delete_device", { name: INTRUSO }); } catch { /* ya no estaba */ }
  try { await tool("pt_create_link", { device_a: PC_INVITADOS, port_a: "FastEthernet0", device_b: SWITCH, port_b: PUERTO }); } catch { /* ya conectado */ }
  console.log(await cli(SWITCH, [
    "configure terminal", `interface ${PUERTO}`, "shutdown", "no shutdown", "end",
    `clear port-security sticky interface ${PUERTO}`, "show port-security",
  ]));
  console.log(await tool("pt_ping", { device: PC_INVITADOS, target: "192.168.30.1", timeout_ms: 30000 }));
}

const accion = process.argv[2];
const acciones: Record<string, () => Promise<void>> = { vlan, intruso, restaurar };
if (!acciones[accion]) {
  console.log("Uso: bun run pt-ataque.ts vlan | intruso | restaurar");
  process.exit(1);
}
await acciones[accion]();
