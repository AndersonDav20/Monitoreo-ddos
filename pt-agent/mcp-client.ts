/**
 * Cliente minimo del puente MCP de Packet Tracer (packet-tracer-mcp, transporte
 * Streamable HTTP). Lo usan pt-agent.ts (recolector) y pt-ataque.ts (ataques).
 */

export const MCP_URL = process.env.PT_MCP_URL ?? "http://127.0.0.1:39011/mcp";

let sessionId: string | undefined;
let conectado = false;
let rpcId = 0;

async function rpc(method: string, params?: unknown, notify = false): Promise<any> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json, text/event-stream",
  };
  if (sessionId) headers["mcp-session-id"] = sessionId;
  const body: any = { jsonrpc: "2.0", method };
  if (params !== undefined) body.params = params;
  if (!notify) body.id = ++rpcId;
  const res = await fetch(MCP_URL, { method: "POST", headers, body: JSON.stringify(body) });
  const sid = res.headers.get("mcp-session-id");
  if (sid) sessionId = sid;
  if (notify) return;
  const text = await res.text();
  if (!res.ok) throw new Error(`MCP ${method} HTTP ${res.status}: ${text.slice(0, 200)}`);
  // La respuesta puede venir como JSON directo o como stream SSE ("data: {...}")
  let msg: any;
  if (text.trimStart().startsWith("{")) msg = JSON.parse(text);
  else {
    const data = text.split("\n").filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim());
    msg = JSON.parse(data[data.length - 1]);
  }
  if (msg.error) throw new Error(`MCP ${method}: ${JSON.stringify(msg.error)}`);
  return msg.result;
}

export function marcarDesconectado() {
  conectado = false;
}

async function asegurarConexion() {
  if (conectado) return;
  sessionId = undefined;
  await rpc("initialize", {
    protocolVersion: "2025-03-26",
    capabilities: {},
    clientInfo: { name: "pt-agent", version: "1.0.0" },
  });
  await rpc("notifications/initialized", undefined, true);
  conectado = true;
}

/** Llama a una herramienta del servidor MCP y devuelve su texto. */
export async function tool(name: string, args: Record<string, unknown>): Promise<string> {
  await asegurarConexion();
  const r = await rpc("tools/call", { name, arguments: args });
  const out = (r?.content ?? []).map((c: any) => c.text ?? "").join("");
  if (r?.isError || out.startsWith("ERROR:")) throw new Error(`${name}: ${out.slice(0, 300)}`);
  return out;
}

/** Ejecuta comandos CLI en un router/switch de PT y devuelve solo la salida nueva. */
export async function cli(device: string, comandos: string[]): Promise<string> {
  const js =
    `(function(){var cl=ipc.network().getDevice(${JSON.stringify(device)}).getCommandLine();` +
    `cl.enterCommand('');cl.enterCommand('enable');var b=cl.getOutput().length;` +
    comandos.map((c) => `cl.enterCommand(${JSON.stringify(c)});`).join("") +
    `return cl.getOutput().substring(b);})()`;
  return tool("pt_send_raw", { code: js, timeout_ms: 15000 });
}
