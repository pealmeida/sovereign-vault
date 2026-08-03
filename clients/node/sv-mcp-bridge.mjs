#!/usr/bin/env node
// sv-mcp-bridge.mjs — Sovereign Vault MCP bridge.
//
// opencode spawns this with stdin/stdout connected to its MCP transport.
// We proxy JSON-RPC directly to a running vault WebSocket gateway (or boot
// one headlessly). NO child processes — we hold the WebSocket open for the
// life of opencode's session, which is what makes the stdio relay work
// reliably (each `mcp-stdio` exec used to race opencode's MCP poll).
//
// Lifecycle:
//   1. Probe 127.0.0.1:9944 for an unlocked desktop vault. If up, fetch the
//      per-launch pairing secret from http://127.0.0.1:9943/pairing and pair.
//   2. If desktop is not running, launch `sovereign-vault serve` headlessly
//      with a pre-provisioned scoped agent credential.
//      - passphrase from SV_PASSPHRASE_FILE (real vault), or
//      - well-known SV_BRIDGE_TEST_PASS for SV_BRIDGE_TEST_ROOT (throwaway).
//   3. Hold the WebSocket open and proxy stdin ↔ WS until opencode closes.

import { spawn, execSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { randomBytes, createHash } from "node:crypto";
import { connect as netConnect } from "node:net";
import process from "node:process";

const BIN = process.env.SV_BIN || "sovereign-vault";
const BOOT_TIMEOUT_S = Number(process.env.SV_BRIDGE_BOOT_TIMEOUT) || 5;
const PAIR_ENDPOINT_HOST = "127.0.0.1";
const PAIR_ENDPOINT_PORT = 9944;
const HTTP_PORT = 9943;

function log(...args) { process.stderr.write(`[sv-mcp-bridge] ${args.join(" ")}\n`); }

function httpGet(port, path) {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: PAIR_ENDPOINT_HOST, port, path, method: "GET", timeout: 1500 }, (res) => {
      let body = "";
      res.on("data", (c) => (body += c.toString("utf8")));
      res.on("end", () => resolve({ status: res.statusCode, body }));
    });
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.end();
  });
}

async function waitForGateway(seconds) {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) {
    try {
      const r = await httpGet(HTTP_PORT, "/.well-known/mcp-pairing");
      if (r.status === 200) return true;
    } catch {}
    await new Promise((res) => setTimeout(res, 200));
  }
  return false;
}

async function fetchPairingSecret() {
  const r = await httpGet(HTTP_PORT, "/.well-known/mcp-pairing");
  if (r.status !== 200) throw new Error(`pairing endpoint returned ${r.status}`);
  const parsed = JSON.parse(r.body);
  return parsed.secret || r.body.trim();
}

// Minimal WebSocket client (RFC 6455) — frame codec + handshake. We avoid
// the `ws` npm package so this stays zero-dependency.
const WS_OP_CONTINUATION = 0x0;
const WS_OP_TEXT = 0x1;
const WS_OP_CLOSE = 0x8;
const WS_OP_PING = 0x9;
const WS_OP_PONG = 0xa;

class WsClient {
  constructor(socket) { this.socket = socket; this.buffer = Buffer.alloc(0); this.onmessage = () => {}; this.onclose = () => {}; this.sendBuffer = []; this.opened = false; }
  static async connect(host, port, path, pairingSecret) {
    return new Promise((resolve, reject) => {
      const socket = netConnect({ host, port }, () => {
        const key = randomBytes(16).toString("base64");
        const req =
          `GET ${path} HTTP/1.1\r\n` +
          `Host: ${host}:${port}\r\n` +
          `Upgrade: websocket\r\nConnection: Upgrade\r\n` +
          `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n` +
          `Origin: http://localhost\r\n` +
          `Sec-WebSocket-Protocol: sovereign-vault-pair/${pairingSecret}\r\n\r\n`;
        socket.write(req);
      });
      let handshakeDone = false;
      const client = new WsClient(socket);
      socket.on("data", (chunk) => {
        if (!handshakeDone) {
          const combined = Buffer.concat([client.buffer, chunk]);
          const sep = combined.indexOf("\r\n\r\n");
          if (sep === -1) { client.buffer = combined; return; }
          const head = combined.subarray(0, sep).toString("utf8");
          if (!/101 Switching/i.test(head)) {
            socket.destroy();
            return reject(new Error(`ws upgrade failed: ${head.splitlines ? head.splitlines()[0] : head.split("\r\n")[0]}`));
          }
          handshakeDone = true;
          client.opened = true;
          const leftover = combined.subarray(sep + 4);
          client.buffer = Buffer.alloc(0);
          resolve(client);
          if (leftover.length > 0) client._ingest(leftover);
          socket.on("data", (c) => client._ingest(c));
        }
      });
      socket.on("error", reject);
      socket.on("close", () => { if (!handshakeDone) reject(new Error("ws closed before handshake")); client.onclose(); });
    });
  }
  _ingest(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (this.buffer.length >= 2) {
      const b0 = this.buffer[0]; const b1 = this.buffer[1];
      const op = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let plen = b1 & 0x7f;
      let off = 2;
      if (plen === 126) {
        if (this.buffer.length < off + 2) return;
        plen = this.buffer.readUInt16BE(off); off += 2;
      } else if (plen === 127) {
        if (this.buffer.length < off + 8) return;
        plen = Number(this.buffer.readBigUInt64BE(off)); off += 8;
      }
      const maskLen = masked ? 4 : 0;
      if (this.buffer.length < off + maskLen + plen) return;
      let payload = this.buffer.subarray(off + maskLen, off + maskLen + plen);
      if (masked) {
        const mask = this.buffer.subarray(off, off + 4);
        const out = Buffer.alloc(payload.length);
        for (let i = 0; i < payload.length; i++) out[i] = payload[i] ^ mask[i % 4];
        payload = out;
      }
      this.buffer = this.buffer.subarray(off + maskLen + plen);
      if (op === WS_OP_TEXT || op === WS_OP_CONTINUATION) {
        this.onmessage(payload.toString("utf8"));
      } else if (op === WS_OP_CLOSE) {
        this.socket.end();
        this.onclose();
      } else if (op === WS_OP_PING) {
        // Server→client pings; we can ignore (no pong required for liveness).
      }
    }
  }
  send(text) {
    const payload = Buffer.from(text, "utf8");
    const mask = randomBytes(4);
    let header;
    if (payload.length < 126) {
      header = Buffer.from([0x80 | WS_OP_TEXT, 0x80 | payload.length]);
    } else if (payload.length < 65536) {
      header = Buffer.alloc(4);
      header[0] = 0x80 | WS_OP_TEXT; header[1] = 0x80 | 126;
      header.writeUInt16BE(payload.length, 2);
    } else {
      header = Buffer.alloc(10);
      header[0] = 0x80 | WS_OP_TEXT; header[1] = 0x80 | 127;
      header.writeBigUInt64BE(BigInt(payload.length), 2);
    }
    const masked = Buffer.alloc(payload.length);
    for (let i = 0; i < payload.length; i++) masked[i] = payload[i] ^ mask[i % 4];
    this.socket.write(Buffer.concat([header, mask, masked]));
  }
  close() { try { this.socket.end(); } catch {} }
}

// node:net without breaking older node versions — require lazily.
async function bootHeadlessFallback() {
  let root; let passphrase;
  const agentId = process.env.SV_AGENT_ID;
  let agentToken = process.env.SV_AGENT_TOKEN;
  if (!agentToken && process.env.SV_AGENT_TOKEN_FILE) {
    const tokenFile = process.env.SV_AGENT_TOKEN_FILE;
    const mode = statSync(tokenFile).mode & 0o777;
    if ((mode & 0o077) !== 0) throw new Error("SV_AGENT_TOKEN_FILE must be owner-only (0600)");
    agentToken = readFileSync(tokenFile, "utf8").trim();
  }
  if (!agentId || !agentToken) {
    throw new Error("headless fallback requires SV_AGENT_ID and SV_AGENT_TOKEN (or SV_AGENT_TOKEN_FILE)");
  }
  if (process.env.SV_PASSPHRASE_FILE) {
    passphrase = readFileSync(process.env.SV_PASSPHRASE_FILE, "utf8").trim();
    root = process.env.SV_ROOT || defaultRoot();
    log("using passphrase-file mode (real vault)");
  } else if (process.env.SV_BRIDGE_TEST_ROOT) {
    root = process.env.SV_BRIDGE_TEST_ROOT;
    passphrase = process.env.SV_BRIDGE_TEST_PASS || "sovereign-vault-bridge-test";
    log("using test mode (NOT real vault)");
  } else {
    // Neither real-vault nor test-mode envs set. The user probably wants the
    // desktop app. Don't try to bootstrap.
    return null;
  }
  const sub = spawn(BIN, [
    "serve", "--root", root, "--passphrase-env", "SV_BRIDGE_PASS",
    "--bind", "127.0.0.1:9944", "--http-bind", "127.0.0.1:9943",
  ], { stdio: ["ignore", "ignore", "pipe"], env: { ...process.env, SV_BRIDGE_PASS: passphrase }, detached: false });
  return new Promise((resolve, reject) => {
    let buf = "";
    let stderrLineBuffer = "";
    let portBusy = false;
    const timer = setTimeout(() => reject(new Error("boot timeout")), BOOT_TIMEOUT_S * 1000);
    sub.stderr.on("data", (c) => {
      const text = c.toString("utf8");
      buf += text;
      stderrLineBuffer += text;
      const lastNewline = stderrLineBuffer.lastIndexOf("\n");
      if (lastNewline !== -1) {
        const completeLines = stderrLineBuffer.slice(0, lastNewline + 1);
        stderrLineBuffer = stderrLineBuffer.slice(lastNewline + 1);
        process.stderr.write(redactPairingSecretLines(completeLines));
      }
      // Detect "Address already in use" → headless can't run, but the desktop
      // (or another headless) is occupying the port. Signal the race caller.
      if (/Address already in use/i.test(text)) portBusy = true;
      if (/headless gateway is up/.test(buf)) {
        clearTimeout(timer);
        resolve({ child: sub, credential: { agentId, token: agentToken } });
      }
    });
    sub.on("exit", (code) => {
      clearTimeout(timer);
      if (stderrLineBuffer) process.stderr.write(redactPairingSecretLines(stderrLineBuffer));
      if (portBusy) reject(Object.assign(new Error("port busy"), { code: "PORT_BUSY" }));
      else reject(new Error(`serve exited (${code})`));
    });
  });
}

// Defense in depth: a future child must never cause a bearer pairing secret
// to be copied into this bridge's stderr, even if it accidentally logs one.
function redactPairingSecretLines(text) {
  return text
    .replace(/^.*pairing secret.*$/gim, "[sv-mcp-bridge] [REDACTED pairing secret]")
    .replace(/^\[serve\]\s+[A-Za-z0-9_-]{20,}\s*$/gm, "[serve] [REDACTED]");
}

function defaultRoot() {
  const home = process.env.HOME;
  return home ? `${home}/.local/share/sovereign-vault` : "/var/lib/sovereign-vault";
}

function desktopProcessRunning() {
  try {
    const out = execSync("pgrep -f sovereign-vault-desktop", { encoding: "utf8", timeout: 2000 });
    return out.trim().length > 0;
  } catch { return false; }
}

let headlessChild = null;

async function openWebSocket(credential) {
  // The WS subprotocol is not an authentication channel; pairing below is.
  const ws = await WsClient.connect(PAIR_ENDPOINT_HOST, PAIR_ENDPOINT_PORT, "/", "scoped-agent");
  // Send pair frame so the server considers us authenticated.
  const pairReq = {
    jsonrpc: "2.0",
    id: 1,
    method: "vault.pair",
    params: credential.agentId
      ? { agent_id: credential.agentId, token: credential.token }
      : { token: credential.token },
  };
  ws.send(JSON.stringify(pairReq));
  // Read the pair response from the WS (server replies before any other frames).
  const pairResp = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("pair response timeout")), 5000);
    ws.onmessage = (text) => {
      clearTimeout(timeout);
      try { resolve(JSON.parse(text)); } catch (e) { reject(e); }
    };
  });
  if (!pairResp.result || pairResp.result.paired !== true) {
    throw new Error(`pair rejected: ${JSON.stringify(pairResp)}`);
  }
  log(`paired as agent ${pairResp.result.agent_id || "(Default)"}`);
  return ws;
}

async function main() {
  log("probing gateway on 9944");
  // Buffer stdin BEFORE we have a WS so any frame opencode sends early
  // (notably `initialize`) is preserved and replayed after pairing.
  const pendingStdout = [];
  const pendingStdin = [];
  process.stdin.setEncoding("utf8");
  let stdinBuf = "";
  const stdinHandler = (chunk) => {
    stdinBuf += chunk;
    let nl;
    while ((nl = stdinBuf.indexOf("\n")) !== -1) {
      const line = stdinBuf.slice(0, nl);
      stdinBuf = stdinBuf.slice(nl + 1);
      if (line.trim().length === 0) continue;
      pendingStdin.push(line);
    }
  };
  process.stdin.on("data", stdinHandler);
  // We INTENTIONALLY don't listen for `end` — opencode holds its stdin pipe
  // open for the entire session; the only way for us to learn that the parent
  // has gone is SIGTERM/SIGINT or the WS server closing.

  const flushStdout = () => {
    while (pendingStdout.length > 0) {
      const text = pendingStdout.shift();
      const ok = process.stdout.write(text);
      if (!text.endsWith("\n")) process.stdout.write("\n");
      if (!ok) process.stdout.once("drain", flushStdout);
    }
  };
  // Belt-and-suspenders: keep stdout flowing in case the consumer is slow.
  if (process.stdout.writableNeedDrain === undefined) {
    process.stdout.on("drain", flushStdout);
  }

  let credential;
  const desktopRunning = desktopProcessRunning();
  if (desktopRunning) log("desktop process detected; waiting for unlock");

  // Start the headless fallback in PARALLEL with the desktop probe — but only
  // if the desktop process is NOT already running (otherwise headless will
  // fail to acquire the vault lock).
  const headlessRace = desktopRunning
    ? Promise.resolve(null)
    : bootHeadlessFallback().catch((e) => e);
  let desktopWins = await waitForGateway(desktopRunning ? BOOT_TIMEOUT_S : 1);
  if (desktopWins) {
    try {
      credential = { token: await fetchPairingSecret() };
      log("using live desktop pairing secret");
      const hb = await headlessRace;
      if (hb && hb.child) try { hb.child.kill("SIGTERM"); } catch {}
    } catch (e) {
      log(`desktop pairing failed (${e.message}); falling back to headless`);
      desktopWins = false;
    }
  }
  if (!desktopWins) {
    // Wait for either: the headless race, OR a real desktop to come up.
    // Whichever pairs first wins.
    log("no live gateway; awaiting any pairing source");
    let resolved = false;
    const tryHeadless = async () => {
      const hb = await headlessRace;
      if (resolved) return;
      if (hb && hb.child && hb.credential) {
        resolved = true;
        headlessChild = hb.child;
        credential = hb.credential;
        log("headless fallback is ready with its scoped agent credential");
      } else if (hb && hb.code === "PORT_BUSY") {
        // The port is in use — assume the desktop is coming up. Poll for it.
        if (!resolved && (await waitForGateway(BOOT_TIMEOUT_S))) {
          resolved = true;
          try {
            credential = { token: await fetchPairingSecret() };
            log("desktop gateway came up after waiting; using live pairing");
          } catch (e) {
            log(`desktop pairing after wait failed: ${e.message}`);
          }
        }
        if (!resolved) {
          log("headless could not bind (port busy) and desktop never appeared");
          process.exit(2);
        }
      } else if (hb) {
        log(`headless failed: ${hb.message || hb}`);
        // wait for desktop instead
        if (!resolved && (await waitForGateway(BOOT_TIMEOUT_S))) {
          resolved = true;
          try {
            credential = { token: await fetchPairingSecret() };
            log("desktop gateway came up; using live pairing");
          } catch (e) {
            log(`desktop pairing failed: ${e.message}`);
          }
        }
        if (!resolved) {
          log("no usable vault: headless failed and desktop not present");
          process.exit(2);
        }
      } else if (desktopRunning) {
        // Desktop process exists but vault is locked. Wait for unlock.
        if (!resolved && (await waitForGateway(BOOT_TIMEOUT_S))) {
          resolved = true;
          try {
            credential = { token: await fetchPairingSecret() };
            log("desktop unlocked; using live pairing");
          } catch (e) {
            log(`desktop pairing after unlock failed: ${e.message}`);
          }
        }
        if (!resolved) {
          log("desktop is running but vault did not unlock in time");
          process.exit(2);
        }
      }
    };
    await tryHeadless();
  }

  const ws = await openWebSocket(credential);
  log("ws connected and paired");

  // Hand the WS callbacks to the producers + drain any pre-queued frames.
  ws.onmessage = (text) => {
    pendingStdout.push(text);
    flushStdout();
  };
  ws.onclose = () => {
    log("ws closed by server or network");
    try { headlessChild?.kill("SIGTERM"); } catch {}
    setTimeout(() => process.exit(0), 100);
  };
  while (pendingStdin.length > 0) ws.send(pendingStdin.shift());
  process.stdin.removeListener("data", stdinHandler);
  process.stdin.on("data", (chunk) => {
    stdinBuf += chunk;
    let nl;
    while ((nl = stdinBuf.indexOf("\n")) !== -1) {
      const line = stdinBuf.slice(0, nl);
      stdinBuf = stdinBuf.slice(nl + 1);
      if (line.trim().length === 0) continue;
      ws.send(line);
    }
  });
}

main().catch((e) => { log("fatal:", e.message); process.exit(1); });

process.on("SIGTERM", () => { try { headlessChild?.kill("SIGTERM"); } catch {} process.exit(0); });
process.on("SIGINT", () => { try { headlessChild?.kill("SIGINT"); } catch {} process.exit(0); });
