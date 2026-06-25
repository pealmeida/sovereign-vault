#!/usr/bin/env node
import { spawn } from "node:child_process";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(here, "..");
const repoRoot = resolve(projectRoot, "../..");
const runId =
  process.env.SV_MOCK_RUN_ID ??
  new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
const containerPrefix = `mock_${runId}`;
const outDir = resolve(repoRoot, "target/mock-ai-project", runId);
const timeoutMs = Number(process.env.SV_MOCK_TIMEOUT_MS ?? 60000);
const isWindows = process.platform === "win32";
const exe = isWindows ? "sovereign-vault.exe" : "sovereign-vault";

function resolveCli() {
  if (process.env.SV_CLI) return process.env.SV_CLI;
  const release = resolve(repoRoot, "target/release", exe);
  const debug = resolve(repoRoot, "target/debug", exe);
  const candidates = [release, debug]
    .map((path) => {
      try {
        return { path, mtimeMs: statSync(path).mtimeMs };
      } catch {
        return null;
      }
    })
    .filter(Boolean)
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
  if (candidates.length) {
    return candidates[0].path;
  }
  return exe;
}

const cli = resolveCli();
let nextId = 1;

function b64(text) {
  return Buffer.from(text, "utf8").toString("base64");
}

function decodeB64(text) {
  return Buffer.from(text, "base64").toString("utf8");
}

function readToolPayload(response) {
  const text = response?.result?.content?.[0]?.text;
  if (typeof text !== "string") return undefined;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function summarizePayload(payload) {
  if (payload === undefined) return "";
  const raw = typeof payload === "string" ? payload : JSON.stringify(payload);
  return raw.length > 240 ? `${raw.slice(0, 237)}...` : raw;
}

function mcpCall(method, params, options = {}) {
  const id = nextId++;
  const frame = JSON.stringify({ jsonrpc: "2.0", id, method, params });
  const timeout = options.timeoutMs ?? timeoutMs;

  return new Promise((resolveCall) => {
    const child = spawn(cli, ["mcp-stdio"], {
      cwd: repoRoot,
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let settled = false;

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.kill();
      resolveCall(result);
    };

    const timer = setTimeout(() => {
      finish({
        ok: false,
        timeout: true,
        stderr,
        detail:
          "No MCP response before timeout. If a desktop approval prompt is visible, approve it and rerun this validation.",
      });
    }, timeout);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString("utf8");
      for (const line of stdout.split(/\r?\n/)) {
        if (!line.trim()) continue;
        try {
          const parsed = JSON.parse(line);
          if (parsed.id === id) {
            finish({ ok: true, response: parsed, stderr });
          }
        } catch {
          // Keep buffering; the proxy emits one JSON-RPC object per line.
        }
      }
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString("utf8");
    });
    child.on("error", (error) => {
      finish({ ok: false, stderr, detail: error.message });
    });
    child.on("exit", (code) => {
      if (!settled && code !== 0) {
        finish({ ok: false, stderr, detail: `mcp-stdio exited with code ${code}` });
      }
    });

    child.stdin.write(`${frame}\n`);
  });
}

function toolCall(name, args = {}, options = {}) {
  return mcpCall("tools/call", { name, arguments: args }, options);
}

function statusFromCall(result, options = {}) {
  if (!result.ok) {
    return {
      status: result.timeout ? "needs_human_approval_or_timeout" : "error",
      evidence: result.detail || result.stderr || "call failed",
    };
  }
  const response = result.response;
  if (response.error) {
    return {
      status: options.expectError ? "pass" : "error",
      evidence: response.error.message,
    };
  }
  if (response.result?.isError) {
    const payload = readToolPayload(response);
    if (options.expectedErrorIncludes) {
      const matched = String(payload).includes(options.expectedErrorIncludes);
      return {
        status: matched ? "pass" : "error",
        evidence: summarizePayload(payload),
        payload,
      };
    }
    return {
      status: options.expectError ? "pass" : "error",
      evidence: summarizePayload(payload),
      payload,
    };
  }
  const payload = readToolPayload(response);
  return { status: "pass", evidence: summarizePayload(payload), payload };
}

async function record(results, id, feature, call, options = {}) {
  const raw = await call();
  const status = statusFromCall(raw, options);
  results.push({
    id,
    feature,
    status: status.status,
    evidence: status.evidence,
    thesisTerms: options.thesisTerms ?? [],
  });
  return status;
}

function skipped(id, feature, evidence, thesisTerms = []) {
  return {
    id,
    feature,
    status: "skipped",
    evidence,
    thesisTerms,
  };
}

async function main() {
  mkdirSync(outDir, { recursive: true });

  const envContent = readFileSync(resolve(projectRoot, ".env.fake"), "utf8");
  const fakePii =
    "Fake customer Jane Example, email jane.example@example.test, CPF 529.982.247-25, card 4242 4242 4242 4242.";
  const transitPayload = "fake payload for vault transit validation";
  const signingPayload = "fake payload for vault signing validation";
  const toolResponse = await mcpCall("tools/list", {});
  const toolPayload = toolResponse.response?.result;
  const toolNames = Array.isArray(toolPayload?.tools)
    ? toolPayload.tools.map((tool) => tool.name)
    : [];
  const brokerEnabled = toolNames.includes("vault.create_broker_secret");

  const results = [];
  results.push({
    id: "DISCOVERY",
    feature: "MCP tool discovery",
    status: toolResponse.ok && toolNames.length > 0 ? "pass" : "error",
    evidence: `${toolNames.length} tools: ${toolNames.join(", ")}`,
    thesisTerms: ["MCP gateway", "artifact availability"],
  });

  const direct = `${containerPrefix}_direct`;
  const approval = `${containerPrefix}_approval`;
  const anon = `${containerPrefix}_anon`;
  const otp = `${containerPrefix}_otp`;

  const directCreate = await record(
    results,
    "C-DIRECT",
    "Create DIRECT project vault",
    () =>
      toolCall("vault.create_container", {
        name: direct,
        mode: "DIRECT",
        description: "Mock live AI project fake env data",
      }),
    { thesisTerms: ["T_hitl", "human consent"] },
  );

  const directReady = directCreate.status === "pass";
  if (!directReady) {
    results.push(
      skipped("F-ENV-WRITE", "Store fake provider .env", "DIRECT container was not created.", [
        "T_vault",
        "encrypted storage",
      ]),
      skipped("F-ENV-READ", "Read fake provider .env", "DIRECT container was not created.", [
        "T_vault",
        "agent retrieval",
      ]),
      skipped(
        "F-ENV-ROUNDTRIP",
        "Fake .env round-trip integrity",
        "DIRECT container was not created.",
        ["data integrity", "local custody"],
      ),
    );
  } else {
    await record(
    results,
    "F-ENV-WRITE",
    "Store fake provider .env",
    () =>
      toolCall("vault.write", {
        container: direct,
        file_name: "mock-ai.env",
        content_b64: b64(envContent),
      }),
    { thesisTerms: ["T_vault", "encrypted storage"] },
    );

    const readEnv = await record(
    results,
    "F-ENV-READ",
    "Read fake provider .env",
    () =>
      toolCall("vault.read", {
        container: direct,
        file_name: "mock-ai.env",
    }),
    { thesisTerms: ["T_vault", "agent retrieval"] },
    );
    const envRoundTrip =
      readEnv.payload?.content_b64 &&
      decodeB64(readEnv.payload.content_b64) === envContent;
    results.push({
      id: "F-ENV-ROUNDTRIP",
      feature: "Fake .env round-trip integrity",
      status: envRoundTrip ? "pass" : "error",
      evidence: envRoundTrip
        ? "Read content matches .env.fake exactly."
        : "Read content did not match .env.fake.",
      thesisTerms: ["data integrity", "local custody"],
    });
  }

  const approvalCreate = await record(
    results,
    "C-APPROVAL",
    "Create APPROVAL project vault",
    () =>
      toolCall("vault.create_container", {
        name: approval,
        mode: "APPROVAL",
        description: "Mock live AI project approval-gated data",
      }),
    { thesisTerms: ["T_hitl", "human consent"] },
  );

  if (approvalCreate.status !== "pass") {
    results.push(
      skipped(
        "F-APPROVAL-WRITE",
        "Approval-gated write",
        "APPROVAL container was not created.",
        ["T_hitl", "human consent"],
      ),
    );
  } else {
    await record(
    results,
    "F-APPROVAL-WRITE",
    "Approval-gated write",
    () =>
      toolCall("vault.write", {
        container: approval,
        file_name: "approval-note.txt",
        content_b64: b64("Fake approval-gated note for live project validation."),
    }),
    { thesisTerms: ["T_hitl", "human consent"] },
    );
  }

  const anonCreate = await record(
    results,
    "C-ANON",
    "Create ANONYMIZED project vault",
    () =>
      toolCall("vault.create_container", {
        name: anon,
        mode: "ANONYMIZED",
        description: "Mock live AI project PII egress masking",
      }),
    { thesisTerms: ["T_filter", "privacy mediation"] },
  );

  if (anonCreate.status !== "pass") {
    results.push(
      skipped("F-ANON-WRITE", "Store fake PII sample", "ANONYMIZED container was not created.", [
        "encrypted storage",
        "privacy mediation",
      ]),
      skipped(
        "F-ANON-READ",
        "ANONYMIZED read masks fake PII",
        "ANONYMIZED container was not created.",
        ["T_filter", "PII masking"],
      ),
      skipped("F-ANON-ASSERT", "PII redaction assertion", "ANONYMIZED container was not created.", [
        "T_filter",
        "privacy mediation",
      ]),
    );
  } else {
    await record(
    results,
    "F-ANON-WRITE",
    "Store fake PII sample",
    () =>
      toolCall("vault.write", {
        container: anon,
        file_name: "fake-customer.txt",
        content_b64: b64(fakePii),
    }),
    { thesisTerms: ["encrypted storage", "privacy mediation"] },
    );

    const anonRead = await record(
    results,
    "F-ANON-READ",
    "ANONYMIZED read masks fake PII",
    () =>
      toolCall("vault.read", {
        container: anon,
        file_name: "fake-customer.txt",
    }),
    { thesisTerms: ["T_filter", "PII masking"] },
    );
    const anonText = anonRead.payload?.content_b64
      ? decodeB64(anonRead.payload.content_b64)
      : "";
    results.push({
      id: "F-ANON-ASSERT",
      feature: "PII redaction assertion",
      status:
        anonText.includes("[REDACTED:EMAIL]") && !anonText.includes("jane.example@example.test")
          ? "pass"
          : "error",
      evidence: anonText || "No anonymized content returned.",
      thesisTerms: ["T_filter", "privacy mediation"],
    });
  }

  const otpCreate = await record(
    results,
    "C-OTP",
    "Create OTP project vault is challenged",
    () =>
      toolCall("vault.create_container", {
        name: otp,
        mode: "OTP",
        description: "Mock live AI project OTP challenge",
      }),
    {
      expectedErrorIncludes: "otp_required",
      thesisTerms: ["T_hitl", "cross-channel consent"],
    },
  );

  if (otpCreate.status === "pass" && otpCreate.payload?.name) {
    await record(
      results,
      "F-OTP-CHALLENGE",
      "OTP write without code is challenged",
      () =>
        toolCall("vault.write", {
          container: otp,
          file_name: "otp-note.txt",
          content_b64: b64("Fake OTP-gated note."),
        }),
      {
        expectedErrorIncludes: "otp_required",
        thesisTerms: ["T_hitl", "cross-channel consent"],
      },
    );
  } else {
    results.push(
      skipped(
        "F-OTP-CHALLENGE",
        "OTP write without code is challenged",
        "OTP container creation stopped at the expected one-time-code challenge.",
        ["T_hitl", "cross-channel consent"],
      ),
    );
  }

  if (!toolNames.includes("vault.create_transit_key")) {
    results.push(
      skipped(
        "T-CREATE",
        "Create transit key",
        "The connected MCP server does not expose vault.create_transit_key. Rebuild/relaunch the desktop app before validating this phase.",
        ["crypto intermediation", "no key exposure"],
      ),
      skipped(
        "T-ENCRYPT",
        "Transit encrypt fake payload",
        "Transit key creation tool is unavailable in the connected MCP server.",
        ["crypto intermediation", "no key exposure"],
      ),
      skipped(
        "T-DECRYPT",
        "Transit decrypt fake payload",
        "Transit key creation tool is unavailable in the connected MCP server.",
        ["crypto intermediation", "no key exposure"],
      ),
      skipped(
        "T-ROUNDTRIP",
        "Transit round-trip integrity",
        "Transit key creation tool is unavailable in the connected MCP server.",
        ["crypto intermediation", "no key exposure"],
      ),
    );
  } else {
    const transitCreate = await record(
      results,
      "T-CREATE",
      "Create transit key",
      () => toolCall("vault.create_transit_key", { name: `mk_${runId}` }),
      { thesisTerms: ["crypto intermediation", "no key exposure"] },
    );

    if (transitCreate.status !== "pass") {
      results.push(
        skipped("T-ENCRYPT", "Transit encrypt fake payload", "Transit key was not created.", [
          "crypto intermediation",
          "no key exposure",
        ]),
        skipped("T-DECRYPT", "Transit decrypt fake payload", "Transit key was not created.", [
          "crypto intermediation",
          "no key exposure",
        ]),
        skipped("T-ROUNDTRIP", "Transit round-trip integrity", "Transit key was not created.", [
          "crypto intermediation",
          "no key exposure",
        ]),
      );
    } else {
      const enc = await record(
        results,
        "T-ENCRYPT",
        "Transit encrypt fake payload",
        () =>
          toolCall("vault.encrypt", {
            key_ref: `mk_${runId}`,
            plaintext_b64: b64(transitPayload),
          }),
        { thesisTerms: ["crypto intermediation", "no key exposure"] },
      );

      const ciphertext = enc.payload?.ciphertext_b64;
      if (!ciphertext) {
        results.push(
          skipped("T-DECRYPT", "Transit decrypt fake payload", "Transit encrypt did not return ciphertext.", [
            "crypto intermediation",
            "no key exposure",
          ]),
          skipped(
            "T-ROUNDTRIP",
            "Transit round-trip integrity",
            "Transit encrypt did not return ciphertext.",
            ["crypto intermediation", "no key exposure"],
          ),
        );
      } else {
        const dec = await record(
          results,
          "T-DECRYPT",
          "Transit decrypt fake payload",
          () =>
            toolCall("vault.decrypt", {
              key_ref: `mk_${runId}`,
              ciphertext_b64: ciphertext,
            }),
          { thesisTerms: ["crypto intermediation", "no key exposure"] },
        );
        results.push({
          id: "T-ROUNDTRIP",
          feature: "Transit round-trip integrity",
          status:
            dec.payload?.plaintext_b64 && decodeB64(dec.payload.plaintext_b64) === transitPayload
              ? "pass"
              : "error",
          evidence: "Payload decrypts only through vault-held transit key.",
          thesisTerms: ["crypto intermediation", "no key exposure"],
        });
      }
    }
  }

  if (!toolNames.includes("vault.create_signing_key")) {
    results.push(
      skipped(
        "S-CREATE",
        "Create signing key",
        "The connected MCP server does not expose vault.create_signing_key. Rebuild/relaunch the desktop app before validating this phase.",
        ["crypto intermediation", "private key non-disclosure"],
      ),
      skipped(
        "S-SIGN",
        "Sign fake payload",
        "Signing key creation tool is unavailable in the connected MCP server.",
        ["crypto intermediation", "private key non-disclosure"],
      ),
      skipped(
        "S-VERIFY",
        "Verify fake payload signature",
        "Signing key creation tool is unavailable in the connected MCP server.",
        ["crypto intermediation", "private key non-disclosure"],
      ),
    );
  } else {
    const signKey = await record(
      results,
      "S-CREATE",
      "Create signing key",
      () => toolCall("vault.create_signing_key", { name: `ms_${runId}` }),
      { thesisTerms: ["crypto intermediation", "private key non-disclosure"] },
    );

    if (signKey.status !== "pass") {
      results.push(
        skipped("S-SIGN", "Sign fake payload", "Signing key was not created.", [
          "crypto intermediation",
          "private key non-disclosure",
        ]),
        skipped("S-VERIFY", "Verify fake payload signature", "Signing key was not created.", [
          "crypto intermediation",
          "private key non-disclosure",
        ]),
      );
    } else {
      const sig = await record(
        results,
        "S-SIGN",
        "Sign fake payload",
        () =>
          toolCall("vault.sign", {
            key_ref: `ms_${runId}`,
            payload_b64: b64(signingPayload),
          }),
        { thesisTerms: ["crypto intermediation", "private key non-disclosure"] },
      );

      const publicKey = sig.payload?.public_key_b64 ?? signKey.payload?.public_key_b64;
      if (publicKey && sig.payload?.signature_b64) {
        await record(
          results,
          "S-VERIFY",
          "Verify fake payload signature",
          () =>
            toolCall("vault.verify", {
              public_key_b64: publicKey,
              payload_b64: b64(signingPayload),
              signature_b64: sig.payload.signature_b64,
            }),
          { thesisTerms: ["crypto intermediation", "private key non-disclosure"] },
        );
      } else {
        results.push({
          id: "S-VERIFY",
          feature: "Verify fake payload signature",
          status: "skipped",
          evidence: "Signing did not return a signature/public key.",
          thesisTerms: ["crypto intermediation", "private key non-disclosure"],
        });
      }
    }
  }

  if (brokerEnabled) {
    await record(
      results,
      "B-CREATE",
      "Create fake brokered provider key",
      () =>
        toolCall("vault.create_broker_secret", {
          name: `openai_fake_${runId}`,
          secret: "sk-proj-FAKE_BROKER_DO_NOT_USE_000000",
          allow: [
            {
              host: "api.openai.com",
              path_prefix: "/v1",
              methods: ["POST"],
            },
          ],
          injection: { type: "bearer_auth" },
        }),
      { thesisTerms: ["broker", "no plaintext exposure"] },
    );

    await record(
      results,
      "B-NEGATIVE",
      "Broker blocks plain HTTP request",
      () =>
        toolCall("vault.broker_request", {
          secret_ref: `openai_fake_${runId}`,
          method: "POST",
          url: "http://api.openai.com/v1/responses",
        }),
      { expectError: true, thesisTerms: ["broker", "fail closed"] },
    );
  } else {
    results.push({
      id: "B-SKIP",
      feature: "Broker tools",
      status: "skipped",
      evidence: "Broker tools are disabled. Relaunch with SV_ENABLE_BROKER=1 to validate broker-secret creation.",
      thesisTerms: ["broker", "no plaintext exposure"],
    });
  }

  const summary = {
    runId,
    generatedAt: new Date().toISOString(),
    cli,
    projectRoot,
    repoRoot,
    fakeDataOnly: true,
    brokerEnabled,
    results,
  };

  writeFileSync(resolve(outDir, "feature-status.json"), JSON.stringify(summary, null, 2));
  writeFileSync(resolve(outDir, "feature-status.md"), renderMarkdown(summary));
  console.log(JSON.stringify(summary, null, 2));
  console.error(`\n[mock-ai-project] wrote ${resolve(outDir, "feature-status.md")}`);
}

function renderMarkdown(summary) {
  const lines = [
    "# Mock AI project feature status",
    "",
    `Run: \`${summary.runId}\``,
    "",
    "| ID | Feature | Status | Thesis / evaluation terms | Evidence |",
    "|---|---|---|---|---|",
  ];
  for (const item of summary.results) {
    lines.push(
      `| ${item.id} | ${escapeCell(item.feature)} | ${item.status} | ${escapeCell(
        item.thesisTerms.join(", "),
      )} | ${escapeCell(item.evidence)} |`,
    );
  }
  lines.push(
    "",
    "All fake credentials are from `examples/mock-ai-project/.env.fake` or generated in this script.",
    "Use this output as engineering evidence for live-project behavior; use `apps/thesis-eval` for controlled latency/adversarial measurements.",
    "",
  );
  return `${lines.join("\n")}\n`;
}

function escapeCell(value) {
  return String(value ?? "")
    .replace(/\r?\n/g, " ")
    .replace(/\|/g, "\\|");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
