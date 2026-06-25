#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const envPath = resolve(here, "../.env.fake");

function parseEnv(raw) {
  const vars = {};
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const index = trimmed.indexOf("=");
    if (index === -1) continue;
    vars[trimmed.slice(0, index)] = trimmed.slice(index + 1);
  }
  return vars;
}

function mask(value) {
  if (!value) return "missing";
  if (value.length <= 12) return `${value.slice(0, 2)}...`;
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
}

const vars = parseEnv(readFileSync(envPath, "utf8"));
const providers = [
  ["OpenAI", "OPENAI_API_KEY"],
  ["Anthropic", "ANTHROPIC_API_KEY"],
  ["Google AI", "GOOGLE_AI_API_KEY"],
  ["Mistral", "MISTRAL_API_KEY"],
];

const report = {
  project: "sovereign-vault-mock-ai-project",
  mode: "local-fake-no-network",
  providerKeys: Object.fromEntries(
    providers.map(([provider, key]) => [
      provider,
      {
        env: key,
        present: Boolean(vars[key]),
        masked: mask(vars[key]),
      },
    ]),
  ),
  operationalSecrets: {
    DATABASE_URL: mask(vars.DATABASE_URL),
    WEBHOOK_SIGNING_SECRET: mask(vars.WEBHOOK_SIGNING_SECRET),
  },
};

console.log(JSON.stringify(report, null, 2));
