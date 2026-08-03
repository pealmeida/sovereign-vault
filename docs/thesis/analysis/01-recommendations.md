# Prioritized paper-revision recommendations

This is an edit plan for the proposal-stage paper, not a code-fix plan. Priority follows the blocking evidence in [00-code-review.md](00-code-review.md). The replacement text is intentionally in Portuguese so it can be adapted into the thesis.

## P0 — claims to correct or remove before presenting results

### P0.1 Replace the OS-level memory-isolation research question

**What to change.** Replace RQ3 (§1.3) and every answer that treats Rust as OS isolation.

**Why.** The MCP gateway and vault handle run in the same desktop process (`apps/desktop/src-tauri/src/lib.rs:1626-1658`); the implementation has no separate service account/process, sandbox, VM, TEE, namespace, or MAC policy. Rust’s source-level unsafe prohibition (`Cargo.toml:26-27`) is not OS memory isolation. [Finding 1.4](00-code-review.md#14-rq3-conflates-language-safety-with-os-level-isolation-the-artifact-does-not-provide-os-process-isolation).

**Replacement wording.**

> RQ3 — Como autenticação local, escopos de capacidade, consentimento humano e auditoria com evidência de adulteração reduzem acessos laterais por agentes MCP comprometidos, dentro de um modelo de ameaça de usuário único e máquina única?

Add a limitation immediately after it:

> O artefato não implementa isolamento de memória no nível do sistema operacional. Processos que executam com a mesma conta do usuário e comprometimentos do sistema operacional permanecem fora do limite de segurança avaliado.

### P0.2 Soften the Rust memory-safety claim and remove the unsubstantiated Tauri comparison

**What to change.** Revise §§2.5 and 3.8; do not say Rust “eliminates” the memory-corruption exfiltration class for the delivered system, and do not claim that Tauri independently minimizes injection surface or runs independent sandboxes.

**Why.** First-party workspace crates forbid unsafe code, but Tauri/WebKit and native keychain integrations are transitive native/FFI surfaces (`apps/desktop/src-tauri/Cargo.toml:25-27`; `crates/sv-keychain/Cargo.toml:13`; `crates/sv-keychain/src/lib.rs:108-118`). The actual desktop configuration demonstrates CSP and capability restrictions, not a comparative security experiment (`apps/desktop/src-tauri/tauri.conf.json:24-26`; `apps/desktop/src-tauri/capabilities/default.json:1-9`). [Findings 1.1–1.3](00-code-review.md#1-memory-safety-tauri-and-the-rq3-isolation-claim).

**Replacement wording.**

> O código Rust próprio do artefato é compilado com proibição de `unsafe`, reduzindo classes de corrupção de memória no código de aplicação auditado. Essa propriedade não se estende automaticamente a dependências nativas, WebView, sistema operacional, kernel ou processos sob a mesma conta do usuário.

> A interface foi implementada em Tauri com CSP e capacidades explícitas. O presente estudo não mede comparativamente a superfície de injeção ou o isolamento de segurança em relação ao Electron.

### P0.3 Restrict the private-key “never exposed” claim and disclose oracle limitations

**What to change.** Replace the absolute sentence in §3.6.3/§3.7 about signing/encrypting “sem que [a chave] jamais seja revelada ou exposta” with a protocol-output claim plus a mediation limitation.

**Why.** The raw private seed is wrapped and not returned (`crates/sv-core/src/transit.rs:368-392`; `crates/sv-mcp/src/lib.rs:1729-1740`), which is real. Desktop asks for a click for transit/signing operations (`apps/desktop/src-tauri/src/lib.rs:764-784`), but the UI does not expose `key_ref` or a payload identity to the approver (`ui/src/lib/types.ts:39-47`; `ui/src/components/ApprovalModal.svelte:29-42`). Worse, headless mode allows mode-less crypto operations and drops every persisted agent scope (`apps/cli/src/serve.rs:188-208,227-253`), while empty scopes are full access (`crates/sv-mcp/src/lib.rs:1854-1857`). [Findings 4.1–4.2](00-code-review.md#4-privacy-mediation-363).

**Replacement wording.**

> Nas operações MCP documentadas, a semente privada e as chaves simétricas não são retornadas ao agente; somente assinatura, cifra ou texto decifrado são retornados após autorização. No modo desktop, operações de trânsito e assinatura exigem aprovação por operação. Esta versão não fornece autorização por chave/uso nem apresenta ao usuário uma descrição verificável do conteúdo a ser assinado ou decifrado; o modo headless está fora dessa garantia de mediação humana.

### P0.4 Replace “PII masking” as a general guarantee with an exact coverage statement

**What to change.** Constrain §3.6.3, §3.9.2, and LGPD-oriented prose to the detector set actually implemented.

**Why.** The detector set is email, CPF, CNPJ, Luhn-valid card, IPv4, formatted phone, and US SSN (`crates/sv-privacy/src/lib.rs:46-77,205-232`). It has no RG, CEP, full-name, address, or bare-phone detector; phones are deliberately restrictive (`crates/sv-privacy/src/lib.rs:480-520`). [Finding 4.3](00-code-review.md#43-pii-coverage-is-narrow-and-heuristic-brazilian-rg-cep-full-names-addresses-and-bare-phones-are-not-covered).

**Replacement wording.**

> O protótipo aplica mascaramento heurístico de e-mail, CPF, CNPJ, números de cartão validados por Luhn, IPv4, telefones explicitamente formatados e SSN. A versão avaliada não detecta RG, CEP, nomes completos, endereços, datas de nascimento ou telefones locais não formatados; portanto o mecanismo reduz exposição, mas não constitui garantia de anonimização ou conformidade LGPD por si só.

### P0.5 Correct the audit-log claim

**What to change.** In §3.6.4, remove “append-only” if it means immutable/non-rollbackable, and replace “hash-chained” with the actual construction.

**Why.** The log uses domain-separated HMAC-SHA256 records and a signed local checkpoint (`crates/sv-audit/src/lib.rs:977-1056,545-617`), which detects modification/truncation relative to that checkpoint. A complete rollback of directory plus prior checkpoint remains valid because no external anchor is written. [Finding 5.2](00-code-review.md#52-the-audit-log-is-hmac-chained-and-fail-closed-on-detected-changes-but-it-is-not-append-only-against-rollback-and-lacks-an-external-trust-anchor).

**Replacement wording.**

> O artefato mantém registros encadeados por HMAC-SHA256 e verificados contra um checkpoint autenticado local. O mecanismo fornece evidência de adulteração, remoção e truncamento em relação ao checkpoint presente, mas não detecta rollback completo sem uma âncora externa confiável, como log de transparência remoto ou contador monotônico protegido.

## P0 — threat model and deployment boundaries to add

### P0.6 Add a threat-model box to Chapters 1 and 3

**What to change.** Add a one-page “limites de segurança e ativos fora de escopo” subsection before/after §3.7.

**Why.** The existing threat model correctly treats the local OS user/keychain as trusted (`docs/threat-model.md:29-35`), but the paper presently reads more broadly. Same-user malware, raw memory scraping, local pairing-secret retrieval, OS compromise, cloud retention, metadata leakage, audit rollback, and the native dependency TCB are not solved by the artifact. [Findings 1.1, 1.4, 2.2, 5.2](00-code-review.md#1-memory-safety-tauri-and-the-rq3-isolation-claim).

**Structure / replacement text.**

> **Modelo de ameaça e limites.** O estudo avalia um usuário, uma máquina e um gateway local desbloqueado. O adversário principal é um agente MCP autenticado e potencialmente comprometido. O estudo não assume proteção contra comprometimento do sistema operacional, processo com a mesma conta do usuário, inspeção de memória, dependências nativas vulneráveis, retenção de dados pelo provedor de IA ou rollback completo do diretório do cofre. A confidencialidade em repouso protege o conteúdo cifrado; nomes/metadados operacionais podem permanecer visíveis.

Include a deployment caveat:

> Os resultados de menor privilégio e de mediação humana referem-se ao gateway desktop WebSocket avaliado. O modo headless não deve ser usado como evidência dessa propriedade na versão corrente.

## P1 — Equation 1 and evaluation method

### P1.1 Replace Equation 1 with a conditional, observable model

**What to change.** Revise §3.9.1’s equation and its prose; do not present human approval, WAN, and cloud inference as one measured fixed sum of artifact latency.

**Why.** Gateway code measures only internal stages and sums `validate + authorize + execute + filter` (`crates/sv-mcp/src/lib.rs:550-587,1202-1225`). `AutoAllow` explicitly excludes human reaction time (`apps/thesis-eval/src/main.rs:123-138`). DIRECT/ANONYMIZED do not prompt (`apps/desktop/src-tauri/src/lib.rs:786-800`). [Finding 6.1](00-code-review.md#61-equation-1-is-not-a-fixed-additive-artifact-latency-it-mixes-different-populations-and-unmeasured-external-terms).

**Replacement wording / structure.**

Use two equations:

> Para uma leitura local mediada, define-se `T_gateway = T_parse+validação+escopo + T_cofre + I_anôn(T_mascaramento) + I_consentimento(T_espera_humana + T_despacho)`, onde `I` é 1 somente quando o modo correspondente é aplicado.

> Para uma experiência fim a fim com modelo remoto, `T_e2e = T_gateway + T_cliente↔WAN + T_inferência + T_rede_resposta`. Os dois últimos termos não são observáveis pelo gateway e devem ser medidos em experimento separado, com limites temporais explicitados.

Report `T_espera_humana` as median, p95, timeout/denial rate for APPROVAL/OTP—not as a microsecond overhead.

### P1.2 Reframe current latency results as a synthetic local microbenchmark

**What to change.** Put a methodology table immediately before results and change the result caption.

**Why.** The harness creates a temporary passphrase vault and seeds four modes × three synthetic sizes (`apps/thesis-eval/src/main.rs:98-117,407-474`); it executes real local stdio reads with `AutoAllow` (`apps/thesis-eval/src/main.rs:431-501`). The current CSV has `N=1,000` in each of 12 cells (`target/thesis-eval/latency.csv:1-61`) but has no self-contained environment manifest. [Finding 6.2](00-code-review.md#62-what-the-latency-harness-actually-measures-and-what-the-checked-in-csv-represents).

**Replacement structure.**

| Field | State in current evidence |
|---|---|
| Unit of analysis | one synthetic `vault.read` through local stdio gateway |
| Conditions | DIRECT, APPROVAL-AutoAllow, OTP-AutoAllow, ANONYMIZED |
| Payloads | 128 B, 1 KiB, 16 KiB |
| N | 1,000 requests per cell in checked-in CSV |
| Measured | validate/scope, controller-dispatch, local vault read, PII filter |
| Not measured | human decision time, WAN, cloud inference, production workload, task utility |

Use this caption:

> “Microbenchmark sintético de leitura local mediada (N=1.000 por célula; AutoAllow; resultados dependentes de host). Os valores não representam latência fim a fim nem tempo de decisão humana.”

Add a reproducibility appendix specifying command, git commit, release/debug profile, OS/kernel, CPU, RAM, storage, rustc, power mode, and raw CSV checksum.

### P1.3 Reframe the 100% adversarial result and state its external-validity ceiling

**What to change.** Rewrite §3.9.2’s outcome language and put the static corpus in an appendix/table.

**Why.** The harness uses exactly ten source-defined requests plus two controls (`apps/thesis-eval/src/main.rs:682-780`), counts an error (including transport/pairing error) as a block (`apps/thesis-eval/src/main.rs:789-804,857-862`), and reports 10/10 and 2/2 (`target/thesis-eval/adversarial.md:3-18`). It contains no external model, adaptive attack loop, or statistical sampling. [Finding 7.1](00-code-review.md#71-the-100-rate-is-a-finite-scripted-request-battery-not-a-prompt-injection-efficacy-estimate).

**Replacement wording.**

> Em uma execução de uma bateria pré-especificada de 10 chamadas JSON-RPC maliciosas, o gateway bloqueou 10/10, enquanto 2/2 controles legítimos foram aceitos. O resultado demonstra cobertura dos controles modelados (escopo, validação de caminho e política de consentimento); não estima a taxa de bloqueio de prompt injection em população de ataques, nem a robustez contra adversário adaptativo ou fluxo de exfiltração por operações permitidas.

Add this external-validity sentence:

> As “injeções de prompt” são simuladas pelo efeito final—chamadas de ferramenta—e não por um LLM real submetido a conteúdo adversarial; por isso a validade externa restringe-se ao protocolo e às negativas enumeradas.

## P1 — two-arm design required by Objective 4

### P1.4 Either remove the cloud comparator, or add a genuine two-arm experiment

**What to change.** Resolve the contradiction between Objective 4 and the actual harness.

**Why.** Objective 4 says “em comparação com modelos tradicionais em nuvem,” but the binary only has `latency`, `micro`, and `adversarial` (`apps/thesis-eval/src/main.rs:71-79`) and explicitly excludes WAN/inference (`apps/thesis-eval/src/main.rs:533-562`). [Finding 8.1](00-code-review.md#81-objective-4-promises-a-cloud-comparison-that-neither-paper-plan-nor-harness-contains).

**Option A — defensible now (recommended).** Replace Objective 4 with:

> Avaliar, em ambiente controlado, a latência interna do gateway local e a cobertura de bloqueio de uma bateria pré-especificada de tentativas de acesso não autorizado.

**Option B — future two-arm structure.** If the cloud comparison is mandatory, add a Chapter 3 protocol before claiming any result:

1. Use a fixed, approved synthetic corpus and paired task/prompt set.
2. Arm A: the same model accesses data only through the local gateway under predeclared modes/scopes.
3. Arm B: the same model/version/region receives the same baseline material directly from a cloud storage/context path.
4. Collect paired end-to-end latency, task success/quality, unauthorized disclosure, PII recall/precision, cost, network failures, and approval outcomes.
5. Pin model/version, region, network conditions, prompts, seed where available, and retention settings; repeat enough times for confidence intervals.
6. State that the current harness supplies part of Arm A only. A cloud adapter, telemetry, baseline policy, data governance protocol, and statistical analysis are still required.

## P1 — RQ/objective/artifact alignment

### P1.5 Narrow the artifact’s empirical scope to secrets/credentials

**What to change.** Add a scope statement in §1.4, §3.5, §3.6, and the conclusion of Chapter 3; revise RQ1 language if it implies implemented RAG/context retrieval.

**Why.** The repository’s own traceability calls the instantiation secrets/credentials-only (`docs/thesis/TRACEABILITY.md:13-17`); context containers, local embedding, ANN index, and `vault.search` are only proposed in ADR-0012 (`docs/adr/0012-context-containers.md:10-18`). The current gateway exposes named file operations, not local RAG. [Finding 8.2](00-code-review.md#82-rq--objective--artifact-gaps).

**Replacement wording.**

> A instância empírica do Sovereign Vault restringe-se ao controle de credenciais e segredos locais identificados por contêiner e arquivo. Ela é usada como demonstração do padrão de mediação; indexação vetorial, recuperação semântica de documentos e processamento local de embeddings não fazem parte do artefato avaliado.

For RQ1, use:

> Como um gateway MCP local pode mediar e reduzir a exposição de leituras nomeadas de segredos/credenciais por agentes externos?

## P2 — precise results chapter that current evidence can honestly support

### P2.1 Add a “what the data support / do not support” results subsection

**What to change.** Begin Chapter 4 with an evidence boundary table.

**Why.** It prevents traceability drift such as the current “15 tools” and completed cloud-objective statement (`docs/thesis/TRACEABILITY.md:44-55`) and distinguishes genuine code paths from claims beyond the artifact. [Findings 3.1, 8.1–8.2](00-code-review.md#3-mcp-gateway-362).

**Suggested table.**

| Claim | Evidence that may be reported | Qualification that must accompany it |
|---|---|---|
| Encrypted local secret storage | XChaCha20-Poly1305; Argon2id KEK; DEK keyring | no per-container keys; metadata remains visible |
| Desktop MCP mediation | scopes + approval/OTP + audit pipeline | only desktop WS path; headless is excluded pending remediation |
| No key-byte return | transit/signing tool implementation | does not preclude output-oracle misuse |
| PII reduction | seven named heuristic categories in ANONYMIZED read egress | not generic PII/LGPD anonymization; text-only egress |
| Local gateway overhead | current N=1,000 synthetic microbenchmark | no human, WAN, inference, cloud baseline, or utility measurement |
| Adversarial result | 10/10 specified request probes, 2/2 controls | no adaptive LLM attacker or population block-rate inference |

### P2.2 Report the present numbers accurately, with both central tendency and limitations

**What to change.** Include the current local figures only under a clearly titled controlled microbenchmark.

**Why.** The values are present in the generated artifact (`target/thesis-eval/latency.md:7-18`; `target/thesis-eval/adversarial.md:3-18`) and follow actual timing/probe code, but they are not end-to-end cloud measurements. [Findings 6.2, 7.1](00-code-review.md#6-latency-model-and-observed-measurements-391).

**Suggested Results text.**

> No hoste Linux registrado, a leitura local DIRECT apresentou médias de 14,70 µs (128 B), 17,77 µs (1 KiB) e 36,64 µs (16 KiB), com N=1.000 por célula. Para ANONYMIZED, as médias foram 15,74 µs, 26,07 µs e 189,79 µs, evidenciando custo crescente do mascaramento heurístico sobre o conteúdo sintético. APPROVAL e OTP foram executados com AutoAllow; seus valores de aproximadamente 14–35 µs não representam o tempo de decisão humana. A bateria de chamadas de ferramenta bloqueou 10/10 solicitações maliciosas pré-definidas e aceitou 2/2 controles. Esses resultados sustentam comportamento do gateway no conjunto avaliado, não superioridade sobre serviços de nuvem nem resistência geral a prompt injection.

### P2.3 Correct the component/tool inventory and mode semantics

**What to change.** Update §3.6 and any figures/tables.

**Why.** The MCP surface is 17 base tools plus three optional broker tools (20 when broker is enabled) (`crates/sv-mcp/src/lib.rs:2152-2449`), not 15. ANONYMIZED is auto-allow + mask-on-read, and ZKP/NATIVE are declared but rejected in live desktop MCP (`apps/desktop/src-tauri/src/lib.rs:786-805`; `crates/sv-mcp/src/lib.rs:1159-1199`). [Findings 3.1, 4.4, 5.1](00-code-review.md#31-the-actual-tool-surface-is-broader-than-the-traceability-document-reports).

**Replacement wording.**

> A superfície MCP da versão analisada expõe 17 ferramentas-base e três ferramentas de broker condicionais (20 no total quando o broker está habilitado). Os modos de contêiner efetivamente suportados no desktop são DIRECT, APPROVAL, OTP e ANONYMIZED; ANONYMIZED realiza mascaramento de saída em leituras UTF-8 e não solicita aprovação. ZKP e NATIVE são valores de enumeração reservados/rejeitados, não mecanismos de isolamento avaliados.

## P2 — limitations to list explicitly as future work, not completed capabilities

1. Correct headless scope preservation and require fail-closed approval for all modeless secret-bearing operations before evaluating/deploying it as a secure gateway (`apps/cli/src/serve.rs:188-208,227-253`).
2. Bind crypto authorization to a displayed key reference, payload hash, operation semantics, recipient/domain where applicable, and agent identity—not merely an opaque “Sign/Decrypt” click (`ui/src/components/ApprovalModal.svelte:29-42`; `crates/sv-mcp/src/lib.rs:489-496`).
3. Add per-container key hierarchy or explicitly retain logical-only segmentation; add cross-platform OS access-control evaluation (`crates/sv-storage/src/lib.rs:520-535,950-1015`).
4. Expand/evaluate PII detectors with precision/recall against Brazilian datasets, including RG/CEP/names/addresses; do not claim coverage until then (`crates/sv-privacy/src/lib.rs:46-77`).
5. Add an external audit-head anchor if rollback resistance is a claimed property (`crates/sv-audit/src/lib.rs:647-727`).
6. Build the stated two-arm cloud design and a real human-consent study before answering cloud comparison or human-latency questions.
