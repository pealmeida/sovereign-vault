# Resultados v2 — medições sobre o artefato real

**Commit avaliado:** `9d05c9fee791c57f56f8caf45d3874c072f9f609` (HEAD, branch `main`)
**Data:** 2026-08-06 · **Máquina:** Intel Core i7-11600H, 12 threads, 32 GiB RAM, kernel 7.0.0-29-generic
**Toolchain:** `rustc 1.96.1 (31fca3adb 2026-06-26)`, perfil `release` (`lto="thin"`, `codegen-units=1`, `strip=true`)
**Governor:** `powersave` em todos os núcleos, turbo habilitado (`intel_pstate/no_turbo=0`). Não há `sudo` sem senha
neste ambiente para alternar para `performance`; todas as medições abaixo foram coletadas sob `powersave`. Isso
infla a variância absoluta mas não deveria enviesar comparações dentro-de-máquina entre braços/modos, que são o
objeto de todas as inferências aqui.

## Nota sobre artefatos provisórios citados no briefing

O briefing que originou esta execução referencia quatro arquivos como já existentes no repositório:
`RESULTS-V2.md` (com os três blocos de prosa a revisar), `probe_coverage_matrix.csv`, `probe_taxonomy.csv` e uma
lista enumerada de "8 itens do revisor". Nenhum desses arquivos existe neste repositório
(`find` confirmou: zero resultados para `RESULTS-V2*`, `probe_coverage_matrix*`, `probe_taxonomy*` em todo o
histórico do diretório de trabalho). Eles existiram apenas na conversa anterior que produziu o briefing, não como
artefato versionado. Consequentemente:

- `probe_coverage_matrix.csv` e `probe_taxonomy.csv` foram **construídos do zero** a partir da superfície real de
  ferramentas MCP (`crates/sv-mcp/src/lib.rs`), não "corrigidos" a partir de um rascunho.
- Os três blocos de prosa (§4.2, §5.2.2/QP2, resumo) foram **escritos do zero** com números do artefato, não
  revisados a partir de `RESULTS-V2.md`.
- A numeração "item do revisor 1–8" não pôde ser reconciliada, com uma exceção: o briefing referencia
  explicitamente "reviewer item 5" três vezes, sempre ligado a `enforce_scopes` no caminho WebSocket autenticado —
  esse mapeamento é seguido abaixo. Os demais são organizados pelos cinco experimentos (E1–E5) do próprio
  briefing, que têm conteúdo textual detalhado e verificável.

## Tabela de proveniência

| Item | Medido no artefato? | Evidência |
|---|---|---|
| Inversão sistemática 6/6 (achado prévio, §0) | Não re-medido (fora de escopo desta rodada — assumido conforme instrução) | herdado |
| E1 — microbenchmark corrigido | **Sim**, k=10, n=1000 | `latency_v2.csv`, `latency_v2_paired_diffs.csv` |
| E2 — ablação ordem×warmup | **Sim**, 4 braços × k=5, n=1000 | `order_ablation.csv`, `order_ablation_contrast_ci.csv`, `order_ablation_position_effect.csv` |
| E3 — enforce_scopes no WS autenticado | **Sim**, k=5, n=1000 | `enforce_scopes.csv`, `enforce_scopes_stages.csv` |
| E4 — caracterização do filtro PII real | **Sim** (determinístico, sem necessidade de k sessões) | `pii_filter_characterization.csv`, `pii_format_robustness.csv`, `pii_cost_size_x_density.csv`, `pii_cost_fit.csv` |
| E5 — bateria de sondas contra a CLI headless real | **Sim**, subprocesso real `sovereign-vault serve` | `headless_probes.csv`, `probe_taxonomy.csv`, `probe_coverage_matrix.csv` |
| Cadeia de auditoria HMAC (E5) | **Sim**, verificada contra o artefato real (`sv_audit::AuditLog::verify_chain`) | 12 entradas, `ok=true` |
| Bateria original A1–A10/C1–C2 (contra `HitlPolicy` simulada) | Sim, re-executada para completude do `probe_taxonomy.csv` | `raw/e5/adversarial/adversarial.csv` |
| Bypass de código do `enforce_scopes` (E3) | **NÃO MEDIDO** — deliberadamente não construído (ver §E3) | — |
| Braço B do EVAL-PROTOCOL.md (cloud-direct) | NÃO MEDIDO — não existe adaptador de nuvem no repositório | `EVAL-PROTOCOL.md` §Estado |

---

## 1. Verificação de ambiente e auditoria do harness

### 1.1 Ambiente

Confirmado: `git rev-parse HEAD` = `9d05c9fee791c57f56f8caf45d3874c072f9f609`; `cargo build --release -p thesis-eval`
e `cargo build --release -p sovereign-vault` compilam limpos; `cargo test -p thesis-eval --release` — 5/5 testes
passam (incluindo após as extensões desta rodada).

### 1.2 Trechos citados pela tese — todos confirmados existentes na HEAD

| Citação | Confirmado |
|---|---|
| `crates/sv-mcp/src/lib.rs:2370-2380,2461-2699` (superfície de ferramentas MCP) | Sim — `tool_descriptors`/`base_tool_descriptors` |
| `crates/sv-privacy/src/lib.rs:49-64,206-233,483-575` (categorias PII) | Sim — `PiiCategory`, `scan`, `find_phones`/`find_ssns` |
| `crates/sv-mcp/src/lib.rs:2156-2165` (enum de modo / `mode_rank`) | Sim |
| `apps/desktop/src-tauri/src/lib.rs:772-819` (ZKP/NATIVE rejeitados) | Sim — `approval_requirement` retorna `Err` para ambos |
| `crates/sv-audit/src/lib.rs:545-727,977-1056` (cadeia de auditoria) | Sim — `AuditLog::record`, `sign_record` |
| `apps/cli/src/serve.rs` (fail-closed headless) | Sim — mas ver §1.4: a política real não é a que a bateria original simula |

### 1.3 Divergência entre `EVAL-PROTOCOL.md` e o harness implementado

O protocolo documentado (`docs/thesis/EVAL-PROTOCOL.md`) já declara seu próprio estado como parcial: só o Braço A
(microbenchmark local + sondas de gateway) existe; não há Braço B (cloud-direct), adaptador de nuvem, estudo
humano ou baseline comparativo. As "Extensões pós-peer-review" do protocolo (linhas 50–60) pedem exatamente o que
esta rodada entrega: `k≥3` sessões independentes com bootstrap (E1/E2 aqui usam k=10 e k=5), registro de
resposta/classe/evento de auditoria por sonda (E5) e uma bateria contra o `ApprovalState` real do desktop — que
**não foi** o que se mediu aqui (ver §1.4: mediu-se a CLI headless real, `apps/cli`, não o `ApprovalState` do
Tauri, que exigiria a aplicação desktop completa e uma UI). Isso é uma lacuna residual que permanece
**NÃO MEDIDO** por esta rodada.

### 1.4 As cinco perguntas do harness — respostas verificadas em código

1. **Ordem fixa?** Sim. `latency_cells(seed: None)` preserva a ordem de declaração
   (`direct,128 → direct,1024 → direct,16384 → approval,... → anon,16384`) — exatamente a ordem de apresentação
   da Tabela 5, confirmado pelo teste `absent_seed_preserves_the_original_cell_order`. Randomização só ocorre
   com `--seed`.
2. **Warmup descartado?** Depende do valor. O *default* da CLI é `--warmup 0`; em `run_latency`, o bloco de
   aquecimento só executa `if warmup > 0` (apps/thesis-eval/src/main.rs, antes desta rodada) — ou seja, a
   invocação padrão **não descarta nenhuma chamada** no braço de latência via gateway (diferente do subcomando
   `micro`, que sempre descarta ≥1 chamada por um piso hardcoded). Isso é diferente do que o comentário de
   `--warmup` no topo do arquivo sugere à primeira leitura ("ainda descarta essa única chamada") — essa garantia
   vale para `micro`, não para `latency`.
3. **Cronômetro por chamada ou por lote? Qual relógio?** Por chamada, `std::time::Instant` (monotônico),
   instrumentado dentro de `McpServer::call_tool` (`crates/sv-mcp/src/lib.rs:1280` em diante) — um `StageTimings`
   por chamada, confirmado empiricamente (n chamadas → n registros no `TimingSink`).
4. **Um processo para os quatro modos, ou um por modo?** Um único processo; um novo `McpServer` (mas o mesmo
   `Arc<Mutex<VaultHandle>>`) é construído por célula (modo×tamanho), 12 vezes por sessão.
5. **Há setup dentro da região cronometrada?** Não fica evidente no código analisado que haja setup por célula
   dentro do laço medido — containers e arquivos são semeados uma única vez, antes de todas as 12 células. **Mas**
   uma descoberta desta rodada (§1.5) mostra que o próprio *cronômetro* tem uma lacuna estrutural.

### 1.5 Achado não solicitado, mas relevante: `T_total` exclui o custo do audit-write

`StageTimings.total = validate + authorize + execute + filter` (`crates/sv-mcp/src/lib.rs:1490`) — uma **soma**
dos quatro sub-estágios, não um relógio de parede fim-a-fim. Só que o audit-write obrigatório de pré-execução
(`self.record_audit(&access, AuditDecision::Attempted, ...)`, linha 1345) ocorre **depois** de `authorize` ser
capturado (linha 1340) e **antes** de `execute_started` ser criado (linha 1371) — no intervalo entre os dois. O
custo dessa escrita de auditoria nunca é atribuído a nenhum dos quatro buckets, então `T_total` (e, por extensão,
toda a Tabela 5 e todas as tabelas E1–E3 desta rodada) **subestima** a latência real de parede em uma quantidade
igual ao custo do audit-write, que não foi isolado nesta rodada (exigiria instrumentar o gateway, o que o
enunciado veda sem *feature flag* explícita — não foi feito). Reportado como limitação de medição, não como
recomendação de correção de escopo.

---

## 2. E1 — Microbenchmark corrigido (`latency_v2.csv`)

**Protocolo:** k=10 sessões independentes, ordem de célula aleatorizada por sessão (`--seed 1..10`), 200 chamadas
de aquecimento descartadas por célula, n=1000 chamadas medidas por célula, 4 modos × 3 payloads (128 B, 1 KiB,
16 KiB). Estatística primária: mediana (p50) com IC95% bootstrap percentílico (B=10.000, unidade de reamostragem
= sessão, seguindo a convenção já estabelecida em `docs/thesis/evidence/aggregate.py`). Média secundária.

### Diferenças pareadas (mediana, µs) — todos os 6 contrastes

| Payload | Contraste | Δ (mediana) | IC95% | Exclui zero? |
|---|---|---|---|---|
| 128 B | DIRECT − APPROVAL | +0,060 | [−0,046, 0,160] | Não |
| 128 B | DIRECT − OTP | +0,046 | [−0,046, 0,136] | Não |
| 1 KiB | DIRECT − APPROVAL | −0,009 | [−0,106, 0,082] | Não |
| 1 KiB | DIRECT − OTP | +0,009 | [−0,050, 0,084] | Não |
| 16 KiB | DIRECT − APPROVAL | −0,134 | [−0,407, 0,063] | Não |
| 16 KiB | DIRECT − OTP | −0,032 | [−0,090, 0,023] | Não |

**Nenhum dos 6 contrastes exclui zero.** Isso é o resultado corrigido, relatado como saiu — na direção
inesperada de que *nada* é detectável, não apenas de que o sinal se inverteu.

### Predições pré-especificadas

- **P1** (a inversão 6/6 não sobrevive ao protocolo corrigido): **CONFIRMADO**. Zero de seis contrastes exclui
  zero sob mediana.
- **P2** (contrastes por mediana recuperam o sinal correto mais que por média): **CONFIRMADO, com um exemplo
  concreto e forte.** Em 16 KiB, DIRECT − OTP por **média** dá +6,005 µs, IC95% [5,690, 6,331] — exclui zero,
  sinal invertido, altamente "significativo". A mesma célula por **mediana** dá −0,032 µs, IC [−0,090, 0,023] —
  não significativo, sinal correto. Investigando a causa: em *todas* as 10 sessões, DIRECT em 16 KiB tem
  p99 entre 38,5 µs e 61,7 µs contra uma mediana de ~29 µs — uma cauda direita pesada e consistente (não um
  outlier de uma sessão) que infla a média mas não a mediana. Isso é evidência direta, e não apenas hipotética, de
  por que a estatística pré-registrada como primária (mediana) importa.
- **P3** (custo do portão de consentimento sob AutoAllow é indistinguível de zero em todo payload): **CONFIRMADO**
  pelos mesmos 6/6 ICs contendo zero acima.

**Falsificação:** não houve. Se algum dos 6 contrastes tivesse saído significativo na direção original, isso
teria sido reportado aqui do mesmo jeito — não houve necessidade, pois nenhum saiu.

---

## 3. E2 — Ablação ordem × warmup (`order_ablation.csv`, `order_ablation_contrast_ci.csv`)

**Protocolo:** 4 braços × k=5 sessões, n=1000, mesmo desenho de células do E1.

| Braço | Ordem | Warmup | Fração de sinal invertido (média sobre 6 contrastes, mediana como estatística) |
|---|---|---|---|
| A | fixa (ordem da Tabela 5) | nenhum — reproduz o protocolo publicado | **70,0%** |
| B | fixa | descartado | **73,3%** |
| C | aleatória | nenhum | **53,3%** |
| D | aleatória | descartado (protocolo corrigido) | **56,7%** |

Ordem parece dominar mais que warmup nesta amostra: aleatorizar sozinho (C) já reduz a fração de sinal invertido
de ~70-73% para ~53%, aproximando-se do acaso (50%); descartar warmup sozinho (B) não reduz nada em relação a A —
na verdade aumenta ligeiramente. Com k=5 por braço isso é indicativo, não definitivo (ver qualificação de amostra
pequena em `aggregate.py`).

### O braço A reproduz a inversão publicada?

**Parcialmente, e apenas com a estatística de média — não com a de mediana, e não em 6/6.** Com IC95% bootstrap
sobre p50 (mediana), o braço A exclui zero em **2 de 6** contrastes, ambos em 128 B (DIRECT − APPROVAL: +0,513 µs
IC[0,363, 0,635]; DIRECT − OTP: +0,440 µs IC[0,286, 0,609]) — ambos na direção esperada (DIRECT mais lento). Com
a estatística de **média**, o braço A exclui zero em **4 de 6** (128 B ambos os contrastes, e 16 KiB ambos os
contrastes), também todos na direção esperada. Nenhum dos dois recupera 6/6.

**Uma causa não presente no código atual foi identificada.** O arquivo `docs/thesis/evidence/latency.csv`
(que sustenta a Tabela 5 publicada) foi commitado em `4b9282d` (2026-08-03 21:21:03 -0300). Entre esse commit e a
HEAD avaliada aqui, `apps/thesis-eval/src/main.rs` recebeu **495 linhas de diff** (418 inserções, 81 remoções) no
commit `2fb252b` ("harness support for the definitive run") — que introduziu justamente as flags `--warmup` e
`--seed` usadas nesta rodada. O harness que gerou a Tabela 5 publicada **não tinha nenhuma noção de warmup ou
ordem configurável**: o laço era um `for (name,_mode) in modes { for size in sizes { ... } }` fixo, sem qualquer
bloco de aquecimento — comportamento equivalente ao braço A atual, mas em um harness fisicamente diferente do
avaliado aqui. Além disso, `docs/thesis/evidence/latency.csv` **não tem `run-metadata.json` associado** em lugar
nenhum do repositório — não há proveniência (commit, CPU, governor) para a execução original. Não é possível
confirmar se a Tabela 5 publicada foi gerada no mesmo commit, sob o mesmo governor, ou com quantas sessões.
Isso é reportado como uma lacuna de proveniência do artefato original, não como uma medição desta rodada.

### Efeito de posição-na-execução (regressão sobre mediana normalizada cruzada-sessão)

| Braço | Inclinação (%/posição) |
|---|---|
| A (fixa/sem warmup) | +0,0285 |
| B (fixa/warmup descartado) | −0,0153 |
| C (aleatória/sem warmup) | **−0,1739** |
| D (aleatória/warmup descartado) | −0,0332 |

O achado do substituto (surrogate) — efeito de posição de −0,15%/posição explicando ~9% da inversão publicada —
não se reproduz de forma direta e comparável aqui: sob o harness real e com ordem *fixa* (braços A/B, que é a
condição que reproduz o protocolo publicado), a inclinação é próxima de zero (+0,03%, −0,02%). O maior efeito de
posição medido (−0,17%) ocorre justamente no braço com ordem *aleatorizada* (C) — mecanicamente o oposto do que
"efeito de posição explica a inversão publicada" exigiria, já que a Tabela 5 publicada usou ordem fixa. **Isso
refuta, para este artefato e nesta amostra, a atribuição quantitativa específica do substituto** (9% de 10,10 µs
atribuídos a posição); o mecanismo real parece ser predominantemente de ordem categórica (DIRECT executa primeiro
e paga custo de estado frio), não uma deriva linear contínua por posição.

---

## 4. E3 — `enforce_scopes` no caminho WebSocket autenticado (item 5 do revisor)

Esta era a medição declarada como `NÃO MEDIDO` no §4.1 da tese ("o caminho stdio não tem resolução de agente nem
imposição de escopo"). Medida aqui pela primeira vez, contra o caminho WS autenticado real
(`crates/sv-mcp/src/lib.rs`, `enforce_scopes`, linhas 2081-2152).

**Protocolo:** k=5 sessões, n=1000, mesmo agente/container/payload do E1 (container DIRECT, payloads 128 B/1 KiB/
16 KiB). Três conjuntos de escopo: 0 (agente sem escopo — usa o ramo `agent.scopes.is_empty() => Ok(())` do
próprio `enforce_scopes`, não um bypass de código), 1 (escopo único, casamento imediato) e 20 (19 escopos-isca +
o escopo correspondente por último, forçando o pior caso da varredura linear).

| Conjunto de escopos | Payload | Δ vs. piso (0 escopos), mediana | IC95% | Exclui zero? |
|---|---|---|---|---|
| 1 | 128 B | −0,454 µs | [−0,855, −0,130] | Sim (negativo — ver nota) |
| 1 | 1 KiB | −0,048 µs | [−0,438, 0,333] | Não |
| 1 | 16 KiB | −0,026 µs | [−0,371, 0,263] | Não |
| 20 | 128 B | **+2,106 µs** | [1,656, 2,511] | **Sim** |
| 20 | 1 KiB | **+2,102 µs** | [1,842, 2,346] | **Sim** |
| 20 | 16 KiB | **+2,231 µs** | [1,601, 2,615] | **Sim** |

**O custo de imposição de escopo é real, estatisticamente detectável, e escala com o tamanho do conjunto de
escopos, não com o payload.** Um conjunto de 20 escopos (pior caso de varredura) custa ~2,1–2,2 µs adicionais de
forma consistente nos três tamanhos de payload — exatamente o padrão esperado de uma varredura linear
`O(len(scopes))` sobre `agent.scopes` dentro de `enforce_scopes`. O delta negativo em 128 B/escopo=1 é
fisicamente implausível como "aceleração" real (uma checagem adicional não pode reduzir latência); é quase
certamente um artefato de ordem — os três braços de escopo rodaram em ordem fixa (0→1→20) dentro de cada sessão,
não aleatorizada, então o braço de 1 escopo se beneficia de estado mais "aquecido" que o piso. Reportado como
limitação de desenho desta medição especifica, consistente com o próprio fenômeno que o E2 investiga.

**Decomposição por estágio:** foram isoláveis `validate` (que inclui `enforce_scopes`), `authorize` (HITL/
AutoAllow), `execute` (vault) e `filter`. O estágio `filter`, porém, **não é diretamente comparável entre stdio e
WS**: `crates/sv-mcp/src/lib.rs:1392-1404` mostra que, quando `transport == AccessTransport::McpWs`, a janela de
tempo de `filter` também inclui uma re-serialização completa da resposta (`serde_json::to_vec`) para impor o
limite de tamanho de mensagem WS — um custo O(tamanho) que não existe no transporte stdio. Isso explica por que
o `filter` mesmo em modo DIRECT (sem PII) cresce com o payload no E3 (0,35 µs em 128 B → 9,9 µs em 16 KiB),
enquanto no E1 (stdio) o `filter` para DIRECT fica ~0,03 µs em todos os tamanhos. Reportado explicitamente para
que a tabela de estágios do E3 não seja lida como comparável, célula a célula, com a do E1.

**Bypass de código:** não construído, por instrução explícita do enunciado ("Do not modify the gateway to make a
measurement easier"). O comparativo acima usa exclusivamente ramos já existentes e reais do `enforce_scopes`
(0 escopos = ramo unscoped real, não simulação) — não há necessidade de um bypass de código para responder "o
custo escala com o tamanho do conjunto de escopos". **Marcado como medido** (não NÃO MEDIDO), com a ressalva acima
sobre o delta negativo em escopo=1/128B.

---

## 5. E4 — Caracterização do filtro PII real (`sv_privacy::scan`/`redact`)

Chamada direta ao crate real, sem vault nem gateway. Todos os identificadores são sintéticos: CPF/CNPJ/cartão
usam os mesmos algoritmos públicos de dígito verificador que `sv-privacy` valida (não há faixa de teste oficial
para CPF/CNPJ; o mesmo CPF fixo já usado em outros pontos deste repositório — `529.982.247-25` — segue essa
convenção); cartão usa o BIN de teste reconhecido 400000; e-mail usa domínios reservados RFC 2606; IPv4 usa
faixas privadas RFC 1918; telefone usa o bloco fictício NANP 555-01XX; SSN usa a faixa de área 900-999, que a SSA
declara nunca emitir.

### (a) Recall por categoria + falso-positivo

**7/7 categorias cobertas: 200/200 (100%) de recall em formato canônico, 0/500 falsos positivos em texto sem PII,
para cada uma.** As 6 lacunas admitidas (RG, CEP, nome completo, endereço, data de nascimento, telefone não
formatado) confirmam recall 0/200, como esperado por construção — não existe detector para nenhuma delas — e
sem detecções colaterais acidentais em nenhuma outra categoria.

### (b) Robustez de formato — o item que importa

O substituto (surrogate) reportou recall canônico de 1,00 mas 0,375 em variantes não-canônicas legítimas,
tratando isso como uma limitação uniforme entre categorias. **Os dados reais refinam essa alegação em vez de
confirmá-la em bloco:**

| Categoria | canônico | variantes sem pontuação/separadas | Robustez |
|---|---|---|---|
| CPF | 100% | 100% em bare/spaced/slashed | **Totalmente robusta** — `collect_grouped_digits` já tolera dígitos soltos |
| CNPJ | 100% | 100% em bare/spaced | **Totalmente robusta** |
| Cartão de crédito | 100% | 100% em bare/spaced/dotted | **Totalmente robusta** |
| IPv4 | 98%* | 0% spaced; 93% CIDR suffix | Rejeita espaçamento; tolera sufixo CIDR |
| Telefone | 100% | 0% bare; 0% sem símbolo; **100% formato internacional +55** | Estrita: exige `+` ou `(` líder |
| SSN | 100% | 0% em bare/spaced/dotted | **A mais estrita** — exige hífen exato |
| E-mail | 100% (+ 100% plus-tag) | 0% espaçado; 0% ofuscado `[at]/[dot]` | Estrita: sem tolerância a espaçamento |

*IPv4 canônico deu 59/60 (98%) em vez de 60/60 no teste de robustez de formato — uma pequena discrepância residual
não totalmente investigada nesta rodada (n=60 é pequeno; possível interação rara entre o gerador de teste e o
texto-veículo). Reportado, não escondido.

**Veredito: a alegação do substituto está parcialmente mal-formulada, não simplesmente confirmada.** CPF, CNPJ e
cartão de crédito — que compartilham a mesma função de varredura de dígitos agrupados no código real
(`collect_grouped_digits`, `crates/sv-privacy/src/lib.rs:394-415`) — são **totalmente robustos** a
despontuação/reagrupamento, contradizendo diretamente o número agregado 0,375 do substituto para essas três
categorias especificamente. Telefone, SSN e e-mail, por outro lado, **são** estritos por formato, exatamente como
o substituto sugeriu. A caracterização correta não é "cobertura é por formato, não por categoria" como afirmação
uniforme — é "três categorias (as que usam dígitos com checksum) são robustas a formato; três categorias (as que
usam sintaxe fixa) não são".

### (c) Decomposição de custo: tamanho × densidade

Ajuste por mínimos quadrados sobre 25 células (5 tamanhos × 5 densidades, R²=0,99979):

```
custo_µs = 0,567 + 0,002683·bytes + 0,004712·bytes·densidade
```

Inclinação em densidade=0: 0,00268 µs/byte (custo puro de varredura). Inclinação em densidade=1: 0,00740 µs/byte.
**A densidade responde por 63,7% da inclinação marginal no caso de densidade máxima** — mais que o dobro do custo
de varredura pura.

**Isso refuta a "qualificação favorável e publicável" que o substituto propôs** (que atribuiu 92,6% do custo à
varredura e apenas 7,4% ao mascaramento, implicando que o custo do ANONYMIZED não escala com o risco de
privacidade do payload). No filtro real, o custo **escala substancialmente** com a densidade de PII — um texto de
mesmo tamanho, mas 100% denso em PII, custa ~2,75× o custo por byte de um texto sem PII nenhuma. Reportado
prominentemente, como instruído, por contradizer o achado do substituto na direção favorável.

---

## 6. E5 — Bateria de sondas estendida (A11–A20, C3–C4) contra a CLI headless real

### Reconciliação de nomes

A política real que o fail-closed headless aplica não é o `HitlPolicy` do harness (`apps/thesis-eval`) usado na
bateria original A1–A10/C1–C2 — esse é, pelo próprio comentário no código, "*a hand-written mirror*" do desktop.
A política real e autoritativa vive em `apps/cli/src/serve.rs`
(`is_headless_allowed_action`/`is_headless_container_action`/`headless_allows_container_mode`, linhas 246-291):
uma **lista de permissão explícita** (allowlist), não uma lista de negação. `apps/cli` não expõe um alvo de
biblioteca, então esta bateria **compilou e executou o binário real** (`sovereign-vault serve`) como subprocesso,
falando WebSocket autenticado real com ele — não uma reimplementação.

Nomes provisórios do briefing → nomes reais confirmados no código:

| Provisório | Real | Ação de acesso |
|---|---|---|
| `transit.decrypt` (A11) | `vault.decrypt` | `Decrypt` |
| `signing.sign` (A12) | `vault.sign` | `Sign` |
| `transit.encrypt` (A13) | `vault.encrypt` | `Encrypt` |
| `broker.issue` (A14) | `vault.create_broker_secret` | `CreateBrokerSecret` |
| `broker.exchange` (A15) | `vault.broker_request` | `Broker` |

A16–A20 e C3–C4 não tinham nome provisório no briefing (que só especificava A11–A15 explicitamente); foram
escolhidos para fechar a cobertura da família crypto/broker/agent-mgmt: `vault.create_signing_key`,
`vault.create_transit_key`, `vault.export_agents`, `vault.import_agents`, `vault.list_broker_secrets` (ataques,
veredito esperado BLOCKED), `vault.verify` e `vault.info` (controles, veredito esperado ALLOWED).

### Resultado — 11/12 vereditos batem com a expectativa pré-especificada

Todos os 5 probes prioritários (A11–A15, a família crypto/broker sem cobertura) foram **BLOCKED**, como esperado
— o subprocesso real recusou `vault.decrypt`, `vault.sign`, `vault.encrypt`, `vault.create_broker_secret` e
`vault.broker_request` mesmo com um agente cujo escopo concedia explicitamente todas essas ações, confirmando que
a correção fail-closed headless está de fato em vigor no artefato compilado, não apenas em teoria. A16–A20
também bateram (todos BLOCKED). C3 (`vault.verify`) bateu (ALLOWED).

**C4 (`vault.info`) não bateu — MISMATCH: esperado ALLOWED, observado BLOCKED.** Esse é o resultado mais valioso
desta bateria, exatamente como o enunciado antecipou que seria. A causa raiz não é a política headless (que
inclui `AccessAction::VaultInfo` explicitamente na sua allowlist, `apps/cli/src/serve.rs:259`) — é um **bug real
e não relacionado em `enforce_scopes`** (`crates/sv-mcp/src/lib.rs:2089-2126`): para ações sem container
(`request.container == None`), a função só reconhece um subconjunto fixo de ações como concedíveis por escopo
(`Verify`, `CreateTransitKey`, `ListTransitKeys`, `Encrypt`, `Decrypt`, `CreateSigningKey`, `ListSigningKeys`,
`Sign`, `CreateBrokerSecret`, `ListBrokerSecrets`, `Broker`) — `VaultInfo`, `ExportAgents` e `ImportAgents`
**não estão nessa lista** e caem no braço `_ => Err(...)`, sendo negadas **incondicionalmente**, não importa o
que o escopo do agente autorize. Como o servidor headless real **recusa agentes sem escopo**
(`apps/cli/src/serve.rs:314-318`, "*headless serve refuses unscoped agents*"), a consequência prática é que
**`vault.info`, `vault.export_agents` e `vault.import_agents` são inalcançáveis por qualquer agente em modo
headless real** — não por design da política headless (que pretendia permitir `vault.info`), mas por um efeito
colateral de uma lacuna em `enforce_scopes` que antecede a política de acesso na ordem de despacho. Isso não
estava listado entre os itens pedidos pelo enunciado; é um achado incidental desta bateria, reportado porque é
exatamente o tipo de coisa que "o veredito observado difere do esperado" deveria capturar.

### Cadeia de auditoria HMAC

Reaberta com `sv_audit::AuditLog::open` usando a chave HMAC real do vault (`handle.audit_hmac_key()`) após o
subprocesso ser encerrado, e verificada com `verify_chain()`: **`ok=true`, 12 entradas, nenhuma quebra**. As 12
sondas headless produziram 12 entradas de auditoria autenticadas e a cadeia bate contra o checkpoint local — a
alegação de bloqueio e a alegação de evidência-de-violação foram testadas juntas, como pedido. (Consistente com
a instrução de não descrever isso como *append-only* resistente a rollback — é tamper-evidence relativo a um
checkpoint local, não mais que isso.)

### Cobertura da superfície de 20 ferramentas

| | Ferramentas cobertas | % |
|---|---|---|
| Bateria original (12 sondas: A1–A10, C1–C2) | 5/20 — `vault.read`, `.write`, `.list`, `.delete`, `.create_container` | 25% |
| + Bateria nova (24 sondas no total) | 17/20 | 85% |
| Ainda sem cobertura após 24 sondas | `vault.destroy`, `vault.list_transit_keys`, `vault.list_signing_keys` | — |

O valor "7/20 (35%)" citado no briefing como já estabelecido **não pôde ser reconciliado** com a contagem direta
da bateria original no código-fonte (`apps/thesis-eval/src/main.rs`, `run_adversarial`), que cobre 5 ferramentas
distintas, não 7. Reportado como discrepância, não silenciosamente ajustado — possivelmente o "7" da conversa
anterior contava algo além da bateria adversarial pura (p.ex. `vault.read` exercitado também pelo E1), mas isso
não foi verificável nesta rodada. **Por instrução explícita do enunciado, esta tabela reporta frações (5/20,
17/20), nunca convertidas para uma taxa de aprovação — a taxa de bloqueio (12/12, 24/24 tomando os pares
esperado=observado corretos exceto C4) permanece uma fração, não um percentual, para não parecer melhor do que a
cobertura de superfície de 25-85% justifica.**

---

## 7. Predições e vereditos consolidados

| Predição/item | Veredito | Contra recomendação do revisor | Contra achado do substituto |
|---|---|---|---|
| P1 — inversão 6/6 não sobrevive ao protocolo corrigido | **CONFIRMADO** | Atendido | Substituto não fez essa previsão diretamente |
| P2 — mediana recupera sinal correto mais que média | **CONFIRMADO** (caso concreto: 16KiB D-OTP) | Atendido | Consistente com o substituto |
| P3 — custo do portão de consentimento indistinguível de zero (AutoAllow) | **CONFIRMADO** | Atendido | — |
| item 5 — `enforce_scopes` no WS autenticado | **MEDIDO** (custo real, escala com |escopos|, não com payload) | Lacuna fechada | — |
| Ordem/warmup — braço A reproduz 6/6? | **REFUTADO** (reproduz só 2/6 por mediana, 4/6 por média) | Parcialmente atendido | Refina o substituto |
| Efeito de posição explica ~9% da inversão | **REFUTADO** para este artefato (efeito maior está no braço aleatorizado, não no fixo) | — | Refuta o substituto |
| PII — robustez de formato uniforme 0,375 | **REFINADO** (CPF/CNPJ/cartão 100% robustos; telefone/SSN/e-mail estritos) | Atendido com nuance | Refina o substituto |
| PII — custo não escala com densidade (92,6/7,4) | **REFUTADO** (densidade = 63,7% da inclinação marginal) | — | Refuta o substituto |
| Headless fail-closed crypto/broker (A11–A15) | **CONFIRMADO** contra o binário real | Lacuna fechada | — |
| Cobertura de sondas sobe de 25% para 85% | **CONFIRMADO** | Lacuna fechada | — |
| C4 (`vault.info`) esperado ALLOWED | **VIOLADO** — revela bug real em `enforce_scopes` | Achado incidental valioso | — |

---

## 8. Blocos de prosa — escritos do zero com números do artefato

*(`RESULTS-V2.md` não existe neste repositório — ver nota de proveniência no topo. Estes blocos são composições
novas, não revisões de um rascunho anterior. Mantidos os cuidados do enunciado: ressalvas do resumo preservadas
e reforçadas; ZKP/NATIVE descritos apenas como valores de enum reservados/rejeitados; cadeia de auditoria descrita
como tamper-evident relativa a checkpoint local, não como armazenamento append-only resistente a rollback; RAG e
isolamento de memória de linguagem/SO não mencionados, por não terem sido tocados por esta rodada.)*

### §4.2 — Latência (substituindo o texto baseado no substituto)

Sob o protocolo corrigido (ordem de célula aleatorizada por sessão, 200 chamadas de aquecimento descartadas por
célula, k=10 sessões independentes, n=1000 chamadas medidas por célula), nenhuma das seis diferenças pareadas
DIRECT−APPROVAL/DIRECT−OTP exclui zero em intervalo de confiança de 95% por bootstrap, em nenhum dos três
tamanhos de payload testados (128 B, 1 KiB, 16 KiB). A inversão de 6/6 relatada na Tabela 5 publicada não
sobrevive à correção de ordem e aquecimento. Uma ablação em quatro braços (ordem fixa/aleatória × aquecimento
presente/ausente, k=5 cada) mostra que reproduzir a ordem fixa e ausência de aquecimento do protocolo publicado
recupera um sinal de inversão parcial e estatisticamente significativo apenas em 128 B (2 de 6 contrastes por
mediana; 4 de 6 por média) — não os 6/6 publicados. Não foi possível confirmar se o harness que gerou a Tabela 5
publicada é o mesmo avaliado nesta rodada: o arquivo de evidência publicado não carrega metadados de proveniência
(commit, CPU, governor), e o harness de avaliação recebeu uma reescrita substancial (495 linhas) entre o commit
que introduziu esse arquivo e a HEAD aqui avaliada. O custo de imposição de escopo no caminho WebSocket
autenticado — não mensurável no caminho stdio usado pelo restante deste capítulo, por não haver ali resolução de
agente — foi medido diretamente pela primeira vez: um conjunto de 20 escopos custa entre 1,6 e 2,6 µs adicionais
sobre um agente sem escopo, de forma consistente através dos três tamanhos de payload testados, confirmando que o
custo escala com o número de escopos concedidos, não com o tamanho do payload.

### §5.2.2 / QP2 — Filtragem de PII

O filtro de privacidade real (`sv-privacy`) atinge 100% de recall em formato canônico e 0% de falso-positivo em
texto neutro para as sete categorias implementadas (e-mail, CPF, CNPJ, cartão validado por Luhn, IPv4, telefone
formatado, SSN), confirmando a especificação documentada. A robustez a variação de formato, porém, não é uniforme
entre categorias, como uma leitura superficial da limitação documentada poderia sugerir: CPF, CNPJ e número de
cartão — que compartilham no código real uma função de varredura de dígitos agrupados tolerante a separadores —
mantêm 100% de recall mesmo sem qualquer pontuação ou reagrupados livremente; telefone, SSN e e-mail, por
dependerem de sintaxe fixa (hífens exatos, símbolo `+`/`(` líder, `@` sem espaçamento), caem para 0% de recall em
variantes não-canônicas equivalentes. A limitação documentada da tese — cobertura por categoria — deveria ser
reformulada como cobertura por formato dentro de um subconjunto de categorias, não como uma propriedade uniforme
de todas as sete. Quanto ao custo: um ajuste por mínimos quadrados sobre 25 combinações de tamanho (128 B–64 KiB)
e densidade de PII (0–100%) no filtro real mostra que a densidade responde por 63,7% da inclinação marginal de
custo por byte no caso de densidade máxima (R²=0,9998) — o custo do modo ANONYMIZED escala substancialmente com o
risco de privacidade do conteúdo, e não apenas com seu tamanho.

### Resumo/abstract — ressalvas reforçadas, não removidas

As ressalvas do resumo original permanecem válidas e são reforçadas pelos dados desta rodada: a avaliação
continua sendo um microbenchmark sintético de braço único (Braço A), sem comparação com um baseline cloud-direct
real; a bateria de sondas adversariais, mesmo após dobrar de 12 para 24 sondas, cobre 17 de 20 ferramentas MCP
(85%) — até a extensão desta rodada, a cobertura era de apenas 5/20 (25%), não os 7/20 citados em versões
anteriores do texto, que não puderam ser reconciliados com o código-fonte da bateria original. A correção
fail-closed para operações headless de criptografia e corretagem foi verificada diretamente contra o binário CLI
real (não uma simulação) e se sustenta para as cinco operações prioritárias testadas; a verificação também expôs,
como efeito colateral, um bug real e não relacionado na imposição de escopo que torna três operações inalcançáveis
por qualquer agente em modo headless, independentemente de escopo concedido — achado que não estava em escopo
original desta avaliação e que permanece sem correção proposta aqui. ZKP e NATIVE seguem sendo valores de enum
reservados e rejeitados, não mecanismos de isolamento avaliados. A cadeia de auditoria segue sendo tamper-evident
relativa a um checkpoint local, não um armazenamento append-only resistente a rollback.

---

## 9. Arquivos gerados

Todos em `docs/thesis/evidence/v2/`: `latency_v2.csv`, `latency_v2_paired_diffs.csv`, `order_ablation.csv`,
`order_ablation_contrast_ci.csv`, `order_ablation_position_effect.csv`, `enforce_scopes.csv`,
`enforce_scopes_stages.csv`, `pii_filter_characterization.csv`, `pii_format_robustness.csv`,
`pii_cost_size_x_density.csv`, `pii_cost_fit.csv`, `headless_probes.csv`, `probe_coverage_matrix.csv`,
`probe_taxonomy.csv`, mais `raw/{e1,e2,e3,e4,e5}/.../run-metadata.json` por sessão (proveniência completa:
commit, comando, host, `power_mode`, `rustc`). Figuras em `docs/thesis/figuras/`: `figura4_corrigida.png`,
`ablacao_ordem.png`, `pii_recall.png`, `cobertura_sondas.png`.

Código novo (todo em `apps/thesis-eval`, nenhuma mudança no gateway real `crates/sv-mcp` nem em `apps/cli`):
subcomandos `enforce_scopes`, `pii`, `headless_probes`; extensão de `Stats`/`summarize` com p99 e IC95% bootstrap
por mediana; feature `process` do `tokio` adicionada ao `Cargo.toml` do harness para permitir spawnar o binário
`sovereign-vault serve` real como subprocesso em `headless_probes`.
