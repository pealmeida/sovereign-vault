# R9b — Verificação de integridade científica (Q1) no diff de paper.tex e EXECUCAO-DEFINITIVA.md

**Revisor:** R9b (ângulo: metodologia/DSR), complementa R9.
**Data:** 04/08/2026.
**Escopo:** Q1 do R9 — integridade científica linha a linha de cada hunk do diff.

---

## VEREDITO

**Q1 CONFIRMADA** — Nenhuma edição do diff altera, remove ou enfraquece número, resultado, taxa, medida, média, p95, contagem, hash SHA-256, versão, alegação de capacidade, qualificação ou limitação. Todas as mudanças em `paper.tex` são de forma (itálico, tradução de terminologia, correção verbal) ou bibliográficas (adição de 5 DOIs + expansão de siglas WAN/RFC). O diff de `EXECUCAO-DEFINITIVA.md` atualiza o estado de implementação do harness preservando todas as justificativas, critérios de aceitação e riscos metodológicos.

---

## Análise hunk a hunk — paper.tex

### Hunks puramente de itálico (sem alteração semântica)

Todos os seguintes apenas envolvem termos estrangeiros em `\textit{}` (ou removem itálico já existente), sem tocar em conteúdo:

| Linha | Termo(s) | Tipo |
|-------|----------|------|
| 41 | `microbenchmark` | +itálico |
| 116 | `embeddings` | +itálico |
| 148 | `pods` | +itálico |
| 217 | `blobs` | +itálico |
| 233 | `headless`, `modeless` (4 ocorrências) | +itálico |
| 242 | `checkpoint`, `append-only`, `rollback` | +itálico |
| 305 | `microbenchmark` (fonte de tabela) | +itálico |
| 317 | `microbenchmark stdio`, `microbenchmark` | +itálico |
| 326 | `microbenchmark` (caption), `stdio` (2×) | +itálico |
| 348 | `harness` | +itálico |
| 362 | `headless` (fronteira), `microbenchmark` (N=1.000) | +itálico |
| 372–373 | `microbenchmark` (título de seção + caption) | +itálico |
| 487, 508–512, 509, 519–521, 529–540, 543, 548–558 | `gateway` (−itálico), `stdio` (+itálico), `token` (+itálico), `Local-First` (−itálico), `embeddings` (+itálico) | itálico ajustado |

Nenhum desses hunks modifica substantivo, número ou qualificação.

### Hunks com mudança de terminologia ou gramática (sem alteração semântica)

| Linha | Antes → Depois | Análise |
|-------|----------------|---------|
| 177 | `o artefato antecede esta proposição` → `o artefato antecedeu esta proposição` | Correção de tempo verbal (presente → pretérito perfeito). O sentido não muda: o artefato existia antes da proposição metodológica. Qualificação de retrospectividade parcial preservada. |
| 244 | `Trata-se de um \textit{trade-off} deliberado que o usuário deve configurar` → `Trata-se de uma relação de compromisso deliberada que o usuário deve configurar` | Tradução de termo estrangeiro. Deliberação e responsabilidade do usuário preservadas. Nenhum conteúdo técnico removido. |
| 273 | `esse \textit{trade-off} deve ser configurado` → `essa relação de compromisso deve ser configurada` | Mesma tradução, mesma análise. |

### Hunk de expansão de sigla (sem alteração semântica)

| Linha | Mudança | Análise |
|-------|---------|---------|
| 326 | `WAN` → `rede de longa distância (\textit{Wide Area Network} --- WAN)` | Expansão explicativa; "WAN" permanece como forma abreviada. Conteúdo inalterado. |
| 572 | `\bibitem{rfc1918} ... RFC 1918, 1996` → `... Request for Comments (RFC) 1918, 1996` | Expansão explicativa da sigla; número e ano do RFC inalterados. |

### Hunks bibliográficos — 5 DOIs

| Entrada | DOI adicionado | Verificação de sentido/precisão |
|---------|---------------|---------------------------------|
| `hevner2004` | `10.2307/25148625` | DOI correto para MIS Quarterly (prefixo 10.2307 = JSTOR). Dados bibliográficos (autores, título, v. 28, n. 1, p. 75–105, 2004) **inalterados**. Não altera sentido nem precisão. |
| `khan2022` | `10.1145/3505244` | DOI correto para ACM Computing Surveys (prefixo 10.1145). Dados (v. 54, n. 10s, p. 1–41, 2022) **inalterados**. |
| `march1995` | `10.1016/0167-9236(94)00041-2` | DOI correto para Decision Support Systems (Elsevier, prefixo 10.1016, ISSN 0167-9236). Dados (v. 15, n. 4, p. 251–266, 1995) **inalterados**. |
| `peffers2007` | `10.2753/MIS0742-1222240302` | DOI correto para Journal of Management Information Systems (Taylor & Francis, prefixo 10.2753, ISSN 0742-1222, v. 24 = 2403, n. 3 = 02). Dados (v. 24, n. 3, p. 45–77, 2007) **inalterados**. |
| `venable2016` | `10.1057/ejis.2014.36` | DOI correto para European Journal of Information Systems (Palgrave/Springer, prefixo 10.1057). Dados (v. 25, n. 1, p. 77–89, 2016) **inalterados**. |

**Conclusão sobre os 5 DOIs:** Nenhum altera o sentido ou a precisão das entradas. Todos são adicionados a registros bibliográficos já completos e corretos; o DOI apenas acrescenta identificador persistente.

### Verificação de preservação de números e medidas-chave

Confirma-se que **nenhum** dos seguintes foi alterado no diff:

- `N=1.000` (aparece em §Plano de Avaliação, Tabela metodologia, fronteira, microbenchmark) — preservado.
- `10/10` sondas maliciosas bloqueadas — preservado.
- `2/2` controles aceitos — preservado.
- `p95` total (coluna de tabela) — preservado.
- `12` sondas pré-especificadas — preservado.
- `20` ferramentas (17 base + 3 broker) — preservado.
- `sete` categorias heurísticas de PII — preservado.
- `200` iterações de warmup (referência cruzada em texto) — preservado.
- `k≥3` sessões / IC 95% bootstrap — preservado.
- `XChaCha20-Poly1305`, `Argon2id`, `HMAC-SHA256`, `SHA-256` — preservados.
- Hashes SHA-256 do apêndice (`micro.csv: d526ed...`, etc.) — **inalterados**.
- Referências de linha de código (`lib.rs:372-447,485-515`, etc.) — inalteradas.
- Todas as qualificações e limitações ("não é anonimização genérica/LGPD", "não elimina risco de uso como oráculo", "não prova geral", etc.) — preservadas palavra por palavra.

---

## Análise hunk a hunk — EXECUCAO-DEFINITIVA.md

O diff reescreve substancialmente a seção sobre suporte do harness ao protocolo, refletindo que as lacunas de implementação foram sanadas (commit `e75ad60`, PR #70). Verifica-se se alguma **qualificação metodológica que deveria permanecer** foi removida:

### 1. Seção "Bloqueante" (linhas 35–56)

- **Removido:** cabeçalho "Bloqueante", descrição detalhada da lacuna e a instrução de ordem de trabalho ("implementar (1) e (2) e só então executar").
- **Substituído por:** cabeçalho "Harness: suporte ao protocolo (atualizado em 04/08/2026)", tabela com colunas "Falta original | Estado | Onde" — **mais detalhada** que a original (inclui mecanismo de descarte, auditoria em metadata CSV, testes de unidade).
- **Verdade material:** o texto original declarava a lacuna; o novo texto declara que foi resolvida. Esta é uma mudança de **status factual**, não de qualificação metodológica. A instrução de ordem de trabalho foi removida porque não mais se aplica.

### 2. §2.2 Randomização (linhas 158–164)

- **Removido:** "O harness atual executa as células em ordem fixa... Isso requer alteração em apps/thesis-eval".
- **Substituído por:** descrição do `--seed` e do fallback para ordem fixa.
- **Preservado:** o bloco de *Justificativa* ("ordem fixa confunde efeito de aquecimento/deriva com efeito de condição") — **mantido integralmente**.

### 3. §2.4 Warmup (linhas 195–204)

- **Removido:** "O harness atual não separa warmup do corpus medido... requer alteração".
- **Substituído por:** descrição da implementação do `--warmup N` (servidor sem `TimingSink` para descarte em latency; `micro_warmup_iterations` para micro).
- **Preservado:** o bloco de *Justificativa* ("sem descarte explícito, as primeiras iterações... ficam misturadas e inflacionam média e p95") — **mantido integralmente**.

### 4. §2.6 "Alterações necessárias no harness" → "estado: implementadas" (linhas 218–254)

- **Removido:** a seção de pré-requisitos ("requer alteração... antes de iniciar s01") e a recomendação operacional com variante degradada.
- **Substituído por:** descrição detalhada do que foi implementado (mecanismo de warmup sem TimingSink, xorshift64 auditável sem nova dependência, testes de unidade cobrindo 4 cenários).
- **Preservado:** a "Variante degradada (obsoleta)" é mantida como **referência histórica da decisão**, com justificativa de por que deixou de ser necessária.

### 5. §3.5 (linha 335)

- **Removido:** nota de que `--warmup`/`--seed` pressupõem alteração do harness.
- **Substituído por:** "As bandeiras `--warmup` e `--seed` são suportadas pelo binário atual". Status factual correto.

### 6. §7 Tabela de riscos (linha 551)

- **Original:** "Harness não implementa `--warmup`/`--seed` (§2.6 não feito) | Falha de parse | **Não prosseguir**..."
- **Novo:** "~~Harness não implementa~~ (resolvido em `e75ad60`, PR #70) | — | Risco aposentado: o binário suporta ambas as bandeiras com testes de unidade."
- **Análise:** O risco é explicitamente riscado e marcado como aposentado, com referência ao commit/PR. A estrutura da tabela de riscos é preservada; as demais linhas de risco (energia, build concorrente, rustc, sonda não-determinística, alteração de código, numpy/scipy) **permanecem intactas**.

### Conclusão sobre EXECUCAO-DEFINITIVA.md

A reescrita **não remove nenhuma qualificação metodológica que devesse permanecer**:

- ✅ Todas as *Justificativas* (warmup, randomização, IC de Wilson) — preservadas.
- ✅ Critérios de aceitação (§6) — não tocados pelo diff.
- ✅ Plano estatístico (§5, bootstrap / IC de Wilson) — não tocado.
- ✅ Tabela de riscos (§7) — estrutura e demais linhas preservadas; apenas uma linha de risco aposentada com documentação do motivo.
- ✅ Variante degradada — mantida como registro histórico, não apagada.

O que mudou é **puramente o status de implementação** (de "não feito" para "feito e testado"), que é uma atualização factual legítima — não uma remoção de qualificação.

> **Nota de escopo:** A verificação Q1 trata da integridade textual. A conferência de que o commit `e75ad60` realmente implementa os recursos reivindicados é tarefa de revisão de código, fora do escopo de Q1.

---

## Hunks suspeitos

**Nenhum.**

---

## Conclusão

O diff de `paper.tex` contém exclusivamente: (a) adição/remoção de itálico em termos estrangeiros; (b) tradução `trade-off` → `relação de compromisso`; (c) correção verbal `antecede` → `antecedeu`; (d) expansão de siglas WAN e RFC; (e) acréscimo de 5 DOIs corretos a registros bibliográficos já completos. Nenhum número, medida, hash, versão, alegação, qualificação ou limitação foi alterado. O diff de `EXECUCAO-DEFINITIVA.md` atualiza o status do harness de "bloqueante" para "implementado e testado", preservando integralmente todas as justificativas metodológicas, critérios de aceitação, plano estatístico e riscos. **Q1 está confirmada.**
