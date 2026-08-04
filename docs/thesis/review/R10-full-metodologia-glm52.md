# R10 — Revisão de Metodologia/DSR (ângulo: avaliabilidade e sustentação do Cap. 4)

**Revisor:** R10 (metodologia/DSR)
**Artefato:** `docs/thesis/paper.tex` (abntex2, PT-BR, 48 pp)
**Data:** 04 ago. 2026

---

## Veredito

**APROVADO sem bloqueantes** — a coerência DSR (Hevner/Peffers/March & Smith/FEDS) é sólida, a fronteira de evidência é respeitada em todas as menções sem vazamento de alegação, as respostas QP1–QP3 correspondem à evidência sem extrapolar, a régua k≥3/IC/bootstrap/warmup é declarada e cumprível pelos instrumentos já implementados, e o apêndice de reprodutibilidade é internamente consistente (hashes, commit, tag e não-ancestralidade verificados). Há apenas correções pontuais de escrita e um valor de SO/kernel a verificar.

---

## Verificações realizadas (rastreabilidade)

| Item | Verificação | Resultado |
|---|---|---|
| `paper.tex` | leitura integral | — |
| `evidence/README.md` | leitura | — |
| `EXECUCAO-DEFINITIVA.md` | leitura (régua k≥3/IC/warmup + estado dos instrumentos) | réguas implementadas em `e75ad60` |
| `EVAL-PROTOCOL.md` | leitura (protocolo de dois braços) | — |
| `git log` | `HEAD = b3447cb`; `e75ad60` presente | instrumentos no HEAD |
| `git tag` | `thesis-evidence-preliminary` existe | → `dfb0a49` |
| `git cat-file dfb0a49` | tipo `commit`, msg "fix(audit): skip unsupported Windows directory sync" | válido |
| `git merge-base --is-ancestor dfb0a49 main` | exit 1 | **não-ancestralidade confirmada** |
| `certutil -hashfile` × 3 | latency `2e914c1b…`, adversarial `845a1d04…`, micro `d526ed70…` | **conferem com o apêndice** |

---

## Achados

### Relevantes

**R1. Valor de SO/kernel "Linux 7.0" no apêndice de reprodutibilidade.**
No apêndice, lê-se: "a plataforma registrada na documentação de avaliação é **Linux 7.0**, CPU 11th Gen Intel Core i7-11600H…". O kernel Linux estável atual é da série 6.x; "Linux 7.0" não corresponde a uma versão de kernel existente. Agravante: `EXECUCAO-DEFINITIVA.md` (§3.1) e o perfil do autor em `AGENTS.md` indicam que o ambiente de execução é **Windows** (`<USER_HOME>…`), com `uname`/`/proc` inexistentes. Há, portanto, ou erro factual (valor inventado/placeholder não marcado como tal) ou contradição entre a plataforma declarada no paper e a do ambiente de execução documentado. Como a régua de reprodutibilidade exige registro correto de SO/kernel, e o próprio apêndice diz que "Os campos de armazenamento e modo de energia estão a finalizar", este é o tipo de inconsistência que deve ser resolvida antes da entrega. **Recomendação:** registrar o SO/kernel real (Windows + versão de build, ou Linux com versão de kernel concreta) ou substituir por "a registrar na execução definitiva", com marcador explícito, como já se faz para armazenamento e modo de energia.

### Menores

**M1. Siglas sem expansão na primeira ocorrência textual.**
A lista de siglas está completa, mas algumas siglas são usadas no corpo antes de serem expandidas inline, contrariando a prática ABNT de expandir na primeira ocorrência textual (a lista é suplementar, não substitutiva):
- **RFC** — primeira ocorrência é via `\cite{rfc2606}`/`\cite{rfc1918}` em §3.9, sem "Request for Comments (RFC)".
- **FEDS** — §3.3 usa "No enquadramento FEDS \cite{venable2016}" sem expandir; a expansão só aparece na lista.
- **HITL** — usado em §3.7.3 (\svnota) e §3.11.2 ("política HITL simulada") antes de qualquer "Human-in-the-Loop (HITL)".
- **IC** — §3.9 ("sem IC") antes de "Intervalo de Confiança (IC)"; no corpo usa-se sempre "intervalo de confiança" por extenso, mas a sigla IC aparece sem expansão inline.
- **CSP** — §3.7.4 traz apenas "Content Security Policy e capacidades explícitas"; a sigla CSP não chega a ser usada no corpo (apenas na lista), então a entrada da lista é órfã.

**Recomendação:** expandir RFC, FEDS, HITL e IC na primeira ocorrência textual; remover CSP da lista de siglas ou introduzi-la no corpo.

**M2. "ponta-a-ponta" → "ponta a ponta" (sem hifens).**
§3.7.3: "A zeroização **ponta-a-ponta** da semente Ed25519…". Conforme o Acordo Ortográfico vigente, a locução adverbial escreve-se sem hifens: "ponta a ponta".

**M3. Concordância/voz em frase do apêndice.**
Apêndice: "Os campos de armazenamento e modo de energia estão **a finalizar** na execução definitiva." Forma estranha. **Recomendação:** "Os campos de armazenamento e modo de energia **serão registrados** na execução definitiva" ou "estão **a ser finalizados**".

**M4. §3.1 (Considerações Iniciais) é genérico e parcialmente redundante.**
O parágrafo limita-se a "Este capítulo apresenta a modelagem, a arquitetura…", repetindo o já dito em §1.6 (Organização do Trabalho). Considerando o limite de páginas, poderia ser fundido em §3.2 (Caracterização da Pesquisa) sem perda.

**M5. Figura 3.1 (ciclos-dsr) referenciada, mas não explicada.**
Após `\label{fig:ciclos-dsr}`, o texto apenas diz "A Figura~\ref{fig:ciclos-dsr} situa esses ciclos no percurso da pesquisa." Ao contrário das demais figuras (3.2, 3.3, 4.1), que são discutidas em detalhe, esta não recebe leitura do conteúdo visual. **Recomendação:** acrescentar uma frase descrevendo o que a figura mostra (posição do ciclo de design no núcleo, conexões de relevância e rigor), para manter o padrão das demais.

---

## Avaliação por foco do plano

### 1. Coerência DSR (Hevner, Peffers, March & Smith, FEDS) — **adequada**

- **Hevner três ciclos** (§3.3): relevância, rigor e design estão definidos e articulados com a base de conhecimento (segurança de memória, MCP, Local-First) e com o ambiente (privacidade/auditoria). O **ciclo de rigor é auditável**: §3.4 e §5.4 documentam a iteração construir–avaliar via ADRs (correção do gate de consentimento para NATIVE) e as sondas A9/A10 decorrentes — encadeamento genuíno de achado → decisão → correção → ampliação da avaliação.
- **Peffers** (§3.4): seis atividades listadas; o texto reconhece honestamente que "O traço de Peffers é parcialmente retrospectivo, pois o artefato antecedeu esta proposição" e justifica com a evidência de iteração documentada. Postura metodológica correta.
- **March & Smith** (§3.5 e §5.4): Modelo, Método e Instanciação estão presentes e **explicitamente limitados** ("Não se afirma que a instância entregue seja um sistema RAG ou um repositório de contexto geral").
- **FEDS** (§3.3 e §3.11): o enquadramento artificial+somativo (atual) vs. naturalística+somativa (futuro) está bem aplicado e define o "teto de generalização" da evidência.

### 2. Fronteira de evidência — **sem vazamento detectado**

A Tabela 4.1 funciona como contrato de leitura e é invocada em §5.1 como subordinação obrigatória. Varri **todas as menções** aos itens que devem permanecer como trabalho futuro:

| Item | Menções verificadas | Limite respeitado? |
|---|---|---|
| RAG / índice vetorial | §1.4 (\svnota), §2.1, §2.3, §3.5, §5.1, §5.3, §5.4 (Modelo), §5.5, §5.6 (ADR-0012) | ✅ sempre "futuro"/"não implementado"/"direção" |
| Isolamento de SO | §1.4, §2.5, §3.7, §5.5 | ✅ sempre "fora do limite avaliado" |
| Comparação com nuvem | §3.11.3, §5.3, §5.5, §5.6 | ✅ "não foi executada" |
| Retenção no provedor | §2.3, §5.5, §5.6 | ✅ "exige verificação própria e não decorre do protocolo" |
| Microbenchmark preliminar/1 sessão/sem IC | Resumo, §3.9, Tab. 4.1, Tab. 4.2 (legenda), Fig. 4.1 (legenda), §5.1, §5.2.2, §5.5 | ✅ sempre qualificado |
| Bateria 10/10 e 2/2 | Tab. 4.1, §4.3, §5.2.3 | ✅ sempre "cobertura da bateria, não taxa populacional" |

Nenhuma alegação ultrapassa a fronteira. As qualificações são **deliberadas e consistentes** — não há endurecimento a corrigir nem afrouxamento a endurecer.

### 3. QP1–QP3 — **respostas correspondem à evidência, sem extrapolação**

- **QP1** (§5.2.1): mediação por identidade+escopo+validação+modos+auditoria; evidência referente ao **desktop WebSocket**; headless excluído; "não há medição de precisão ou recall"; "não equivale a garantia de anonimização". — Corresponde à Tabela 4.1.
- **QP2** (§5.2.2): barreira < 1 ms; filtro PII domina ANONYMIZED 16 KiB; não mede fim a fim, WAN, inferência, utilidade, decisão humana; AutoAllow = "piso mecânico". — Corresponde à Tabela 4.2 e à metodologia (Tabela 3.2).
- **QP3** (§5.2.3): 10/10 + 2/2; "não isola a contribuição causal"; HitlPolicy simulada, não controlador desktop; "cobertura da bateria executada, não uma taxa populacional". — Corresponde à Tabela 4.3.

### 4. Régua k≥3 / IC 95% bootstrap / warmup — **declarada e cumprível**

- A régua é enunciada em §3.9, Tabela 4.1, §4.2, §5.2.2, §5.5 e §5.6: "k≥3 sessões independentes, IC de 95% por *bootstrap* e regra explícita de *warmup*/descarte".
- `EXECUCAO-DEFINITIVA.md` confirma que os instrumentos estão **implementados e testados** em `e75ad60` (presente no HEAD `b3447cb`): `--warmup N` (descarte via servidor sem `TimingSink`), `--seed S` (randomização xorshift64 auditável), `collect-metadata.sh` e `aggregate.py` (bootstrap sobre médias de sessão; IC de Wilson para adversarial). O documento declara explicitamente: "Não há mais bloqueante de instrumento — resta executar o protocolo".
- O desenho da execução definitiva usa **k=5** (≥3), 2.000 iterações cronometradas + 200 de warmup, 10.000 reamostragens, critério de aceitação por CV≤10% e detecção de deriva térmica. **A régua é cumprível** pelos instrumentos atuais.

### 4b. Apêndice de reprodutibilidade — **internamente consistente** (com a ressalva R1)

- Hashes SHA-256: conferem exatamente (verificados via `certutil`).
- Commit `dfb0a49f7360`: existe e é tipo `commit`.
- Tag `thesis-evidence-preliminary`: existe e aponta para o commit correto.
- Não-ancestralidade: confirmada (`merge-base --is-ancestor` → exit 1), coerente com a declaração do paper e do `evidence/README.md`.
- Único ponto: o valor "Linux 7.0" (R1) quebra a consistência factual do registro de SO/kernel.

### 5. Estrutura ABNT e normas de escrita — **adequada, com pontuais a corrigir**

- **Impessoalidade e tempo presente**: predominantemente corretos ("propõe-se", "define-se", "estrutura-se", "apresenta"). Formas em futuro ("observará", "requer") são justificadas pela natureza prospectiva do protocolo.
- **Siglas**: ver M1.
- **Figuras/tabelas/equaÃ§Ãµes**: todas referenciadas; Equações 3.1 e 3.2 explicadas; exceção é a Figura 3.1 (M5).
- **Bibliografia**: 22 referências; todas as `\cite` têm `\bibitem` correspondente; formato ABNT NBR 6023 consistente; sem órfãos detectados. Uso correto de `\codigo`/`\url` para RFCs e URLs.
- **Resumo/Abstract**: alinhados em conteúdo; o abstract traduz fielmente as limitações (inclusive RG/CEP/nomes sem máscara e Art. 5º da LGPD).
- **Ortografia**: M2 ("ponta-a-ponta").
- **Concordância**: M3.

---

## Recomendações consolidadas (por prioridade)

1. **[relevante — R1]** Corrigir "Linux 7.0" no apêndice: registrar o SO/kernel real (Windows + versão de build, ou Linux com versão de kernel concreta da série 6.x) ou marcar explicitamente como "a registrar na execução definitiva", com marcador visível (como já se faz para armazenamento e energia).
2. **[menor — M1]** Expandir RFC, FEDS, HITL e IC na primeira ocorrência textual; remover CSP da lista de siglas ou introduzi-la no corpo.
3. **[menor — M2]** "ponta-a-ponta" → "ponta a ponta".
4. **[menor — M3]** "estão a finalizar" → "serão registrados" / "estão a ser finalizados".
5. **[menor — M4]** Fundir §3.1 em §3.2 ou enriquecê-la.
6. **[menor — M5]** Acrescentar leitura do conteúdo da Figura 3.1.

---

## Observação de escopo

Nenhuma qualificação ou limitação deliberada do texto é objeto de proposta de remoção ou endurecimento. O resultado negativo bem medido (microbenchmark preliminar de uma sessão sem IC; bateria finita 10/10+2/2 sobre política HITL simulada; exclusões explícitas de RAG, índice vetorial, isolamento de SO, comparação com nuvem e retenção no provedor) é tratado como contribuição válida, em conformidade com o contexto R1–R8 / A0–A4.
