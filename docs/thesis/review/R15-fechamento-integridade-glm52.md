# R15 — Parecer de fechamento de integridade (rodada final pré-commit)

**Revisor:** GLM-5.2 (ângulo: integridade de alegações e coerência transversal)
**Escopo:** fechamento do ciclo de revisão A0–R14 sobre `paper.tex`,
`TRACEABILITY.md` e documentos de orientação; verificação de que as correções
declaradas em `response-to-reviewers-r13-r14.md` e `response-to-reviewers-adr0013.md`
efetivamente aterrissaram no código e nos documentos.
**Data:** 05 ago. 2026
**Tipo:** parecer de fechamento — não introduz novos achados de fundo; verifica
aderência, coerência e prontidão.

> **Método.** Releu-se integralmente `paper.tex` (biblioteca, §2.6, §5.3, §5.4,
> svnotas e apêndice), `TRACEABILITY.md`, `PONTOS-DE-APOIO-TESE.md`,
> `PUBLICACOES-KALINKA-LINKS.md`, os pareceres R9–R14, R9b e R6, e as duas
> respostas consolidadas. Cruzou-se cada item ACEITO das respostas contra o
> texto vigente. Nenhum arquivo foi editado neste round.

---

## Veredito (uma linha)

**APROVADO para commit** — todas as correções declaradas em R13/R14 e no
encaminhamento do ADR-0013 aterrissaram nos artefatos; a coerência entre
`paper.tex`, `TRACEABILITY.md` e documentos de orientação foi restaurada; não há
sobrealegação, falsa equivalência ou divergência bibliográfica remanescente; os
únicos itens em aberto são estritamente externos a esta rodada (valor de SO/kernel
no apêndice, R10-R1, e expansão pontual de siglas, R10-M1), nenhum bloqueante.

---

## Achados por severidade

### BLOQUEANTE

Nenhum.

### RELEVANTE

**1. [arrastado de R10-R1, fora do escopo R13/R14] Valor "Linux 7.0" no apêndice de reprodutibilidade permanence sem resolução.**
O apêndice de `paper.tex` ainda diz "Linux --- versão de núcleo anotada como 7.0
no momento da captura, valor a reconferir". "Linux 7.0" não corresponde a um
kernel existente (série estável atual: 6.x). O texto já carrega o marcador "valor
a reconferer", o que blinda parcialmente o leitor, mas o depósito final com um
valor factualmente impossível é exposição evitável. Este achado **não foi
objeto** das respostas R13/R14 nem do ADR-0013; pertence à trilha R10. **Ação
antes do depósito:** substituir pelo SO/kernel real (Windows + build, ou kernel
Linux concreto da série 6.x) ou trocar por "a registrar na execução definitiva"
com marcador visível, como já se faz para armazenamento e modo de energia.

### MENOR

**2. [arrastado de R10-M1, parcialmente resolvido] Expansão de siglas na primeira ocorrência textual ainda incompleta para HITL.**
R10-M1 recomendava expandir RFC, FEDS, HITL, IC inline e remover/introduzir CSP.
Verificação do estado atual:
- **RFC** — expandida inline em §3.11 ("rede de longa distância (\textit{Wide
  Area Network} --- WAN)") e na bibitem `rfc1918` ("Request for Comments (RFC)
  1918"). ✓ resolvido.
- **FEDS** — expandida inline em §3.3 ("No enquadramento FEDS (\textit{Framework
  for Evaluation in Design Science Research})"). ✓ resolvido.
- **IC** — expandida na lista de siglas e usada consistentemente; o corpo
  prefere "intervalo de confiança" por extenso. Aceitável. ✓
- **CSP** — introduzida inline em §3.7.4 ("política de segurança de conteúdo
  (\textit{Content Security Policy} --- CSP)"). ✓ resolvido (não é mais órfã).
- **HITL** — a primeira ocorrência no corpo é na svnota do modelo de ameaça
  (§3.7) antes da expansão "humano no circuito (\textit{Human-in-the-Loop} ---
  HITL)" que aparece em §3.11.2. A lista de siglas supre, mas a prática ABNT de
  expandir na primeira ocorrência textual ainda não é satisfeita para HITL.
  **Ação (opcional):** expandir HITL na svnota do modelo de ameaça ou adiar a
  primeira ocorrência da sigla até §3.11.2.

**3. [verificação de consistência tipográfica] Critério de itálico é defensável mas não auditado por grep neste round.**
R9 (achado 8) recomendava um grep de auditoria para confirmar consistência do
critério de itálico entre *gateway*, *Local-First*, *token*, *stdio*,
*microbenchmark*. A leitura integral de `paper.tex` não detectou instância
claramente divergente, mas a verificação sistemática por grep não foi executada
neste round (escopo de fechamento, não de forma). **Ação (opcional, pré-depósito):**
`grep -nE '\\textit\{(gateway|Local-First|token|stdio|microbenchmark|pods|embeddings)\}' docs/thesis/paper.tex`
e revisar divergências, se houver.

---

## Correção bibliográfica de Mammen / McMahan / HAMSTER

Esta seção verifica as três correções bibliográficas que R13/R4 e R13/M3
solicitaram e que a resposta declara como aceitas.

### McMahan et al. (AISTATS 2017) — **CORRIGIDO** ✓

| Aspecto | Estado R13 (antes) | Estado atual (vigente) |
|---|---|---|
| Presença no `paper.tex` | Ausente; FL ancorada apenas em Imteaj/Mammen 2021 | `\bibitem{mcmahan2017}` presente, com PMLR v. 54, p. 1273-1282, URL `proceedings.mlr.press/v54/mcmahan17a.html` |
| Citação no corpo | — | `\cite{mcmahan2017,mammen2021}` em §2.6 (corpo e tabela) e §5.3 |
| Papel metodológico | — | McMahan = fonte primária (método de FL); Mammen = síntese de oportunidades e desafios |

A dupla citação (fonte primária + survey) segue exatamente a recomendação R13-R4.
A `fonte` da tabela `tab:posicionamento-correlatos` lista ambos. A coluna "Natureza
da evidência mobilizada" da linha FL diz "método primário avaliado e síntese de
oportunidades e desafios" — calibração precisa aos dois tipos de fonte. ✓

### Mammen (arXiv:2101.05428) — **CORRIGIDO** ✓

| Aspecto | Estado R13 (antes) | Estado atual (vigente) |
|---|---|---|
| Autoria | R13 referia-se a "Imteaj 2021" (atribuição incorreta herdada dos documentos de orientação) | `\bibitem{mammen2021}` com "MAMMEN, Priyanka Mary" — autor correto conforme arXiv |
| DOI | — | `10.48550/arXiv.2101.05428` presente |
| Tipo de fonte | | "arXiv preprint" — corretamente rotulado como preprint não revisado por pares |

A correção de autoria (Imteaj → Mammen) foi aplicada tanto na bibitem quanto nas
citações do corpo e da tabela. Não há referência residual a "Imteaj" em `paper.tex`.
✓

### HAMSTER / Pigatto et al. (JIRS, 2016) — **CORRIGIDO** ✓

Três frentes de correção, todas verificadas:

1. **Ano:** `\bibitem{pigatto2016}` com v. 84, p. 705-723, DOI
   `10.1007/s10846-016-0356-x`. O ano **2016** está correto e consistente entre
   `paper.tex`, `REVISAO-ESTRUTURAL-CONCEITUAL.md` e `PONTOS-DE-APOIO-TESE.md`.
   A divergência "2017" em `PUBLICACOES-KALINKA-LINKS.md` (R13-M3) foi corrigida:
   a tabela rápida agora diz "2016" para o item 2 (HAMSTER/JINT). ✓

2. **Força de evidência:** R13-R3 e R14-M2 solicitavam alinhar a prosa
   ("avaliada empiricamente") à formulação mais cautelosa. Verificação:
   - §2.6 agora diz "acompanhada de estudos de caso avaliativos" (não mais
     "avaliada empiricamente"). ✓
   - §5.4 diz "arquitetura nomeada, com camada de segurança explícita e
     acompanhada de estudos de caso avaliativos [...] segue precedente
     estabelecido em arquiteturas de segurança para sistemas críticos". ✓
   - A tabela diz "arquitetura e estudos de caso no próprio domínio". ✓
   A coerência interna entre tabela, §2.6 e §5.4 foi restaurada: nenhum dos três
   pontos sobrealega avaliação empírica controlada. ✓

3. **Equivalência de modelo de falha:** R14-R1 solicitava qualificar que a
   "negação por padrão" do HAMSTER (fail-closed de autenticação) não equivale à
   autorização por escopos do SV (fail-open em escopos vazios). Verificação:
   - §2.6: "O modelo de falha, porém, não é equivalente: chamadas fora da
     concessão são negadas somente para agentes com escopos definidos; escopos
     vazios significam superfície irrestrita, ainda sujeita ao modo do
     contêiner." ✓
   - §5.3: "a negação por padrão do HAMSTER não equivale à autorização por
     escopos do Sovereign Vault, na qual escopos vazios representam superfície
     irrestrita ainda sujeita ao modo do contêiner." ✓

**Conclusão bibliográfica:** as três correções (McMahan adicionado, Mammen
corrigido, HAMSTER calibrado e ano corrigido) estão presentes, consistentes e
sem resíduo. Não há `\cite` sem `\bibitem` nem `\bibitem` sem `\cite` nesta
família de referências.

---

## Decisão P3

**P3** (PONTOS-DE-APOIO-TESE.md, item 3) propunha citar Da Silva, Ferrão, Dezan,
Espes e Castelo Branco (ICUAS, 2023) — IDS por anomalia para enxames de VANTs —
como precedente de "postura adversarial explícita" para legitimar a bateria
pré-especificada de 12 sondas.

**Decisão registrada no próprio documento de orientação (§4):**

> P3: avaliar e rejeitar a inserção — o artigo ICUAS avalia classificadores IDS
> contra ataques e conjuntos de dados, não uma bateria pré-especificada de
> chamadas MCP; a analogia metodológica seria excessiva

**Veredito R15: REJEIÇÃO CORRETA E DEFENSÁVEL.**

A rejeição é metodologicamente acertada por três razões:

1. **Desproporção de analogia.** O artigo ICUAS avalia classificadores de
   detecção de intrusão contra conjuntos de dados de ataque conhecidos (tarefa
   de aprendizado de máquina com métricas de precisão/recall sobre distribuição
   de tráfego). A bateria do Sovereign Vault é um conjunto pré-especificado de
   12 chamadas JSON-RPC com veredito declarado *antes* da execução (tarefa de
   caixa-preta sobre política de gateway). Os dois instrumentos não compartilham
   unidade de análise, métrica nem regime de validação. A citação seria
   decorativa, não de filiação metodológica.

2. **Exposição a cobrança.** Citar um trabalho de IDS por anomalia como
   precedente de "postura adversarial" convidaria a banca (cuja orientadora é
   coautora do ICUAS 2023) a perguntar onde está o classificador de anomalia —
   que não existe no artefato. A citação criaria expectativa que o texto não
   satisfaz.

3. **A bateria já tem filiação suficiente.** A bateria pré-especificada com
   veredito declarado *antes* da execução é instrumento defensável por si: evita
   seleção *post-hoc* de resultados e é coerente com a régua FEDS
   artificial+somativa. Não precisa de âncora externa para ser legítima; precisa
   apenas de qualificação honesta de sua fronteira (feito em §3.11.2, Tabela
   `tab:fronteira-evidencia` e QP3).

**Estado no `paper.tex`:** `\bibitem` de Da Silva et al. (ICUAS 2023) **não está
presente** na bibliografia. Não há `\cite` residual. A rejeição foi efetivada
no artefato. ✓

> Nota: P1 (Silva et al. 2016, JNCA — método de microbenchmark) e P2 (HAMSTER —
> forma da contribuição) e P4 (Ferrão et al. 2022, Sensors — fronteira
> safety/security) **foram aplicados** e estão presentes com `\bibitem` e `\cite`
> consistentes. P5 (enquadramento de governança de dados) foi aplicado como
> enquadramento textual em §1.2, sem citação (correto, pois não é citação e sim
> moldura argumentativa).

---

## Coerência TRACEABILITY

R13-R1 e R13-R2 eram os achados mais sensíveis desta rodada, porque
`TRACEABILITY.md` — o contrato entre tese e artefato — continha duas divergências
em relação a `paper.tex`. Verificação do estado atual:

### R13-R1: sobrealegação de isolamento de SO na RQ3 — **CORRIGIDO** ✓

| Aspecto | Estado R13 (antes) | Estado atual (vigente) |
|---|---|---|
| Linha RQ3 de TRACEABILITY.md | "OS-level isolation mitigating lateral exfiltration" | "Local authentication, capability scopes, configured consent and tamper-evident audit reduce the enumerated lateral accesses within the single-user, single-machine threat model" |
| Qualificação de isolamento | Ausente | "**No OS/process isolation is implemented or evaluated.**" (negrito no original) |

A linha RQ3 agora reflete fielmente a QP3 de §1.3 ("modelo de ameaça de usuário
único e máquina única") e a svnota do modelo de ameaça de §3.7 ("Estão fora de
escopo: comprometimento do sistema operacional [...] inspeção de memória"). A
sobrealegação foi removida. ✓

### R13-R2: contagem de ferramentas 15 vs 17+3 — **CORRIGIDO** ✓

| Localização em TRACEABILITY.md | Estado R13 (antes) | Estado atual (vigente) |
|---|---|---|
| §1 (módulo 2) | "15 tools" | "17 base tools plus 3 broker-conditional tools" |
| §2 (objetivo 1) | "15 tools" | "17 base tools plus 3 broker-conditional tools" |
| §5 (MCP) | "15 tools" | "17 base tools plus 3 tools exposed only when the broker is enabled" |

As três ocorrências foram atualizadas e são agora consistentes com `paper.tex`
§3.7.2 e a Figura `fig:arquitetura-referencia` ("17 ferramentas-base + 3
condicionais de broker (20 com broker habilitado)"). ✓

### Verificação cruzada adicional

- **Âncoras de linha de código:** TRACEABILITY.md não cita
  `crates/sv-mcp/src/lib.rs:2370-2380, 2461-2699` (que `paper.tex` cita para a
  contagem), mas o documento declara em seu rodapé "If a symbol moves, search by
  name", o que torna a ausência de âncora de linha aceitável para um documento de
  apoio (não é o paper).
- **Data de verificação:** TRACEABILITY.md fecha com "Line numbers and counts
  were checked against the working tree on 2026-08-04", posterior às correções
  de R13. Coerente.
- **Coerência §4 (March & Smith):** TRACEABILITY.md §4 diz "March & Smith
  **instantiation** | the whole repository" e separa **model** e **method** como
  linhas distintas — alinhado a R13-M2 (que pedia não rotular a linha SV da
  tabela apenas como "instantiação DSR"). A tabela do paper agora diz "modelo,
  método e instanciação DSR", e o TRACEABILITY.md reflete essa separação. ✓

**Conclusão TRACEABILITY:** as duas divergências relevantes (R1, R2) foram
resolvidas; o documento está coerente com `paper.tex` nos pontos que R13
sinalizou.

---

## Aderência às respostas R13 / R14

Verificação item a item das respostas consolidadas em
`response-to-reviewers-r13-r14.md` contra o texto vigente.

### R13 (metodologia/DSR e integridade de alegações)

| # | Resposta declarada | Verificado no artefato? | Detalhe |
|---|---|---|---|
| 1 | TRACEABILITY.md alinhado à QP3 (sem isolamento de SO, sem comparação com nuvem executada) | ✓ | Ver seção "Coerência TRACEABILITY" acima |
| 2 | Contagem de ferramentas revalidada: 17 base + 3 broker | ✓ | Ver seção "Coerência TRACEABILITY" acima |
| 3 | Força do precedente HAMSTER alinhada a "arquitetura acompanhada de estudos de caso avaliativos" | ✓ | Ver seção "Correção bibliográfica — HAMSTER" acima |
| 4 | McMahan adicionado como âncora primária; autoria de arXiv:2101.05428 corrigida para Mammen | ✓ | Ver seção "Correção bibliográfica — McMahan / Mammen" acima |
| 5 | Não se afirmou ausência de prior art próximo (R13-R5 não aplicado) | ✓ | §2.6 não contém afirmação de ausência de prior art; a renúncia ao levantamento exaustivo permanece como "não [...] levantamento exaustivo" |
| 6 | Linha do SV limitada ao caminho WS; modelo/método/instanciação distinguidos | ✓ | Tabela: "gateway MCP antes da operação no cofre, no caminho WebSocket autenticado"; natureza da evidência: "modelo, método e instanciação DSR" |
| 7 | Tabela rápida de PUBLICACOES-KALINKA-LINKS.md corrigida 2017 → 2016 | ✓ | Item 2 agora diz "2016" |

### R14 (segurança e fronteira conceitual)

| # | Resposta declarada | Verificado no artefato? | Detalhe |
|---|---|---|---|
| 1 | "Negação por padrão" qualificada: falha só para agentes com escopos; vazios = superfície irrestrita sujeita ao modo | ✓ | §2.6 e §5.3 contêm a qualificação literal (ver "Correção bibliográfica — HAMSTER", frente 3) |
| 2 | Célula de comportamento separa autorização (escopo), consentimento (APPROVAL/OTP) e ausência deliberada (DIRECT/ANONYMIZED) | ✓ | Tabela: "autorização por escopo para agentes escopados; consentimento em APPROVAL/OTP; DIRECT e ANONYMIZED não solicitam aprovação" |
| 3 | Confronto remete ao modelo de ameaça de usuário único/máquina única; exclui isolamento de processo/SO | ✓ | §5.3 abre com "A linha do Sovereign Vault deve ser lida no modelo de ameaça declarado na metodologia: usuário único, máquina única [...], sem isolamento de processo ou de sistema operacional" |
| 4 | Legenda registra que naturezas de evidência não são diretamente comparáveis | ✓ | Caption da tabela: "as naturezas de evidência não são diretamente comparáveis entre si" |
| 5 | Assimetria de evidência permanece explícita (estudos de caso avaliativos vs. artificial/somativa/preliminar/uma sessão/sem IC) | ✓ | §5.4 fecha o parágrafo de contribuições com a qualificação completa |

### Verificações pós-resposta declaradas

A resposta declara quatro verificações executadas após as correções:

| Verificação | Declarada | Observação R15 |
|---|---|---|
| `scripts/sync-uspsc-body.py`: 26 citações, 26 entradas, 0 órfãs | ✓ | Não reexecutada neste round (escopo de fechamento); confiável se o estado dos `\cite`/`\bibitem` não mudou desde então — e não mudou, pois nenhum item bibliográfico foi tocado após a resposta |
| Três passadas de `pdflatex` em `paper.tex` e `paper-uspsc.tex`: zero erros, referências indefinidas ou overfull | ✓ | Não reexecutada; same caveat |
| Renderização visual da tabela nas duas variantes | ✓ | Não reexecutada; same caveat |
| `cargo test --workspace`: zero falhas | ✓ | Não reexecutada; same caveat |

> **Ressalva de fechamento:** este round não reexecutou compilação nem testes.
> A aderência verificada é textual (presença das correções no código/paper), não
> de compilação. Se o depósito for precedido de qualquer edição posterior — mesmo
> de vírgula — as quatro verificações devem ser reexecutadas.

---

## Checklist de prontidão para commit

### Itens resolvidos (prontos)

- [x] **R13-R1:** TRACEABILITY.md RQ3 sem sobrealegação de isolamento de SO
- [x] **R13-R2:** TRACEABILITY.md contagem de ferramentas 17+3 coerente com paper.tex
- [x] **R13-R3:** Força de evidência de HAMSTER calibrada (estudos de caso, não "empiricamente avaliada")
- [x] **R13-R4:** McMahan (AISTATS 2017) adicionado; Mammen com autoria correta
- [x] **R13-R5:** Não-aplicação registrada e justificada (não é revisão sistemática)
- [x] **R13-R6:** Linha do SV na tabela limitada ao WS; modelo/método/instanciação distinguidos
- [x] **R13-R7 / M3:** Ano do HAMSTER 2016 corrigido em PUBLICACOES-KALINKA-LINKS.md
- [x] **R13-M1:** Célula "ponto de controle" qualifica caminho WS
- [x] **R13-M2:** "Instantiação DSR" substituída por "modelo, método e instanciação DSR"
- [x] **R14-R1:** Modelo de falha de "negação por padrão" qualificado (fail-open em escopos vazios ≠ fail-closed de HAMSTER)
- [x] **R14-R2:** Célula de comportamento separa autorização / consentimento / ausência deliberada
- [x] **R14-R3:** Modelo de ameaça referenciado na leitura da tabela
- [x] **R14-R4:** Legenda advierte que naturezas de evidência não são comparáveis
- [x] **R14-R5:** Assimetria de força de evidência explícita
- [x] **P1:** Silva et al. 2016 (JNCA) citado como precedente de microbenchmark
- [x] **P2:** HAMSTER citado pela forma da contribuição (não pelo domínio)
- [x] **P3:** Rejeição de Da Silva et al. (ICUAS 2023) registrada e justificada
- [x] **P4:** Ferrão et al. 2022 (Sensors) citado na fronteira safety/security
- [x] **P5:** Enquadramento de governança de dados aplicado textualmente em §1.2
- [x] **ADR-0013:** Permanece *Proposed*; nenhuma implementação iniciada; seis bloqueantes aceitos e encaminhados; decisão de postura de segurança (rebaixar vs. defender) pendente de decisão do autor, mas **não bloqueia o commit do paper** (o paper não depende do ADR-0013)

### Itens pendentes (não bloqueantes para commit, mas resolver antes do depósito final)

- [ ] **R10-R1 [relevante]:** Valor "Linux 7.0" no apêndice — substituir por SO/kernel real ou marcador explícito "a registrar na execução definitiva". **Recomendado resolver antes do depósito.**
- [ ] **R10-M1 [menor, parcial]:** Expandir HITL na primeira ocorrência textual (svnota do modelo de ameaça) ou adiar primeira ocorrência da sigla até §3.11.2.
- [ ] **R9-8 [menor]:** Grep de auditoria de itálicos para fechar consistência tipográfica.
- [ ] **R9-1/R9-2 [processuais, do harness, não do paper]:** Remover `PLACEHOLDER_FIXAR_ANTES_DA_SESSAO` de `collect-metadata.sh`; endurecer `check_integrity` contra campos `n/a`. Não bloqueiam o paper, mas bloqueiam a execução definitiva.
- [ ] **R9-3/R9-4 [processuais]:** Qualificar na legenda que IC bootstrap e Spearman são indicativos em `k=3` (ou elevar mínimo prático para `k≥5`). Pendente para a execução definitiva, não para o paper atual.

### Verificações a reexecutar imediatamente antes do commit

- [ ] `latexmk -pdf -pdflatex="pdflatex %O %S" paper.tex` — zero erros, zero referências indefinidas, zero overfull
- [ ] `latexmk` em `paper-uspsc.tex` — idem
- [ ] `python scripts/sync-uspsc-body.py` — 26/26 citações, 0 órfãs
- [ ] `cargo test --workspace` — zero falhas
- [ ] Inspeção visual da página de `tab:posicionamento-correlatos` nas duas variantes (legibilidade, margens, sem sobreposição)
- [ ] `git diff --stat` confirmar que apenas os arquivos pretendidos estão no stage

---

## Observação de escopo

Este parecer é de **fechamento de integridade**: verifica que as correções
declaradas foram efetivadas e que a coerência transversal foi restaurada. Não
reabre achados de fundo já tratados em R9–R14, não reexecuta compilação nem
testes (instrução de não edição), e não avalia o mérito científico do ADR-0013
(já tratado em R6–R8 e mantido em *Proposed* por decisão registrada). Os itens
arrastados de R10 (R1, M1) estão listados para rastreabilidade, mas pertencem à
trilha R10 e devem ser resolvidos nessa trilha antes do depósito final, não
nesta.

O resultado negativo bem medido do artefato — microbenchmark preliminar de uma
sessão sem IC; bateria finita 10/10 + 2/2 sobre `HitlPolicy` simulada;
exclusões explícitas de RAG, índice vetorial, isolamento de SO, comparação com
nuvem e retenção no provedor — permanece tratado como contribuição válida, em
conformidade com o princípio DSR de que resultado negativo bem medido é
contribuição. Nenhuma qualificação ou limitação deliberada é objeto de proposta
de remoção ou endurecimento.
