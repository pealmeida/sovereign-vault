# Auditoria de Forma Acadêmica e Normas ABNT — Paper.tex

**Arquivo auditado:** `docs/thesis/paper.tex` (classe abntex2, ~44 pp., português brasileiro)
**Data da auditoria:** 2026
**Veredito:** O texto é impessoal e o tempo verbal está majoritariamente correto, mas há **deficiências graves na expansão de siglas no corpo do texto** (14 siglas jamais expandidas), **citações híbridas que quebram o sistema autor-data**, **tabelas e figuras não referenciadas no texto**, **parágrafos de uma frase como padrão de ressalva**, e **inconsistência na italicização de estrangeirismos**. O Capítulo 5 é inteiramente placeholder (TODO). A bibliografia manual tem uma entrada com número incorreto de autores e omissão inconsistente de DOI. Corrigir antes da entrega é mandatório.

---

## 1. IMPESSOALIDADE E TEMPO VERBAL

**Veredito: Bem resolvido, com uma ocorrência pontual.**

O texto mantém linguagem impessoal de forma consistente: "Esta pesquisa propõe", "formula-se a seguinte questão", "definem-se três questões", "Não se afirma que", "Não se infere daí". Não foram encontradas ocorrências de primeira pessoa ("eu", "nós") no corpo textual.

**Tempo verbal:** Predomina o presente do indicativo, conforme exigido. O futuro aparece exclusivamente em contexto metodológico ou de trabalho futuro, o que é aceitável pela norma da disciplina ("observará", "devem", "exige").

**Única ocorrência problemática:**

> "O traço de Peffers é parcialmente retrospectivo, pois o artefato antecede esta proposição." (Cap. 3, §3.4)

- **Ação:** "antecede" está no presente. Se a intenção é narrar a cronologia do desenvolvimento, o pretérito perfeito ("antecedeu") seria mais natural. Não é erro de norma, mas o presente soa estranho para um fato passado. **Sugestão:** unificar com o pretérito do período composto: "pois o artefato antecedeu esta proposição."

---

## 2. SIGLAS — EXPANSÃO NO CORPO DO TEXTO

**Veredito: ERRO DE NORMA generalizado.** Das 21 siglas da lista, apenas 7 são expandidas na primeira ocorrência do corpo textual. As demais 14 aparecem apenas na lista de siglas ou são usadas sem expansão, violando a exigência de "sigla definida na primeira ocorrência".

### 2.1 Siglas CORRETAMENTE expandidas no texto (7/21)

| Sigla | Expansão no texto | Local |
|-------|-------------------|-------|
| IA | "Inteligência Artificial (IA)" | Cap. 1, §1, linha 1 |
| MCP | "Model Context Protocol (MCP)" | Cap. 1, §1.2 |
| DSR | "Design Science Research (DSR)" | Cap. 1, §1.5 |
| SaaS | "Software as a Service (SaaS)" | Cap. 1, §1 |
| RAG | "Geração Aumentada por Recuperação (Retrieval-Augmented Generation --- RAG)" | Cap. 2, §2.1 |
| ADR | "Registros de Decisão de Arquitetura (ADRs)" | Cap. 3, §3.3 |
| KEK | "KEK via Argon2id" — **NÃO expandida** (ver abaixo) | — |

**Correção sobre KEK:** "da qual se deriva uma KEK via Argon2id" (Cap. 3, §3.6.1) — KEK **não** é expandida. Apenas aparece na lista de siglas. Mesmo caso das demais abaixo.

### 2.2 Siglas NUNCA expandidas no corpo do texto — ERRO DE NORMA (14/21)

| Sigla | Onde aparece pela primeira vez | Trecho |
|-------|-------------------------------|--------|
| **LLM** | Cap. 2, §2.1 | "em relação aos LLMs tradicionais" |
| **LGPD** | Resumo (primeira ocorrência no documento) | "Art.~5º da LGPD" |
| **GDPR** | Cap. 2, §2.2 | "a GDPR na União Europeia" |
| **PII** | Cap. 3, §3.6.3 | "filtro de PII" |
| **FEDS** | Cap. 3, §3.3 | "No enquadramento FEDS" |
| **HITL** | Cap. 3, §3.9.2 | "política HITL simulada" |
| **DEK** | Cap. 3, §3.6.1 | "A DEK versionada é envolvida" |
| **OTP** | Cap. 3, §3.6.3 | "DIRECT, APPROVAL, OTP e ANONYMIZED" |
| **HMAC** | Cap. 3, §3.6.4 | "registros encadeados por HMAC-SHA256" |
| **JSON-RPC** | Cap. 3, §3.9.1 | "serialização JSON-RPC no cliente" |
| **WAN** | Cap. 3, Tabela 3.2 | "WAN, inferência em nuvem" |
| **IC** | Cap. 3, §3.8 | "sem IC" |
| **CSP** | Cap. 3, §3.6.4 | "Content Security Policy" (por extenso, mas sigla CSP nunca usada) |
| **RFC** | Bibliografia | "RFC 1918", "RFC 2606" (sigla RFC nunca usada como termo independente) |

**Ação para todas:** Na primeira ocorrência de cada sigla no corpo textual, expandi-la por extenso seguida da sigla entre parênteses. Exemplo: "em relação aos Large Language Models (LLMs) tradicionais". Depois disso, usar somente a sigla.

**Casos especiais:**
- **CSP:** A expressão "Content Security Policy" aparece por extenso, mas a sigla CSP jamais é usada no texto. Ou usar a sigla após expandi-la, ou remover CSP da lista de siglas.
- **RFC:** "RFC" nunca aparece como termo independente; sempre vem seguida de número ("RFC 1918"). Se a intenção é listar a sigla, expandi-la na primeira ocorrência: "Request for Comments (RFC) 1918".

### 2.3 Sigla expandida repetidamente após definição

Não foram encontradas reexpansões indevidas. Uma vez definidas, as siglas são usadas corretamente só como sigla. ✓

---

## 3. ESTRANGEIRISMOS

**Veredito: Inconsistência moderada.** A maioria dos termos em inglês está em itálico, mas há um conjunto de termos técnicos que ora aparecem em itálico, ora não, sem critério claro.

### 3.1 Termos corretamente em itálico (consistente)

`Agentic AI`, `prompt-response`, `Hosts`, `Clients`, `Servers`, `buffer overflows`, `human-in-the-loop`, `artificial + somativa`, `naturalística + somativa`, `trade-off`, `harness`, `post-hoc`, `fail-closed`, `warmup`, `bootstrap`, `prompt injection`

### 3.2 Termos em inglês NÃO italicizados — INCONSISTÊNCIA

| Termo | Ocorrências | Deveria estar em itálico? |
|-------|------------|--------------------------|
| `microbenchmark` | ~15 ocorrências, nenhuma em itálico | Sim — não tem tradução corrente em português |
| `gateway` | ~20 ocorrências, nenhuma em itálico | Discutível — já incorporado ao jargão técnico em português |
| `rollback` | Cap. 3, §3.6.4 | Sim |
| `checkpoint` | Cap. 3, §3.6.4 | Sim |
| `blobs` | Cap. 3, §3.6.1 | Sim |
| `embeddings` | Cap. 1, §1.5 (svnota) | Sim |
| `pods` | Cap. 2, §2.6 | Sim |
| `token` | Cap. 3, §3.7 (svnota) | Sim |
| `stdio` | Cap. 3, §3.9.1 | Sim |
| `WebSocket` | ~8 ocorrências, nenhuma em itálico | Discutível |
| `append-only` | Cap. 3, §3.6.4 | Sim |
| `modeless` | Cap. 3, §3.6.3 e svnota | Sim |
| `desktop` | ~15 ocorrências, nenhuma em itálico | Discutível — amplamente incorporado |
| `software` | ~5 ocorrências | Não — já incorporado ao português |
| `hardware` | Cap. 1, §1.2 | Não — já incorporado |

### 3.3 Termo em itálico que deveria ter tradução em português

> "Trata-se de um \textit{trade-off} deliberado" (Cap. 3, §3.7)

- **Ação:** "trade-off" tem tradução corrente: "compensação", "relação de compromisso" ou "escolha deliberada". A norma da disciplina pede para evitar. **Sugestão:** "Trata-se de uma escolha deliberada de projeto" ou "uma relação de compromisso deliberada".

### 3.4 Termo com tradução disponível — "performance"

Não foi encontrada nenhuma ocorrência de "performance". O texto usa "desempenho". ✓

### 3.5 Ação recomendada

Adotar um critério uniforme: (a) termos sem tradução corrente em português → itálico; (b) termos já incorporados ao jargão técnico brasileiro (software, hardware, desktop, gateway) → redondo, sem itálico; (c) termos com tradução → usar a tradução. Documentar o critério e aplicá-lo consistentemente.

---

## 4. PARÁGRAFOS DE UMA FRASE

**Veredito: Inconsistência.** Há pelo menos 5 parágrafos de frase única no corpo do texto, todos funcionando como ressalvas ou qualificações. Não são erros de norma ABNT, mas a orientação da disciplina é "evitar".

| # | Trecho | Local |
|---|--------|-------|
| 1 | "RAG é aqui fundamentação e direção futura, não uma capacidade implementada ou avaliada nesta instância." | Cap. 2, final do §2.1 |
| 2 | "Essa é uma direção arquitetural: a presente avaliação não verifica descarte de dados por provedores de IA nem implementa índice vetorial." | Cap. 2, final do §2.3 |
| 3 | "Portanto, segurança de memória de linguagem não é isolamento de memória no sistema operacional, nem prova geral contra exfiltração em tempo de execução." | Cap. 2, final do §2.5 |
| 4 | "Não se afirma que a instância entregue seja um sistema RAG ou um repositório de contexto geral: suas operações avaliadas são leituras nomeadas por contêiner e arquivo." | Cap. 3, final do §3.5 |
| 5 | "Nomes lógicos, modos, tamanhos de blobs e outros metadados podem permanecer visíveis." | Cap. 3, final do §3.6.1 |

**Ação:** Incorporar cada parágrafo de uma frase ao parágrafo imediatamente anterior, do qual ele é continuação lógica. Exemplo para o #1: a frase "RAG é aqui fundamentação..." pode ser unida ao parágrafo anterior sobre Şakar e Emekçi, com ponto-e-vírgula ou dois-pontos.

**Nota adicional:** O Capítulo 5 inteiro é composto de seções placeholder com comentários `% TODO Fase 4`. Isso será resolvido quando o capítulo for redigido, mas na versão atual cada seção é zero frases — pior que parágrafo de uma frase.

---

## 5. REFERÊNCIAS CRUZADAS (FIGURAS, TABELAS, EQUAÇÕES)

**Veredito: Duas tabelas não são referenciadas no texto corrente.** Figuras e equações estão OK.

### 5.1 Tabelas NÃO referenciadas no texto — ERRO DE NORMA

| Tabela | \label | Situação |
|--------|--------|----------|
| "Conjunto sintético da avaliação atual" | `tab:dados-avaliacao` | **NÃO é referenciada no texto.** A tabela simplesmente aparece após o parágrafo sobre IC/bootstrap. Nenhum `\ref{tab:dados-avaliacao}` no corpo textual. |
| "O que os dados e o código sustentam" | `tab:fronteira-evidencia` | **NÃO é referenciada no texto.** A tabela abre o Capítulo 4 sem que nenhum parágrafo a anuncie. |

**Ação:** Inserir frase-chamada antes de cada tabela. Exemplo: "A Tabela~\ref{tab:dados-avaliacao} resume o conjunto sintético utilizado." e "A Tabela~\ref{tab:fronteira-evidencia} delimita o que a evidência atual sustenta."

### 5.2 Figuras — OK

Todas as figuras são referenciadas e explicadas:
- `fig:ciclos-dsr` → "A Figura~\ref{fig:ciclos-dsr} situa esses ciclos" ✓
- `fig:arquitetura-referencia` → "A Figura~\ref{fig:arquitetura-referencia} representa os quatro módulos" ✓
- `fig:fluxo-requisicao` → "A Figura~\ref{fig:fluxo-requisicao} explicita a ordem" ✓
- `fig:latencia-estagios` → "A Figura~\ref{fig:latencia-estagios} decompõe as médias" ✓

### 5.3 Equações — OK

- `eq:gateway` → discutida no texto após a definição ✓
- `eq:e2e` → discutida no texto após a definição ✓

---

## 6. BIBLIOGRAFIA E CITAÇÕES

**Veredito: ERRO DE NORMA em citações híbridas e em entrada bibliográfica.** O sistema autor-data do abntex2 é comprometido por citações textuais que bypassam o `\cite`.

### 6.1 Citações híbridas (hardcoded + \cite) — ERRO DE NORMA

O documento mistura dois estilos de citação de forma inconsistente:

| Trecho | Problema |
|--------|----------|
| "Segundo Nisa et al. (2025), essa mudança paradigmática..." (Cap. 1, §1) | Citação 100% textual, sem `\cite`. Não gerará entrada na bibliografia automaticamente. O ano "(2025)" não está vinculado a `\bibitem{nisa2025}`. |
| "Nisa et al. \cite{nisa2025} estruturam o fluxo..." (Cap. 2, §2.1) | Redundante: "Nisa et al." textual + `\cite{nisa2025}`. Produzirá algo como "Nisa et al. (NISA et al., 2025)" — duplicação autor-ano. |

**Ação:** Unificar para o padrão abntex2:
- Citação narrativa: usar `\citeonline{nisa2025}` (se disponível na classe) ou reescrever para citação parentética com `\cite{nisa2025}`.
- Citação parentética: usar `\cite{nisa2025}`.
- **Remover todas as citações textuais** como "Nisa et al. (2025)" e "Kleppmann et al. (2019)" que aparecem sem `\cite`.

**Citações corretas (somente \cite):** `\cite{vaswani2017}`, `\cite{liu2024}`, `\cite{wu2011}`, `\cite{zuboff2019}`, `\cite{anthropic2024}`, `\cite{kleppmann2019}`, `\cite{lewis2020}`, `\cite{sakar2024}`, `\cite{lorenzon2021}`, `\cite{cavoukian2011}`, `\cite{nsa2022}`, `\cite{imteaj2021}`, `\cite{sambra2016}`, `\cite{simon1996}`, `\cite{hevner2004}`, `\cite{hevner2007}`, `\cite{venable2016}`, `\cite{peffers2007}`, `\cite{march1995}`, `\cite{rfc2606}`, `\cite{rfc1918}` — todas usam exclusivamente `\cite`, formato correto. ✓

### 6.2 Entrada com número incorreto de autores — ERRO DE NORMA (NBR 6023)

> `\bibitem{hevner2004} HEVNER, Alan R.; MARCH, Salvatore T.; PARK, Jinsoo; RAM, Sudha.`

São **4 autores**. A NBR 6023 determina que, para mais de 3 autores, usa-se apenas o primeiro seguido de "et al.".

**Ação:** Reduzir para: `HEVNER, Alan R. et al. Design science in information systems research...`

### 6.3 Omissão inconsistente de DOI

Várias entradas que possuem DOI não o incluem, enquanto outras sim:

| Entrada | Tem DOI? | Situação |
|---------|----------|----------|
| `hevner2004` | Sim (10.2307/25148625) | **Faltando** |
| `hevner2007` | Sim | **Faltando** |
| `march1995` | Sim (10.1016/0167-9236(94)00041-O) | **Faltando** |
| `peffers2007` | Sim (10.2753/MIS0742-1222240302) | **Faltando** |
| `venable2016` | Sim (10.1057/ejis.2014.36) | **Faltando** |
| `khan2022` | Sim (10.1145/3505244) | **Faltando** |
| `lorenzon2021` | Provável | **Faltando** |
| `nisa2025` | Sim | Presente ✓ |
| `wu2011` | Sim | Presente ✓ |
| `sakar2024` | Sim | Presente ✓ |

**Ação:** Adicionar DOI a todas as entradas que o possuam, uniformizando o formato.

### 6.4 Uso de \begin{thebibliography} manual

O documento usa `\begin{thebibliography}{99}` em vez de BibTeX/biblatex. Isso **não é um erro** — o abntex2 suporta bibliografia manual e formata as citações em autor-data corretamente. Porém, é frágil: qualquer inconsistência de digitação no campo author/ano dentro do `\bibitem` pode quebrar a formatação. Para trabalhos futuros, recomenda-se migrar para um arquivo `.bib` com `\bibliography`, mas não é mandatório para esta entrega.

### 6.5 Formato das entradas — OK

As entradas seguem o padrão ABNT: autor em versalete/MAIÚSCULAS, título em itálico, elementos na ordem: autor, título, periódico/evento, volume, número, páginas, data. ✓

---

## 7. ESTRUTURA ABNT (ELEMENTOS PRÉ-TEXTUAIS)

**Veredito: Estrutura correta.** A ordem dos elementos pré-textuais segue a NBR 14724:

1. Capa (`\imprimircapa`) ✓
2. Folha de rosto (`\imprimirfolhaderosto`) ✓
3. Resumo em português ✓
4. Resumo em inglês (Abstract) ✓
5. Lista de figuras ✓
6. Lista de tabelas ✓
7. Lista de siglas ✓
8. Sumário ✓

**Elementos ausentes (todos opcionais, não configuram erro):**
- Folha de aprovação — tipicamente exigida na versão final. O campo `\orientador` ainda está como placeholder `[ORIENTADOR(A) A CONFIRMAR]`.
- Dedicatória — opcional.
- Agradecimentos — opcional.

**Ação:** Preencher o nome do(a) orientador(a) antes da entrega. A folha de aprovação provavelmente será exigida pela secretaria do curso; verificar com o orientador.

---

## 8. CONSISTÊNCIA TIPOGRÁFICA

**Veredito: Bem resolvido, com uma observação pontual.**

### 8.1 Separador decimal — OK

Uso consistente de vírgula: "14,70", "17,77", "189,79". ✓

### 8.2 Unidades com espaço não separável — OK

O comando `\micro` é definido como `\newcommand{\micro}{\,$\mu$s}`, que insere espaço não separável (`\,`) antes de "µs". ✓

### 8.3 Aspas — OK

Uso correto de aspas duplas no padrão LaTeX para português: ```capitalismo de vigilância''`, ```injeções''`. ✓

### 8.4 Travessões — OK

- Em-dash (---): "Retrieval-Augmented Generation --- RAG", "Aviso de segurança --- modo headless". ✓
- En-dash (--): "construir--avaliar" (range/relação). ✓

### 8.5 "et al." — OK

Uso consistente de "et al." sem itálico nas entradas bibliográficas, conforme prática corrente em ABNT. ✓

### 8.6 Observação: "et al." em citações textuais

> "Segundo Nisa et al. (2025)" (Cap. 1)

Se esta citação for convertida para `\citeonline`, o abntex2 deve formatar "et al." automaticamente. Mas se permanecer textual, verificar que "et al." está em redondo (está), consistente com o restante.

---

## 9. LISTA FINAL PRIORIZADA — O QUE CORRIGIR ANTES DA ENTREGA

### 🔴 Crítico (erro de norma — corrigir obrigatoriamente)

1. **Expandir 14 siglas no corpo do texto** (LLM, LGPD, GDPR, PII, FEDS, HITL, DEK, OTP, HMAC, JSON-RPC, WAN, IC, CSP, RFC). Cada uma deve ser expandida na primeira ocorrência textual, não apenas na lista de siglas. (§2)

2. **Corrigir citações híbridas.** Remover "Nisa et al. (2025)" textual e "Nisa et al. \cite{nisa2025}" redundante. Usar exclusivamente `\cite{}` (parentética) ou `\citeonline{}` (narrativa). (§6.1)

3. **Referenciar as duas tabelas órfãs no texto:** `tab:dados-avaliacao` e `tab:fronteira-evidencia` precisam de `\ref{}` no corpo textual antes de aparecerem. (§5.1)

4. **Corrigir entrada `hevner2004`:** reduzir para 1 autor + "et al." (NBR 6023). (§6.2)

### 🟡 Importante (inconsistência — corrigir para uniformidade)

5. **Unificar italicização de estrangeirismos.** Definir critério e aplicá-lo a: microbenchmark, gateway, rollback, checkpoint, blobs, embeddings, pods, token, stdio, WebSocket, append-only, modeless. (§3)

6. **Incorporar parágrafos de uma frase** aos parágrafos anteriores (5 ocorrências). (§4)

7. **Adicionar DOI faltante** às entradas bibliográficas que o possuem (hevner2004, hevner2007, march1995, peffers2007, venable2016, khan2022, lorenzon2021). (§6.3)

8. **Substituir "trade-off"** por tradução em português ("relação de compromisso", "escolha de projeto"). (§3.3)

### 🟢 Sugestão (preferência estilística — recomendado)

9. **Preencher o Capítulo 5** (Discussão e Considerações Finais) — atualmente só contém placeholders `% TODO Fase 4`.

10. **Preencher `\orientador{}`** com o nome confirmado do(a) orientador(a).

11. **Revisar "antecede"** no Cap. 3, §3.4 — considerar "antecedeu" para consistência temporal.

12. **Migrar de `\begin{thebibliography}` para BibTeX** em iteração futura (não mandatório para esta entrega).

---

*Fim da auditoria. Nenhuma edição foi feita no arquivo paper.tex.*
