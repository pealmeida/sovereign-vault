# Resposta consolidada às auditorias — padrões científicos e open source

**Rodada:** 03/08/2026 · quatro auditorias independentes, domínios separados
**Escopo:** `paper.tex` (forma e evidência) e codebase (saúde open source)

| Auditoria | Domínio | Modelo | Veredito |
|---|---|---|---|
| [A0](A0-verificacao-autor.md) | Verificação direta (execução) | — | reprodutibilidade íntegra; 4 citações corrigidas |
| [A1](A1-auditoria-dados-qwen35.md) | Dados e conferência numérica | `ollama/qwen3.5:397b` | sem achados |
| [A2](A2-auditoria-rastreabilidade-deepseek.md) | Rastreabilidade código↔tese | `ollama/deepseek-v4-pro` | aprovado com ressalvas |
| [A3](A3-auditoria-opensource-qwen35.md) | Saúde open source | `ollama/qwen3.5:397b` | lacunas de citabilidade |
| [A4](A4-auditoria-forma-abnt-deepseek.md) | Forma e normas ABNT | `ollama/deepseek-v4-pro` | 4 erros de norma |

---

## Aplicado nesta rodada

### Forma acadêmica (A4)

| Achado | Verificação | Ação |
|---|---|---|
| Siglas nunca expandidas no corpo | A4 relatou 14; **medição própria: 11** (CSP, FEDS e HITL já estavam expandidas) | Expandidas 9 na primeira ocorrência em prosa: KEK, DEK, OTP, HMAC, LGPD, GDPR, LLM, PII, JSON-RPC |
| Citação híbrida | Confirmado: linha 86 tinha `Nisa et al. (2025)` sem `\cite` | Trocado por `\cite{nisa2025}` |
| Tabelas órfãs | Confirmado: `tab:dados-avaliacao` e `tab:fronteira-evidencia` | Referenciadas e explicadas no texto |
| **Equações órfãs** | **Não relatado pelo A4 — achado próprio:** `eq:gateway` e `eq:e2e` também estavam órfãs | Ambas referenciadas com `\eqref` |
| `hevner2004` com 4 autores | Confirmado; NBR 6023 pede "et al." acima de 3 | `HEVNER, Alan R. et al.` |

**Resultado medido:** siglas não expandidas de 11 → 2; órfãos em tabelas, figuras e
equações: 0. Compilação: 0 erros, 0 referências indefinidas, 0 *overfull* > 20 pt,
44 páginas.

**As duas siglas remanescentes (RFC, WAN) foram deixadas deliberadamente.** Ambas
só ocorrem em tabela e em bibliografia, nunca em prosa. Inserir prosa artificial
só para expandi-las pioraria o texto; a lista de siglas cumpre a norma nesses casos.

### Saúde open source (A3)

| Achado | Ação |
|---|---|
| `CITATION.cff` ausente | **Criado.** Validado contra o schema CFF 1.2.0 (YAML válido, campos obrigatórios completos). Inclui referência cruzada à monografia. Dois `TODO` explícitos: `date-released` (não há tags) e `doi` (depende do Zenodo) |
| CI não validava licenças | **Corrigido.** `deny.toml` definia a lista de licenças permitidas, mas o CI rodava só `bans` e `sources` — política existia e não era aplicada. Comando passou a `check bans sources licenses` |
| Licença do texto acadêmico ambígua | **Sinalizado, não decidido.** `docs/thesis/README.md` dizia apenas que o PDF *não* é Apache-2.0. Escolha do autor, possivelmente condicionada às regras de depósito da USP |

---

## Verificado por execução (não por leitura)

| Verificação | Resultado |
|---|---|
| `cargo fmt --all -- --check` | limpo |
| `cargo clippy --workspace --all-targets` | 0 erros, 0 avisos |
| Hashes SHA-256 do apêndice vs. CSVs | 3/3 conferem byte a byte |
| Commit de proveniência declarado | existe |
| 24 células da tabela de latência vs. `latency.csv` | 24/24 conferem |
| Citações `arquivo:linha` | 13/13 válidas após correção |
| Proibição de `unsafe` | presente nos 9 crates |
| Contagem 17 + 3 = 20 ferramentas MCP | confirmada por enumeração |

**CI já cobre**, em três plataformas: build, testes `--all-features`, clippy com
`-D warnings`, `fmt`, `cargo audit`, `cargo deny`, MSRV, auditoria de dependências
de UI e validação de gateway ponta a ponta. As actions são **fixadas por SHA** —
prática de cadeia de suprimentos recomendada pelo OpenSSF e pouco adotada.

---

## Onde as auditorias erraram

Registro para calibrar a confiança em rodadas futuras. **Nenhum erro alterou a
conclusão**, mas todos exigiram verificação.

1. **A2 — contagem de apps.** Afirmou proibição de `unsafe` em "9 crates e 3
   apps". São **quatro** apps, e `apps/sv-validate` **não** tem a proibição
   (`grep -rn unsafe_code apps/sv-validate/` não retorna nada). A conclusão sobre
   o plural continua correta.
2. **A2 — localização alucinada.** Afirmou que as linhas citadas na tese
   (`2139-2147`, `2877-2914`) *contêm* os testes de contagem de ferramentas. Os
   testes estão em **3168** e **3192**; as funções canônicas em **2370** e
   **2461**. Chegou à recomendação certa por um caminho factualmente errado.
3. **A4 — contagem de siglas.** Relatou 14 siglas nunca expandidas; a medição
   direta encontrou **11**. Incluiu CSP, FEDS e HITL, que já estavam expandidas.
4. **A4 — omissão.** Não detectou que as **duas equações** também estavam órfãs,
   embora tenha detectado as tabelas.
5. **R7 (rodada anterior) — auto-atribuição.** Declarou-se `glm-4.6`; a execução
   real usou `glm-5.2`. Modelos erram a própria identidade.

**Lição de processo:** auditoria delegada é excelente para *encontrar* candidatos
a defeito, e não confiável para *confirmar* fatos. Todo achado que motive edição
deve ser reverificado por execução.

---

## Pendente de decisão do autor

1. **DOI via Zenodo.** É o que permite a tese citar o artefato de forma estável.
   A integração GitHub-Zenodo leva minutos e exige uma tag de release — hoje não
   há nenhuma. Recomendado antes da entrega.
2. **Licença do texto acadêmico.** Declarar qual é, não apenas qual não é.
3. **`cargo deny check licenses` não foi validado localmente** (`cargo-deny` não
   está instalado nesta máquina). Se a lista de licenças permitidas estiver
   incompleta, o CI falhará no próximo *push* — a correção é ajustar a lista,
   não remover a checagem.
4. **Bibliografia manual.** O documento usa `thebibliography` em vez de
   `abntex2cite`. Funciona e compila, mas a migração daria formatação autor-data
   automática conforme a ABNT. Trabalho de baixo risco, ainda pendente do plano
   original (Fase 4).
