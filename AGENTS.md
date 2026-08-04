# AGENTS.md — contexto para agentes que trabalham neste repositório

Este repositório é **duas coisas ao mesmo tempo**, e confundi-las é a principal
fonte de erro:

1. Um produto de software real (Sovereign Vault — cofre local + gateway MCP).
2. O **artefato de instanciação** de uma pesquisa de mestrado profissional
   (Design Science Research), cujo texto vive em `docs/thesis/paper.tex`.

Toda mudança de código pode virar uma alegação na tese. Toda alegação na tese
precisa de código verificável que a sustente. Trate os dois lados como
acoplados.

---

## 1. A regra que não se negocia: integridade científica

O texto da tese passou por revisão por pares interna
(`docs/thesis/review/R1-R5*.md` + `response-to-reviewers.md`). A calibração das
alegações é **deliberada**: cada número tem uma qualificação ao lado, e cada
limitação foi negociada com os revisores.

**Nunca**, ao editar `docs/thesis/`:

- alterar um número, resultado, taxa ou medida;
- remover, enfraquecer ou "melhorar" uma qualificação, ressalva ou limitação;
- afirmar capacidade que o código não tem;
- descrever trabalho futuro como se estivesse implementado.

Se você acredita que uma alegação está errada, **não a corrija silenciosamente**:
diga-o no relatório e deixe a decisão para o autor.

Em particular, estas capacidades **NÃO existem** no artefato avaliado e não
devem aparecer em texto ou figura como se existissem:

- RAG, índice vetorial, busca semântica, embeddings locais;
- isolamento de memória no nível do sistema operacional;
- comparação executada com um braço em nuvem;
- retenção/descarte de dados verificado no provedor de IA.

Todas constam como trabalho futuro (ver `docs/adr/0012-context-containers.md` e
`docs/thesis/EVOLUTION.md`).

---

## 2. Mapa do repositório

| Caminho | O que é |
|---|---|
| `crates/sv-core` | Cofre: contêineres, chaves, trânsito |
| `crates/sv-crypto` | XChaCha20-Poly1305, Argon2id, Ed25519 |
| `crates/sv-storage` | Formato `.svault`, validação de nomes/caminhos |
| `crates/sv-mcp` | Gateway MCP: ferramentas, escopos, consentimento |
| `crates/sv-privacy` | Detecção e mascaramento de PII (modo ANONYMIZED) |
| `crates/sv-audit` | Log encadeado por HMAC-SHA256 |
| `apps/desktop` | Interface Tauri (human-in-the-loop) |
| `apps/thesis-eval` | **Harness de avaliação da tese** — gera a evidência do Cap. 4 |
| `docs/adr/` | Registros de Decisão de Arquitetura (ciclo de rigor da DSR) |
| `docs/thesis/` | Tese, protocolos de avaliação, rastreabilidade |

Leituras de orientação antes de mexer em algo relevante:
`docs/thesis/TRACEABILITY.md` (código ↔ tese), `docs/thesis/EVALUATION.md`
(como a evidência é produzida), `docs/threat-model.md` (o que está dentro e fora
do escopo de segurança).

---

## 3. Como esta pesquisa decide (DSR)

O método é Design Science Research, com os três ciclos de Hevner. Na prática,
para um agente, isso significa:

- **Toda decisão de projeto relevante vira um ADR** em `docs/adr/`, numerado em
  sequência, seguindo o formato dos existentes: Context / Decision /
  Consequences / Alternatives considered / References. O ADR-0010 é um bom
  modelo de densidade e honestidade.
- **Alternativas rejeitadas são parte do resultado**, não ruído. Registre por que
  foram rejeitadas — é isso que torna o ciclo de rigor auditável.
- **Resultado negativo bem medido é contribuição válida.** Se um classificador
  tem recall ruim, reporte o recall ruim. Não ajuste o experimento até o número
  ficar bonito.
- **Evidência tem fronteira.** O Cap. 4 tem uma tabela chamada "Fronteira de
  Evidência" que declara o que os dados sustentam e o que não sustentam. Ao
  adicionar evidência, adicione também sua qualificação.

---

## 4. Evidência experimental: a régua

A evidência atual no texto é **preliminar** (uma sessão, sem intervalo de
confiança) e está rotulada como tal em todo lugar. A execução definitiva exige,
conforme já declarado no próprio texto:

- k ≥ 3 sessões independentes;
- intervalo de confiança de 95% por *bootstrap*;
- regra explícita de *warmup*/descarte;
- registro de SO/kernel, CPU, RAM, armazenamento, `rustc`, perfil, comando,
  modo de energia e data;
- perfil `--release` (medições em `debug` não são reportáveis).

Comando: `cargo run --release -p thesis-eval -- all --out target/thesis-eval --iterations 1000`

Se você gerar dados novos, **atualize também os hashes SHA-256** no apêndice de
reprodutibilidade de `paper.tex`. Números no texto que não batem com o CSV
versionado são um defeito grave.

---

## 5. LaTeX: o que quebra e como não quebrar

`docs/thesis/paper.tex` usa a classe **abntex2** (normas ABNT, português
brasileiro). Toolchain local nesta máquina:

```
C:\Users\pealm\AppData\Local\Programs\MiKTeX\miktex\bin\x64\pdflatex.exe
```

Compile com 2–3 passadas (`-interaction=nonstopmode`) para resolver sumário,
listas e referências cruzadas. **Sempre compile antes de reportar sucesso** —
verificação estática de LaTeX não é confiável e já deixou passar 68 erros.

Armadilhas já pagas neste projeto — não as reintroduza:

- **`\imprimirfolhaderosto` tem argumento opcional.** A linha em branco logo
  depois dele é obrigatória; sem ela o LaTeX consome o `\begin{resumo}` seguinte
  e o documento quebra em cascata. Há um comentário no arquivo explicando.
- **`\listadefiguras` / `\listadetabelas` não existem** na abntex2. O documento
  usa `\listoffigures*` e `\listoftables*`. Não "corrija".
- **`step` é chave reservada do TikZ.** Não nomeie um estilo assim.
- **`\codigo` (definido via `\DeclareUrlCommand`) quebra em argumento móvel.**
  Em `\caption`, use `\protect\codigo{...}` ou uma caption curta opcional:
  `\caption[curta]{longa}`.
- **`ytick=data` no pgfplots exige coordenadas numéricas.** Rótulos de texto como
  coordenada fazem o pgfplots tentar avaliá-los como expressão matemática.
- Figuras largas: envolva em `\resizebox{\textwidth}{!}{...}` (o `graphicx` já
  está carregado) para não estourar a margem ABNT.

Ao terminar, **apague os artefatos de build**: `paper.aux`, `paper.log`,
`paper.out`, `paper.toc`, `paper.lof`, `paper.lot`, `paper.pdf`. Nenhum deles
deve ficar no repositório.

Norma de escrita da disciplina: linguagem **impessoal** (nunca "eu"/"nós"),
tempo **presente** (futuro só em metodologia), estrangeirismos em *itálico*,
sigla definida na primeira ocorrência e depois só a sigla, evitar parágrafos de
uma única frase. Toda figura e tabela **deve** ser referenciada com `\ref{}` e
explicada no texto — é exigência explícita da orientadora.

---

## 6. Convenções de código

- Rust, workspace Cargo. Crates próprios proíbem `unsafe` — é uma alegação da
  tese (`crates/sv-mcp/src/lib.rs:18`); não introduza `unsafe`.
- `cargo test --workspace` antes de reportar conclusão.
- `deny.toml` governa licenças e advisories; dependência nova pode quebrar o CI
  e amplia a superfície de suprimentos — que é argumento da tese. Justifique.
- Mudança que afeta segurança deve vir com teste de regressão e, quando muda o
  modelo de ameaça, atualização de `docs/threat-model.md`.
- Commits: Conventional Commits. **Não faça commit nem push sem pedido
  explícito** — o autor revisa antes.

---

## 7. Orquestração multi-agente

Este projeto usa vários modelos, com papéis distintos. A regra é: **quem
escreve não é quem revisa.**

### Codex (via plugin `codex`)
Dois modelos, escolhidos pela natureza da tarefa:

- **`gpt-5.6-sol`** — tarefas densas em julgamento: redação de ADR, decisões de
  arquitetura, redação da tese, análise de trade-off.
- **`gpt-5.6-terra`** — tarefas mecânicas verificáveis: implementação com
  especificação fechada, correção de compilação, refactor, testes. É o default
  em `~/.codex/config.toml`.

Uso: `--model gpt-5.6-sol` na primeira linha do prompt delegado.

### AnyModel (via plugin `anymodel`)
Usado para **revisão por pares**, com modelos diferentes do que escreveu o
texto — é o que dá independência à crítica. A tese já tem precedente disso: as
revisões R1–R5 em `docs/thesis/review/` foram feitas com GLM e Qwen.

Sintaxe que funciona (descoberta na marra; as demais falham):

```bash
node "C:/Users/pealm/.claude/plugins/cache/any-model/anymodel/0.3.0/scripts/companion.mjs" \
  delegate --wait --engine direct --model zai/glm-5.2 --write "<prompt>"
```

Pontos que quebram se ignorados:
- **`--engine direct` é obrigatório.** O default é `codex`, que só aceita
  modelos OpenAI e rejeita `glm-*` com HTTP 400.
- **O modelo precisa do prefixo de registro**: `zai/glm-5.2`, não `glm-5.2`.
- `--provider zai` sozinho **não** funciona — é filtro de listagem, não
  seletor de engine.
- `--write` é necessário se o revisor deve gravar o arquivo de revisão.

Modelos disponíveis: `zai/glm-{4.5,4.5-air,4.6,4.7,5,5-turbo,5.1,5.2}` e um
conjunto local via `ollama/` (probe com `companion.mjs models ""`).

### Divisão de papéis por ângulo
Ao revisar uma decisão relevante, use revisores com ângulos **separados**, para
que não convirjam no óbvio. O padrão adotado:

| Ângulo | Modelo usado | Pergunta central |
|---|---|---|
| Metodologia / DSR | `zai/glm-5.2` | A alegação é avaliável? O protocolo sustenta? |
| Segurança / ameaças | `zai/glm-5.1` | Que caminho quebra o invariante? |
| Privacidade / LGPD | `zai/glm-4.7` | A métrica técnica corresponde ao conceito jurídico? |

Revisões vão para `docs/thesis/review/R<N>-<assunto>-<modelo>.md`, no formato
dos R1–R5: veredito de uma linha, achados numerados por severidade
(bloqueante / relevante / menor), recomendações concretas.

**O revisor não edita o artefato revisado.** Ele reporta; a decisão de aplicar
é do autor.

---

## 8. Como reportar

Ao final de uma tarefa, reporte nesta ordem:

1. O que mudou, arquivo por arquivo.
2. O que foi **verificado por execução** (compilação, testes) e o que não foi —
   diga explicitamente quando não conseguiu executar algo.
3. Decisões que precisam de confirmação humana.
4. O que da especificação você **não** conseguiu cumprir, e por quê.

Não reporte sucesso sem ter executado a verificação. É melhor dizer "não
consegui compilar neste ambiente" do que entregar uma verificação estática como
se fosse compilação.
