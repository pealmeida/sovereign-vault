# A0 — Verificação direta do autor (pré-auditoria)

**Executado por:** condução da sessão, com comandos verificáveis · **Data:** 03/08/2026
**Escopo:** reprodutibilidade do apêndice e alegações absolutas de alto risco do Capítulo 3.
**Método:** execução real de `sha256sum`, `git cat-file` e leitura do código — não inspeção de texto.

Complementa as auditorias delegadas [A1](A1-auditoria-dados-qwen35.md) (dados) e
[A2](A2-auditoria-rastreabilidade-deepseek.md) (rastreabilidade).

---

## Veredito

Reprodutibilidade **íntegra**. Duas alegações de alto risco **confirmadas**. Um
defeito de citação encontrado: números corretos, localização errada.

---

## 1. Hashes do apêndice — CONFEREM

Recalculados com `sha256sum` e comparados ao publicado no apêndice:

| Arquivo | Publicado | Recalculado | Confere |
|---|---|---|---|
| `latency.csv` | `2e914c1b…9adc` | `2e914c1b…9adc` | sim |
| `adversarial.csv` | `845a1d04…1d5f` | `845a1d04…1d5f` | sim |
| `micro.csv` | `d526ed70…bf4c` | `d526ed70…bf4c` | sim |

Os dados publicados correspondem byte a byte aos arquivos versionados. Não houve
regeneração silenciosa.

## 2. Commit declarado — EXISTE

`dfb0a49f7360aedf37ee89152b99e2d970b6cfd6` resolve para um objeto do tipo
`commit` no repositório (`git cat-file -t`). A cadeia de proveniência do apêndice
está intacta.

## 3. "Proibição de `unsafe` nos crates próprios" — CONFIRMADA

A tese usa o plural. Verificado em todos os nove crates:

| Crate | `forbid`/`deny(unsafe_code)` |
|---|---|
| sv-audit, sv-core, sv-crypto, sv-http, sv-keychain, sv-mcp, sv-privacy, sv-recovery, sv-storage | presente em todos |

A alegação no plural **se sustenta**.

**Nuance para o autor decidir.** Entre os *apps*, `apps/sv-validate` não tem a
proibição (`cli`, `desktop` e `thesis-eval` têm). A tese diz "crates próprios", e
`sv-validate` é app, não crate — a frase está tecnicamente correta. Se quiser
blindar contra questionamento em banca, vale precisar: "nos nove crates da
biblioteca". Não é erro; é precisão opcional.

> **Correção à auditoria A2.** O A2 afirma que a proibição está nos 9 crates
> "e 3 apps". São **quatro** apps (`cli`, `desktop`, `sv-validate`,
> `thesis-eval`), e `sv-validate` **não** tem a proibição — confirmado por
> `grep -rn unsafe_code apps/sv-validate/`, sem resultado. A conclusão do A2
> sobre o plural continua correta; a contagem de apps, não.

## 4. "17 ferramentas-base + 3 de broker = 20" — NÚMERO CONFIRMADO, CITAÇÃO ERRADA

**O número está certo.** Enumeração dos nomes de ferramenta declarados em
`crates/sv-mcp/src/lib.rs`:

- 21 nomes `vault.*` distintos;
- menos `vault.pair` (handshake de pareamento, não ferramenta de dado) → 20;
- destes, 3 são de broker: `broker_request`, `create_broker_secret`,
  `list_broker_secrets`;
- restam **17 base**. Logo 17 + 3 = 20. **Confere.**

**A citação de linha está errada.** A tese cita
`crates/sv-mcp/src/lib.rs:2139-2147,2877-2914` como evidência dessa contagem. O
conteúdo real dessas faixas é:

- `2139-2147` — validação de teto de modo em escopo de agente
  (`mode_ceiling cannot widen container mode`);
- `2877-2914` — código de teste do broker (`broker_secrets.lock()`).

Nenhuma das duas faixas contém a declaração das ferramentas nem a contagem. As
localizações corretas, verificadas por `grep`, são:

| O que | Linha real |
|---|---|
| `fn tool_descriptors(broker_enabled: bool)` — definição canônica com broker | 2370 |
| `fn base_tool_descriptors()` — as 17 ferramentas-base | 2461 |
| teste `tools_list_omits_broker_when_disabled` (assert 17) | 3168 |
| teste `tools_list_includes_broker_when_enabled` (assert 20) | 3192 |
| declarações individuais `vault.*` | ~1179 a ~1784 |

> **Divergência entre auditorias — resolvida por verificação.** A auditoria
> [A2](A2-auditoria-rastreabilidade-deepseek.md) afirma que as faixas citadas
> *contêm* os testes de contagem (linhas 2139-2147 e 2877-2914). Isso é
> **incorreto**: os testes estão em 3168 e 3192. O A2 chegou à conclusão certa
> (a citação é frágil e deveria apontar para as funções canônicas) por um
> caminho factualmente errado — descreveu conteúdo que existe, mas em outro
> lugar do arquivo. A recomendação do A2 permanece válida; a justificativa dele,
> não.

**Ação recomendada:** citar `crates/sv-mcp/src/lib.rs:2370` e `:2461` (definição
canônica), em vez de faixas de teste — funções nomeadas são mais estáveis a
refatoração do que números de linha de teste.

**Severidade: relevante.** Não é alegação falsa — é evidência que aponta para o
lugar errado. Numa defesa, um avaliador que abrir a linha citada não encontra o
que a tese diz estar ali, o que fragiliza a percepção de rigor de *todas* as
demais citações.

**Ação:** corrigir a citação para a faixa onde as ferramentas são efetivamente
declaradas, ou apontar para o teste que fixa a contagem, se existir.

---

## Implicação transversal

O defeito nº 4 é de um tipo que se propaga: a tese contém dezenas de citações
`arquivo:linha`, e o código evoluiu desde que foram escritas. Uma citação
apodrecida foi encontrada nas primeiras que verifiquei. A auditoria
[A2](A2-auditoria-rastreabilidade-deepseek.md) varre o conjunto completo.

**Recomendação de processo:** antes da entrega, verificar programaticamente
*todas* as citações `arquivo:linha` do `paper.tex` — arquivo existe, faixa existe,
conteúdo corresponde. É verificação automatizável e deveria rodar antes de cada
versão entregue.

---

## 5. Correção aplicada — todas as 13 citações `arquivo:linha` (03/08/2026)

Varredura completa do `paper.tex`: 77 ocorrências de `\codigo{}`, das quais 13
com `arquivo:linha`. Todas verificadas em **conteúdo**, não apenas em existência.
**Quatro estavam erradas** e foram corrigidas:

| Alegação | Citação anterior | Conteúdo real dela | Citação corrigida |
|---|---|---|---|
| 17 + 3 = 20 ferramentas MCP | `sv-mcp:2139-2147,2877-2914` | validação de teto de modo; teste de broker | `sv-mcp:2370-2380,2461-2699` (`tool_descriptors`, `base_tool_descriptors`) |
| 7 categorias de PII | `sv-privacy:46-77,205-232` | enum vai de 49 a 64; detectores em 483+ | `sv-privacy:49-64,206-233,483-575` |
| ZKP/NATIVE reservados e rejeitados | `sv-mcp:1159-1199` | trecho não relacionado | `sv-mcp:2156-2165` (`mode_rank`) |
| Modos suportados no desktop | `desktop:786-805` | função começa na 772 | `desktop:772-819` (`approval_requirement`) |

Uma faixa foi **estendida** por truncar a evidência: `sv-mcp:1715-1740` cobria
`vault.encrypt` (1723) e `vault.decrypt` (1732), mas deixava `vault.sign` (1741)
de fora — passou a `1715-1750`.

As oito restantes foram **confirmadas em conteúdo**: `sv-crypto` (Argon2id em 92,
AEAD em 149), `sv-core/keyring.rs` (`WrappedDek`/`dek_version` em 206),
`sv-core/lib.rs` (`CustodyMode` e `unlock`), `sv-core/transit.rs`, `sv-audit`,
`sv-mcp:18` (`#![forbid(unsafe_code)]`), e os dois arquivos de configuração do
Tauri.

Após a correção: `pdflatex` compila com **0 erros, 0 referências indefinidas, 0
overfull > 20 pt, 44 páginas**.

### Verificação automatizada instalada

O verificador foi versionado em `scripts/check-thesis-citations.py` (caminhos
relativos ao repositório). Rode antes de cada versão entregue:

```
python3 scripts/check-thesis-citations.py
```

Ele confere existência do arquivo e validade da faixa. **A conferência de
conteúdo continua manual** — é o passo que pegou as quatro citações erradas, já
que uma faixa pode ser válida e ainda assim apontar para o trecho errado.
