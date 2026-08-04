# R9 — Revisão do delta (metodologia/DSR) · rodada CHECKLIST-ENTREGA

Revisor: R9 (ângulo: metodologia / DSR).
Escopo: delta não commitado de `docs/thesis/paper.tex`, `docs/thesis/EXECUCAO-DEFINITIVA.md`, e arquivos novos em `docs/thesis/evidence/` (`aggregate.py`, `collect-metadata.sh`).
Data: 2026-06.

---

## Veredito (uma linha)

**APROVADO COM RESSALVAS** — nenhuma edição no delta altera número, taxa, medida ou qualificação do paper (pelos títulos declarados das mudanças); `aggregate.py` cumpre §5–§6 e a estatística está correta; mas há três pontos que o autor não deve aceitar acriticamente: (i) o diff literal fornecido neste prompt está corrompido (BOM UTF-16 `ÿþd`, sem corpo), de modo que a afirmação "nenhum número mudou" **não pôde ser confirmada linha a linha** — precisa de re-emissão do diff ou de um `git diff --word-diff` anexo; (ii) `collect-metadata.sh` carrega um `power_mode: "PLACEHOLDER_FIXAR_ANTES_DA_SESSAO"` hardcoded, que vira lixo de proveniência se não for editado; (iii) bootstrap percentílico e Spearman com `k=3` (mínimo declarado) produzem IC/deriva estatisticamente fracos — defensável, mas tem de ser dito na legenda.

---

## Achados por severidade

### BLOQUEANTE

Nenhum achado estritamente bloqueante, **contanto que** o item Lacuna‑1 abaixo seja resolvido (re‑emitir o diff ou anexar `git diff --word-diff docs/thesis/paper.tex`) antes de assinar a ausência de alteração numérica. Sem o texto do diff, a pergunta central 1 ("alguma edição altera número/resultado/taxa/medida/alegação?") não é auditável por mim.

> **Lacuna-1 (processo, não do artefato):** o bloco `=== DIFF ===` neste prompt contém apenas o BOM UTF-16 (`ÿþd`). Não há diff visível. Trabalhei, portanto, sobre (a) a descrição em prosa do delta fornecida no próprio prompt, (b) leitura direta de `apps/thesis-eval/src/main.rs`, (c) leitura de `docs/thesis/evidence/aggregate.py` e `docs/thesis/evidence/collect-metadata.sh`. O veredito acima é condicional a essa descrição em prosa estar completa e fiel.

### RELEVANTE

1. **`collect-metadata.sh` grava `power_mode` como placeholder fixo.** Linha:
   ```json
   "power_mode": "PLACEHOLDER_FIXAR_ANTES_DA_SESSAO"
   ```
   Isso não é um valor de campo — é um lembrete. Se o script rodar como está na sessão real, o `run-metadata.json` (e o `aggregate-metadata.json`, que herda a sessão) conterá proveniência literalmente falsa, violando o espírito do §3 (metadados de host) e o critério de reprodutibilidade do §5.2. **Recomendação:** transformar `power_mode` em argumento posicional obrigatório (ou falhar com `set -u` se vazio) antes de qualquer coleta definitiva; nunca mergulhar placeholder no repositório.

2. **`collect-metadata.sh` é acoplado a Linux/proc e o próprio script admite que retorna `n/a` no Windows.** Em `aggregate.py`, `check_integrity` apenas confere *existência* de `run-metadata.json` e que os CSVs tenham ≥2 linhas — **não valida que os campos de host sejam não-`n/a`**. Resultado: uma sessão Windows rodada sem preenchimento manual dos campos `n/a` passa no §6.5 mas produz metadados inúteis. **Recomendação:** adicionar em `check_integrity` um veto a `"n/a"` nos campos `cpu_model`, `cpu_cores`, `ram_kb`, `rustc` (ou ao menos um warning na seção de ressalvas), senão a régua de integridade do §6.5 dá falsa sensação de conformidade.

3. **Bootstrap percentílico sobre `k=3` médias de sessão é estatisticamente fraco.** `aggregate.py` está correto na forma (unidade independente = sessão; reamostragem com reposição via `random.Random.choices`; percentis 2,5/97,5 com interpolação linear, mesma convenção do `numpy.percentile` default; semente declarada `RNG_SEED=20260606`). Mas com o mínimo `MIN_SESSIONS=3`, o IC 95% percentílico de bootstrap é determinado praticamente pelo triplo (mín, med, máx) das três médias — larga variabilidade e coverage pobre. **Recomendação:** o protocolo §5.2 deve (a) declarar explicitamente que `k=3` é mínimo *estrutural* e que o IC nessa fronteira é apenas indicativo, ou (b) subir o mínimo prático para `k≥5` (mantendo `MIN_SESSIONS=3` só como trava anti-execução acidental). Não é bug — é qualificação que falta.

4. **Spearman de deriva (§6.2) com `k=3` é quase sempre ±1.** `spearman(range(k), vals)` com 3 pontos: qualquer sequência sem empate exato dá |ρ|=1; com um empate, |ρ|≈0,5 ou 0. O limiar `SPEARMAN_MAX=0.8` será disparado em praticamente toda célula com `k=3`, gerando uma cascata de "ressalvas" que mais refletem o tamanho de amostra do que deriva real. **Recomendação:** ou aplicar o §6.2 apenas quando `k≥4`, ou trocar o critério de deriva por slope de Theil–Sen (robusto a n pequeno) e reportar ρ só descritivamente. Documentar a limitação.

5. **`aggregate_adversarial` confunde "disponibilidade" com "sucesso de pareamento/transporte".** No harness, `run_probe` retorna `blocked=true` também quando o WS/pareamento falha (não só quando a política nega). O agregador então conta `not blocked` como sucesso de *controle* (disponibilidade). Logo, uma falha de transporte aleatória reduz a taxa de disponibilidade reportada e infla a de "bloqueio" indiretamente. Com `n_sondas` pequeno por sessão, isso é material. **Recomendação:** distinguir no CSV da sonda um terceiro veredito (`transport_error`) e excluir esses casos do numerador de *ambas* as taxas (ataque e controle), reportando-os à parte como falha de infraestrutura — senão o IC de Wilson está sendo aplicado sobre uma mistura de efeito de política e de ruído de transporte.

6. **O harness **não** invoca `collect-metadata.sh`; o acoplamento é implícito.** Confirmei em `apps/thesis-eval/src/main.rs`: não há nenhuma chamada a `collect-metadata.sh` nem escrita de `run-metadata.json`. Logo, a afirmação do §2.6 reescrito ("`run-metadata.json` é coberto por script externo") é verdadeira *apenas se* o operador rodar o script manualmente entre sessões. Se o protocolo reescrito não documentar essa sequência obrigatória (rodar o script **antes** de cada sessão, no mesmo diretório), `aggregate.py` vai abortar com `run-metadata.json ausente (§3)` e a execução inteira falha. **Recomendação:** o §2.6 deve tornar essa etapa explícita e não-opcional (ou, melhor, o harness deveria chamar o script via `std::process::Command` ao final de cada sessão, para eliminar a dependência de disciplina humana).

### MENOR

7. **Plausibilidade dos 5 DOIs (não pude resolver contra o DOI System, mas conferi prefixos/ISSN):**
   - `10.2307/25148625` — Hevner et al. 2004, *MIS Quarterly*. Prefixo JSTOR `10.2307` bate com MISQ. **Plausível.**
   - `10.1145/3505244` — ACM (`10.1145`). **Plausível.**
   - `10.1016/0167-9236(94)00041-2` — Elsevier (`10.1016`), *Decision Support Systems* (ISSN 0167-9236). March & Smith 1995. **Plausível e consistente com o padrão Elsevier antigo.**
   - `10.2753/MIS0742-1222240302` — prefixo M.E. Sharpe `10.2753`, ISSN JMIS `0742-1222`, vol. 24(3) artigo 2. Peffers et al. **Plausível.**
   - `10.1057/ejis.2014.36` — Palgrave Macmillan / Springer `10.1057`, *European Journal of Information Systems*. Venable et al. 2016. **Plausível.**
   Formato consistente com as entradas pré-existentes (assumindo que estas já usam o esquema `https://doi.org/<doi>`). **Recomendação:** rodar um `curl -LH 'Accept: application/x-bibtex' https://doi.org/<doi>` em cada um antes do depósito final e colar o cabeçalho `title` no rodapé de revisão — confirmação barata e custa uma linha.

8. **Critério de itálico é defensável, mas parcialmente arbitrário.** Italizar *microbenchmark*, *stdio*, *checkpoint*, *rollback*, *append-only* é corrente em CST/CE. Já manter *gateway* e *Local-First* em redondo é uma escolha legítima (termo corrente em português técnico / nome próprio composto), mas criar uma fronteira onde *token* fica em itálico e *gateway* não é difícil de sustentar consistentemente num texto longo. **Recomendação:** grep de auditoria (`grep -nE '\\textit\{(gateway|Local-First|token|stdio|microbenchmark|pods|embeddings)\}' docs/thesis/paper.tex`) para confirmar zero divergências; se houver uma única instância escapando da regra, o critério vira inconsistência tipográfica citável pela banca.

9. **`modeless` e `headless` em itálico é incomum.** São adjetivos correntes; italizá-los sugere estranheza que provavelmente não é intencional. Se a intenção é marcar jargão, ok; se é só herança de substituição em massa, reconsiderar. **Recomendação:** confirmar a intenção com o autor; se for estilístico, manter; se não, desligar.

10. **Tradução `trade-off → relação de compromisso` está correta** e é preferível em texto acadêmico em PT-BR. `antecede → antecedeu` (pretérito) é correto se o tempo do verbo ao redor já é passado; **caveat:** não pude conferir a concordância de tempo sem o diff. Recomendação: checar que a frase hospedeira não ficou híbrida (pretérito + presente).

11. **`write_micro_metadata` suprime metadados quando `warmup==0`.** Defensável (preserva schema legado), mas cria uma assimetria de auditabilidade: o path default (`warmup==0`) faz *uma* leitura de priming silenciosa (`micro_warmup_iterations(0)==1`) que não aparece em nenhum CSV. Não é um erro — está documentado em comentário — mas é o tipo de detalhe que um revisor hostl aponta como "descarte não declarado de 1 observação". **Recomendação:** mencionar explicitamente na legenda do microbench que o path default descarta 1 chamada de priming por tamanho.

12. **`micro_warmup_iterations(0)==1` viola a semântica literal de "`--warmup` controla o número de chamadas descartadas".** Quando o usuário *não* passa `--warmup`, descarta-se 1; quando passa `--warmup 0`, a semântica estrita seria "descartar 0", mas o código ainda descarta 1. O comentário justifica ("legacy one-shot priming"), mas é uma incoerência entre a flag e o comportamento no valor-limite `0`. **Recomendação:** ou tornar `--warmup 0` literalmente zero descartes (e exigir priming explícito), ou documentar no §2.6 que `--warmup` é um *override* e que o piso é sempre 1. Hoje é o segundo; deixe explícito.

---

## Respostas diretas às perguntas centrais

**Q1 — Integridade científica:** Pelos *títulos* das mudanças (DOIs, expansão de siglas WAN/RFC, tradução de *trade-off*, correção de tempo verbal, normalização tipográfica), **nenhuma** edição deveria alterar número, taxa, medida, resultado ou qualificação. **Mas não posso atestar linha a linha: o diff literal não veio** (Lacuna-1). Re-emissão obrigatória.

**Q2 — DOIs, siglas e itálico:** DOIs plausíveis e bem-formados, prefixos coerentes com as editoras (achado 7). Expansão `WAN→Wide Area Network` e `RFC→Request for Comments` (em `rfc1918`) estão corretas; `trade-off → relação de compromisso` está correta (achado 10). Critério de itálico é defensável mas parcialmente arbitrário; requer grep de auditoria para fechar consistência (achados 8, 9).

**Q3 — A reescrita do protocolo descreve fielmente o harness?** Sim, no essencial, verificado em `apps/thesis-eval/src/main.rs`:
- `--warmup` e `--seed` existem e são parseados (defaults `0` e `None`).
- `latency_cells(seed)` aplica `shuffle_cells` (xorshift64) só quando `seed` é `Some`; testes `absent_seed_preserves_the_original_cell_order`, `same_seed_has_the_same_order_and_different_seed_changes_it`, `zero_warmup_keeps_the_measured_iteration_count` cobrem o contrato.
- O servidor de warmup **não tem** `TimingSink` (construído sem `.with_timing_sink(...)`), exatamente como o protocolo afirma — descarte não contamina o buffer de medição.
- `write_latency_metadata` / `write_micro_metadata` emitem CSVs companheiros só quando `warmup>0` ou `seed` é `Some`, preservando o schema legado.
- Porém o harness **não** escreve `run-metadata.json`; isso é delegado a `collect-metadata.sh` (achado 6), e o protocolo precisa tornar essa etapa obrigatória e explícita.

**Q4 — `aggregate.py` cumpre §5–§6 e a estatística está correta?** Sim, com ressalvas:
- Bootstrap sobre as **k médias de sessão** (não sobre iterações) — correto, evita pseudorreplicação (§5.1–§5.2). A `boot_ci` reamostra com reposição (`rng.choices`), B=10.000, percentis por interpolação linear. **Correto.**
- Wilson `score interval` exato (§5.3), fórmula conferida, não recorre à aproximação normal. **Correto.**
- Spearman via ranks com média em empates (Pearson sobre rangs). **Correto na implementação.**
- CV amostral com `ddof=1`. **Correto.**
- Nada é descartado: divergências vão para `reservations`, nunca silenciadas (§5.4). **Correto.**
- Limitações materiais: bootstrap e Spearman fracos em `k=3` (achados 3, 4); confusão disponibilidade×transporte no adversarial (achado 5); integridade não checa conteúdo dos metadados (achado 2).

---

## Recomendações concretas (priorizadas)

1. **Re-emitar o diff** do `paper.tex` (e do `EXECUCAO-DEFINITIVA.md`) em UTF-8 limpo ou como `git diff --word-diff`, anexando ao relatório. Sem isto, R9 não fecha a pergunta Q1.
2. **Remover `PLACEHOLDER_FIXAR_ANTES_DA_SESSAO`** de `collect-metadata.sh`, transformando `power_mode` em argumento obrigatório.
3. **Endurecer `check_integrity`** em `aggregate.py` para rejeitar campos `n/a` em `cpu_model`/`cpu_cores`/`ram_kb`/`rustc`.
4. **Qualificar na legenda** que, em `k=3`, IC bootstrap e Spearman são indicativos (ou elevar o mínimo prático para `k≥5`).
5. **Separar `transport_error` de `blocked`** no CSV adversarial e excluir do numerador de ambas as taxas.
6. **Tornar a chamada a `collect-metadata.sh` obrigatória e explícita no §2.6** (ou, melhor, invocá-la do próprio harness ao fim de cada sessão).
7. **Grep de auditoria** de itálicos para fechar consistência tipográfica antes do depósito.
8. **Resolver os 5 DOIs** via `curl` contra `doi.org` e anexar o `title` retornado.

---

## Lacunas declaradas

- **Diff literal ausente** neste prompt (Lacuna-1). Veredito é condicional à fidelidade da descrição em prosa.
- Não executei `git diff` (instrução do enunciado) nem rotei o harness — a revisão é estática sobre `main.rs`, `aggregate.py` e `collect-metadata.sh`.
- Não verifiquei o conteúdo efetivo do `EXECUCAO-DEFINITIVA.md` reescrito (o `grep` falhou no shell disponível); working assumption: a reescrita afirma o que o prompt descreve.
- DOIs não foram resolvidos contra o DOI System; only verificação de prefixo/ISSN.
