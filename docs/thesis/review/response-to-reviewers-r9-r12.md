# Resposta consolidada aos pareceristas — rodada R9–R12

**Artefatos revisados:** `docs/thesis/paper.tex`, `docs/thesis/EXECUCAO-DEFINITIVA.md`,
`docs/thesis/evidence/aggregate.py`, `docs/thesis/evidence/collect-metadata.sh`,
`apps/thesis-eval/src/main.rs`
**Rodada:** 04/08/2026 · cinco pareceres independentes, ângulos separados
**Situação:** todos os achados acionáveis foram implementados ou registrados como
decisão do autor. Nenhum bloqueante permanece aberto no artefato ou no texto.

## Síntese editorial

| Parecer | Ângulo | Modelo | Veredito |
|---|---|---|---|
| [R9](R9-delta-checklist-glm52.md) | Metodologia / DSR (delta) | `zai/glm-5.2` | aprovado com ressalvas |
| [R9b](R9b-integridade-diff-glm52.md) | Integridade científica do diff | `zai/glm-5.2` | Q1 confirmada |
| [R10](R10-full-metodologia-glm52.md) | Metodologia / DSR (texto integral) | `zai/glm-5.2` | aprovado, sem bloqueantes |
| [R11](R11-full-seguranca-glm51.md) | Segurança / ameaças | `zai/glm-5.1` | nenhum invariante quebrado |
| [R12](R12-full-privacidade-glm47.md) | Privacidade / LGPD | `zai/glm-4.7` | aprovado com refinamentos menores |

R9 levantou a única lacuna de processo da rodada: o diff literal não chegou ao
parecerista, de modo que a pergunta de integridade científica (Q1) ficou
condicional. R9b foi executado especificamente para fechá-la, hunk a hunk, e
**confirmou Q1**: nenhuma edição do delta altera número, taxa, medida, resumo
criptográfico, versão, alegação de capacidade ou qualificação.

---

## Achados implementados — instrumentos

### R9-2 — `power_mode` gravado como *placeholder*. **[ACEITO]**

`collect-metadata.sh` passou a exigir `power_mode` como quarto argumento
posicional obrigatório: sem ele, o script sai com código 2 e mensagem de uso.
Não há valor padrão. O comentário de cabeçalho registra a razão — um
*placeholder* no `run-metadata.json` seria proveniência literalmente falsa.

### R9-3 — Integridade não validava o conteúdo dos metadados. **[ACEITO]**

`check_integrity` (§6.5) deixou de conferir apenas existência. Agora rejeita, com
mensagem nomeando o campo ofensor, qualquer um de `cpu_model`, `cpu_cores`,
`ram_kb`, `power_mode`, `rustc` (e demais campos de *host*) que esteja ausente,
vazio, igual a `n/a` ou contendo `PLACEHOLDER`/`FIXAR`. O script de coleta ganhou
o mesmo veto na origem, além de coleta via WMI/PowerShell no Windows, de modo que
um ambiente não coberto **falha** em vez de produzir metadados inúteis.

Verificado por execução: sessões sintéticas com `power_mode` de *placeholder* e
com `cpu_model=n/a` são rejeitadas com saída não-zero e diagnóstico específico.

### R9-4 — Bootstrap e Spearman degenerados em `k=3`. **[ACEITO]**

Duas mudanças, ambas de qualificação, nenhuma de resultado:

- **Deriva (§6.2):** `drift()` retorna `None` para `k < SPEARMAN_MIN_K = 4`. Com
  três pontos sem empate, `|rho|` é sempre 1 e o critério mediria o tamanho da
  amostra, não o fenômeno. Nessa fronteira o agregador emite ressalva explícita
  de que a deriva **não foi verificada**, em vez de uma cascata de falsos
  positivos.
- **IC (§5.2):** com `k < 5`, o agregador emite ressalva declarando que o IC 95%
  por *bootstrap* é indicativo nessa fronteira, determinado pelos extremos das
  médias de sessão. `MIN_SESSIONS=3` permanece como trava anti-execução
  acidental; a execução definitiva planeja `k=5`.

### R9-5 — Disponibilidade confundida com sucesso de transporte. **[ACEITO]**

Este era o achado com consequência numérica. O harness distinguia apenas
`blocked`, e uma falha de pareamento ou de WebSocket entrava como bloqueio,
inflando a taxa de bloqueio e deprimindo a de disponibilidade com ruído de
infraestrutura.

Implementado em `apps/thesis-eval/src/main.rs`:

- `ProbeResult` ganhou o campo `transport_error`;
- `adversarial.csv` ganhou a coluna homônima (coluna acrescentada, nenhuma
  renomeada — CSVs anteriores continuam legíveis);
- a apuração das taxas foi extraída para `tally_adversarial`, função pura que
  remove observações com `transport_error` do numerador **e** do denominador de
  ambas as taxas e conta os erros à parte;
- o Markdown e a saída de console reportam os erros de transporte como linha
  separada, rotulada "excluded from both rates".

Em `aggregate.py`, `aggregate_adversarial` aplica a mesma exclusão, reporta a
contagem de erros de transporte e a converte em ressalva quando houver qualquer
ocorrência.

Cobertura de teste: `transport_errors_leave_both_rates_untouched` verifica que
acrescentar uma sonda de ataque e uma de controle com falha de transporte não
move nenhuma das duas taxas nem seus denominadores.

### R9-6 — Acoplamento implícito com `collect-metadata.sh`. **[ACEITO]**

`EXECUCAO-DEFINITIVA.md` §2.6 passou a declarar explicitamente que **o harness
não emite `run-metadata.json`** e que rodar o script antes de cada sessão é etapa
obrigatória do protocolo, com a consequência nomeada: sem ela, `aggregate.py`
aborta em §6.5 e a sessão é perdida.

*Não* se moveu a chamada para dentro do harness. Fazê-lo colocaria inventário de
*host* na superfície de dependências do artefato, contrariando a política de
`deny.toml` (`AGENTS.md` §6) — a mesma razão que motivou o script externo.

### R9-12 — `--warmup 0` não descarta zero. **[ACEITO como documentação]**

O comportamento é mantido (preserva o esquema legado de `micro.csv`), mas deixou
de ser implícito: o cabeçalho de `main.rs` declara que `--warmup` é um *override*
acima de um piso de uma chamada de *priming*, e que `--warmup 0` e a bandeira
ausente compartilham esse piso. Teste
`warmup_is_an_override_above_a_floor_of_one_discarded_call` fixa o contrato.

### R9-11 — Descarte de uma leitura de *priming* não declarado. **[ACEITO]**

Coberto pela mesma documentação de R9-12: o descarte da chamada de *priming* no
caminho padrão passa a ser explícito, e não uma nota de comentário interno.

### Achado próprio — leitura de booleano sensível ao caso. **[CORRIGIDO]**

Encontrado por verificação independente após a implementação de R9-5, não por
parecerista. É o achado mais grave da rodada.

O harness em Rust serializa booleanos como `true`/`false` (minúsculas, via
`Display` de `bool`). `aggregate_adversarial` comparava contra `"True"`
(maiúscula, convenção do Python). Efeito sobre o `adversarial.csv` preliminar já
versionado:

| Grandeza | Antes da correção | Real |
|---|---|---|
| Taxa de bloqueio | 0/30 (0,0%) | 30/30 (100,0%) |
| IC de Wilson | [0,0; 11,4] | [88,6; 100,0] |

O modo de falha é o pior possível para uma dissertação: **não** levanta exceção,
**não** produz saída implausível e inverte o resultado principal do braço
adversarial. A mesma comparação afetava a coluna `transport_error`, de modo que
erros de transporte reais nunca teriam sido excluídos — anulando na prática a
correção de R9-5.

Correção: `csv_bool()` normaliza o caso, aceita `true/false/1/0` e **aborta** com
mensagem nomeando arquivo e coluna diante de qualquer valor não reconhecido, em
vez de silenciosamente devolver `False`. Nenhum outro ponto do agregador lê
booleano; latency e micro leem numéricos, que já falham alto.

Regressão fixada em `docs/thesis/evidence/test_aggregate.py` (12 testes), que
cobre também a compatibilidade com o CSV legado sem a coluna `transport_error`,
os intervalos de Wilson contra valor de referência publicado, o comportamento do
bootstrap em entrada constante, o gate de Spearman e as regras de integridade.

> **Consequência para o texto:** nenhuma. Os números do Capítulo 4 foram
> produzidos pelo harness, não pelo agregador — que ainda não havia sido usado
> para gerar resultado publicado. O defeito teria corrompido a execução
> definitiva, que é exatamente o que ainda está por rodar.

### R13 — revisão adversarial do agregador (`zai/glm-4.7`). **[2 de 3 ACEITOS]**

Rodada adicional, disparada sobre `aggregate.py` já corrigido, para verificar a
própria correção. Três achados:

1. **`{"host": null}` derrubava o agregador. [ACEITO — confirmado]**
   `meta.get("host", {})` devolve `None` quando a chave existe com valor nulo: o
   padrão só cobre a chave *ausente*. Reproduzido — `AttributeError` abortava a
   execução inteira. O mesmo valia para `toolchain`. Corrigido com
   `meta.get("host") or {}` mais verificação de tipo; a sessão passa a ser
   **rejeitada com diagnóstico** em vez de derrubar o processo.

2. **Denominador zero indistinguível de falha real. [ACEITO]**
   Se todas as observações de uma classe forem excluídas por erro de transporte,
   `wilson_ci(0, 0)` devolve 0% com IC [0,0] — visualmente idêntico a "nada foi
   bloqueado". Mantido o retorno numérico (NaN contaminaria os CSVs), mas
   `main()` passa a emitir ressalva explícita nomeando a classe e declarando que
   a taxa é artefato de amostra vazia, não resultado.

3. **Interpolação de percentil divergiria do numpy. [REJEITADO — falso positivo]**
   Verificado por comparação direta contra `numpy.percentile` em 300 amostras
   aleatórias (n ∈ {3, 5, 10, 15, 100, 10.000}, q ∈ {0,025; 0,5; 0,975}): a
   divergência máxima é 1,4·10⁻¹⁴, ou seja, ruído de ponto flutuante. A
   implementação **é** a convenção linear declarada na docstring. Nenhuma
   mudança. Teste `test_percentile_matches_numpy_default_convention` fixa a
   equivalência (pula se numpy não estiver instalado, em vez de aprovar em
   silêncio).

---

## Achados implementados — texto

### R10-M4 — §Considerações Iniciais genérica. **[ACEITO]**

Enriquecida em vez de removida: a seção passa a declarar o que cada parte do
capítulo entrega (caracterização, enquadramento DSR, modelagem do artefato,
plano de avaliação), eliminando a redundância pura com §1.6.

### R10-M5 — Figura 3.1 referenciada sem leitura. **[ACEITO]**

Acrescentada a leitura do conteúdo visual (ciclo de design ao centro; relevância
ligando o ambiente de aplicação; rigor ligando a base de conhecimento, com o
retorno das contribuições), alinhando o tratamento ao das Figuras 3.2, 3.3 e 4.1.

### R11-R1 — Fronteira `stdio` enunciada só como escopo de medição. **[ACEITO]**

O modelo de ameaça passa a afirmar *in terminis* que pareamento, resolução de
agente, aplicação de escopo e consentimento valem **exclusivamente** para o
transporte WebSocket autenticado, e que iniciar o binário em `stdio` opera com
`PairState::AlreadyPaired(None)` — portanto sem `enforce_scopes` — equivalendo a
acesso local direto, já fora do limite avaliado. Nenhuma qualificação anterior
foi removida.

### R11-R2 — Enumeração do modo *headless* por sub-enunciação. **[ACEITO]**

A `svnota` de segurança passa a enumerar também operações de contêiner DIRECT e
consultas de metadados (listagem de contêineres e arquivos, `vault.info`,
verificação de auditoria, listagem de chaves retornando nome, versão e chave
pública). A asserção de segurança — recusa *fail-closed* de operações *modeless*
portadoras de segredo — permanece intacta.

### R12-R1 — "Detectores ambíguos" sem definição. **[ACEITO]**

Definidos no ponto de uso como aqueles sem validação por dígito verificador ou
soma de verificação e, por isso, sujeitos a maior taxa de falsos positivos.

### R12-R2 — Vínculo com o Art. 5º implícito na resposta a QP1. **[ACEITO]**

A passagem passa a dizer explicitamente que a **combinação** de campos não
detectados — em especial nome e endereço — é precisamente o que pode sustentar a
identificabilidade referida no Art. 5º da LGPD. Nenhuma alegação foi reforçada ou
enfraquecida; apenas o vínculo jurídico já afirmado ficou explícito.

### R9-8 / R9-9 — Critério de itálico. **[ACEITO — auditado]**

Auditoria por varredura confirmou consistência do critério adotado
(estrangeirismos sem tradução corrente em itálico; termos incorporados ao jargão
técnico em português, como *gateway*, em redondo). `modeless` e `headless`
permanecem em itálico por decisão deliberada: são jargão do próprio artefato, não
adjetivos correntes em português.

### R9-7 / checklist §5 — DOIs. **[PARCIALMENTE ACEITO]**

Acrescentados `kleppmann2019` (`10.1145/3359591.3359737`) e `imteaj2021`
(`10.48550/arXiv.2101.05428`). As demais entradas sem DOI são atas de congresso
(NeurIPS) e fontes sem identificador persistente atribuído; **não** se inventou
identificador. A recomendação de R9-7 de resolver cada DOI contra `doi.org` antes
do depósito permanece como verificação final do autor.

---

## Achados não implementados — com razão declarada

### R10-R1 — "Linux 7.0" no apêndice de reprodutibilidade

Já resolvido no delta anterior a este parecer: o apêndice registra a plataforma
com a anotação explícita `valor a reconferir` e declara que armazenamento e modo
de energia serão registrados na execução definitiva. A ressalva de R10 está,
portanto, atendida na forma que ele próprio recomendou (marcador explícito), e
o valor definitivo entra com a execução de `k=5`.

### R10-M1, M2, M3 — siglas, "ponta a ponta", "estão a finalizar"

Corrigidos no delta anterior a este parecer. Verificado por varredura: RFC, FEDS,
HITL e IC expandidos na primeira ocorrência textual; CSP introduzida no corpo com
expansão; "ponta a ponta" sem hifens; a construção "estão a finalizar" não ocorre
mais no texto.

### R9-1 — Re-emissão do diff

Atendida por R9b, que recebeu o diff íntegro e fechou Q1 hunk a hunk.

---

## Verificação

| Verificação | Resultado |
|---|---|
| `cargo test -p thesis-eval` | 5 testes, 5 passam |
| `cargo clippy -p thesis-eval --all-targets` | sem avisos |
| `cargo fmt -p thesis-eval` | aplicado |
| `aggregate.py` sobre sessões sintéticas `k=3` com erros de transporte | taxas preservadas, erros contados à parte, ressalvas de `k<4` e `k<5` emitidas |
| `aggregate.py` com `power_mode` de *placeholder* | rejeitado, saída 1, campo nomeado |
| `aggregate.py` com `cpu_model=n/a` | rejeitado, saída 1, campo nomeado |
| `aggregate.py` com `k=2` | aborta com o mínimo declarado (§5.2) |
| `bash -n collect-metadata.sh` | sintaxe válida |
| `paper.tex` — chaves balanceadas, `\cite`↔`\bibitem` | delta 0; nenhuma citação órfã, nenhum item não citado |

**Integridade científica do delta desta rodada:** nenhuma edição de texto altera
número, taxa, medida, resumo criptográfico, versão, alegação ou qualificação. As
mudanças de instrumento **não** alteram nenhum resultado já publicado: a evidência
preliminar do apêndice foi produzida antes delas e permanece rotulada como
preliminar. A separação `transport_error` muda como taxas futuras serão apuradas,
e essa mudança está declarada aqui e no protocolo.
