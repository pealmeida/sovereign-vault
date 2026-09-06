# Auditoria de `RESULTS-V2-ARTEFATO.md`

Revisão dos resultados medidos sobre o artefato real (commit `9d05c9fe`), confrontados com
a análise prévia. **Veredito geral: aceitar a maior parte, corrigir um item, e promover dois
achados que o relatório subvaloriza.**

Onde o artefato contradiz o substituto, **o artefato ganha** — essa era a função do
substituto e errar é seu modo de falha aceitável. Duas exceções abaixo não são o artefato
contradizendo o substituto; são um estimador aplicado fora de sua condição de validade.

---

## Resumo dos vereditos

| # | Alegação do relatório | Veredito da auditoria |
|---|---|---|
| 1 | E1: 0/6 contrastes excluem zero sob protocolo corrigido | **ACEITO** — resultado principal, sólido |
| 2 | E1/P2: média dá inversão falsa em 16 KiB que a mediana rejeita | **ACEITO e PROMOVIDO** — é o achado metodológico mais forte da rodada |
| 3 | E2: braço A reproduz 2/6 (mediana), 4/6 (média), não 6/6 | **ACEITO** |
| 4 | E2: harness reescrito (495 linhas), sem `run-metadata.json` na Tabela 5 | **ACEITO e PROMOVIDO** — muda o enquadramento do item bloqueante |
| 5 | E2: efeito de posição do substituto **REFUTADO** | **REJEITADO** — estimador não identificável nos braços de ordem fixa |
| 6 | E3: `enforce_scopes` ~2,1–2,2 µs, escala com \|escopos\| | **ACEITO** — lacuna do item 5 fechada |
| 7 | E4(b): robustez de formato **REFINADA** por categoria | **ACEITO** — correção legítima do substituto |
| 8 | E4(c): densidade = 63,7 % da inclinação, substituto **REFUTADO** | **ACEITO e REFORÇADO** — com validação cruzada que o relatório não fez |
| 9 | E5: A11–A15 BLOCKED contra o binário real | **ACEITO** — fecha a lacuna crypto/broker |
| 10 | E5/C4: bug em `enforce_scopes` torna 3 operações inalcançáveis | **ACEITO e PROMOVIDO** — achado de maior impacto da rodada |
| 11 | Cobertura original é 5/20, não 7/20 | **ACEITO — erro meu**, ver §C |
| 12 | §1.5: `T_total` exclui o custo do audit-write | **ACEITO e PROMOVIDO** — não solicitado, e é uma limitação de medição de primeira ordem |

---

## A. O único item a corrigir: a "refutação" do efeito de posição (§3, E2)

O relatório conclui que o efeito de posição está **refutado** porque, sob ordem fixa
(braços A/B — a condição que reproduz o protocolo publicado), a inclinação é ≈ 0
(+0,029 %, −0,015 %), enquanto o maior efeito (−0,17 %) aparece no braço *aleatorizado* (C) —
"mecanicamente o oposto do que a atribuição exigiria".

**Esse raciocínio inverte a lógica do estimador.** O procedimento normaliza cada célula pela
sua própria mediana entre sessões e regride sobre `order_index`. Em ordem fixa, **cada célula
ocupa exatamente uma posição em todas as sessões**. Normalizar pela mediana da própria célula
remove, por construção, toda a variância que o regressor poderia explicar: célula e posição
são colineares perfeitos. A inclinação ≈ 0 nos braços A/B não é evidência de ausência de
efeito de posição — é o comportamento algébrico esperado do estimador quando ele não é
identificável.

Verificação direta nos dados do substituto, onde o mecanismo é **idêntico nos dois braços por
construção** (mesmo binário, mesma máquina, mesma sessão de medição):

| braço | inclinação | p | posições distintas por célula |
|---|---|---|---|
| ordem fixa | **+0,024 %/posição** | 0,61 | **1** |
| ordem aleatorizada | **−0,151 %/posição** | 0,070 | 6–9 |

O substituto reproduz exatamente o padrão que o relatório interpretou como refutação — e no
substituto sabemos que não há diferença de mecanismo entre os braços. O sinal desaparece na
ordem fixa porque o estimador não consegue vê-lo ali, não porque ele não esteja lá.

![identificabilidade]({{artifact:art_5ad8ac81-ae8c-4d05-ae8a-e93b0f3e7eab}})

**Consequência prática — pequena.** A conclusão *substantiva* do relatório provavelmente está
certa: ele propõe que o mecanismo real é **categórico** ("DIRECT executa primeiro e paga custo
de estado frio"), não uma deriva linear contínua. Concordo, e isso é mais coerente com o braço
A reproduzir a inversão apenas em 128 B. O que precisa mudar é apenas o *estatuto epistêmico*:

- ❌ "o efeito de posição está REFUTADO para este artefato"
- ✅ "a atribuição linear de −0,15 %/posição não é testável em ordem fixa, porque o estimador
  não é identificável nesse desenho; o padrão observado (inversão concentrada em 128 B, ausente
  nos demais) favorece um efeito categórico de estado frio na primeira célula sobre uma deriva
  linear por posição"

**Teste que decidiria a questão**, se valer o custo: braço A com a ordem de células
*invertida* (ANONYMIZED primeiro, DIRECT por último). Se a inversão acompanhar a posição em
vez do modo, o efeito de ordem está confirmado sem depender de nenhuma regressão.

---

## B. Dois achados que o relatório subvaloriza

### B1. A ausência de proveniência da Tabela 5 é maior que o item bloqueante original

O relatório reporta, dentro de E2, que `docs/thesis/evidence/latency.csv` foi commitado em
`4b9282d`, que `apps/thesis-eval/src/main.rs` recebeu **495 linhas de diff** depois disso, e
que **não existe `run-metadata.json` para a execução original**. Isso está enterrado como
qualificação de um sub-item.

Deveria ser promovido, porque **reformula o item bloqueante do parecer**. A pergunta deixa de
ser "por que o artefato exibe uma inversão impossível?" e passa a ser "a Tabela 5 publicada
não é reproduzível a partir deste repositório, e a inversão que ela exibe não é reproduzível
nem sob o braço que replica seu protocolo". Combinado com o braço A recuperando apenas 2/6
(mediana) ou 4/6 (média), a leitura honesta é:

> A Tabela 5 foi gerada por um harness que não existe mais na sua forma original, sem registro
> de proveniência, e o protocolo publicado tal como reconstruível hoje não reproduz o padrão
> publicado.

Isso é mais defensável do que qualquer explicação mecanicista, e resolve o item bloqueante de
forma limpa: os números devem ser **substituídos** pelos do E1, não explicados. Recomendo que
a §4.2 diga isso explicitamente e que a ausência de `run-metadata.json` entre nas limitações —
é exatamente a lacuna que o protocolo corrigido elimina daqui em diante.

### B2. `T_total` exclui o audit-write (§1.5) — reportar no corpo, não em nota

O relatório descobriu, sem que isso fosse pedido, que
`StageTimings.total = validate + authorize + execute + filter` é uma **soma de sub-estágios**,
não um relógio de parede, e que o audit-write obrigatório de pré-execução cai no intervalo
entre `authorize` e `execute` — sendo, portanto, **nunca contabilizado**.

Isso afeta toda a Tabela 5 e todas as tabelas E1–E3, e afeta a tese em um ponto de tese, não de
medição: o custo da **auditoria à prova de violação** — um dos três pilares do Sovereign Vault —
é sistematicamente invisível em toda a avaliação de desempenho. A tese afirma sobrecusto de
mediação baixo enquanto omite do denominador o custo de um dos mecanismos que caracterizam a
arquitetura.

Recomendo: declarar isso explicitamente em §4.1 como limitação da instrumentação, e medir o
audit-write na próxima rodada (é barato — um quinto bucket em `StageTimings`, atrás de feature
flag, exatamente como o enunciado previa).

### B3. O bug do `enforce_scopes` (C4) merece seção própria

Três operações — `vault.info`, `vault.export_agents`, `vault.import_agents` — são
**inalcançáveis por qualquer agente em modo headless real**, porque `enforce_scopes` as nega
incondicionalmente para requisições sem container, e o servidor headless recusa agentes sem
escopo. A política headless *pretende* permitir `vault.info`.

Isso é exatamente o que uma sonda com veredito pré-especificado existe para encontrar, e vale
mais que os 11 acertos juntos: valida empiricamente a tese metodológica de que a extensão da
bateria de sondas era necessária. **Recomendo tratá-lo como resultado, não como nota de
rodapé** — e registrar que ele foi encontrado por uma sonda cujo veredito esperado foi
congelado antes da execução, o que é a diferença entre um achado e uma racionalização.

---

## C. Onde o relatório está certo e eu estava errado

**Cobertura: 5/20, não 7/20.** Minha matriz foi reconstruída da prosa da tese com nomes de
ferramentas provisórios; o relatório contou diretamente em `run_adversarial`. Contagem no
código-fonte real prevalece. Os números corretos são **5/20 (25 %) → 17/20 (85 %)**, e todo o
material anterior que cite 7/20 (35 %) deve ser corrigido, inclusive o resumo.

**Nomes de ferramentas.** `transit.decrypt` → `vault.decrypt`, `signing.sign` → `vault.sign`,
`transit.encrypt` → `vault.encrypt`, `broker.issue` → `vault.create_broker_secret`,
`broker.exchange` → `vault.broker_request`. Adotar os reais.

**Robustez de formato (E4b).** O agregado 0,375 do substituto mascarava estrutura real:
CPF/CNPJ/cartão compartilham `collect_grouped_digits` e são **100 % robustos**; telefone/SSN/
e-mail dependem de sintaxe fixa e caem a 0 %. A formulação correta não é "cobertura é por
formato, não por categoria", mas "**as três categorias com dígito verificador são robustas a
formato; as três com sintaxe fixa não são**". Isso é uma correção legítima e a redação da
§5.2.2 deve segui-la.

**Densidade de PII (E4c).** O substituto atribuiu 92,6 % da inclinação à varredura; o filtro
real atribui 63,7 % à densidade — errei por **8,6×**, e na direção que favorecia o artefato.
Retirar integralmente a "qualificação favorável".

### Validação cruzada que o relatório não fez, e que reforça seu próprio resultado

O ajuste real, avaliado em densidade = 1, prediz o `micro.csv` publicado quase exatamente:

| | inclinação |
|---|---|
| `micro.csv` publicado (3 pontos) | 7,626 ns/B |
| ajuste do artefato em densidade = 1 | 7,395 ns/B |
| concordância | **97,0 %** |

Predição pontual: 8,14 µs vs 7,86 µs medidos em 1 KiB; 121,7 µs vs 125,08 µs em 16 KiB. **O
ajuste novo é consistente com os dados publicados** — o que confirma que as células publicadas
de fato operavam em densidade saturada, e que a decomposição nova é uma explicação *do mesmo
fenômeno*, não uma medição divergente. Isso torna a refutação mais forte do que o relatório a
apresenta, e dá um número publicável:

> O custo de filtragem relatado (7,63 ns/B) é o custo em **densidade máxima de PII**. Um
> documento do mesmo tamanho sem nenhuma PII custa 2,68 ns/B — **36,6 % do valor publicado**.
> A Tabela do `micro.csv` mede o pior caso, não o caso típico.

Recomendo incluir essa frase na §5.2.2: ela é favorável ao artefato *e* correta, ao contrário
da qualificação que eu havia proposto.

---

## D. Itens a fechar antes de submeter

1. **Corrigir o estatuto da refutação de posição** (§A) — de REFUTADO para NÃO IDENTIFICÁVEL,
   mantendo a conclusão substantiva de efeito categórico.
2. **Promover a lacuna de proveniência da Tabela 5** (§B1) à §4.2 e às limitações.
3. **Declarar a exclusão do audit-write de `T_total`** (§B2) na §4.1; medir na próxima rodada.
4. **Elevar o bug C4 a resultado** (§B3), registrando a pré-especificação do veredito.
5. **Corrigir 7/20 → 5/20** em todo o material, inclusive resumo.
6. **Adicionar a validação cruzada de densidade** (§C) à §5.2.2.
7. **Governor `powersave`** — o relatório declara corretamente que isso infla variância sem
   enviesar comparações dentro-de-máquina. Concordo para E1/E2/E5. Para **E3** há uma ressalva:
   os três braços de escopo rodaram em **ordem fixa (0→1→20)**, e o relatório já atribui a
   isso o delta negativo fisicamente implausível em 128 B/escopo=1. Como o efeito de ~2,1 µs é
   grande e consistente nos três payloads, a conclusão se sustenta — mas **aleatorizar a ordem
   dos braços de escopo** na próxima rodada removeria a única ressalva do único item que fecha
   uma lacuna declarada da tese.
8. **Ainda NÃO MEDIDO**, e a manter declarado: bateria contra o `ApprovalState` real do
   desktop; Braço B cloud-direct; custo isolado do audit-write; `vault.destroy`,
   `vault.list_transit_keys`, `vault.list_signing_keys` (3/20 sem cobertura).

---

## E. Higiene de submissão

O trabalho está em *working tree*, sem commit. Antes de commitar, verificar que nenhum CSV de
evidência contém material sensível — os identificadores são declaradamente sintéticos
(RFC 1918, RFC 2606, NANP 555-01XX, SSN 900-999, BIN 400000), o que está correto, mas a chave
HMAC de auditoria e quaisquer caminhos de container reais não devem aparecer em
`run-metadata.json`. Vale um `grep` antes do commit.

Recomendo commits separados: (i) extensões do harness em `apps/thesis-eval`, (ii) evidências
em `docs/thesis/evidence/v2/`, (iii) relatório e figuras. O bug do `enforce_scopes` merece
issue própria, **não** correção na mesma rodada — corrigi-lo agora invalidaria a evidência
E5 recém-coletada.
