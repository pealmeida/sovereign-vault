# Checklist de entrega — TCC MBA em IA e Big Data (USP/ICMC)

**Gerado em:** 04/08/2026 · **Estado do documento auditado:** `docs/thesis/paper.tex`, 48 páginas
**Prazo:** dezembro/2026

> ## Aviso de procedência das exigências
>
> Este checklist é montado a partir de **três fontes verificáveis**:
>
> 1. **Material das disciplinas** de Metodologia e Projeto I, II e III
>    (`C:\Users\pealm\Downloads\MBA-IA-TCC\`), incluindo as "Dicas para a Escrita
>    Científica" e as instruções da orientadora;
> 2. **ABNT** — NBR 14724 (estrutura de trabalhos acadêmicos), NBR 6023
>    (referências), NBR 6028 (resumo), conforme implementadas pela classe
>    `abntex2`;
> 3. **Verificação direta** do estado atual do documento e do repositório.
>
> **O que este checklist NÃO é:** o regulamento oficial de depósito do ICMC/USP.
> Não tive acesso a ele. Os itens marcados **[CONFIRMAR]** dependem de norma
> institucional que só a secretaria do programa ou a orientadora podem informar
> — e alguns deles podem invalidar uma entrega se descumpridos.
>
> **Ação recomendada:** confirmar os itens [CONFIRMAR] com a coordenação antes de
> novembro, para haver tempo de corrigir.

---

## 1. Elementos pré-textuais (ABNT NBR 14724)

| Item | Obrigatoriedade | Estado | Ação |
|---|---|---|---|
| Capa | obrigatório | ✅ presente | — |
| Folha de rosto | obrigatório | ✅ presente | — |
| **Nome do orientador na folha de rosto** | obrigatório | ❌ **`[ORIENTADOR(A) A CONFIRMAR]`** | **Bloqueante.** Preencher |
| **Folha de aprovação** | obrigatório | ❌ **ausente** | Ver §1.1 abaixo |
| Errata | opcional | ausente | — |
| Dedicatória | opcional | ausente | decisão do autor |
| Agradecimentos | opcional | ausente | decisão do autor |
| Epígrafe | opcional | ausente | decisão do autor |
| Resumo em português | obrigatório | ✅ ~297 palavras | dentro da faixa 150–500 (NBR 6028) |
| Palavras-chave (PT) | obrigatório | ✅ 5 | — |
| Resumo em inglês (*abstract*) | obrigatório | ✅ presente | — |
| *Keywords* | obrigatório | ✅ presente | — |
| Lista de ilustrações | obrigatório se houver | ✅ 4 figuras | — |
| Lista de tabelas | obrigatório se houver | ✅ 5 tabelas | — |
| Lista de abreviaturas e siglas | obrigatório se houver | ✅ 21 entradas | — |
| Lista de símbolos | obrigatório se houver | ausente | há símbolos matemáticos nas equações — **[CONFIRMAR]** se o programa exige |
| Sumário | obrigatório | ✅ presente | — |

### 1.1 Folha de aprovação — decisão necessária

A NBR 14724 lista a folha de aprovação como **elemento obrigatório** de trabalho
submetido a banca. Ela contém nome, título, data de aprovação e assinaturas dos
membros da banca — portanto só é preenchível **após** a defesa.

Prática comum: a versão entregue para defesa traz a folha em branco ou omitida, e
a versão final depositada traz a folha assinada. **[CONFIRMAR]** qual o
procedimento do ICMC: alguns programas exigem a folha já na submissão, outros
apenas no depósito final.

Se for exigida, o `abntex2` fornece `\imprimirfolhadeaprovacao`.

---

## 2. Elementos textuais

| Item | Estado | Observação |
|---|---|---|
| Introdução com problema, objetivos e questões | ✅ Cap. 1 | contextualização, problema, justificativa, QP1–QP3, objetivos geral e específicos, organização |
| Fundamentação teórica | ✅ Cap. 2 | 6 seções + trabalhos correlatos |
| Metodologia | ✅ Cap. 3 | DSR, três ciclos de Hevner, Peffers, March e Smith, FEDS |
| Dados: obtenção, tratamento, características | ✅ Cap. 3, seção "Dados da Avaliação" | exigência explícita da Metodologia III |
| Resultados | ✅ Cap. 4 | com tabela de Fronteira de Evidência |
| Discussão e conclusões | ✅ Cap. 5 | responde QP1–QP3, contribuições, limitações, trabalhos futuros |

**Conformidade com a rubrica da Metodologia III** (obtenção → tratamento →
características dos dados): atendida pela seção "Dados da Avaliação", que cobre
origem sintética, justificativa LGPD, composição das cargas e limite de validade.

---

## 3. Elementos pós-textuais

| Item | Obrigatoriedade | Estado |
|---|---|---|
| Referências | obrigatório | ✅ 23 entradas |
| Glossário | opcional | ausente |
| Apêndice (autoria própria) | opcional | ✅ Apêndice de reprodutibilidade |
| Anexo (autoria de terceiros) | opcional | ausente |
| Índice | opcional | ausente |

---

## 4. Normas de escrita científica (exigências da orientadora)

Fonte: "Dicas para a Escrita Científica" da disciplina.

| Norma | Estado | Verificação |
|---|---|---|
| Linguagem impessoal — nunca "eu"/"nós" | ✅ | auditado, sem ocorrências |
| Tempo verbal presente (futuro só em metodologia) | ✅ | auditado |
| Sigla definida na primeira ocorrência | ⚠️ **parcial** | 2 de 21 (RFC, WAN) só ocorrem em tabela e bibliografia; a lista de siglas cobre |
| Estrangeirismos em itálico | ⚠️ verificar | auditoria A4 apontou ~12 inconsistências; **não corrigidas** |
| Evitar parágrafos de uma frase | ⚠️ verificar | A4 apontou 5 ocorrências; **não corrigidas** |
| Não usar inglês havendo tradução | ⚠️ verificar | A4 apontou anglicismos evitáveis |
| Toda figura/tabela/equação referenciada **e explicada** | ✅ | 0 órfãos: 4 figuras, 5 tabelas, 2 equações |
| Sem plágio | ⚠️ **[CONFIRMAR]** | ver §7 |

**Pendência real:** os três itens ⚠️ vêm da auditoria
[A4](review/A4-auditoria-forma-abnt-deepseek.md) e ainda não foram corrigidos.
São de baixo risco individual, mas somam.

---

## 5. Referências e citações (NBR 6023 / 6024)

| Item | Estado | Ação |
|---|---|---|
| Sistema de citação consistente (autor-data) | ⚠️ | `thebibliography` manual, não `abntex2cite`. Compila e é legível, mas a formatação autor-data não é automática |
| Sobrenome em versalete/maiúscula | ✅ | conferido nas 23 entradas |
| Título em itálico | ✅ | conferido |
| "et al." acima de 3 autores | ✅ | corrigido em `hevner2004` |
| DOI quando disponível | ⚠️ | A4 apontou 7 entradas sem DOI |
| Data de acesso em fonte eletrônica | ✅ | presente nas entradas com URL |
| Toda citação no texto tem entrada na lista | ✅ | 0 citações indefinidas na compilação |

**Recomendação:** migrar para `abntex2cite` (o pacote **está instalado**
localmente). É a última tarefa mecânica pendente, de baixo risco, e elimina toda
essa classe de inconsistência de formatação.

---

## 6. Formatação (NBR 14724)

Aplicada automaticamente pela classe `abntex2` com as opções em uso
(`12pt, openright, twoside, a4paper`):

- fonte 12 pt no corpo, menor em citações longas e notas;
- margens 3 cm (esquerda/superior) e 2 cm (direita/inferior);
- espaçamento 1,5 no corpo;
- paginação a partir da folha de rosto, número visível a partir da introdução.

**[CONFIRMAR]** se o ICMC exige impressão em **frente e verso** (`twoside`, atual)
ou **só frente** (`oneside`). Isso muda a paginação e a posição das margens — e é
um erro caro de descobrir tarde.

---

## 7. Integridade acadêmica

| Item | Estado | Ação |
|---|---|---|
| Verificação antiplágio | ⚠️ **[CONFIRMAR]** | O programa exige relatório (Turnitin ou similar)? Se sim, gerar antes da entrega |
| Declaração de uso de IA | ⚠️ **[CONFIRMAR]** | Muitos programas passaram a exigir declaração de uso de ferramentas de IA. Este trabalho usou assistência de IA extensivamente — **confirmar a política do ICMC e declarar se exigido** |
| Autoria e coautoria | ✅ | autor único |
| Licença do texto acadêmico | ⚠️ pendente | declarada apenas por negação ("não é Apache-2.0") |

> **Sobre a declaração de uso de IA:** este item merece atenção específica. O
> desenvolvimento do artefato e a redação passaram por assistência de IA em várias
> etapas, documentadas nos ADRs e nos arquivos de revisão. Se o programa exigir
> declaração, o material para redigi-la já existe e é rastreável. Se não exigir,
> declarar voluntariamente ainda é defensável e coerente com o tema do trabalho.

---

## 8. Artefato de software (específico deste trabalho)

Itens que não constam de norma ABNT, mas sustentam a alegação de rigor da
pesquisa e podem ser cobrados em banca.

| Item | Estado |
|---|---|
| Código público e acessível | ✅ github.com/pealmeida/sovereign-vault |
| Licença de código explícita | ✅ Apache-2.0 |
| `CITATION.cff` | ✅ criado, validado contra o schema CFF 1.2.0 |
| **DOI / arquivamento permanente** | ❌ **ausente** — ver §8.1 |
| Evidência versionada e recuperável | ✅ `docs/thesis/evidence/`, resumos SHA-256 conferem |
| Âncora de proveniência | ✅ tag `thesis-evidence-preliminary` |
| Citações código↔tese verificáveis | ✅ 13/13 válidas; verificador em `scripts/` |
| Instruções de reprodução | ✅ apêndice + `EVALUATION.md` + `EXECUCAO-DEFINITIVA.md` |
| CI reprodutível | ✅ 12 checagens, 3 plataformas |

### 8.1 DOI — recomendado antes da entrega

Sem um identificador persistente, a tese cita o artefato por URL do GitHub, que
não é estável no sentido acadêmico (o repositório pode ser movido, renomeado ou
tornado privado). O Zenodo emite DOI a partir de um *release* do GitHub, leva
minutos, e o `CITATION.cff` já tem o campo `doi` reservado.

Agora é viável: existe uma tag no repositório.

---

## 9. Evidência experimental

| Item | Estado | Ação |
|---|---|---|
| Dados brutos versionados | ✅ | `docs/thesis/evidence/` |
| Resumos criptográficos publicados | ✅ | 3/3 conferem |
| Comando de reprodução registrado | ✅ | no apêndice |
| Ambiente registrado | ⚠️ parcial | falta armazenamento e modo de energia |
| **k ≥ 3 sessões independentes** | ❌ **1 sessão** | **Bloqueante para a versão final** |
| **IC de 95% por *bootstrap*** | ❌ ausente | **Bloqueante para a versão final** |
| Regra de *warmup*/descarte | ✅ instrumento pronto | `--warmup` implementado; falta executar |
| Proveniência do código medido | ⚠️ | o commit da execução preliminar **não é ancestral da `main`**; declarado no apêndice |

**Estado:** a evidência atual está corretamente rotulada como preliminar em todo
o texto, o que é honesto — mas a versão final deve trazer a execução definitiva.
Protocolo pronto em [`EXECUCAO-DEFINITIVA.md`](EXECUCAO-DEFINITIVA.md).

---

## 10. Processo da disciplina

Exigência recorrente nas três disciplinas de Metodologia:

- [ ] Depositar o PDF final no **drive compartilhado particular**
- [ ] Depositar o **feedback recebido** no mesmo drive
- [ ] **[CONFIRMAR]** formato e prazo exatos da submissão final

---

## Resumo executivo — o que bloqueia a entrega

**Bloqueantes (impedem entrega):**

1. **Nome do orientador** na folha de rosto — hoje sai `[ORIENTADOR(A) A CONFIRMAR]` visível no PDF.
2. **Execução definitiva** — k ≥ 3 sessões com IC 95%. Instrumento pronto; falta rodar.
3. **Folha de aprovação** — [CONFIRMAR] se exigida já na submissão.

**A confirmar com a coordenação (podem virar bloqueantes):**

4. Relatório antiplágio.
5. Declaração de uso de IA.
6. `oneside` vs `twoside`.
7. Lista de símbolos.

**Recomendados (fortalecem, não bloqueiam):**

8. DOI via Zenodo.
9. Migração para `abntex2cite`.
10. Correções de forma pendentes da auditoria A4 (itálico, parágrafos de uma frase, anglicismos).
11. Licença do texto acadêmico.
12. DOIs faltantes em 7 referências.

---

## Como reverificar

```bash
# citações arquivo:linha
python3 scripts/check-thesis-citations.py

# compilação limpa
cd docs/thesis && pdflatex -interaction=nonstopmode paper.tex

# resumos da evidência
sha256sum docs/thesis/evidence/*.csv
```
