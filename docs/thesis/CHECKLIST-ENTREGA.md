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
> **Atualização de 04/08/2026 — fontes institucionais consultadas.** As 23 fontes
> das disciplinas de Metodologia foram consultadas no NotebookLM
> ("Framework for Academic Thesis Composition"), incluindo os materiais que eu
> não tinha: `Aula 4 — Outras normas, template Word e ficha`,
> `Aula 5 — template LaTeX`, `esqueleto para TCC`, `Aula 2 — Plágio e Citações`
> e `Aula 3 — Referências`. Isso resolveu vários `[CONFIRMAR]` e **revelou dois
> requisitos obrigatórios que este checklist não continha** (§0).
>
> **O que ainda NÃO é:** o regulamento formal de depósito. Os `[CONFIRMAR]`
> remanescentes seguem dependendo da coordenação.

---

## 0. Requisitos institucionais descobertos — AÇÃO NECESSÁRIA

Fonte: relatórios "Guia Consolidado e Context Dump para Estruturação de TCC" e
"Methodology and Project Guidelines for AI and Big Data II", ambos derivados das
23 fontes das disciplinas.

### 0.1 Ficha catalográfica — OBRIGATÓRIA, ausente

> "A ficha catalográfica é elemento obrigatório. Ela deve ser gerada
> eletronicamente através do sistema da **Biblioteca Achille Bassi (ICMC)**."

Gerar em:
`https://www.icmc.usp.br/institucional/estrutura-administrativa/biblioteca/servicos/ficha`

Ela é inserida no verso da folha de rosto e garante a indexação do trabalho nos
sistemas da USP.

**Estado (04/08/2026): o lugar existe, o conteúdo não.** O `paper.tex` passou a
usar `\imprimirfolhaderosto*` (variante com estrela, que termina em `\newpage`
em vez de `\cleardoublepage`) seguido do ambiente `fichacatalografica`, de modo
que o bloco cai no **verso da folha de rosto** — página 4 do PDF, imediatamente
após a folha de rosto na página 3, como a NBR 14724 exige. O bloco atual traz um
aviso visível `[FICHA CATALOGRÁFICA A GERAR]`.

**Ação restante:** gerar no sistema da Biblioteca e colar o texto retornado no
lugar do bloco marcado, sem reformatar. Nenhuma mudança estrutural é necessária.

### 0.2 Pacote USPSC 3.2 — OBRIGATÓRIO, não utilizado

> "É **obrigatório** o uso do pacote customizado para o ICMC, baseado na classe
> `abntex2`. Para o MBA, as siglas de identificação são: **MBAIAp** para
> trabalhos em Português e **MBAIAe** para Inglês."

O documento atual usa `\documentclass{abntex2}` diretamente. O USPSC é uma
camada sobre o `abntex2` com a estrutura de arquivos pré-textual do ICMC
(`USPSC-pre-textual-ICMC.tex`) e a identificação do programa.

**Estado (04/08/2026): FEITO.** O pacote foi baixado da Biblioteca do Campus
(`USPSC-3.2.zip`), a classe e os arquivos de Unidade foram versionados em
`docs/thesis/uspsc/`, e a variante `docs/thesis/paper-uspsc.tex` **compila
limpa em 50 páginas, com 0 erros e 0 citações/referências indefinidas**.

Identificação institucional aplicada: `\siglaunidade{ICMC}` +
`\programa{MBAIAp}`. Isso faz a classe emitir o preâmbulo oficial do programa
("Monografia apresentada ao Departamento de Ciências de Computação... título de
Especialista em Inteligência Artificial e Big Data"), a área de concentração e
a capa institucional USP/ICMC — nenhum desses textos é escrito à mão.

> **Detalhe não óbvio:** a sigla correta é `ICMC`, **não** `ICMC-TCC`. Só
> `USPSC-pre-textual-ICMC.tex` define `MBAIAp`; o arquivo de TCC conhece apenas
> os programas de graduação (BCCp/BSIp). Monografia de MBA usa o modelo de
> teses/dissertações da Unidade.

**Fonte única de conteúdo.** O corpo do texto não é duplicado: `paper.tex`
continua canônico e `scripts/sync-uspsc-body.py` extrai os fragmentos que a
variante USPSC carrega. Rodar o script após qualquer edição em `paper.tex`.

### 0.3 Normas ABNT completas

O mapeamento oficial das disciplinas inclui normas que este checklist não
listava:

| Norma | Função | Coberto? |
|---|---|---|
| NBR 14724:2011 | Apresentação de trabalhos acadêmicos | ✅ |
| NBR 6023:2018 | Referências | ✅ |
| **NBR 10520:2023** | **Citações em documentos (atualizada)** | ⚠️ verificar |
| **NBR 6024:2012** | **Numeração progressiva das seções** | ✅ (abntex2) |
| **NBR 6027:2012** | **Sumário** | ✅ (abntex2) |
| NBR 6028:2003 | Resumos | ✅ |

A NBR 10520 foi **atualizada em 2023** e mudou regras de citação. O documento usa
`thebibliography` manual — mais um argumento para migrar ao sistema automatizado.

### 0.4 Decisão necessária: migrar para USPSC?

| Opção | Prós | Contras |
|---|---|---|
| **Migrar para USPSC 3.2** | Cumpre a exigência declarada; ficha e pré-textuais do ICMC vêm prontos; conformidade normativa automática | Reorganização do documento; risco de retrabalho a ~4 meses do prazo |
| **Manter `abntex2` puro** | Zero retrabalho; compila limpo hoje | **Descumpre exigência explícita**; risco na banca |

**Recomendação:** migrar. A exigência é explícita ("é obrigatório"), o USPSC é
baseado na mesma classe que já está em uso, e quanto mais tarde a migração, mais
caro o retrabalho. Confirmar com a orientadora antes de executar.

---

## 1. Elementos pré-textuais (ABNT NBR 14724)

| Item | Obrigatoriedade | Estado | Ação |
|---|---|---|---|
| Capa | obrigatório | ✅ presente | — |
| Folha de rosto | obrigatório | ✅ presente | — |
| **Nome do orientador na folha de rosto** | obrigatório | ❌ **`[ORIENTADOR(A) A CONFIRMAR]`** | **Bloqueante.** Preencher — o nome não consta de nenhuma fonte do repositório e não deve ser inferido |
| **Folha de aprovação** | obrigatório | ✅ **estrutura presente** | Renderiza com autor, título, preâmbulo e linhas de assinatura; nomes da banca e data só após a defesa. Ver §1.1 |
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

**Estado (04/08/2026): implementada em branco.** O `paper.tex` usa o ambiente
`folhadeaprovacao` do `abntex2`, na posição correta (após a ficha, antes do
resumo). A página renderiza autor, título, preâmbulo, linha de data em branco e
três linhas de assinatura: orientador(a) — que herda `\imprimirorientador`, hoje
o mesmo *placeholder* da folha de rosto — e dois membros da banca marcados
`[MEMBRO DA BANCA 1|2]`.

Esta é a variante submetível: os nomes da banca e a data de aprovação só existem
**após** a defesa. Nada a fazer até lá, exceto confirmar o procedimento do ICMC.

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
| Sigla definida na primeira ocorrência | ✅ | auditado por varredura em 04/08: todas as siglas do corpo têm expansão na primeira ocorrência textual (exceto rótulos de figura, onde a expansão vem na prosa adjacente) |
| Estrangeirismos em itálico | ✅ | A4 corrigida; critério auditado (sem tradução corrente → itálico; jargão incorporado, como *gateway*, → redondo) |
| Evitar parágrafos de uma frase | ✅ | §Considerações Iniciais enriquecida (R10-M4); varredura de 04/08 encontra 1 remanescente em prosa (l. 189, ressalva deliberada de fronteira de alegação) — os demais são chamadas de lista, equações e opções de figura |
| Não usar inglês havendo tradução | ✅ | *trade-off* → relação de compromisso; siglas expandidas em português |
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
| DOI quando disponível | ✅ | 9 entradas com DOI. As restantes são atas de congresso (NeurIPS), normas RFC, livros e fontes sem identificador persistente atribuído — nenhum DOI foi inventado. Resolver cada DOI contra `doi.org` antes do depósito (R9-7) |
| Data de acesso em fonte eletrônica | ✅ | presente nas entradas com URL |
| Toda citação no texto tem entrada na lista | ✅ | 0 citações indefinidas na compilação |

**Recomendação revista (04/08).** A migração para `abntex2cite` deixa de ser
tarefa isolada: se o USPSC 3.2 for adotado (§0.2), ele já traz o sistema de
citação configurado conforme ABNT, incluindo a **NBR 10520:2023**. As fontes
também indicam gestão bibliográfica via **arquivo `.bib` com BibTeX**, não
`thebibliography` manual.

**Não migrar para `abntex2cite` isoladamente** — fazer isso e depois migrar para
o USPSC seria retrabalho duplicado. Decidir §0.4 primeiro.

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
| Ambiente registrado | ✅ instrumento pronto | `collect-metadata.sh` exige `power_mode` como argumento obrigatório e falha se qualquer campo de *host* vier vazio ou `n/a`; `aggregate.py` veta `n/a`/*placeholder* em §6.5 |
| **k ≥ 3 sessões independentes** | ❌ **1 sessão** | **Bloqueante para a versão final** — instrumento pronto; falta executar |
| **IC de 95% por *bootstrap*** | ❌ ausente | **Bloqueante para a versão final** — `aggregate.py` pronto (bootstrap sobre médias de sessão, B=10.000, semente declarada); emite ressalva de IC indicativo quando k<5 |
| Regra de *warmup*/descarte | ✅ instrumento pronto | `--warmup` implementado; documentado como *override* acima de um piso de 1 chamada de *priming* (R9-12) |
| Separação política × falha de transporte | ✅ | sondas com `transport_error` excluídas do numerador **e** do denominador de ambas as taxas e reportadas à parte (R9-5) |
| Deriva térmica (§6.2) | ✅ instrumento pronto | Spearman aplicado só com k≥4; em k=3 emite ressalva de "deriva não verificada" em vez de falso positivo (R9-4) |
| Proveniência do código medido | ⚠️ | o commit da execução preliminar **não é ancestral da `main`**; declarado no apêndice |

**Estado:** a evidência atual está corretamente rotulada como preliminar em todo
o texto, o que é honesto — mas a versão final deve trazer a execução definitiva.
Protocolo pronto em [`EXECUCAO-DEFINITIVA.md`](EXECUCAO-DEFINITIVA.md).

**Ensaio de ponta a ponta (04/08/2026).** O encadeamento
harness → `collect-metadata.sh` → `aggregate.py` foi exercitado com k=3 sessões
curtas (40 iterações, `--warmup 5`, *seeds* distintas) em diretório descartável,
apenas para validar o instrumento — **não é evidência** e foi descartado. O que
o ensaio estabelece:

- o harness emite os três CSVs mais os metadados companheiros por sessão;
- `collect-metadata.sh` coleta CPU, núcleos, RAM, armazenamento e *build* do
  Windows sem nenhum campo `n/a` (o caminho WMI/PowerShell funciona);
- `aggregate.py` consome saída real do harness, apura 30/30 bloqueios com IC de
  Wilson [88,6; 100,0], aplica as ressalvas de k<5 e k<4 e sai com código 2.

> O caso 30/30 é exatamente o que o defeito de leitura booleana teria reportado
> como 0/30. O ensaio confirma a correção contra dados reais, não sintéticos.

**Por que a execução definitiva não foi disparada aqui:** o §1 do protocolo
exige árvore limpa em `main` publicada, etiqueta anotada sobre esse commit e
*host* controlado (energia fixa, sem *build* concorrente, aplicações fechadas).
Este ramo não está integrado à `main`, e o controle do *host* não é verificável
de forma automatizada. Rodar assim produziria números não-ancestrais e com
variância de ambiente — reproduzindo o defeito de proveniência que o apêndice já
documenta, e queimando o nome de etiqueta `thesis-eval-v1`. É decisão do autor,
com a máquina em estado controlado.

---

## 10. Processo da disciplina

Exigência recorrente nas três disciplinas de Metodologia:

- [ ] Depositar o PDF final no **drive compartilhado particular**
- [ ] Depositar o **feedback recebido** no mesmo drive
- [ ] **[CONFIRMAR]** formato e prazo exatos da submissão final

---

## Resumo executivo — o que bloqueia a entrega

**Bloqueantes (impedem entrega):**

1. **Ficha catalográfica** — estrutura no lugar certo (verso da folha de rosto,
   p. 4) nas duas variantes; falta **gerar o conteúdo** na Biblioteca Achille
   Bassi e colar. Ver §0.1.
2. **Execução definitiva** — k ≥ 3 sessões com IC 95%. Instrumento pronto e
   ensaiado de ponta a ponta; falta rodar sob as pré-condições do §1 do
   protocolo (`main` publicada + *host* controlado). Ver §9.

> **Fechados em 04/08/2026:**
> **Pacote USPSC 3.2** (§0.2) — variante `paper-uspsc.tex` compila limpa com a
> identificação oficial `MBAIAp`.
> **Nome da orientadora** — Profa. Dra. Kalinka Regina Lucas Jaquie Castelo
> Branco, confirmada pelo autor; perfil e pontos de apoio à pesquisa em
> [`orientacao/`](orientacao/PERFIL-ORIENTADORA.md).

> **Deixou de ser bloqueante:** a folha de aprovação, agora implementada em
> branco na posição correta (§1.1) — variante submetível, já que os nomes da
> banca só existem após a defesa. Resta apenas confirmar o procedimento do ICMC.

> **Passo a passo dos itens restantes:**
> [`ENTREGA-FINAL-PASSOS.md`](ENTREGA-FINAL-PASSOS.md) traz, para cada
> bloqueante, o comando ou a ação exata, e registra por que cada um exige o
> autor: informação que não existe no repositório (nome do orientador, ficha),
> decisão a alinhar com a orientadora (USPSC) ou condição de ambiente que não é
> verificável por automação (execução definitiva).

> Os itens 1 e 2 vieram da consulta às fontes institucionais e **não estavam
> neste checklist na primeira versão**. São os de maior risco: descumprem
> exigência explícita e ficam mais caros quanto mais tarde forem tratados.

**A confirmar com a coordenação (podem virar bloqueantes):**

6. Relatório antiplágio — as fontes tratam plágio com severidade (anulação do
   projeto, revogação do título), mas não indicam se há verificação formal.
7. Declaração de uso de IA.
8. `oneside` vs `twoside` — provavelmente resolvido pelo USPSC.
9. Lista de símbolos.
10. Conformidade com a **NBR 10520:2023** (citações), atualizada.

**Recomendados (fortalecem, não bloqueiam):**

8. DOI via Zenodo.
9. Migração para `abntex2cite` — decidir §0.4 primeiro.
10. Licença do texto acadêmico.
11. Resolver cada DOI contra `doi.org` antes do depósito e anexar o `title` retornado (R9-7).

**Fechados na rodada R9–R12 (04/08/2026):** correções de forma da auditoria A4
(itálico, parágrafos de uma frase, anglicismos, expansão de siglas), DOIs
faltantes onde há identificador atribuído, e todos os achados acionáveis dos
cinco pareceres — ver
[response-to-reviewers-r9-r12.md](review/response-to-reviewers-r9-r12.md).

---

## Como reverificar

```bash
# citações arquivo:linha
python3 scripts/check-thesis-citations.py

# testes do agregador de evidência
python3 docs/thesis/evidence/test_aggregate.py

# resumos da evidência
sha256sum docs/thesis/evidence/*.csv
```

Compilação limpa — **duas passagens**, pois `thebibliography` e `\ref` só
resolvem na segunda:

```bash
cd docs/thesis && pdflatex -interaction=nonstopmode -halt-on-error paper.tex && pdflatex -interaction=nonstopmode -halt-on-error paper.tex
```

> **Estado verificado em 04/08/2026:** compila em 48 páginas, 0 erros, 0
> citações indefinidas, 0 referências indefinidas, 0 *overfull boxes*
> (MiKTeX-pdfTeX 4.23). Um `\cite` ou `\ref` órfão gera apenas *warning* — o PDF
> sai com marcadores `[?]` e a compilação continua "bem-sucedida". Por isso a
> CI falha explicitamente diante de qualquer um deles (job `thesis-evidence`).
>
> No Windows, o binário pode não estar no `PATH`; o instalador por usuário fica
> em `%LOCALAPPDATA%\Programs\MiKTeX\miktex\bin\x64`.
