# Resposta consolidada aos pareceristas — ADR-0013

**Artefato revisado:** `docs/adr/0013-sensitivity-classifier-adaptive-consent.md` (status *Proposed*)
**Rodada:** 03/08/2026 · três pareceristas independentes, ângulos separados
**Situação:** o ADR **não** deve ser promovido a *Accepted* nem implementado como está.

## Síntese editorial

| Parecer | Ângulo | Modelo | Veredito |
|---|---|---|---|
| [R6](R6-adr0013-methodology-glm52.md) | Metodologia / DSR | `zai/glm-5.2` | aceitar com revisões |
| [R7](R7-adr0013-security-glm52.md) | Segurança / adversarial | `zai/glm-5.2` | **major revisions** |
| [R8](R8-adr0013-lgpd-glm47.md) | Privacidade / LGPD | `zai/glm-4.7` | **major revisions** |

Seis bloqueantes no total. O mais grave (R7-1) foi **verificado aritmeticamente**
e invalida o desenho do escore como proposto.

> **Nota de proveniência.** O parecer R7 declara no próprio cabeçalho ter sido
> produzido por `glm-4.6`; a execução real usou `glm-5.2`. Modelos frequentemente
> erram a própria identidade. A atribuição registrada aqui e no nome do arquivo
> reflete o comando efetivamente executado, não a auto-declaração.

Os três pareceres convergem, por caminhos independentes, num mesmo diagnóstico:
**o limiar é uma heurística de calibração apresentada como fronteira.** R7 mostra
que ele não resiste a adversário; R6 mostra que ele não tem critério de aceitação;
R8 mostra que ele não corresponde ao conceito jurídico que pretende endereçar.

---

## Bloqueantes

### R7-1 — Diluição por densidade derrota a elevação. **[ACEITO — verificado]**

O parecer afirma que o escore é derrotável por preenchimento. **Confirmado por
cálculo direto sobre a fórmula do §4:**

| Cenário | S | Eleva? |
|---|---|---|
| 1 CPF em 256 B | 8 | sim |
| 1 CPF em 10 KiB de preenchimento | 7 | **não** |
| 10 CPFs em 20 KiB | 7 | **não** |
| 100 CPFs em 200 KiB | 7 | **não** |
| 1.000 CPFs em 2 MB | 7 | **não** |

O escore **pune o documento pequeno e libera o vazamento em massa** — exatamente
o inverso do pretendido.

Causa raiz: o peso de categoria é somado **uma vez por categoria distinta**, não
por ocorrência. Volume da mesma categoria só afeta o termo de densidade, e
densidade é diluída linearmente pelo tamanho do documento. Como o maior peso
isolado é 6 e o limiar é 8, **nenhuma categoria sozinha atinge o limiar** — todo
achado de categoria única é derrotável por preenchimento.

**Ação:** redesenhar o escore antes de qualquer implementação. Opções do parecer,
por ordem de robustez: (a) qualquer achado validado por *checksum* (CPF, cartão,
SSN) eleva incondicionalmente, independentemente do escore; (b) limitar a
densidade por categoria antes de dividir; (c) remover densidade da decisão de
elevação e usá-la apenas para escalonamento a OTP.

### R7-2 — O limiar não resiste a adversário com acesso de escrita. **[ACEITO]**

O adversário primário do modelo de ameaça é um agente MCP autenticado e
comprometido — que **escreve** no cofre. Pesos e limiar são públicos (repositório
aberto). O agente molda o conteúdo para ficar abaixo do limiar e depois lê sem
disparar consentimento.

O ADR trata o limiar como problema de precisão/recall, nunca como problema
adversarial; a sonda A11 testa que conteúdo sensível **eleva**, jamais que um
adversário consegue **evitar** a elevação.

**Ação:** escolher uma das duas posturas e declará-la explicitamente:
1. **Rebaixar a alegação** — consentimento adaptativo é rede de segurança de
   usabilidade, não controle de segurança, e não resiste a adversário com escrita.
   O escopo da alegação em QP1 muda conforme.
2. **Defender** — exigir consentimento para leitura, pelo agente, de conteúdo que
   o próprio agente escreveu; ou mínimo de achados por contêiner que eleva
   independentemente do escore.

A opção 1 é honesta e barata; a 2 é mais forte e mais cara. **Decisão do autor.**

### R6-B1 — Sem critério de aceitação, o experimento não é falsificável. **[ACEITO]**

O §7 promete precisão/recall sobre conjunto rotulado, mas não define piso de
recall abaixo do qual a capacidade é considerada não entregue, nem piso de
precisão abaixo do qual a elevação é nociva (fadiga de consentimento). Sem
pré-registro, qualquer resultado será lido *post hoc* como sucesso.

**Ação:** pré-registrar o par (piso de recall, piso de precisão) com justificativa,
antes de qualquer execução, e declarar o que acontece com a alegação de capacidade
se o piso não for atingido.

### R6-B2 — Onze constantes livres sem protocolo de calibração. **[ACEITO]**

Sete pesos + limiar + coeficiente de densidade + teto de densidade + coeficiente
de diversidade. Calibrar isso em conjunto sintético sem *hold-out*, validação
cruzada nem pré-registro da busca é a configuração canônica de sobreajuste.

**Ação:** definir particionamento treino/calibração/teste com proporções e *seed*
versionadas; congelar todos os parâmetros antes de tocar o conjunto de teste;
versionar o procedimento de busca junto do conjunto rotulado.

> **Nota:** R6-B2 e R7-1 interagem. Não faz sentido calibrar 11 constantes de uma
> fórmula estruturalmente derrotável. **R7-1 vem primeiro.**

### R8-1 — Escore sintático ≠ identificabilidade da LGPD. **[ACEITO]**

A LGPD (Art. 5º) define dado pessoal por **identificabilidade**, não por presença
de padrão formatado. Documento com nome completo + endereço e sem CPF pontua
baixo e permanece juridicamente dado pessoal. O ADR reconhece a limitação
semântica, mas não a conecta à definição legal.

**Ação:** declarar no Context que a pontuação é estritamente sintática e não
equivale a avaliação de identificação sob o Art. 5º.

### R8-2 — Cegueira estrutural ao dado sensível do Art. 5º, II. **[ACEITO]**

Origem racial, convicção religiosa, opinião política, filiação sindical, saúde,
vida sexual, dado genético ou biométrico: nenhuma dessas categorias tem forma
sintática detectável. O classificador é cego justamente à categoria que a lei mais
protege. Risco de leitura invertida: "pontuação alta = mais proteção LGPD".

**Ação:** declarar em *Negative consequences*, com destaque.

> **Ressalva ao parecer:** R8 afirma "oito categorias" no Art. 5º, II. A contagem
> depende do agrupamento do inciso. Recomenda-se que a tese **cite as categorias
> e não fixe um número.**

---

## Relevantes

| # | Origem | Achado | Encaminhamento |
|---|---|---|---|
| R7-3 | Segurança | Classificação pré-consentimento é oráculo observável por tempo/erro: o agente infere densidade de PII mesmo em leitura **negada** | **[ACEITO]** Declarar como limitação, ou restringir o resultado pré-consentimento a binário que não varie com contagem |
| R7-4 | Segurança | Escore registrado em auditoria é canal lateral: `S` é função invertível da composição do conteúdo | **[ACEITO]** Registrar apenas a decisão e o modo efetivo; nunca o escore numérico nem a composição |
| R7-5 | Segurança | "Aritmética limitada" é requisito sem especificação; `panic` em `sv-classify` capturado pelo gateway pode virar liberação silenciosa | **[ACEITO]** Especificar aritmética saturante e contrato *panic → deny* na fronteira do gateway |
| R7-6 | Segurança | Superfície pré-consentimento não declarada: parsers rodam sobre plaintext influenciado pelo agente; limiar em arquivo local editável | **[ACEITO]** Declarar a superfície; definir se integridade do arquivo de configuração está no escopo |
| R6-R4 | Metodologia | `T_classify` e `T_filter` dupla-contam o mesmo *scan* | **[ACEITO — verificado no código]** ver abaixo |
| R6-R5 | Metodologia | Leitura pré-consentimento desloca a fronteira de `T_vault` do ADR-0011 | **[ACEITO]** Reespecificar *timestamps* por estágio |
| R6-R6 | Metodologia | Sondas A11/A12 não declaram transporte (stdio não executa `enforce_scopes`) | **[ACEITO]** Declarar WebSocket autenticado |
| R6-R7 | Metodologia | Alegação de "mediação dependente de conteúdo" pode ser vazia se o recall for baixo | **[ACEITO]** Vincular a alegação ao piso de recall de R6-B1 |
| R6-R3 | Metodologia | Validade externa do conjunto sintético declarada por referência, não por mecanismo | **[ACEITO]** Declarar independência gerador↔detector; versionar prevalência e *seed* |
| R8-3 | LGPD | Detectores em camada candidata podem gerar falsa percepção de cobertura | **[ACEITO]** Advertir que ausência de detecção sintática não implica ausência de dado pessoal |
| R8-4 | LGPD | Calibração sintética distante do dado real brasileiro, sobretudo para nomes/endereços | **[ACEITO]** Qualificar toda alegação de cobertura |

### R6-R4 verificado no código

`redact()` chama `scan()` internamente (`crates/sv-privacy/src/lib.rs:200`). Se o
classificador executa `scan()` antes do consentimento e o mascaramento ANONYMIZED
executa `redact()` depois, **o scan roda duas vezes**. Não é apenas ambiguidade de
notação: é trabalho desperdiçado no caminho crítico.

**Ação:** passagem única compartilhada, com o custo atribuído a exatamente um termo
da equação; redefinir `T_filter` como apenas a transformação de mascaramento sobre
achados já obtidos.

---

## Menores

- **R7-7** — a fronteira de "operações que produzem egresso" é imprecisa; busca ou
  *snippet* que retorne fragmentos pode escapar da classificação. Definir como
  "qualquer resposta que contenha bytes originários de plaintext de contêiner".
- **R7-8** — o par `Unknown × ANONYMIZED` não é enumerado. Provavelmente
  *fail-closed* por autoridade do modo configurado, mas deve ser explícito.
- **R6-M8** — granularidade inconsistente: elevação é decisão por documento;
  métricas por categoria são por achado.
- **R6-M9** — constantes auxiliares (divisor 1024, coeficiente 2, teto 10) sem
  análise de sensibilidade.
- **R6-M10** — "v1 não sintetiza OTP a partir de conteúdo" não consta como
  limitação explícita de versão.
- **R6-M11** — "regras contextuais" para nomes/endereços não enumeradas.
- **R8-5** — distinção controlador (usuário titular) / processador automatizado
  (classificador) não explícita.
- **R8-6** — janela de exposição de plaintext em memória sem garantia formal.

---

## Achados do autor, fora dos pareceres

### Divergência de notação entre tese e ADRs

Três equações incompatíveis convivem no projeto:

| Fonte | Notação |
|---|---|
| `paper.tex` (vigente, pós-R1–R5) | `T_gateway = T_parse+validacao+escopo + T_cofre + I_anon(...) + I_consentimento(...)` |
| `ADR-0011` | `T_total = T_vault + T_filter + T_hitl + T_wan + T_inference` |
| `ADR-0013` | idem ADR-0011, mais `T_classify` |

O ADR-0013 estendeu a notação **antiga**. A tese foi revisada e adotou termos
indicadores `I`; os ADRs não acompanharam. Reconciliar antes de gerar evidência,
sob pena de o Capítulo 4 sair com fronteiras de estágio ambíguas.

### Precedente de *fail-closed* já existe no código

O caminho ANONYMIZED recusa egresso de conteúdo não-UTF-8
(`crates/sv-mcp/src/lib.rs:1446`): *"anonymized egress denied: content is not
valid UTF-8 and cannot be safely redacted"*. O `Unknown` *fail-closed* do
ADR-0013 é **consistente com o que o gateway já faz** — vale citar como
precedente, em vez de apresentá-lo como invenção nova.

### Falha do classificador não é exceção

`scan()` retorna `Vec<Finding>` sem `Result` e não contém *panics* óbvios. A falha
do classificador, portanto, **não dispara caminho de erro**: ela é uma
classificação silenciosamente errada. Tratar `Unknown` apenas como "exceção
capturada" (R7-5) seria insuficiente — o estado perigoso é o escore baixo obtido
por engano, não a exceção.

---

## Encaminhamento proposto

1. **Redesenhar o escore** (R7-1) — bloqueia todo o resto; a calibração de R6-B2
   é inútil sobre fórmula derrotável.
2. **Decidir a postura da alegação de segurança** (R7-2) — rebaixar a alegação ou
   defender. Decisão do autor; muda o enunciado de QP1.
3. **Pré-registrar critério de aceitação** (R6-B1) antes de qualquer execução.
4. **Inserir as qualificações de LGPD** (R8-1, R8-2) no ADR.
5. **Reconciliar a notação** de latência entre tese e ADRs.
6. Só então revisar o ADR-0013 e submetê-lo a nova rodada.

O ADR permanece **Proposed**. Nenhuma implementação deve começar antes de (1) e (2).
