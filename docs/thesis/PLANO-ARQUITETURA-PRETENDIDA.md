# Plano — Implementar a Arquitetura Pretendida e Gerar Novos Resultados

**Criado:** 03/08/2026 · **Prazo do TCC:** dezembro/2026 (~4 meses)
**Origem:** o diagrama de sequência entregue na Metodologia III descreve capacidades que o artefato avaliado **não possui**. Este plano fecha a lacuna e produz evidência nova para o Capítulo 4.

---

## 1. A lacuna, item a item

| # | No diagrama Met III | No artefato hoje | Natureza |
|---|---|---|---|
| G1 | "Alta/Baixa Criticidade" dispara consentimento | Consentimento vem do **modo do contêiner** (DIRECT/APPROVAL/OTP), fixo por configuração | Capacidade ausente |
| G2 | Usuário "Aprova, **Edita** ou Rejeita" | Só aprova ou rejeita; não há edição do contexto | Capacidade ausente |
| G3 | "Retorna Resposta Sanitizada **e Cifrada**" ao agente | ANONYMIZED mascara texto; não cifra a resposta | Alegação incorreta no diagrama |
| G4 | Filtro de Privacidade "Valida escopo" | Escopo é do gateway (`enforce_scopes`); o filtro só mascara PII | Atribuição incorreta de responsabilidade |

**G3 e G4 são erros de desenho, não funcionalidades a construir.** Cifrar a resposta ao agente seria contraproducente: o agente precisa ler o conteúdo para usá-lo, e o canal já é protegido por TLS/WSS. G4 é apenas realocação de caixa no diagrama.

**G1 e G2 são capacidades reais e valiosas.** São elas que justificam desenvolvimento.

---

## 2. Recomendação de escopo

Implementar **G1 e G2**; corrigir G3/G4 no texto e nas figuras (já feito na Fase 2 — a Figura 3 reflete o fluxo real).

Motivo: G1 responde à QP1 com força muito maior que a versão atual. Hoje a mediação é estática (o usuário configura o modo do contêiner uma vez). Com classificação de sensibilidade, a mediação passa a ser **dependente do conteúdo** — que é a alegação central da tese sobre soberania. G2 fortalece a QP1 por outro ângulo: o usuário deixa de ter uma escolha binária e passa a exercer controle granular sobre o que sai.

**Risco a nomear:** cada capacidade nova amplia a superfície de avaliação. Com Cap. 5, execução definitiva, estudo humano e figuras já no caminho crítico, implementar as duas é agressivo para 4 meses. O corte natural, se o tempo apertar, é entregar **G1 completo** e deixar G2 como trabalho futuro — G1 sozinho já sustenta a contribuição.

---

## 3. G1 — Classificação de sensibilidade e consentimento adaptativo

### Desenho
Novo crate `sv-classify`, ou módulo em `sv-privacy` (decidir por ADR). O gateway, antes de aplicar a política de consentimento, classifica o conteúdo a ser retornado e eleva o modo efetivo quando a sensibilidade excede um limiar configurado.

- **Entrada:** conteúdo decifrado + modo configurado do contêiner.
- **Saída:** modo efetivo (≥ modo configurado; nunca rebaixa).
- **Regra de segurança:** a classificação só pode **elevar** a exigência de consentimento. Um classificador falho nunca deve abrir acesso que a configuração fechava. Isso é *fail-closed* e deve constar em teste de regressão.

### Sinais de classificação (determinísticos, sem LLM)
Reusar os detectores de `sv-privacy` e ponderar por categoria e densidade:
- Categorias já detectadas: e-mail, CPF, CNPJ, cartão (Luhn), IPv4, telefone formatado, SSN.
- Categorias a adicionar (também endereçam a limitação (iii) já registrada no Cap. 4): RG, CEP, nomes completos, endereços, datas de nascimento, telefones sem formatação.
- Escore = f(categorias distintas, densidade por KB, presença de categorias de alto risco).

**Decisão de projeto a registrar em ADR:** classificador determinístico, não LLM. Um LLM local introduziria latência de ordens de grandeza superior, não determinismo na avaliação, e uma dependência que contradiz o argumento Local-First de auditabilidade. Determinístico é auditável, reprodutível e mensurável — o que a DSR exige.

### Impacto na avaliação
- Nova condição no microbenchmark: `ADAPTIVE`, com custo do classificador medido como estágio próprio (`classify`), somando-se à Equação 1.
- Novas sondas adversariais: conteúdo de alta sensibilidade em contêiner DIRECT deve passar a exigir consentimento (A11); classificador não deve rebaixar modo (A12).
- Métrica nova, e é a mais valiosa cientificamente: **precisão e recall do classificador** sobre um conjunto rotulado. Sem isso a capacidade não é avaliável.

### Esforço
Implementação 2–3 semanas; detectores brasileiros novos ~1 semana; conjunto rotulado e avaliação ~1 semana.

---

## 4. G2 — Edição de contexto pelo usuário (human-in-the-loop granular)

### Desenho
Estender o diálogo de consentimento do desktop (Tauri): além de Aprovar/Rejeitar, permitir **Editar** — o usuário vê o conteúdo que sairá, com os trechos detectados destacados, e pode redigir ou remover trechos antes da liberação.

- Ponto de integração: `apps/desktop/src-tauri` — o gate de consentimento já intercepta a operação; falta devolver conteúdo modificado em vez de um booleano.
- O contrato `ApprovalState` passa a carregar `Decision::EditedContent(Vec<u8>)`.
- A auditoria deve registrar **que houve edição** e o hash do antes/depois — sem registrar o conteúdo, para não criar um segundo repositório de dado sensível.

### Ganho científico
Responde a uma limitação hoje explícita no texto: *"Esta versão não fornece autorização vinculada à chave/uso nem apresenta ao usuário uma descrição verificável do conteúdo a assinar ou decifrar."* A edição de contexto ataca diretamente a transparência do consentimento.

### Impacto na avaliação
- Habilita medir `T_espera_humana` **com decisão real**, não AutoAllow — que hoje é a maior lacuna do Cap. 4.
- Estudo com usuários: n≥30 aprovações, reportar mediana, p95, taxa de timeout e **taxa de edição** (com que frequência o usuário de fato corta algo).

### Esforço
Backend 1 semana; UI 1–2 semanas; estudo com usuários 2 semanas (incl. recrutamento).

---

## 5. Cronograma proposto (integrado ao plano principal)

| Período | Entrega | Observação |
|---|---|---|
| Ago, sem. 1–2 | ADR do classificador; `sv-classify` com detectores atuais | Decidir crate novo vs. módulo |
| Ago, sem. 3–4 | Detectores brasileiros (RG, CEP, nome, endereço, data, telefone) | Fecha limitação (iii) do Cap. 4 |
| Set, sem. 1 | Consentimento adaptativo no gateway + sondas A11/A12 | Regra fail-closed testada |
| Set, sem. 2 | Conjunto rotulado + precisão/recall do classificador | Métrica nova do Cap. 4 |
| Set, sem. 3–4 | **Execução definitiva** (k≥3 sessões, IC 95%) já com `ADAPTIVE` | Caminho crítico do plano principal |
| Out, sem. 1–2 | G2: edição de contexto (backend + UI) | Cortável se atrasar |
| Out, sem. 3–4 | Estudo humano: `T_espera_humana` + taxa de edição | Cortável se atrasar |
| Nov | Cap. 4 reescrito com evidência nova; Cap. 5 | Caminho crítico |
| Dez | Revisão final e entrega | |

**Ponto de decisão em 30/set:** se o classificador e a execução definitiva não estiverem fechados, cortar G2 e registrar como trabalho futuro.

---

## 6. O que muda na tese

- **Cap. 3:** nova subseção do classificador e do consentimento adaptativo; ADR correspondente; Figura 3 atualizada com o ramo de classificação; Equação 1 ganha o termo `T_classify`.
- **Cap. 4:** condição `ADAPTIVE` nas tabelas; tabela nova de precisão/recall; sondas A11/A12; se G2 entrar, distribuição de `T_espera_humana` real.
- **Cap. 5:** a resposta à QP1 passa a poder afirmar mediação **dependente de conteúdo**, não apenas mediação configurada — um resultado substancialmente mais forte.
- **Limitações:** o classificador determinístico não detecta sensibilidade semântica (ex.: um texto sem PII explícito mas revelador). Declarar desde já.

---

## 7. Estado: ADR-0013 escrito e revisado (03/08/2026)

`docs/adr/0013-sensitivity-classifier-adaptive-consent.md` — status **Proposed**.
Revisado por três pareceristas independentes (padrão R1–R5), em
`docs/thesis/review/`.

Três pareceres: [R6](../thesis/review/R6-adr0013-methodology-glm52.md) (metodologia),
[R7](../thesis/review/R7-adr0013-security-glm52.md) (segurança),
[R8](../thesis/review/R8-adr0013-lgpd-glm47.md) (LGPD). Consolidação e vereditos em
[response-to-reviewers-adr0013.md](../thesis/review/response-to-reviewers-adr0013.md).

### Bloqueantes a resolver ANTES de implementar

| # | Origem | Problema | Ação |
|---|---|---|---|
| **B0** | **R7 (segurança)** | **O escore é derrotável por preenchimento — verificado por cálculo. 1.000 CPFs em 2 MB pontuam 7 e NÃO elevam; um CPF em 256 B pontua 8 e eleva. O escore pune o documento pequeno e libera o vazamento em massa** | **Redesenhar o escore. Qualquer achado validado por checksum deve elevar incondicionalmente, ou limitar densidade por categoria, ou tirar densidade da decisão de elevação** |
| **B0b** | **R7 (segurança)** | **O limiar não resiste ao adversário primário do modelo de ameaça: agente com escrita conhece pesos e limiar (repo aberto) e molda o conteúdo para ficar abaixo** | **Decidir: rebaixar a alegação (rede de usabilidade, não controle de segurança) OU defender (consentimento para leitura de conteúdo que o próprio agente escreveu)** |
| B1 | R6 (metodologia) | Precisão/recall prometidos **sem critério de aceitação pré-registrado** — experimento não falsificável | Pré-registrar pisos de recall e precision e declarar o que acontece com a alegação se não forem atingidos |
| B2 | R6 (metodologia) | ≥11 constantes livres (7 pesos + limiar + 3 coeficientes) sem hold-out nem pré-registro da busca | Definir particionamento treino/calibração/teste com *seed* versionada; congelar parâmetros antes do teste. **Depende de B0** — não faz sentido calibrar fórmula derrotável |
| B3 | R8 (LGPD) | Escore é sintático; LGPD define dado pessoal por **identificabilidade** (Art. 5º). Nome + endereço sem CPF pontua baixo e continua sendo dado pessoal | Declarar explicitamente que a pontuação não equivale a avaliação de identificação sob Art. 5º |
| B4 | R8 (LGPD) | Classificador é **estruturalmente cego** ao dado sensível do Art. 5º, II — categorias sem forma sintática | Declarar em Negative consequences; evitar leitura invertida "pontuação alta = mais proteção" |

**Ordem obrigatória:** B0 → B0b → B1 → demais. B0 invalida o desenho atual; B0b
muda o enunciado da alegação em QP1 e é decisão do autor, não do agente.

### Achados verificados no código (não só no texto)

- **Dupla execução do scan (R4/R6).** `redact()` chama `scan()` internamente
  (`crates/sv-privacy/src/lib.rs:200`). Classificar antes do consentimento e
  mascarar depois faria o scan rodar **duas vezes**. Não é só ambiguidade de
  notação — é trabalho desperdiçado. Decidir: passagem única compartilhada, com
  o custo atribuído a exatamente um termo da equação.
- **Precedente de fail-closed já existe.** O caminho ANONYMIZED recusa egresso
  de conteúdo não-UTF-8 (`crates/sv-mcp/src/lib.rs:1446`), com
  *"anonymized egress denied"*. O `Unknown` fail-closed do ADR-0013 é
  consistente com isso, não uma invenção nova — vale citar no ADR.
- **Erro de classificação não é exceção.** `scan()` retorna `Vec<Finding>` sem
  `Result` e não tem panics óbvios. Logo a falha do classificador não dispara
  caminho de erro: ela é uma classificação silenciosamente errada. Tratar
  `Unknown` como "exceção capturada" seria insuficiente.

### Divergência de notação a reconciliar

Três equações incompatíveis convivem no projeto:

| Fonte | Notação |
|---|---|
| `paper.tex` (vigente, pós-R1–R5) | `T_gateway = T_parse+validacao+escopo + T_cofre + I_anon(...) + I_consentimento(...)` |
| ADR-0011 | `T_total = T_vault + T_filter + T_hitl + T_wan + T_inference` |
| ADR-0013 | idem ADR-0011, mais `T_classify` |

O ADR-0013 estendeu a notação **antiga**. A tese foi revisada e adotou termos
indicadores `I`; os ADRs não acompanharam. Reconciliar antes de gerar evidência
nova, sob pena de o Cap. 4 sair com fronteiras de estágio ambíguas.

---

## 8. Riscos

| Risco | Mitigação |
|---|---|
| Escopo maior que o prazo | Ponto de decisão em 30/set; G2 é cortável por construção |
| Classificador com recall baixo vira resultado negativo | Resultado negativo bem medido **é** contribuição válida em DSR; reportar honestamente |
| Estudo humano exige aprovação ética | Verificar exigência do comitê da USP **agora**, não em outubro |
| Regressão em capacidade existente | Regra "só eleva" coberta por teste; suíte atual (`sv-validate`) roda em CI |
