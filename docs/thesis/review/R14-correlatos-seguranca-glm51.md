# R14 — Revisão independente: trabalhos correlatos, segurança e fronteira conceitual (GLM-5.1)

**Revisor:** R14 — ângulo: **segurança e fronteira conceitual** (revisão independente; não
editou `paper.tex` nem qualquer artefato revisado).
**Data:** 04 ago. 2026
**Objeto da revisão:** alteração estrutural recente em `docs/thesis/paper.tex` —
Tabela `tab:posicionamento-correlatos` (§2.6) e ajustes em §2.6 (Trabalhos Correlatos),
§5.3 (Confronto com os Trabalhos Correlatos) e §5.4 (Contribuições).
**Complementa:** R10 (metodologia/DSR), R11 (segurança/ameaças), R12 (privacidade/LGPD).

---

## Veredito de uma linha

**Aprovado sem bloqueantes** — a Tabela de posicionamento e os textos de §2.6/§5.3/§5.4 são
deliberadamente restritivos e, em pontos críticos, **mais honestos do que o documento de
orientação que os originou** (recusam-se a equiparar modos de contêiner a categorias de
criticidade de HAMSTER e não generalizam FL/Solid); há, porém, uma equivalência parcialmente
enganosa em "negação por padrão" (HAMSTER ↔ Sovereign Vault) e um empacotamento conceitual de
escopo/consentimento/DIRECT que infla a aparência de correspondência estrutural — nenhum
quebra invariante de segurança, mas ambos merecem qualificação textual.

---

## Revisão independente — escopo e arquivos lidos

Esta é uma revisão **independente**, conduzida sem acesso a pareceres anteriores sobre esta
alteração específica (a leitura de R10/R11/R12 ocorreu apenas para alinhar o padrão de
saída e o tom; nenhum achado foi importado). Arquivos efetivamente lidos:

| Arquivo | Para quê |
|---|---|
| `docs/thesis/paper.tex` | Objeto da revisão (§2.6, §5.3, §5.4, Tabela, svnotas de modelo de ameaça) |
| `docs/thesis/orientacao/REVISAO-ESTRUTURAL-CONCEITUAL.md` | Origem da alteração; cruzar alegações de correspondência HAMSTER↔SV |
| `crates/sv-mcp/src/lib.rs` | `enforce_scopes`, `serve_stdio`, `call_tool`, `resolve_pairing` — checar "negação por padrão" e fronteira stdio/WS |
| `crates/sv-privacy/src/lib.rs` | Confirmar escopo do filtro ANONYMIZED (7 categorias) citado em §2.6 |
| `apps/cli/src/serve.rs` | `HeadlessAccessController` — checar capacidades do modo headless citadas em §3.7 |
| `apps/thesis-eval/src/main.rs` | Sonda A8 e `HitlPolicy` — checar a alegação "escopos negam por padrão" |
| `docs/adr/0012-context-containers.md` | Confirmar que RAG/contexto é "Proposed" (carga futura citada em §5.3) |
| `docs/thesis/review/R10-*`, `R11-*`, `R12-*`, `R3-*` | Apenas padrão de saída e tom; não fonte de achados |

---

## Achados por severidade

### BLOQUEANTE
*Nenhum.*

Nenhuma invariante de segurança afirmada no paper é quebrada pela nova Tabela ou pelos textos
de §2.6/§5.3/§5.4. As equivalências traçadas são de **forma** (arquitetura nomeada, ponto único
de mediação, autenticação prévia), não de mecanismo ou de força de evidência, e estão
cercadas por qualificações que correspondem ao código. O resultado é de posicionamento, não de
afirmação de superioridade, isolamento ou comparação empírica.

### RELEVANTE

**R1 — "Negação por padrão" é uma equivalência parcialmente enganosa; o Sovereign Vault é
fail-OPEN no estado de escopos vazios, ao passo que HAMSTER é fail-CLOSED de autenticação.**

A Tabela e os textos de §2.6 e §5.3 transpõem, do HAMSTER/Sphere para o Sovereign Vault, a
"negação por padrão" como traço estrutural compartilhado. Verificação no código:

- `enforce_scopes` (`crates/sv-mcp/src/lib.rs:2081-2085`):
  ```rust
  // No scopes means unscoped: full surface, still subject to the mode flow.
  if agent.scopes.is_empty() {
      return Ok(());
  }
  ```
  Um agente **sem escopos** (vazio) recebe `Ok(())` — ou seja, **superfície completa** — e
  só depois entra no fluxo de modo por contêiner. A ausência de escopos é **permissiva**, não
  restritiva.
- O agente "Default" (segredo compartilhado, `apps/thesis-eval/src/main.rs`,
  `ensure_default_agent(PAIRING_SECRET)`) é sem escopos e, portanto, tem full surface perante
  `enforce_scopes`.
- A sonda **A8** (`apps/thesis-eval/src/main.rs`, `Creds::Default`, `vault.read` de
  `secrets/api.key`) é bloqueada por `HitlPolicy` ao negar `SecurityMode::Approval`
  (`"APPROVAL requires desktop consent"`), **não** por `enforce_scopes`. Se o contêiner
  `secrets` fosse `DIRECT`, o Default agent sem escopo leria o segredo sem consentimento.

Contraste com HAMSTER: a "postura *almost deny all*" é **fail-closed de autenticação** —
nenhum módulo opera até prova de identidade. A negação é o **estado de falha**. No Sovereign
Vault, a negação por escopo é **condicional à existência prévia de escopos**; o estado de
falha (sem escopos) é permissivo. Estes são dois modelos materialmente diferentes.

O documento de orientação (`REVISAO-ESTRUTURAL-CONCEITUAL.md`, §1.1) agrava o problema ao
mapear explicitamente "sonda A8: agente Default sem escopo → bloqueado" como evidência de
"escopos negam por padrão". Esta leitura **não corresponde ao código**: A8 demonstra bloqueio
por **modo**, não por **escopo**. O `paper.tex` é, felizmente, mais cuidadoso que o documento
de orientação — diz "negação por padrão **no âmbito dos escopos**" (§2.6) — mas a Tabela, na
coluna "Comportamento padrão pertinente", ainda apresenta "chamadas fora do escopo são
negadas" sem qualificar que o estado de falha (escopos vazios) é permissivo. A aparência de
correspondência estrutural com HAMSTER fica, assim, mais forte do que o código sustenta.

*Recomendação:* adicionar à Tabela (ou ao texto que a interpreta) uma cláusula curta
distinguindo os dois modelos, por exemplo: "no Sovereign Vault, a negação por escopo aplica-se
somente a agentes **com escopos definidos**; o agente sem escopos (incluindo o Default do
segredo compartilhado) tem superfície completa, sendo a contenção providenciada pelo modo do
contêiner, não pelo escopo". Não alterar a asserção de adjacência estrutural — que é legítima
em **forma** —, mas evitar que o leitor a leia como equivalência de **modelo de falha**. Não
remover a qualificação existente.

**R2 — A coluna "Comportamento padrão pertinente" do Sovereign Vault empacota três mecanismos
distintos (escopo, consentimento por modo, DIRECT sem aprovação) sob um rótulo comparável a
uma única propriedade de HAMSTER.**

Na Tabela, a linha HAMSTER/Sphere tem "módulo não é considerado autêntico até prova em
contrário" — uma propriedade de **autenticação fail-closed**. A linha Sovereign Vault tem
"chamadas fora do escopo são negadas; consentimento depende do modo, e DIRECT não solicita
aprovação" — três mecanismos de natureza diferente:

1. **Escopo** (autorização): restrição de superfície, condicional à definição prévia (R1).
2. **Consentimento por modo** (HITL): gate humano para APPROVAL/OTP; **ausente** em DIRECT e
   ANONYMIZED (este último mascara, mas não solicita aprovação).
3. **DIRECT sem aprovação**: não é um "comportamento padrão de segurança" — é, por projeto, a
   **ausência** de mediação humana para aquele contêiner (§3.8, svnota do modelo de ameaça:
   "Leituras DIRECT retornam dados sem consentimento por projeto, e contêineres DIRECT estão
   fora da garantia de mediação humana").

Empacotar os três na mesma célula, ao lado de uma propriedade única do HAMSTER, sugere uma
simetria que não existe. Em particular, listar "DIRECT não solicita aprovação" como
"comportamento padrão pertinente" é desconcertante: é exatamente o ponto em que o Sovereign
Vault **abandona** mediação, não onde a exerce. Um leitor pode inferir que o SV tem, como
HAMSTER, um único e coerente controle fail-closed, quando na verdade o desenho é um trade-off
explícito (e honestamente declarado em §3.8 e §5.5) entre conveniência e mediação.

*Recomendação:* separar, na célula do Sovereign Vault, o que é **autorização** (escopo, com a
ressalva de R1) do que é **mediação humana** (consentimento por modo) e do que é **ausência
deliberada de mediação** (DIRECT). Em vez de uma lista compacta, usar linguagem que preserve
a distinção: "autorização por escopo (apenas para agentes escopados); consentimento humano
somente em APPROVAL/OTP; DIRECT e ANONYMIZED não solicitam aprovação". Não suavizar a
declaração de que DIRECT está fora da garantia de mediação — ela já está correta em §3.8.

### MENOR

**M1 — A Tabela não expõe o modelo de ameaça do Sovereign Vault; sem ele, um leitor apressado
pode superestimar o escopo de segurança.**

As três linhas de correlatos descrevem etapa, ponto de controle e comportamento, mas a linha
do Sovereign Vault não registra o **modelo de ameaça** (usuário único, máquina única, agente
MCP autenticado e potencialmente comprometido; fora do limite: SO, processo sob a mesma conta,
inspeção de memória, roubo de token, rollback de auditoria). Este modelo é a chave de leitura
de toda a Tabela 4.1 (fronteira de evidência) e da svnota de modelo de ameaça em §3.8, mas não
aparece na Tabela de correlatos. Sem ele, a "natureza da evidência mobilizada" para o SV
(avaliação artificial, uma sessão, sem IC) pode ser lida como limitação metodológica
genérica, e não como consequência direta de um modelo de ameaça estreito.

*Recomendação:* opcionalmente, adicionar uma nota de rodapé à Tabela ou uma frase no
parágrafo interpretativo referindo o modelo de ameaça (remetendo à svnota de §3.8) como
contexto obrigatório de leitura da linha do Sovereign Vault.

**M2 — "Precedente estabelecido em arquiteturas de segurança para sistemas críticos" (§5.4)
é defensável como forma, mas a assimetria de força de evidência entre HAMSTER e o SV merece
ficar mais visível.**

A frase ancora a *forma* da contribuição (arquitetura nomeada, camada explícita, proposta e
avaliada empiricamente) no precedente de HAMSTER. O texto já qualifica "nesta instanciação,
porém, a avaliação é artificial e somativa, preliminar, de uma sessão e sem IC". A Tabela,
na coluna "Natureza da evidência mobilizada", registra corretamente a diferença
("arquitetura e estudos de caso no próprio domínio" para HAMSTER vs. "instanciação DSR com
avaliação artificial e somativa preliminar, uma sessão sintética sem IC" para o SV). A
assimetria está declarada, mas fica diluída em duas localizações diferentes (Tabela e §5.4).

*Recomendação:* opcionalmente, na frase de §5.4, tornar explícito que a *forma* é
compartilhada mas a *força* da evidência é estritamente menor na instância atual
(arquitetura + estudos de caso vs. microbenchmark + bateria de uma sessão). Isto não altera o
veredito nem exige novo experimento; é clareza de posicionamento.

**M3 — A coluna "Natureza da evidência mobilizada" mistura tipos incomensuráveis; a ressalva
de "não comparação experimental" é necessária, mas não suficiente, para evitar leitura de
ranking implícito.**

A Tabela lista, lado a lado: "síntese de oportunidades e desafios" (FL), "relatório técnico
da plataforma" (Solid), "arquitetura e estudos de caso no próprio domínio" (HAMSTER) e
"instanciação DSR com avaliação artificial e somativa preliminar" (SV). São quatro regimes
epistêmicos diferentes colocados numa mesma coluna. O rodapé do parágrafo interpretativo
("não se infere que as demais abordagens careçam de controles próprios nem que uma delas seja
empiricamente inferior") é bom e necessário. Ainda assim, o formato tabular convida o leitor
a comparar linhas e inferir hierarquia. O `REVISAO-ESTRUTURAL-CONCEITUAL.md` reconhece este
risco e o paper o mitiga; não há correção adicional estritamente necessária, mas a legenda
poderia reiterar "posicionamento funcional, não ranking de evidência".

*Recomendação:* opcionalmente, reforçar a legenda da Tabela com "As naturezas de evidência
não são diretamente comparáveis entre si" para evitar a leitura coluna-a-coluna como ranking.

**M4 — Generalizações sobre Aprendizado Federado e Solid estão adequadamente contidas;
nenhuma correção necessária.**

Verificação direta: a Tabela diz "não se aplica ao tipo de mediação de ferramentas em
inferência examinado nesta pesquisa" (FL) e "não caracterizado, na fonte mobilizada, como
política para chamadas MCP" (Solid). §2.6 e §5.3 reiteram a diferença de etapa (treinamento
vs. execução; custódia Web vs. chamada de ferramenta) e declaram "O Sovereign Vault não
substitui essa abordagem" e "não há experimento comparativo". Não há equivalência indevida
entre FL/Solid e o SV; o recorte é de **complementaridade**, não de competição ou identidade.
Este é um ponto em que o paper é explicitamente mais cuidadoso do que o mapeamento de
correspondência estrutural do `REVISAO-ESTRUTURAL-CONCEITUAL.md` (que sugeriria, na sua
tabela de §1.1, analogias mais fortes). Achado positivo, registrado para equilíbrio.

**M5 — Não há alegação indevida de isolamento ou de comparação em nuvem; a fronteira está
declarada.**

Cruzamento com §3.7 ("essa separação não equivale a isolamento de processo ou de sistema
operacional"), §5.4 ("não inclui isolamento de memória no SO"), §5.3 ("não se executa
experimento comparativo entre as arquiteturas") e §5.5/§5.6 ("não há braço de comparação em
nuvem, verificação de retenção ou descarte pelo provedor"). A nova Tabela e os textos de
§2.6/§5.3/§5.4 **não introduzem** nenhuma alegação de isolamento, baixa latência em nuvem,
efemeridade no provedor ou superioridade empírica. A fronteira conceitual segurança↔privacidade
(filtro técnico vs. anonimização jurídica, Art. 5º LGPD), espelhada em Ferrão et al.
(§5.5), está preservada e não é tensionada pela alteração. Achado positivo.

---

## Resposta direta ao ângulo (segurança e fronteira conceitual)

A pergunta central desta revisão: **a nova Tabela e os ajustes de §2.6/§5.3/§5.4 traçam
equivalências indevidas, generalizam FL/Solid, confundem escopo/consentimento/negação por
padrão, ou alegam isolamento/comparação em nuvem que o código não sustenta?**

- **Equivalência HAMSTER/Sphere ↔ Sovereign Vault:** a *forma* (arquitetura nomeada, ponto
  único de mediação, autenticação prévia) é defensável. A *negação por padrão* é parcialmente
  enganosa (R1): o SV é fail-open em escopos vazios; HAMSTER é fail-closed de autenticação.
  O paper é mais cuidadoso que o documento de orientação, mas a Tabela ainda deixa o leitor
  inferir simetria de modelo de falha.
- **Generalizações FL/Solid:** não há. O recorte é de complementaridade, com ressalvas
  explícitas de etapa e objeto (M4).
- **Confusão escopo/consentimento/negação por padrão:** existe, na forma de empacotamento
  (R2). A célula do SV mistura três mecanismos de natureza diferente sob um rótulo comparável
  a uma única propriedade do HAMSTER, e inclui "DIRECT não solicita aprovação" — que é
  ausência de mediação, não controle.
- **Isolamento / comparação em nuvem:** nenhuma alegação indevida. A fronteira está
  declarada em §3.7, §5.3, §5.4, §5.5 (M5).

Nenhum destes pontos quebra invariante de segurança. São correções de **precisão
conceitual** na fronteira entre segurança (autorização/autenticação) e mediação (consentimento
humano), exatamente o tipo de fronteira que a literatura de sistemas críticos (Ferrão et al.,
já citada em §5.5) adverte tratar conjuntamente. Recomendam-se dois ajustes textuais (R1, R2)
e três opcionais (M1, M2, M3); nenhum exige novo experimento nem altera o veredito de
segurança.

---

## Recomendações consolidadas (por prioridade)

1. **[relevante — R1]** Qualificar a "negação por padrão" do SV como condicional à definição
   prévia de escopos; registrar que o agente sem escopos (incluindo o Default do segredo
   compartilhado) tem superfície completa e que a sonda A8 demonstra bloqueio por **modo**,
   não por escopo. Evitar que a Tabela sugira equivalência de modelo de falha com HAMSTER.
2. **[relevante — R2]** Separar, na célula "Comportamento padrão pertinente" do SV,
   autorização (escopo), mediação humana (APPROVAL/OTP) e ausência deliberada de mediação
   (DIRECT/ANONYMIZED). Não tratar "DIRECT não solicita aprovação" como controle.
3. **[menor — M1]** Adicionar referência ao modelo de ameaça (svnota de §3.8) como contexto
   obrigatório de leitura da linha do SV na Tabela.
4. **[menor — M2]** Tornar explícita, em §5.4, a assimetria de força de evidência entre a
   forma compartilhada (HAMSTER: arquitetura + estudos de caso) e a instância atual
   (SV: uma sessão, sem IC).
5. **[menor — M3]** Reforçar a legenda da Tabela: as naturezas de evidência não são
   diretamente comparáveis; posicionamento funcional, não ranking.

---

## Observação de escopo

Nenhuma qualificação ou limitação deliberada do texto é objeto de proposta de remoção ou
endurecimento. O resultado negativo bem medido (microbenchmark preliminar de uma sessão sem
IC; bateria finita 10/10+2/2 sobre `HitlPolicy` simulada; exclusões explícitas de RAG, índice
vetorial, isolamento de SO, comparação com nuvem e retenção no provedor) é tratado como
contribuição válida, em conformidade com o contexto R1–R12 / A0–A4. Os achados R1 e R2 são de
**precisão de fronteira conceitual**, não de correção de segurança: o código sustenta todas
as invariantes que o paper afirma; o que se pede é que a Tabela não sugira, por simetria
visual, uma correspondência mais forte do que a que existe.
