# R13 — Revisão independente da alteração estrutural em Trabalhos Correlatos / Confronto

**Revisor:** GLM-5.2 (ângulo: metodologia/DSR e integridade de alegações)
**Escopo:** nova `Tabela~\ref{tab:posicionamento-correlatos}` (§2.6) e ajustes em
§2.6 (Trabalhos Correlatos), §5.3 (Confronto) e §5.4 (Contribuições).
**Data:** 05 ago. 2026

> **Revisão independente.** Este parecer foi produzido sem contato com o autor
> da alteração estrutural (`REVISAO-ESTRUTURAL-CONCEITUAL.md`) e sem leitura
> prévia das revisões R10–R12 sobre os mesmos trechos. Os cruzamentos com R10/R11
> que aparecem ao final são apenas constatações de convergência, não insumo.
> Nenhum arquivo foi editado: `paper.tex` e o artefato revisado
> (`REVISAO-ESTRUTURAL-CONCEITUAL.md`) foram mantidos intactos, conforme
> solicitado.

---

## Arquivos lidos (para auditoria)

| Arquivo | Lido integralmente? |
|---|---|
| `docs/thesis/paper.tex` | Sim (foco em §1.2, §2.6, §3.5, §3.7, §3.10.1, §5.2–§5.6) |
| `docs/thesis/orientacao/REVISAO-ESTRUTURAL-CONCEITUAL.md` | Sim |
| `docs/thesis/TRACEABILITY.md` | Sim |
| `docs/thesis/orientacao/PONTOS-DE-APOIO-TESE.md` | Sim (contexto das inserções P1–P5) |
| `docs/thesis/orientacao/PUBLICACOES-KALINKA-LINKS.md` | Sim (conferência bibliográfica das fontes da tabela) |
| `docs/thesis/orientacao/PERFIL-ORIENTADORA.md` | Sim (perfil de escrutínio esperado) |
| `docs/thesis/review/R10-full-metodologia-glm52.md`, `R11…`, `R12…` | Apenas para calibrar severidade com a régua já usada; lidos **após** a formação dos achados |

Fontes primárias dos correlatos (Imteaj 2021, Sambra 2016, Pigatto 2016, Silva
2016, Ferrão 2022) **não** foram lidas no original: trabalho sobre as
paráfrases/curadoria dos documentos de orientação, com a ressalva explícita de
quais alegações dependem de verificação contra o PDF (ver R3 e M4).

---

## Veredito (uma linha)

**APROVADO sem bloqueantes** — a nova tabela e os ajustes de §2.6/§5.3/§5.4
evitam falsa equivalência com caulibração honesta da força de evidência e
aderência plena às QPs e ao enquadramento FEDS/March&Smith; os únicos pontos a
endurecer são duas contradições **entre documentos** (uma em `TRACEABILITY.md`
que sobrealega isolamento de SO na QP3 e outra de contagem de ferramentas 15 vs
17/20) e três calibrações pontuais de evidência na própria seção revisada.

---

## Achados por severidade

### BLOQUEANTE

Nenhum. Nenhuma alegação da seção revisada extrapola a fronteira de evidência
(`tab:fronteira-evidencia`), equipara indevidamente o artefato aos correlatos,
ou atribui ao `Sovereign Vault` capacidade declarada apenas como trabalho futuro.

### RELEVANTE

**R1 — `TRACEABILITY.md` parafraseia a QP3 como "OS-level isolation mitigating
lateral exfiltration", o que contradiz diretamente o escopo do próprio `paper.tex`.**
Em `TRACEABILITY.md` (§3, linha da RQ3), lê-se:

> RQ3 | OS-level **isolation** mitigating lateral exfiltration | Memory-safe Rust (`forbid(unsafe_code)`); loopback-only binding + per-launch pairing; scope enforcement; adversarial block-rate

O `paper.tex`, porém, afirma de forma consistente e repetida o **oposto**: §1.3
("O artefato não implementa isolamento de memória no nível do sistema
operacional"), §2.5 ("segurança de memória de linguagem não é isolamento de
memória no sistema operacional"), §3.7 ("A separação indicada é somente lógica"),
e a svnota do modelo de ameaça ("Estão fora de escopo: comprometimento do
sistema operacional [...] inspeção de memória"). A QP3 real (§1.3) é
deliberadamente delimitada a "modelo de ameaça de usuário único e máquina
única" — não invoca isolamento de SO. A paráfrase de `TRACEABILITY.md` é,
portanto, uma **sobrealegação** que contradiz o documento de rastreabilidade o
qual é, por definição, o contrato entre tese e artefato.
**Impacto:** não corrói a seção revisada (§2.6/§5.3/§5.4 estão corretos), mas é
o tipo de defeito que, se lido pela banca, expõe o autor a uma cobrança
imediata ("seu próprio documento de rastreabilidade alega isolamento de SO que
você diz não ter"). Como meu ângulo é integridade de alegações, elevo a
relevante.
**Recomendação:** corrigir a linha RQ3 de `TRACEABILITY.md` para refletir o
escopo usuário-único/máquina-única e a qualificação "sem isolamento de SO",
alinhando-a à svnota do modelo de ameaça e à QP3 de §1.3. (Não editar `paper.tex`.)

**R2 — `TRACEABILITY.md` diz "15 tools" onde `paper.tex` diz "17 ferramentas-base
+ 3 condicionais de broker (20 com broker)".**
`TRACEABILITY.md` aparece com "15 tools" em §1 (módulo 2: "Rust-native MCP
server, stdio + WS, 15 tools"), §3 (linha do RQ1: "15 tools") e §5 (MCP: "15
tools"). O `paper.tex` §3.7.2 e a Figura `fig:arquitetura-referencia` declaram
"17 ferramentas-base e três ferramentas condicionais de broker, totalizando 20
quando o broker está habilitado". O documento de rastreabilidade é datado de
2026-06-06 e admite "If a symbol moves, search by name" — está, portanto,
**defasado** em pelo menos duas ferramentas-base e nas três de broker.
**Impacto:** direto sobre a integridade do registro de instanciação (March &
Smith *instantiation*). Embora a nova tabela de correlatos não cite contagem de
ferramentas, a divergência mina a confiabilidade do documento que sustenta a
afirmação de que o artefato é uma instanciação genuína.
**Recomendação:** atualizar `TRACEABILITY.md` para "17 base + 3 condicionais de
broker (20 com broker habilitado)", citando `crates/sv-mcp/src/lib.rs:2370-2380,
2461-2699` como já faz o `paper.tex`.

**R3 — A "natureza da evidência" de HAMSTER na tabela ("arquitetura e estudos de
caso no próprio domínio") é mais fraca do que a alegação de §2.6 e §5.4
("proposta e avaliada empiricamente"), e nenhuma das duas foi conferida contra o
PDF primário.**
A coluna de força de evidência da tabela é, para FL e Solid, **precisamente
calibrada** às fontes efetivamente mobilizadas: FL → "síntese de oportunidades e
desafios" (Imteaj 2021 é literalmente um *opportunities and challenges*
preprint); Solid → "relatório técnico da plataforma" (Sambra 2016 é um
*Technical Report* do MIT CSAIL). Para HAMSTER, porém, a tabela diz "arquitetura
e estudos de caso no próprio domínio", enquanto o corpo de §2.6 e §5.4 eleva a
"arquitetura nomeada [...] proposta e **avaliada empiricamente**" e "precedente
estabelecido". "Estudos de caso" e "avaliada empiricamente" não são sinônimos
rigorosos: o primeiro admite demonstração descritiva; o segundo sugere
experimento controlado. Como não li o JIRS v. 84, p. 705-723, não posso atestar
qual caracterização é a correta — mas **há tensão interna entre a tabela (mais
cautelosa) e a prosa (mais forte)**, e ambas carecem de verificação primária.
**Impacto:** se a banca (cuja orientadora é coautora do HAMSTER) considerar a
avaliação do HAMSTER menos rigorosa do que "empiricamente avaliada" sugere, a
ancoragem da *forma* da contribuição enfraquece por associação.
**Recomendação:** (a) alinhar a prosa de §2.6/§5.4 à formulação mais cautelosa da
tabela ("arquitetura acompanhada de estudos de caso no próprio domínio"), ou
(b) confirmar contra o PDF primário que HAMSTER reporta avaliação empírica
(medição/caso controlado) antes de manter "avaliada empiricamente". Em qualquer
dos casos, registrar a verificação.

**R4 — Âncora de Aprendizado Federado repousa em preprint arXiv não revisado por
pares (Imteaj 2021), fonte fraca para sustentar um "corpo adjacente" no
posicionamento.**
Imteaj et al. 2021 (`arXiv:2101.05428`) é um *survey* de oportunidades e
desafios, não uma contribuição primária de FL. A alegação de posicionamento é
estreita e defensável ("treina modelos de forma cooperativa sem centralizar
dados brutos; seu objeto central não é a mediação de chamadas de ferramenta
durante a inferência") — mas, para um trabalho cuja orientadora valoriza rigor
de revisão (é autora de revisão sistemática, segundo `PERFIL-ORIENTADORA.md`),
 ancorar FL apenas num preprint é uma exposição evitável.
**Impacto:** não invalida o posicionamento, mas deixa a linha de FL como a
célula mais fraca da tabela em força de fonte.
**Recomendação:** adicionar a referência canônica de FL (McMahan et al.,
*Communication-Efficient Learning of Deep Networks from Decentralized Data*,
AISTATS 2017) ao lado de Imteaj 2021, mantendo este último para a caracterização
"oportunidades e desafios". Uma citação dupla (fonte primária + survey) é
padrão aceito e fortalece a célula sem inflar o corpo de correlatos.

**R5 — Exaustividade do posicionamento: a tabela cobre três corpos *adjacentes*,
mas nenhum *vizinho mais próximo* (gestores de segredos/credenciais, middleware
de segurança MCP, redatores de PII).**
§2.6 enquadra FL, Solid e HAMSTER/Sphere como "três corpos adjacentes" e
explicitamente renuncia ao levantamento exaustivo ("não [...] levantamento
exaustivo"). A renúncia é honesta e defensável para um TCC. Contudo, a tabela
demonstra que SV difere de três corpos *distantes* (treinamento, custódia Web,
veículos), sem nunca confrontar o **vizinho mais próximo**: sistemas de gestão
de segredos/credenciais (p.ex. HashiCorp Vault), *gateways* de privacidade para
LLM, ou — admitindo a novidade do MCP (2024) — a própria ausência de *prior art*
de mediação de chamadas de ferramenta por agentes. O leitor arguto pode concluir
que SV é distinto dos três mostrados, mas não sabe se é distinto do mais
próximo, que não aparece.
**Impacto:** risco de cobrança direta ("por que não comparar com um cofre de
segredos existente?"). O argumento de que "MCP é de 2024, não há prior art"
é válido, mas **não está dito no texto**.
**Recomendação (opcional, baixo custo):** acrescentar uma frase em §2.6 ou §5.3
reconhecendo que a mediação de chamadas de ferramenta de agentes de IA a
segredos locais não tem, até onde se sabe, *prior art* estabelecido, e que o MCP
\cite{anthropic2024} é o protocolo que viabiliza essa mediação. Isso converte a
ausência de vizinho próximo em *gap* explicitado, não em omissão.

### MENOR

**M1 — A célula "ponto de controle" de SV na tabela não cavea que escopo,
*pairing* e consentimento valem apenas no caminho WebSocket autenticado.**
A tabela diz, para SV: "ponto de controle: *gateway* MCP antes da operação no
cofre". Isto é verdade para o caminho desktop WS, mas o caminho `stdio` opera
com `PairState::AlreadyPaired(None)` e não invoca `enforce_scopes` (§3.11,
limitações; svnota do modelo de ameaça). A §2.6 é posicionamento, não alegação
de segurança, então o impacto é baixo — mas a tabela pode ser lida como
"mediação uniforme em todo o gateway", o que a §3.7 e a svnota desdizem.
**Recomendação:** qualificar a célula como "*gateway* MCP antes da operação no
cofre (caminho WebSocket autenticado)", ou adicionar nota de rodapé remetendo à
svnota do modelo de ameaça. Converge com R1 de R11 (fronteira stdio/WS
sub-enunciada).

**M2 — A SV é rotulada na tabela como "instantiação DSR", o que colide com a
taxonomia March & Smith do próprio texto (Modelo, Método **e** Instanciação
como três tipos de artefato, todos produzidos).**
A coluna "natureza da evidência" da linha SV diz "instantiação DSR com avaliação
artificial e somativa [...]". O rótulo "instantiação DSR" é coloquialmente
aceitável, mas §3.5 e §5.4 atribuem evidência aos três tipos (Modelo =
arquitetura de referência; Método = protocolo de mediação; Instanciação =
protótipo). Um leitor rigoroso pode ler "instantiação DSR" como "apenas a
instanciação tem evidência", enfraquecendo as contribuições de Modelo e Método.
**Recomendação:** trocar "instantiação DSR" por "instanciação do artefato
(Modelo/Método/Instanciação) com avaliação artificial e somativa [...]" ou
similar, alinhando à linguagem de §3.5/§5.4.

**M3 — Inconsistência de ano do HAMSTER entre documentos de orientação:
`PUBLICACOES-KALINKA-LINKS.md` (tabela rápida, item 2) diz "2017"; `paper.tex`,
`REVISAO-ESTRUTURAL-CONCEITUAL.md` (§1.1 e §4) e `PONTOS-DE-APOIO-TESE.md` dizem
"2016".**
O `\bibitem{pigatto2016}` (v. 84, p. 705-723, DOI `10.1007/s10846-016-0356-x`) e
a afirmação "paginação de HAMSTER conferida na fonte primária" no
`REVISAO-ESTRUTURAL-CONCEITUAL.md` indicam **2016** como ano correto. O "2017"
da tabela rápida de `PUBLICACOES-KALINKA-LINKS.md` é, quase certamente, o ano de
complementação do fascículo vs. ano de atribuição — um descuido de curadoria.
**Impacto:** baixo (a referência oficial no `paper.tex` está correta), mas o
autor poderia propagar "2017" por engano em futuras citações se confiar na
tabela rápida.
**Recomendação:** corrigir "2017" → "2016" na tabela rápida de
`PUBLICACOES-KALINKA-LINKS.md`. (Não é o artefato revisado; edição permitida.)

**M4 — A caracterização "estudos de caso" para HAMSTER (R3) não é a única
alecação de força de evidência que depende de PDF primário não lido por mim.**
Declaro explicitamente: as alegações de §2.6 sobre HAMSTER ("postura de negação
por padrão, na qual nenhum componente é considerado autêntico até prova em
contrário"; "categoriza componentes por criticidade primários/secundários";
"autentica cada módulo antes da operação") são plausíveis e coerentes com o
mapeamento de `REVISAO-ESTRUTURAL-CONCEITUAL.md`, mas **não foram por mim
conferidas contra o JIRS v. 84**. A revisão assume fidelidade das paráfrases dos
documentos de orientação, que por sua vez declaram leitura integral dos PDFs.
**Recomendação (processual):** manter o apontamento de que a confiança cadeada
(paper → REVISAO → PDF) é aceitável para TCC, mas registrar a verificação
primária no relatório de revisão final, como já fez `REVISAO-ESTRUTURAL-CONCEITUAL.md`
§4 para paginação.

---

## Verificação focada por eixo solicitado

### Falsa equivalência — **ausente, com garda robusta**

A seção revisada emprega, de forma consistente, os seguintes anti-guardas:
- §2.6: "Trata-se de posicionamento funcional [...], não de comparação
  experimental, levantamento exaustivo ou classificação de superioridade";
- §2.6 (após tabela): "não se infere que as demais abordagens careçam de
  controles próprios nem que uma delas seja empiricamente inferior";
- §5.3 (FL): "A avaliação realizada não compara desempenho, privacidade ou
  utilidade entre as duas abordagens";
- §5.3 (Solid): "não demonstra superioridade sobre Solid, pois não há
  experimento comparativo";
- §5.3 (HAMSTER): "a correspondência não equipara os modos de contêiner do
  Sovereign Vault às categorias de criticidade de HAMSTER";
- §5.4: "nesta instanciação, porém, a avaliação é artificial e somativa,
  preliminar, de uma sessão e sem IC" — qualificador que **explicitamente
  enfraquece** a evidência de SV em relação ao precedente, bloqueando leitura
  implícita de "tão bom quanto HAMSTER".

A inclusão de SV na mesma tabela que FL/Solid/HAMSTER poderia, por si, sugerir
equivalência de contribuição; o enquadramento "posicionamento funcional" (não
"comparação") e a calibração por coluna de força de evidência dissipam esse
risco. **Sem falsa equivalência detectada.**

### Força da evidência — **calibração excelente, com R3 como única ressalva**

A coluna "Natureza da evidência mobilizada" é o ponto mais forte da tabela: ela
quantifica, para cada linha, *o quê* foi efetivamente usado (survey, relatório
técnico, arquitetura+estudos de caso, instanciação DSR). Esse dispositivo é raro
em TCCs e demonstra maturidade epistêmica. As três células externas calibram-se
precisamente ao tipo de fonte; a célula SV reutiliza corretamente o vocabulário
FEDS ("artificial e somativa") de §3.3/§3.11, mantendo coerência terminológica
entre metodologia e posicionamento. Único reparo: R3 (calibração de HAMSTER e
verificação primária pendente).

### Exaustividade — **renúncia honesta, com R5 como reforço recomendado**

A renúncia ao levantamento exaustivo é declarada e legítima. A escolha de três
corpos adjacentes é coerente com a estratégia de citação do grupo
(`PONTOS-DE-APOIO-TESE.md`: "Citar 3, não 7"). O ponto cego é o vizinho mais
próximo (R5): recomenda-se uma frase explicitando a ausência de *prior art* de
mediação MCP, convertendo omissão em *gap* declarado.

### Aderência às QPs — **plena**

- A tabela não introduz alegação que conflite com as respostas de §5.2 (QP1–QP3).
- A célula "comportamento padrão pertinente" de SV ("chamadas fora do escopo são
  negadas; consentimento depende do modo, e DIRECT não solicita aprovação") é
  consistente com QP1 e QP3 e com a svnota do modelo de ameaça (DIRECT fora da
  garantia de mediação humana).
- A §5.3 não atribui a SV capacidades de QP1–QP3 além do que §5.2 sustenta.
- Única precisão: M1 (caveat do caminho WS na célula de ponto de controle), já
  coberto por R11-R1.

### Contradição entre documentos — **duas em `TRACEABILITY.md` (R1, R2), uma em
`PUBLICACOES-KALINKA-LINKS.md` (M3)**

R1 e R2 são os achados de maior severidade desta revisão, não pela seção
revisada (que está correta), mas porque `TRACEABILITY.md` — documento que
materializa a instanciação DSR e é leitura provável da banca — sobrealega
isolamento de SO (R1) e subconta ferramentas (R2) em desacordo com o `paper.tex`.
R1 é especialmente sensível porque reproduz, em outro documento, exatamente o
tipo de sobrealegação que a seção revisada trabalha para evitar.

---

## Recomendações consolidadas (priorizadas)

1. **[relevante — R1]** Corrigir a linha RQ3 de `TRACEABILITY.md`: remover
   "OS-level isolation" e refletir o escopo usuário-único/máquina-única + "sem
   isolamento de SO", alinhando à QP3 de §1.3 e à svnota do modelo de ameaça.
2. **[relevante — R2]** Atualizar `TRACEABILITY.md` de "15 tools" para "17
   ferramentas-base + 3 condicionais de broker (20 com broker)", citando
   `crates/sv-mcp/src/lib.rs:2370-2380, 2461-2699`.
3. **[relevante — R3]** Alinhar a prosa de §2.6/§5.4 ("avaliada empiricamente")
   à formulação mais cautelosa da tabela ("estudos de caso"), **ou** confirmar
   contra o PDF do JIRS v. 84 que HAMSTER reporta avaliação empírica antes de
   manter a redação atual. Registrar a verificação.
4. **[relevante — R4]** Adicionar McMahan et al. (AISTATS 2017) como âncora
   primária de FL ao lado de Imteaj 2021, mantendo este para a caracterização de
   oportunidades/desafios.
5. **[relevante — R5, opcional]** Acrescentar uma frase em §2.6 ou §5.3
   explicitando a ausência de *prior art* de mediação de chamadas de ferramenta
   por agentes de IA a segredos locais, ancorando no MCP \cite{anthropic2024}.
6. **[menor — M1]** Qualificar a célula "ponto de controle" de SV com "(caminho
   WebSocket autenticado)" ou nota remetendo à svnota do modelo de ameaça.
7. **[menor — M2]** Substituir "instantiação DSR" por formulação que abranja
   Modelo/Método/Instanciação, alinhando a §3.5/§5.4.
8. **[menor — M3]** Corrigir "2017" → "2016" na tabela rápida de
   `PUBLICACOES-KALINKA-LINKS.md`.
9. **[menor — M4, processal]** Registrar verificação primária das paráfrases de
   HAMSTER no relatório de revisão final.

---

## Lacunas declaradas

- Não li os PDFs primários de Imteaj 2021, Sambra 2016, Pigatto 2016, Silva 2016
  e Ferrão 2022; trabalho sobre as curadorias de
  `PUBLICACOES-KALINKA-LINKS.md` (que declara DOIs resolvidos) e
  `REVISAO-ESTRUTURAL-CONCEITUAL.md` (que declara leitura integral das três obras
  da orientadora). Achados R3, R4 e M4 dependem dessa cadeia de confiança.
- Não recompilei o `paper.tex` (instrução de não edição); a conferência de
  `\cite`/`\bibitem` apoia-se no §4 de `REVISAO-ESTRUTURAL-CONCEITUAL.md`
  (`sync-uspsc-body.py`: 26/26, 0 órfãs; `latexmk`: zero indefinidas).
- Não verifiquei o ramo USPSC ou a variante `paper-uspsc.tex`; o
  `REVISAO-ESTRUTURAL-CONCEITUAL.md` declara essa recompilação como pendente.
- R1 e R2 (contradições em `TRACEABILITY.md`) são defeitos de documento de
  apoio, não da seção revisada; foram elevados a relevante porque o ângulo
  solicitado inclui "contradição entre documentos" e porque a banca pode ler
  `TRACEABILITY.md`.
