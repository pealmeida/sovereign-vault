# Reviewer E — data privacy / Brazilian LGPD compliance

**Model:** `zai/glm-4.7` (anymodel, independent voice) · **Lens:** privacy / LGPD · **Run:** 2026-08 · black-box (ADR text only).

Context for consistency: Previous review R5-privacy-lgpd-glm46.md established that the artifact does NOT claim LGPD compliance, only exposure reduction; that RG, CEP, names, addresses, dates, and unformatted phones are NOT detected; and that documents may remain identifying even after CPF+CNPJ masking when other fields pass through unmasked.

---

## VERDICT: major-revision

## MAJOR ISSUES

1. **§Context / §Decision, point 2 — Conceito de "sensibilidade" no classificador vs. LGPD** — O ADR usa "sensitivity" como pontuação derivada de detecção sintática de PII, mas a LGPD Art. 5º define dado pessoal por **IDENTIFICABILIDADE** (capacidade de identificar, direta ou indiretamente, uma pessoa natural), não por presença de padrões formatados. Um documento com nome completo + endereço pode não conter CPF/CNPJ/cartaço (e então receber pontuação baixa), mas permanecer identificável e exigir tratamento de dado pessoal. O texto diz que "Text can reveal health, political, financial, or other sensitive facts without containing explicit PII. Detecting that semantic sensitivity is out of scope", mas **não conecta explicitamente essa limitação à definição jurídica de dado pessoal**. O classificador pode classificar como "baixa sensibilidade" algo que, juridicamente, é dado pessoal. Isso precisa ser declarado em uma frase que diga: "A pontuação de sensibilidade é estritamente sintática e não equivale a uma avaliação de identificação sob LGPD Art. 5º; documentos sem PII formatado podem permanecer identificáveis por contexto."

2. **§Context — Cegueira estrutural a dado sensível (LGPD Art. 5º, II)** — O ADR reconhece que sensibilidade semântica (saúde, convicções, vida sexual, origem racial, biometria) está fora do escopo, mas **não declara que essas são exatamente as categorias mais protegidas pela LGPD**. O Art. 5º, II define dado sensível com oito categorias; nenhuma delas tem formato sintático detectável por expressões regulares. O classificador é estruturalmente cego à categoria que a lei mais protege, e isso deveria ser destacado na seção de Limitations/Negative consequences ou em nota explícita vinculando à LGPD. Sem isso, leitores podem assumir que "alta pontuação" = "maior proteção LGPD", quando a relação é inversa: as categorias mais protegidas passam invisíveis.

3. **§6 — Camadas de confiança e risco de falsa sensação de cobertura** — A seção propõe detectores brasileiros ambíguos (RG, CEP, nome completo, endereço, data de nascimento, telefone sem formatação) em "candidate tier", desabilitados por padrão e excluídos da elevação de modo. O ADR diz que isso evita consent fatigue, mas **não admite o risco oposto**: que usuários ao verem esses detectores listados (mesmo desabilitados) possam inferir que o sistema é capaz de protegê-los. A revisão R5 já alertou que "documents containing CPF+CNPJ masked but exposing name+address may remain identifying under LGPD Art. 5". Se o ADR adiciona detectores que jamais serão usados para elevação sem evidência de performance, a transparência de omissões diminui. O ADR deveria declarar explicitamente: "Mesmo quando habilitados, detectores ambíguos não devem ser usados como prova de cobertura de dado pessoal; a ausência de detecção sintática não implica ausência de dado pessoal."

4. **§Decision, point 4 / §Consequences — Calibração em conjunto sintético vs. dado real brasileiro** — O ADR estabelece corretamente que o conjunto de calibração deve ser sintético por minimização de dados (LGPD Art. 7º), mas **não qualifica a distância entre sintético e real para PII brasileiro**. Detectores de CPF/CNPJ com checksum validam formato, mas nomes e endereços brasileiros têm estrutura linguística, distribuição geográfica e variação ortográfica que não são capturadas por dados sintáticos. O ADR reconhece "known synthetic-to-real limitation" no §7, mas não detalha que essa distância é **particularmente crítica** para as categorias ambíguas propostas (RG, CEP, nomes, endereços). A consequência para a tese: qualquer alegação de "cobertura de PII brasileiro" baseada em resultados sintáticos precisa ser fortemente qualificada como "em conjunto sintético; performance em dados reais desconhecida".

## MINOR ISSUES

5. **§Decision, point 3 — Status de "Unknown" e princípio LGPD de finalidade** — O ADR define `Unknown` como fail-closed (requer aprovação ou nega liberação), que é defensável do ponto de vista de segurança. Do ponto de vista de LGPD, o usuário (titular/controlador) decide sobre tratamento de dado pessoal, mas o classificador opera como um processador automatizado. A distinção entre controlador (usuário) e processador (classificador) não é explícita, embora o ADR acerte ao deixar o limiar sob controle do usuário. Uma frase esclarecendo que "o classificador é um auxiliar de decisão automatizado sob controle do titular, não um substituto de julgamento jurídico" reforçaria a postura correta.

6. **§Decision, point 5 — Leitura pré-consentimento e janela de exposição** — O ADR honestamente admite que a leitura local para classificação muda a janela de exposição e não reclama isolamento de memória verificado. Do ponto de vista de LGPD Art. 7º (princípios), especialmente o princípio da segurança, o ADR deveria mencionar explicitamente que a janela de exposição do plaintext em memória (após decriptação, antes de consentimento) é um vetor que não está coberto por garantias formais. Isso não bloqueia o design, mas deve constar como limitação explícita.

## STRENGTHS

- Mantém consistência com R5: não alega conformidade à LGPD, apenas redução de exposição.
- Elevation-only behavior (o classificador nunca afrouxa proteção configurada) é invariante de segurança crucial.
- Reconhecimento honesto de que detecção sintática não cobre sensibilidade semântica e que dados sensíveis (saúde, política, etc.) são invisíveis.
- Separação clara entre DETECT (`sv-privacy`) e DECIDE (`sv-classify`) preserva responsabilidade, coerente com ADR-0010.
- Decisão correta de rejeitar LLM local por latência, não-determinismo e opacidade, coerente com Privacy-by-Design (Cavoukian).
- Requisito explícito de conjunto rotulado versionado e separação entre calibração e avaliação, coerente com rigor metodológico da tese.
- Limiar sob controle do usuário, coerente com princípio de que o titular decide sobre tratamento de seus dados.

## RECOMENDAÇÕES

1. **Adicionar frase explícita no Context** conectando a limitação de detecção sintática à LGPD Art. 5º: "A pontuação de sensibilidade é estritamente sintática e não equivale a uma avaliação de identificação sob LGPD Art. 5º; documentos sem PII formatado podem permanecer identificáveis por contexto."

2. **Adicionar nota na seção Negative consequences** ou em parágrafo específico: "O classificador é estruturalmente incapaz de detectar dado sensível conforme LGPD Art. 5º, II (origem racial, convicção religiosa, opinião política, saúde, vida sexual, biometria), pois essas categorias não têm formato sintático detectável; essas são precisamente as categorias que a lei mais protege."

3. **Na seção 6**, adicionar advertência de que a existência de detectores em candidate tier não deve ser interpretada como cobertura funcional: "Mesmo quando habilitados, detectores ambíguos não devem ser usados como prova de cobertura de dado pessoal; a ausência de detecção sintática não implica ausência de dado pessoal."

4. **No §7 (DSR evaluation harness)**, qualificar explicitamente a distância sintético-real: "A performance reportada em conjunto sintético pode não generalizar para dados reais brasileiros, especialmente para detectores ambíguos (RG, CEP, nomes, endereços) que dependem de contexto linguístico e geográfico; qualquer alegação de cobertura deve incluir essa limitação."

5. **Considerar adicionar frase curta** no §Decision, point 3 sobre a distinção controlador/processador: "O classificador opera como auxiliar de decisão automatizado sob controle do titular (que é o controlador sob LGPD), não como substituto de julgamento jurídico sobre tratamento de dados."

6. **Não fazer alegação de conformidade à LGPD** em qualquer parte da tese relacionada ao classificador; manter linguagem de "redução de exposição" e "auxílio à decisão do usuário", como estabelecido em R5.

---

**Bloqueantes:** itens 1 e 2 (definição de sensibilidade vs. LGPD; cegueira a dado sensível) — devem ser tratados antes de aceitação deste ADR para garantir que a tese não apresente o classificador como mais completo do que é juridicamente.

**Relevantes:** itens 3 e 4 (camadas de confiança vs. falsa sensação de cobertura; calibração sintética vs. dado real) — importantes para qualificação adequada de alegações de cobertura.

**Menores:** itens 5 e 6 (status de Unknown e janela de exposição) — melhorias de clareza, mas não bloqueiam o design.