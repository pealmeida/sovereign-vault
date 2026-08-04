# Revisão R12 — Privacidade/LGPD

**Revisor:** GLM-47 (ângulo: privacidade/LGPD)  
**Pergunta central:** A métrica técnica corresponde ao conceito jurídico?

---

## Veredito

**APROVADO COM SUGESTÕES MENORES DE REFINAMENTO TEXTUAL**

A correspondência entre a métrica técnica (sete categorias de detecção/mascaramento em saída ANONYMIZED) e o conceito jurídico central do Art. 5º da LGPD (identificabilidade) é tratada com qualificação explícita e consistente em todo o texto. O trabalho evita alegações de conformidade e reconhece limitações de forma deliberada.

---

## Achados

### A1. Art. 5º da LGPD e distinção mascaramento ≠ anonimização — CONFORME

**Localização:** Resumo (l. 44-46), Abstract (l. 49-51), Cap. 3 §3.6 (l. 228-230), Tabela 4.1 (l. 364), QP1 (l. 495-496), Limitações (l. 532), Trabalhos futuros (l. 544).

**Verificação:** O texto afirma de forma consistente que:
1. Mesmo com CPF/CNPJ mascarados, um documento contendo nome + endereço pode permanecer identificável sob o Art. 5º da LGPD.
2. O mascaramento parcial **não** equivale a anonimização genérica ou conformidade à LGPD.
3. O artefato não é adequado a documentos em que a vinculação de identidade por campos não mascarados seja risco realista.
4. A qualificação é repetida em pelo menos 7 pontos estratégicos do texto (resumo, abstract, metodologia, fronteira de evidência, resultados, limitações, trabalhos futuros).

A distinção jurídica entre mascaramento (técnico) e anonimização (jurídico, irreversível) está clara e não é enfraquecida em nenhuma passagem.

---

### A2. Sete categorias e exclusões — CONSISTENTES

**Localização:** Cap. 3 §3.6 (l. 228), Tabela 4.1 (l. 364), QP1 (l. 493), Limitações (l. 532), código (crates/sv-privacy/src/lib.rs:49-64,72-80).

**Verificação técnica vs. textual:**

| Categoria | Código (enum + validador) | Texto (Cap. 3, Tab. 4.1) | Consistente? |
|-----------|---------------------------|--------------------------|--------------|
| E-mail | `Email` + `find_emails` (RFC-shaped) | "e-mail" | ✅ |
| CPF | `Cpf` + `cpf_valid` (check-digit) | "CPF" | ✅ |
| CNPJ | `Cnpj` + `cnpj_valid` (check-digit) | "CNPJ" | ✅ |
| Cartão com Luhn | `CreditCard` + `luhn_valid` (13-19 dígitos) | "números de cartão válidos por Luhn" | ✅ |
| IPv4 | `Ipv4` + `find_ipv4` (dotted-quad ≤255) | "IPv4" | ✅ |
| Telefones formatados | `Phone` + `find_phones` (requer + ou () | "telefones explicitamente formatados" | ✅ |
| SSN | `Ssn` + `find_ssns` (`\d{3}-\d{2}-\d{4}`) | "SSN dos Estados Unidos" | ✅ |

**Exclusões mencionadas:** RG, CEP, nomes completos, endereços, datas de nascimento, telefones sem formatação.

**Verificação:** O código implementa exatamente as sete categorias descritas e **não** implementa as exclusões listadas. A enumeração `PiiCategory::ALL` contém 7 variantes, e os validadores correspondentes estão presentes. Não há inconsistência entre código e texto.

**Exemplo ilustrativo no texto:** "João Silva, Rua X, CEP 12345-678" passa sem máscara (l. 228) — coerente com as exclusões declaradas.

---

### A3. Redução de PII na fronteira de evidência — QUALIFICADA ADEQUADAMENTE

**Localização:** Tabela 4.1 "Fronteira de evidência" (l. 363-364), QP1 (l. 493-495), Limitações (l. 532).

**Qualificação presente:**
- Tabela 4.1: "sete categorias heurísticas em saída ANONYMIZED & **não é anonimização genérica/LGPD; somente texto; NÃO detecta RG, CEP, nomes, endereços, datas de nascimento e telefones sem formatação**"
- QP1: "A redução de exposição sustentada pela evidência é, portanto, operacional e delimitada... O filtro cobre exatamente sete categorias heurísticas, mas as cargas sintéticas ANONYMIZED exercitam somente e-mail, CPF e IPv4; **não há medição de precisão ou recall**."
- Limitações: "O filtro ANONYMIZED opera somente sobre texto... as cargas medidas não representam documentos reais e não estabelecem precisão ou recall."

**Verificação:** O texto evita implicar conformidade à LGPD em todas as ocorrências. A qualificação é tripla:
1. **Escopo:** "somente texto" (não dados estruturados, binários, etc.)
2. **Cobertura:** apenas 7 categorias, com exclusões explícitas
3. **Evidência:** cargas sintéticas limitadas a 3 das 7 categorias; sem medição de precisão/recall

Não há alegação de "anonimização em conformidade com a LGPD" em nenhum ponto do texto.

---

### A4. Dados sintéticos e justificativa de minimização — COERENTE COM LGPD

**Localização:** Cap. 3 §3.9 "Dados da Avaliação" (l. 277-287).

**Justificativa explícita:**
> "O uso de dados pessoais reais para medir o filtro de PII criaria o próprio risco que o artefato busca mitigar; por não haver necessidade para a medição, não se trata dado pessoal real, em consonância com a minimização esperada pela LGPD."

**Qualificação dos identificadores sintéticos:**
- `example.com` — RFC 2606 (reservado para documentação)
- `192.168.0.1` — RFC 1918 (espaço IPv4 privado)
- CPF de teste — válido apenas no dígito verificador, não atribuído a pessoa real

**Verificação:** A justificativa está alinhada com o princípio da minimização (Art. 6º, III, LGPD) e com a seleção de identificadores em faixas reservadas. O texto não sugere que os CPFs de teste sejam "anônimos" em sentido jurídico; apenas que são fictícios.

---

### A5. Abstract em inglês — FIEL AO RESUMO EM PT

**Localização:** Resumo (l. 44-46) vs. Abstract (l. 49-51).

**Comparação:**

| Elemento | Resumo PT | Abstract EN | Fidelidade? |
|----------|-----------|-------------|-------------|
| Escopo da avaliação | "microbenchmark local sintético e a uma bateria finita de chamadas de ferramenta" | "synthetic local microbenchmark and a finite suite of tool calls" | ✅ |
| O que NÃO mede | "não mede inferência em nuvem, utilidade de tarefa ou tempo de decisão humana" | "it does not measure cloud inference, task utility, or human decision time" | ✅ |
| Limitação ANONYMIZED | "nomes completos, endereços, RG, CEP e telefones sem formatação passam sem máscara" | "full names, addresses, Brazilian RG identification numbers, CEP postal codes, and unformatted telephone numbers pass through unmasked" | ✅ |
| Art. 5º da LGPD | "um documento com nome e endereço pode permanecer identificável sob o Art.~5º da LGPD" | "a document containing a name and address may remain identifiable under Article 5 of the LGPD" | ✅ |
| Conclusão de inadequação | "o artefato não é adequado a documentos em que a vinculação de identidade por campos não mascarados seja risco realista" | "the artifact is not suitable for documents in which identity linkage through unmasked fields is a realistic risk" | ✅ |

**Verificação:** O abstract em inglês é fiel ao resumo em português, incluindo todas as ressalvas jurídicas e técnicas. Não há suavização ou omissão de limitações na tradução.

---

### A6. Trabalhos futuros de PII — DESCRITOS COMO NÃO IMPLEMENTADOS

**Localização:** Cap. 5 §5.6 "Trabalhos Futuros" (l. 544).

**Texto analisado:**
> "Os detectores de PII devem ser ampliados e avaliados para dados brasileiros, incluindo RG, CEP, nomes e endereços, com precisão e recall por categoria em conjunto rotulado. Detectores ambíguos devem permanecer fora da elevação adaptativa até satisfazerem critério pré-especificado, e desempenho sintético deve conservar a ressalva de validade externa. Essa linha de trabalho reduz lacunas conhecidas do mascaramento, mas não estabelece conformidade à LGPD."

**Verificação:**
1. Uso de tempo verbal futuro/dever: "devem ser ampliados", "devem permanecer fora" — indicando trabalho futuro, não estado atual.
2. Não há afirmação de que detectores brasileiros (RG, CEP, nomes, endereços) já existam.
3. A ressalva final é explícita: "não estabelece conformidade à LGPD".
4. A descrição menciona "precisão e recall por categoria" como requisito de avaliação, não como métrica já obtida.

**Conclusão:** Não há descrição de trabalhos futuros como se já existissem. As qualificações de "não implementado" e "não estabelece conformidade" estão presentes.

---

## Recomendações

### R1. Menor — Consistência terminológica em trabalhos futuros

**Observação:** Em Trabalhos Futuros (l. 544), o termo "detectores ambíguos" aparece sem definição prévia. Considerando o contexto de elevação adaptativa mencionada no ADR-0013, seria útil especificar se "ambíguos" se refere a detectores com alta taxa de falsos positivos ou a detectores não-validados por check-digit.

**Ação sugerida (opcional):** Adicionar uma breve qualificação entre parênteses, por exemplo: "detectores ambíguos (aqueles sem validação por checksum e com maior risco de falso positivo)".

---

### R2. Menor — Reforço de vinculação ao Art. 5º em uma passagem

**Observação:** Em QP1 (l. 495), a frase "RG, CEP, nomes completos, endereços, datas de nascimento e telefones sem formatação não são detectados" poderia reforçar explicitamente que **essa combinação** de campos não detectados é precisamente o que pode manter a identificabilidade sob o Art. 5º, já que o parágrafo seguinte afirma "essa resposta não equivale a garantia de anonimização ou de não identificabilidade".

**Ação sugerida (opcional):** Considerar adicionar ", e essa combinação de campos pode ser suficiente para identificar um indivíduo" após a listagem de campos não detectados, para reforçar o vínculo jurídico.

---

## Considerações Finais

A métrica técnica (sete categorias de PII detectadas/mascaradas em saída textual) é apresentada com correspondência qualificada ao conceito jurídico de identificabilidade do Art. 5º da LGPD. O texto:

1. **Distingue claramente** mascaramento (técnico, reversível, parcial) de anonimização (jurídica, irreversível);
2. **Consistentemente qualifica** que o artefato não é adequado a documentos com campos não mascarados (nomes, endereços, etc.);
3. **Não alega conformidade** à LGPD em qualquer passagem;
4. **Justifica o uso de dados sintéticos** alinhado ao princípio da minimização;
5. **Mantém consistência** entre código, resumo, abstract, tabelas e limitações;
6. **Descreve trabalhos futuros** como não implementados, com ressalvas de evidência.

As recomendações são de refinamento textual menor e não afetam a correção jurídico-técnica da argumentação.