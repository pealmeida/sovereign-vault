# Plano de Atualização do TCC — Revisão Completa (03/08/2026)

**Aluno:** Pedro Oliveira — MBA em IA e Big Data, USP/ICMC (Turma 5)
**Tema:** Arquitetura de Soberania de Dados para Agentes de IA Pessoais (artefato: Sovereign Vault)
**Prazo final estimado:** envio completo até dezembro/2026 (conf. orientação da Met III). Restam ~4 meses.

---

## 1. Diagnóstico — estado atual

Existem **duas linhagens do texto**, com divergências relevantes:

| Fonte | Data | Conteúdo |
|---|---|---|
| Google Doc "…Met III" (Drive) | 02/06/2026 | Cap. 1–3 + referências. Foi o entregável da Met III. |
| `docs/thesis/paper.tex` (repo) | 03/08/2026 | Cap. 1–4 (com resultados preliminares reais), apêndice de reprodutibilidade, revisão por pares interna (R1–R5) incorporada. **Versão mais avançada.** |

### 1.1 Pontos fortes (manter)
- Metodologia DSR bem amarrada: três ciclos de Hevner, Peffers, taxonomia March & Smith, enquadramento FEDS (artificial+somativa vs. naturalística+somativa).
- Harness de avaliação reprodutível (`apps/thesis-eval`): microbenchmark de latência (N=1.000/célula) e bateria adversarial (10/10 bloqueios, 2/2 controles), com CSVs e hashes SHA-256 no apêndice.
- Rastreabilidade código↔tese (`TRACEABILITY.md`), ADRs 0001–0012, honestidade científica exemplar sobre limites de evidência (Tabela "Fronteira de Evidência").
- Revisão interna R1–R5 + `response-to-reviewers.md` já aplicada ao texto.

### 1.2 Problemas encontrados

**A. Estruturais (bloqueiam a entrega final)**
1. `paper.tex` ainda se declara "Projeto de Pesquisa / versão revisada" (`\tipotrabalho`, `\preambulo`, bloco pré-textual) — precisa virar **monografia de TCC**.
2. **Falta o Capítulo 5** (Discussão e Considerações Finais). A Seção "Organização do Trabalho" diz "capítulos subsequentes *poderão* abordar…" — linguagem provisória.
3. **Zero figuras no documento inteiro.** A orientadora exige figuras/gráficos referenciados e explicados no texto. Faltam: diagrama da arquitetura (§3.6), fluxo de execução (§3.7), ciclos DSR (§3.3), gráficos de latência, captura da UI de consentimento.
4. Elementos pré-textuais ABNT incompletos: capa/folha de rosto padrão USP, **Abstract em inglês**, listas de figuras/tabelas/siglas, palavras-chave no abstract.
5. No Google Doc da Met III: Equação 1 com símbolos perdidos ("custo temporal ponta a ponta ()") e espaços vazios onde deveriam estar as figuras de §3.3 e §3.7 — se esse doc for reapresentado, está quebrado.

**B. Alinhamento com as exigências da disciplina (Met III)**
6. A Met III exige Cap. 3 estruturado em torno de **dados** (obtenção → tratamento → características, com técnicas básicas de ML/estatística). O Cap. 3 atual é de arquitetura/método (correto para DSR), mas convém adicionar seção explícita "Dados da Avaliação": composição das cargas sintéticas (128 B/1 KiB/16 KiB), desenho da bateria adversarial (classes A1–A10, controles C1–C2), dados de auditoria, com estatística descritiva (distribuições, boxplots) — satisfaz a rubrica sem descaracterizar a DSR.
7. Divergência entre versões: QP3 e Objetivo Específico 4 mudaram entre o doc da Met III (isolamento de memória no SO; comparação com nuvem) e o `paper.tex` (autenticação/escopos/auditoria; bateria pré-especificada). A mudança é legítima (re-escopo honesto), mas precisa ser **comunicada à orientadora** e refletida em uma única versão canônica.

**C. Evidência experimental (Cap. 4)**
8. Dados atuais são "execução preliminar de desenvolvimento": 1 sessão, sem IC. O próprio texto define a régua da execução definitiva: **k≥3 sessões independentes, IC 95% por bootstrap, regra de warmup/descarte, campos de host completos**. Falta executar e substituir tabelas + hashes.
9. Latência fim-a-fim (Eq. 2, T_e2e) definida mas nunca medida — instrumentar timestamps no cliente ou declarar formalmente como não medida.
10. Comparação de dois braços com nuvem (EVAL-PROTOCOL.md) não executada. Decidir: executar versão mínima até out/2026 **ou** manter como trabalho futuro com justificativa (recomendado se o tempo apertar).
11. `T_espera_humana` (APPROVAL/OTP): coletar distribuição real (mediana, p95, taxa de timeout) com usuário real — mesmo pequeno n já responde melhor a RQ2 que AutoAllow.

**D. Forma e escrita (normas do curso)**
12. Bibliografia manual (`thebibliography`) — migrar para `abntex2cite` (citações autor-data ABNT corretas e automáticas).
13. Varredura de escrita científica: impessoalidade, tempo presente, siglas definidas 1ª vez, itálico em estrangeirismos, evitar parágrafos de frase única, traduzir inglês desnecessário.
14. Processo: submeter PDF final + feedbacks recebidos no drive compartilhado particular (exigência recorrente das 3 disciplinas).

---

## 2. Plano de execução (ago → dez/2026)

### Fase 1 — Consolidação estrutural (ago, semanas 1–2)
- [ ] Eleger `paper.tex` como **fonte canônica**; sincronizar com Overleaf (`OVERLEAF-INTEGRATION.md`) para revisão da orientadora; aposentar/arquivar os Google Docs com aviso no topo.
- [ ] Converter preâmbulo de "Projeto de Pesquisa" para monografia (capa/folha de rosto modelo USP, `\tipotrabalho{Trabalho de Conclusão de Curso}`).
- [ ] Adicionar elementos pré-textuais: Abstract (EN) + keywords, lista de figuras, lista de tabelas, lista de siglas.
- [ ] Reescrever "Organização do Trabalho" sem linguagem provisória (Cap. 5 incluído).
- [ ] Enviar à orientadora nota curta explicando o re-escopo de QP3/Objetivo 4 (com justificativa DSR).

### Fase 2 — Figuras e dados do Cap. 3 ✅ CONCLUÍDA (03/08/2026)
- [x] 4 figuras (não 5 — a figura da bateria adversarial foi cortada por duplicar a Tabela de sondas):
  - Fig. 1 ciclos DSR — **reaproveitada** do entregável da Met III (`figuras/dsr-tres-ciclos.png`)
  - Fig. 2 arquitetura de referência (TikZ)
  - Fig. 3 fluxo de execução (TikZ) — desenhada fiel ao artefato real, **não** ao diagrama da Met III
  - Fig. 4 decomposição da latência por estágio (pgfplots, dados reais de `latency.csv`)
- [x] Seção "Dados da Avaliação" no Cap. 3, com origem sintética, composição das cargas, justificativa LGPD e limitação de validade da composição de PII.
- [x] Compila limpo: 0 erros, 0 refs indefinidas, 0 overfull > 20pt, 44 páginas.

> **Achado da Fase 2.** O diagrama de sequência entregue na Met III descreve capacidades que o artefato não possui (criticidade automática, edição de contexto, resposta cifrada). Ver [PLANO-ARQUITETURA-PRETENDIDA.md](PLANO-ARQUITETURA-PRETENDIDA.md) para o plano de implementação e o impacto no cronograma.

### Fase 3 — Execução definitiva da avaliação (set)
- [ ] Rodar `thesis-eval` k≥3 sessões, IC 95% bootstrap, warmup documentado, host fixo (SO, CPU, RAM, storage, energia, rustc, data); atualizar Tabelas de latência + hashes do apêndice.
- [ ] Gerar gráficos de resultados (barras/boxplot por modo×carga; componente cofre vs. filtro).
- [ ] Medir T_e2e instrumentado (cliente stdio/WS) ou registrar formalmente como não medido.
- [ ] Estudo pequeno de T_espera_humana (n≥30 aprovações reais; mediana/p95/timeouts).
- [ ] Decisão go/no-go da comparação de dois braços (nuvem). No-go ⇒ mover definitivamente para Trabalhos Futuros.

### Fase 4 — Capítulos finais (out)
- [ ] Cap. 4 final: substituir dados preliminares pelos definitivos; discutir cada tabela/figura no texto.
- [ ] **Cap. 5 — Discussão e Considerações Finais**: responder QP1–QP3 explicitamente uma a uma; confrontar com trabalhos correlatos (Federated Learning, Solid); limitações; contribuições (modelo/método/instanciação); trabalhos futuros (ADR-0012, RAG de borda, âncora externa de auditoria, PII brasileira).
- [ ] Migrar bibliografia para `abntex2cite`; conferir todas as citações no texto.

### Fase 5 — Revisão e entrega (nov → dez)
- [ ] Varredura de escrita científica (item D.13) — passada completa, depois releitura com distância temporal.
- [ ] Compilação final `latexmk` limpa; verificação ABNT (margens, sumário, paginação).
- [ ] Revisão externa: enviar à orientadora com antecedência para 1 ciclo de feedback.
- [ ] Submeter PDF + feedback no drive compartilhado particular.
- [ ] Congelar tag no repo (`thesis-final`) com commit citado no apêndice de reprodutibilidade.

---

## 3. Riscos

| Risco | Mitigação |
|---|---|
| Comparação com nuvem não couber no prazo | Já tratada no texto como futura; formalizar decisão até 15/set |
| Orientadora esperar Cap. 3 "de dados" clássico | Fase 2 adiciona seção de dados; alinhar por mensagem antes |
| Execução definitiva divergir da preliminar | Rodar cedo (início de set) para sobrar tempo de reescrita |
| Overleaf/abntex2 com atrito de compilação | `paper.tex` já compila em pdflatex/abntex2 (PR #58); testar no Overleaf na Fase 1 |
