# Publicações da orientadora — links, resumos e sinergia com a pesquisa

**Complementa:** [`PERFIL-ORIENTADORA.md`](PERFIL-ORIENTADORA.md) e
[`PONTOS-DE-APOIO-TESE.md`](PONTOS-DE-APOIO-TESE.md)
**Levantado em:** 04/08/2026

> **Estado de verificação.** Os DOIs abaixo foram resolvidos contra o editor ou
> contra fonte aberta (PMC, HAL, Dimensions) e estão marcados como
> **[DOI verificado]**. Os resumos são paráfrases próprias a partir das páginas
> públicas — não são transcrições. As entradas sem DOI verificado estão
> marcadas e **não devem entrar no `paper.tex`** antes de conferência.
>
> ScienceDirect e Springer responderam 403/paywall; para esses, os metadados
> vieram de BV FAPESP, Dimensions e Semantic Scholar. Conferir volume/página
> contra o Lattes antes do depósito.

---

## Tabela de decisão rápida

| # | Trabalho | Ano | Sinergia | Onde citar |
|---|---|---|---|---|
| 1 | Crypto performance evaluation (JNCA) | 2016 | **Muito alta** — método | §3.9, Cap. 5 |
| 2 | HAMSTER (JINT) | 2017 | **Alta** — forma da contribuição | §2, §5.4 |
| 3 | Air taxis: security & safety (Sensors) | 2022 | **Alta** — fronteira de ameaça | §3.7, §5.5 |
| 4 | IDS por anomalia em enxame (ICUAS) | 2023 | Média — postura adversarial | §3.9.2 |
| 5 | ECC/El-Gamal MIRACL vs. RELIC (JACR) | 2011 | Média — precedente do método | §3.9 (reforço) |
| 6 | Certificação em linha de produto (SPLC) | 2012 | Baixa — analogia normativa | §5.5 (opcional) |
| 7 | Índices de carga (tese de doutorado) | 2004 | Contextual — **conhecer, não citar** | — |

---

## 1. Avaliação de desempenho de algoritmos criptográficos ⭐ ÂNCORA PRINCIPAL

**[DOI verificado]**

> SILVA, N. B. F. da; PIGATTO, D. F.; MARTINS, P. S.; CASTELO BRANCO, K. R. L. J.
> **Case studies of performance evaluation of cryptographic algorithms for an
> embedded system and a general purpose computer.** *Journal of Network and
> Computer Applications*, v. 60, p. 130-143, 2016.

- DOI: <https://doi.org/10.1016/j.jnca.2015.10.007>
- ScienceDirect: <https://www.sciencedirect.com/science/article/abs/pii/S1084804515002283>
- BV FAPESP: <https://bv.fapesp.br/en/publicacao/116975/case-studies-of-performance-evaluation-of-cryptographic-algo>
- ResearchGate: <https://www.researchgate.net/publication/284930097>

**Resumo.** Avaliação comparativa de desempenho de RC2, AES, Blowfish, DES,
3DES, ECC e RSA em dois ambientes distintos — um sistema embarcado e um
computador de propósito geral. As grandezas medidas são **tempo de resposta,
uso médio de processador, uso de memória e consumo de energia**. O ponto do
trabalho é que a escolha de primitiva criptográfica tem custo mensurável e
dependente de plataforma, e que esse custo precisa ser caracterizado
empiricamente, não presumido.

**Sinergia — a mais forte de todas.** É o precedente metodológico direto do
Capítulo 4 desta monografia, assinado pela própria orientadora:

1. **Mesma pergunta de pesquisa em outra escala.** "Quanto custa, em tempo, a
   proteção criptográfica em ambiente com restrição?" — sua monografia mede o
   custo do XChaCha20-Poly1305 e do Argon2id no caminho de leitura do cofre.
2. **Mesmo par de grandezas.** Tempo de resposta e uso de recurso são
   exatamente o que o seu *microbenchmark* reporta.
3. **Mesma postura epistêmica.** Trata sobrecarga criptográfica como grandeza de
   engenharia a ser medida, não como detalhe de implementação a ser afirmado.

**Como usar.** Na justificativa do método em §3.9, ancorando a decisão de medir
por *microbenchmark* controlado. Argumento a construir: a caracterização
empírica do custo de primitivas criptográficas em ambiente com restrição de
recurso é prática estabelecida, e esta monografia a aplica ao caminho de
mediação de um *gateway* MCP local.

**Ganho na banca.** Tira do método a aparência de escolha *ad hoc*. Não citar
este trabalho é o erro mais caro desta lista.

---

## 2. HAMSTER — arquitetura de comunicação orientada a segurança

**[DOI verificado — versão de periódico]**

> PIGATTO, D. F.; GONÇALVES, L.; PINTO, A. S. R.; ROBERTO, G. F.;
> RODRIGUES FILHO, J. F.; CASTELO BRANCO, K. R. L. J.
> **The HAMSTER data communication architecture for unmanned aerial, ground and
> aquatic systems.** *Journal of Intelligent & Robotic Systems*, v. 84, 2016.

- DOI: <https://doi.org/10.1007/s10846-016-0356-x>
- Semantic Scholar: <https://www.semanticscholar.org/paper/f9e12cc2ac25b33b2328faa760d9fe8b3205d917>
- Dimensions: <https://app.dimensions.ai/details/publication/pub.1024999151>

Versão anterior, de conferência (**[DOI não verificado]** — usar a de periódico):

> PIGATTO, D. F. et al. **HAMSTER — Healthy, mobility and security-based data
> communication architecture for unmanned aircraft systems.** In: ICUAS, 2014,
> p. 52-63.
> Repositório aberto: <https://repositorio.unesp.br/handle/11449/183940>

Plataforma de segurança associada, **SPHERE**:
<https://www.researchgate.net/publication/279885497>

**Resumo.** Especificação completa de uma arquitetura de comunicação de dados
para sistemas não tripulados (aéreos, terrestres e aquáticos), construída sobre
conceitos de *safety*, mobilidade e segurança. A arquitetura é nomeada,
estruturada em camadas e acompanhada da plataforma SPHERE, dedicada a
*safety & security*.

**Sinergia.** Precedente de **forma da contribuição**, não de tema:

- propor uma arquitetura nomeada, com camadas de segurança explícitas, **e**
  avaliá-la empiricamente é exatamente o formato do Sovereign Vault + avaliação
  em dois braços;
- sustenta, na produção do grupo, que arquitetura é contribuição científica
  legítima em DSR — e não "apenas engenharia";
- reforça a tríade Modelo/Método/Instanciação de March e Smith usada em §5.4.

**Como usar.** Em trabalhos correlatos (§2) e na discussão da contribuição
(§5.4). **Cuidado:** citar pela forma arquitetural, nunca sugerindo que sua
pesquisa é de veículos não tripulados.

---

## 3. Segurança e *safety* em táxis aéreos — revisão sistemática

**[DOI verificado · acesso aberto]**

> FERRÃO, I. G.; ESPES, D.; DEZAN, C.; CASTELO BRANCO, K. R. L. J.
> **Security and safety concerns in air taxis: a systematic literature review.**
> *Sensors*, v. 22, n. 18, art. 6875, 2022.

- DOI: <https://doi.org/10.3390/s22186875>
- Texto integral (PMC): <https://pmc.ncbi.nlm.nih.gov/articles/PMC9505145/>
- HAL: <https://hal.science/hal-03841221/document>

**Resumo.** Revisão sistemática de mais de 210 artigos publicados entre 2015 e
janeiro de 2022. Achado central: **arquiteturas desenhadas para requisitos de
*safety* podem conter lacunas de *security*, e vice-versa** — e apenas três dos
trabalhos revisados tratavam as duas dimensões conjuntamente. Categoriza as
ameaças em ataques a GPS (*spoofing*, *jamming*), ameaças ciberfísicas, negação
de serviço e interceptação de dados com impacto de privacidade de localização.

**Sinergia.** Duas frentes:

1. **Fronteira de ameaça.** Sustenta metodologicamente a decisão do Cap. 3 de
   declarar explicitamente o que **não** está no modelo de ameaça. O achado de
   que garantir uma dimensão não garante a outra é precisamente o argumento por
   trás da sua qualificação de que mascaramento de PII **não** é anonimização.
2. **Rigor de revisão.** Se a banca cobrar sistematicidade no levantamento
   bibliográfico, este é o padrão do grupo — e um trabalho recente e aberto.

**Como usar.** No modelo de ameaça (§3.7) e nas limitações (§5.5), ao separar
propriedade técnica garantida de conformidade normativa.

---

## 4. IDS baseado em anomalia para enxames de VANTs

**[DOI verificado]**

> DA SILVA, L. M.; FERRÃO, I. G.; DEZAN, C.; ESPES, D.;
> CASTELO BRANCO, K. R. L. J.
> **Anomaly-based intrusion detection system for in-flight and network security
> in UAV swarm.** In: *International Conference on Unmanned Aircraft Systems
> (ICUAS)*, 2023, p. 812-819.

- DOI: <https://doi.org/10.1109/ICUAS57906.2023.10155873>
- HAL: <https://hal.science/hal-04159577/>

**Resumo.** Sistema de detecção de intrusão por anomalia cobrindo simultaneamente
segurança de voo e segurança de rede em enxames de VANTs. Trabalho recente, com
coautoria internacional (Lab-STICC, França).

**Sinergia.** Precedente de **postura adversarial explícita** na avaliação:
testar o sistema contra comportamento hostil declarado é prática do grupo, o que
legitima sua bateria pré-especificada de 12 sondas (§3.9.2) como instrumento
metodológico, e não como teste improvisado.

**Cuidado.** Sua pesquisa **não** faz detecção de intrusão. O apoio é sobre
postura de avaliação. Citação mal enquadrada aqui é facilmente detectável.

---

## 5. Criptografia de curvas elípticas — MIRACL vs. RELIC

**[DOI não verificado]** — periódico de menor circulação; conferir no Lattes.

> PIGATTO, D. F.; SILVA, N. B. F. da; CASTELO BRANCO, K. R. L. J.
> **Performance evaluation and comparison of algorithms for elliptic curve
> cryptography with El-Gamal based on MIRACL and RELIC libraries.**
> *Journal of Applied Computing Research*, v. 1, n. 2, 2011.

- ResearchGate: <https://www.researchgate.net/publication/228444712>

**Resumo.** Comparação de desempenho de implementações de ECC com El-Gamal em
duas bibliotecas criptográficas distintas — mesma pergunta do item 1, aplicada à
escolha de biblioteca em vez de algoritmo.

**Sinergia.** Reforço secundário do item 1: mostra que a linha de avaliação
empírica de criptografia é sustentada e não episódica. Útil se você quiser
sustentar que a escolha de implementação (não só de algoritmo) tem custo
mensurável — relevante porque sua tese usa implementações Rust específicas.

**Recomendação.** Citar **apenas** se o texto discutir escolha de biblioteca.
Caso contrário, o item 1 basta.

---

## 6. Certificação em modelagem de linha de produto

**[DOI não verificado]**

> BRAGA, R. T. V.; TRINDADE JR., O.; CASTELO BRANCO, K. R. L. J.; LEE, J.
> **Incorporating certification in feature modelling of an unmanned aerial
> vehicle product line.** In: *SPLC*, 2012, p. 249-258.

**Resumo.** Trata requisitos de certificação normativa como características
modeláveis de engenharia dentro de uma linha de produto de software.

**Sinergia (fraca, opcional).** Analogia útil ao argumentar por que conformidade
normativa não decorre automaticamente de propriedade técnica implementada —
exatamente o que você afirma sobre o Art. 5º da LGPD. **Só citar se o argumento
for efetivamente desenvolvido no texto.**

---

## 7. Tese de doutorado — raiz metodológica

> CASTELO BRANCO, K. R. L. J. **Índices de carga e desempenho em ambientes
> paralelos/distribuídos.** Tese (Doutorado) — ICMC/USP, 2004.

- Google Scholar (25 citações): <https://scholar.google.com/citations?hl=pt-BR&user=XMwzMF8AAAAJ>

**Sinergia.** **Não citar** — seria referência de cortesia, e a banca percebe.
Mas **conhecer é obrigatório**: define o padrão pelo qual seu Capítulo 4 será
lido. Avaliação de desempenho não é competência periférica dela; é a origem da
carreira. Toda fragilidade de régua de medição (k baixo, ausência de IC,
*warmup* não declarado, ambiente não controlado) será vista imediatamente.

---

## Estratégia de citação — recomendação

**Citar 3, não 7.** Excesso de citação da orientadora é lido como bajulação e
enfraquece o trabalho.

| Prioridade | Item | Justificativa |
|---|---|---|
| **Obrigatório** | 1 (JNCA 2016) | Precedente metodológico direto; sua ausência é lacuna real |
| **Recomendado** | 3 (Sensors 2022) | Aberto, recente, sustenta a fronteira de ameaça |
| **Recomendado** | 2 (HAMSTER) | Legitima arquitetura como contribuição |
| Opcional | 4 | Só se a bateria adversarial for muito questionada |
| Evitar | 5, 6, 7 | Só com argumento genuíno no texto |

### Antes de inserir qualquer um

1. Resolver o DOI contra `doi.org` e conferir autores, volume e páginas;
2. Conferir a grafia do nome — ela aparece como `BRANCO, K. R. L. J. C.`,
   `CASTELO BRANCO, K. R. L. J.` e `Branco, Kalinka R. L. J. C.` em bases
   distintas. **Padronizar em `CASTELO BRANCO, Kalinka Regina Lucas Jaquie`**,
   consistente com as demais entradas ABNT do `paper.tex`;
3. Seguir o padrão de `\bibitem` já usado no arquivo (sobrenome em versalete,
   periódico em itálico, `DOI: <doi>.` ao final);
4. Recompilar e confirmar zero citações indefinidas.

---

## Fontes consultadas

- Google Scholar: <https://scholar.google.com/citations?hl=pt-BR&user=XMwzMF8AAAAJ>
- BV FAPESP: <https://bv.fapesp.br/en/pesquisador/45222/kalinka-regina-lucas-jaquie-castelo-branco/>
- dblp (Pigatto, coautor frequente): <https://dblp.org/pid/72/10701.html>
- LSEC: <https://www.lsec.icmc.usp.br/publicacoes> (indisponível na coleta)
- `scriptLattes` ICMC: `prodacad.icmc.usp.br` (recusou conexão na coleta)
