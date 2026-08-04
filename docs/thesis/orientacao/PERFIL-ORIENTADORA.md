# Perfil da orientadora — Profa. Dra. Kalinka Regina Lucas Jaquie Castelo Branco

**Levantado em:** 04/08/2026 · **Fontes:** página pessoal ICMC, BV FAPESP, Google
Scholar, IEA/USP, CeMEAI, repositórios USP/ICMC (links ao final)

> **Aviso de proveniência.** Este dossiê foi montado a partir de fontes públicas
> acessadas na data acima. O `scriptLattes` do ICMC
> (`prodacad.icmc.usp.br`) e o site do LSEC recusaram conexão no momento da
> coleta (`ECONNREFUSED`), de modo que a lista de publicações vem do Google
> Scholar e não do Lattes canônico. **Conferir contra o Lattes antes de citar
> qualquer entrada em texto avaliado.**

---

## 1. Identificação

| Campo | Valor |
|---|---|
| Nome completo | Kalinka Regina Lucas Jaquie Castelo Branco |
| Vínculo | Professora Associada, Departamento de Sistemas de Computação (SSC) |
| Instituição | ICMC/USP — São Carlos |
| Sala | 4-202, Av. Trabalhador São-carlense, 400, São Carlos/SP, 13560-970 |
| E-mail | `kalinka@icmc.usp.br` |
| Formação | Tecnologia em Processamento de Dados (1995); Mestrado em Ciências de Computação, USP (1999); Doutorado em Ciências de Computação, USP (2004) |
| Atuação institucional | Secretária Regional SBC (SP-Oeste) |

### Métricas de citação (Google Scholar, ago/2026)

| Métrica | Total | Desde 2021 |
|---|---|---|
| Citações | 1.678 | 869 |
| Índice h | 23 | 16 |
| Índice i10 | 53 | 30 |

---

## 2. Linhas de pesquisa declaradas

- Arquitetura de sistemas de computação
- Redes de computadores — com **ênfase declarada em Segurança**
- Computação paralela e sistemas distribuídos
- Sistemas embarcados críticos
- **Avaliação de desempenho**
- Veículos aéreos não tripulados (VANTs/UAVs)

### Laboratórios

| Sigla | Nome | Papel |
|---|---|---|
| LSEC | Laboratório de Sistemas Embarcados Críticos | coordenadora |
| LaSDPC | Laboratório de Sistemas Distribuídos e Programação Concorrente | integrante |
| LRM | Laboratório de Robótica Móvel | integrante |

---

## 3. O que isso significa para esta pesquisa

A orientadora **não** é pesquisadora de LGPD nem de agentes de IA. É
pesquisadora de **segurança em sistemas distribuídos e embarcados, com
tradição forte em avaliação de desempenho**. Três consequências práticas:

1. **O capítulo mais escrutinado será o de método de medição, não o jurídico.**
   A tese de doutorado dela (2004) é *Índices de carga e desempenho em ambientes
   paralelos/distribuídos* — avaliação de desempenho é a competência central,
   não periférica. Régua fraca de medição é o risco número um desta monografia
   diante dela.
2. **Há precedente metodológico direto** para o *microbenchmark* de criptografia
   (§4 abaixo): ela publicou exatamente esse tipo de estudo, com as mesmas
   grandezas.
3. **O enquadramento "arquitetura + avaliação empírica de um artefato"** é o
   formato nativo do grupo. O trabalho está alinhado por construção; o que
   precisa ser defendido é o *rigor da medida*, não a pertinência do tema.

---

## 4. Pontos de apoio para a tese — publicações da própria orientadora

Ordenados por força de sustentação. **Todos precisam de conferência
bibliográfica antes de virar `\bibitem`.**

### 4.1 Âncora metodológica principal — avaliação de desempenho de criptografia

> PIGATTO, D. F.; SILVA, N. B. F. da; MARTINS, P. S.; CASTELO BRANCO, K. R. L. J.
> **Case studies of performance evaluation of cryptographic algorithms for an
> embedded system and a general purpose computer.**
> *Journal of Network and Computer Applications*, v. 60, p. 130-143, jan. 2016.
> DOI: `10.1016/j.jnca.2015.10.007`

Avalia RC2, AES, Blowfish, DES, 3DES, ECC e RSA medindo **tempo de resposta, uso
médio de processador e memória, e consumo de energia**.

**Por que é o apoio mais forte:** legitima, na produção da própria orientadora, o
desenho do Capítulo 4 desta monografia — medir custo de operação criptográfica
por *microbenchmark* controlado, reportando tempo por operação e decompondo por
componente. Também dá precedente para a escolha de reportar **p95 além da
média**, e para tratar sobrecarga criptográfica como grandeza de engenharia e
não como detalhe de implementação.

**Como usar:** citar na justificativa do método do §3.9 (plano de avaliação) e
na discussão do Capítulo 5 ao qualificar o custo do XChaCha20-Poly1305 e do
Argon2id. Frase de ancoragem sugerida: a decomposição por estágio adotada aqui
segue a tradição de avaliação de desempenho de primitivas criptográficas em
ambientes com restrição de recurso.

> Complemento anterior, mesma linha:
> PIGATTO, D. F.; SILVA, N. B. F. da; CASTELO BRANCO, K. R. L. J.
> **Performance evaluation and comparison of algorithms for elliptic curve
> cryptography with El-Gamal based on MIRACL and RELIC libraries.**
> *Journal of Applied Computing Research*, v. 1, n. 2, 2011.

### 4.2 Arquitetura de comunicação orientada a segurança — HAMSTER

> PIGATTO, D. F.; GONÇALVES, L.; PINTO, A. S. R.; ROBERTO, G. F.;
> RODRIGUES FILHO, J. F.; CASTELO BRANCO, K. R. L. J.
> **HAMSTER — Healthy, mobility and security-based data communication
> architecture for Unmanned Aircraft Systems.**
> *International Conference on Unmanned Aircraft Systems (ICUAS)*, 2014.

Arquitetura de comunicação de dados com segurança como preocupação de primeira
classe, incluindo a plataforma **Sphere** para *safety & security*.

**Por que apoia:** precedente do grupo para **propor uma arquitetura nomeada,
com camadas de segurança explícitas, e avaliá-la** — que é exatamente a forma
desta monografia (Sovereign Vault + avaliação em dois braços). Sustenta a
legitimidade do artefato como contribuição, não apenas o resultado numérico.

### 4.3 Detecção de anomalias e postura adversarial

> DA SILVA, L. M.; FERRÃO, I. G.; DEZAN, C.; ESPES, D.;
> CASTELO BRANCO, K. R. L. J.
> **Anomaly-based intrusion detection system for in-flight and network security
> in UAV swarm.** *International Conference on Unmanned Aircraft Systems*, 2023.

**Por que apoia:** precedente recente (2023) de avaliação com **postura
adversarial explícita** — sustenta a bateria pré-especificada do §3.9.2 desta
monografia como instrumento legítimo, e não como teste *ad hoc*.

### 4.4 Segurança como requisito em sistemas críticos

> FERRÃO, I. G.; ESPES, D.; DEZAN, C.; CASTELO BRANCO, K. R. L. J.
> **Security and safety concerns in air taxis: a systematic literature review.**
> *Sensors*, v. 22, n. 18, 2022.

**Por que apoia:** distinção operacional entre *safety* e *security* e tratamento
de requisitos de segurança em domínio crítico — útil ao delimitar o modelo de
ameaça do Capítulo 3 e a fronteira do que o artefato **não** protege.

### 4.5 Certificação e linha de produto

> BRAGA, R. T. V.; TRINDADE JR., O.; CASTELO BRANCO, K. R. L. J.; LEE, J.
> **Incorporating certification in feature modelling of an unmanned aerial
> vehicle product line.** *SPLC*, 2012.

**Por que apoia (secundário):** trata conformidade normativa como requisito
modelável de engenharia — analogia útil ao discutir por que mascaramento técnico
**não** equivale a conformidade jurídica (Art. 5º da LGPD), tema já qualificado
no texto.

### 4.6 Raiz metodológica — avaliação de desempenho distribuído

> CASTELO BRANCO, K. R. L. J. **Índices de carga e desempenho em ambientes
> paralelos/distribuídos.** Tese (Doutorado) — Universidade de São Paulo, 2004.

**Por que apoia:** é a origem da exigência de rigor em medição. Citá-la é
opcional, mas **conhecê-la não é**: define o padrão pelo qual o Capítulo 4 será
lido.

### 4.7 Dissertação orientada — precedente direto de tema

> **Segurança em sistemas embarcados críticos — utilização de criptografia para
> comunicação segura.** Dissertação, ICMC/USP.
> Repositório: `repositorio.icmc.usp.br/handle/RIICMC/4993`

**Por que importa:** demonstra que "usar criptografia para proteger comunicação
em sistema com restrição" já foi tema de orientação dela. O presente trabalho é
continuidade reconhecível dessa linha, transposta de sistemas embarcados para
agentes de IA.

---

## 5. Projetos em andamento com aderência ao tema

Fonte: BV FAPESP.

| Projeto | Aderência |
|---|---|
| **IntegraSanca: conectando dados, transformando São Carlos** — integração e interoperabilidade de dados em administração pública fragmentada | **Alta.** Soberania e governança de dados sob custódia institucional; o problema de mediar acesso a dados sensíveis entre sistemas é o mesmo desta monografia em outra escala |
| **Governança de dados em cidades inteligentes** (bolsa, estudo de caso São Carlos) | **Alta.** Governança de dados é o vocabulário compartilhado entre o trabalho dela e este |
| Arquitetura orientada a serviços para sistemas embarcados críticos complexos | Média. Precedente de arquitetura como objeto de pesquisa avaliável |
| Videomonitoramento inteligente e segurança do cidadão; sensores IoT urbanos | Média. Tensão privacidade × utilidade em dado pessoal |

> **Oportunidade de enquadramento.** A introdução pode explicitar que soberania
> de dados no nível do *indivíduo* (esta monografia) é o análogo, em outra
> escala, do problema de governança de dados no nível da *cidade* — linha ativa
> da orientadora. Isso conecta o trabalho à agenda dela sem forçar o escopo.

---

## 6. Colaboradores frequentes

Marcos José Santana · Regina Helena Carlucci Santana · Daniel Fernando Pigatto
(UNICAMP/UTFPR) · Natassya Barlate Floro da Silva · Paulo S. Martins ·
Onofre Trindade Jr. · Rosana T. V. Braga · Alex S. R. Pinto ·
Catherine Dezan e David Espes (Univ. Brest, França) · Iberê G. Ferrão

> Útil para sugerir banca e para reconhecer o vocabulário do grupo.

---

## 7. Riscos previsíveis na defesa

| Risco | Origem | Mitigação já no texto |
|---|---|---|
| **Rigor da medição** — k, IC, *warmup*, randomização, controle de ambiente | Especialidade central dela | §3.9 declara a régua; `EXECUCAO-DEFINITIVA.md` a operacionaliza. **Executar antes da entrega é obrigatório** |
| **Evidência preliminar de uma sessão sem IC** | Idem | Qualificada em todas as ocorrências; substituir pela execução definitiva |
| **Modelo de ameaça frouxo** | Segurança é a ênfase dela | Cap. 5 declara fronteira, transporte `stdio` fora do limite, HITL simulada |
| **Confundir mascaramento com anonimização** | Rigor conceitual | Qualificado em 7 pontos do texto (parecer R12) |
| **"Onde está a comparação?"** | Tradição de avaliação comparativa | Declarado como trabalho futuro (protocolo de dois braços). Ponto legítimo de cobrança — ter resposta pronta |
| Tema fora do domínio VANT/embarcado | — | Enquadrar via governança de dados (§5) e via segurança em sistema com restrição de recurso |

---

## 8. Fontes

- Página pessoal: <https://sites.icmc.usp.br/kalinka/>
- Currículo Lattes: <https://buscatextual.cnpq.br/buscatextual/visualizacv.do> (CNPq)
- Google Scholar: <https://scholar.google.com/citations?hl=pt-BR&user=XMwzMF8AAAAJ>
- BV FAPESP: <https://bv.fapesp.br/en/pesquisador/45222/kalinka-regina-lucas-jaquie-castelo-branco/>
- IEA/USP: <https://www.iea.usp.br/pessoas/pasta-pessoak/kalinka-regina-lucas-jaquie-castelo-branco>
- CeMEAI/USP: <https://cemeai.icmc.usp.br/kalinka-regina-lucas-jaquie-castelo-branco/>
- LSEC: <https://www.lsec.icmc.usp.br/> (indisponível na coleta)
- JNCA 2016: <https://doi.org/10.1016/j.jnca.2015.10.007>
- Repositório USP: <https://repositorio.usp.br/item/002750600>
