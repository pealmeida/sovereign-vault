# Pontos de apoio — onde ancorar a tese na produção da orientadora

**Complementa:** o perfil de trabalho local mantido fora do repositório público.
**Objetivo:** transformar o levantamento em ações concretas sobre o `paper.tex`.

> **Regra de integridade.** Nenhuma citação abaixo deve entrar no texto sem
> conferência bibliográfica contra o Lattes ou o DOI. Citar trabalho da
> orientadora **por conveniência** é pior que não citar: a banca conhece a
> produção dela e detecta citação decorativa. Cada entrada abaixo tem um
> argumento de por que é pertinente ao ponto onde é usada.

---

## 1. Inserções recomendadas, por prioridade

### P1 — Justificativa do método de medição (§3.9)

**Onde:** plano de avaliação, no parágrafo que justifica o desenho do
*microbenchmark*.

**Citar:** Pigatto, Silva, Martins e Castelo Branco (JNCA, 2016).

**Argumento:** o trabalho avalia primitivas criptográficas (AES, Blowfish, 3DES,
ECC, RSA) por tempo de resposta e uso de recurso, em sistema embarcado e em
computador de propósito geral. É o precedente metodológico direto para medir
custo de operação criptográfica por *microbenchmark* controlado.

**Ganho:** o método deixa de parecer escolha *ad hoc* e passa a filiar-se a uma
tradição estabelecida — na produção de quem avalia o trabalho.

**Risco se omitido:** a banca pode perguntar "por que essa forma de medir?" sem
que o texto ofereça filiação.

---

### P2 — Legitimidade do artefato como contribuição (§2 e §5.4)

**Onde:** trabalhos correlatos e discussão da contribuição (March e Smith:
Modelo, Método, Instanciação).

**Citar:** versão de periódico de HAMSTER (Pigatto et al., 2016).

**Argumento:** arquitetura de comunicação nomeada, com camadas de segurança
explícitas, proposta **e** avaliada — mesma forma desta monografia. Sustenta que
"propor uma arquitetura e avaliá-la empiricamente" é contribuição reconhecida no
grupo, não apenas engenharia.

---

### P3 — Bateria adversarial como instrumento legítimo (§3.9.2)

**Onde:** justificativa da bateria pré-especificada.

**Citar:** Da Silva, Ferrão, Dezan, Espes e Castelo Branco (ICUAS, 2023) —
IDS baseado em anomalia para enxame de VANTs.

**Argumento:** precedente recente de avaliação com postura adversarial explícita
em sistema distribuído crítico. Reforça que testar contra sondas pré-declaradas
é prática do campo.

**Cuidado:** não sugerir que este trabalho faz detecção de intrusão. O apoio é
sobre **postura de avaliação**, não sobre técnica.

---

### P4 — Fronteira entre *safety*, *security* e conformidade (§3.7 e §5.5)

**Onde:** modelo de ameaça e limitações.

**Citar:** Ferrão, Espes, Dezan e Castelo Branco (*Sensors*, 2022) — revisão
sistemática sobre *security* e *safety* em táxis aéreos.

**Argumento:** sustenta a distinção operacional entre garantir propriedade
técnica e satisfazer requisito normativo — exatamente a distinção que o texto já
faz entre mascaramento de PII e anonimização sob o Art. 5º da LGPD.

---

### P5 — Enquadramento na agenda de governança de dados (§1.1 ou §1.3)

**Onde:** contextualização ou justificativa.

**Não é citação — é enquadramento.** O projeto **IntegraSanca** e a linha de
**governança de dados em cidades inteligentes** tratam de custódia,
interoperabilidade e governança de dados sensíveis em escala municipal. Esta
monografia trata do mesmo problema em escala individual.

**Frase de ancoragem sugerida** (adaptar, não colar):

> A soberania de dados no nível do indivíduo é o análogo, em outra escala, do
> problema de governança de dados sob custódia institucional: em ambos os casos,
> a questão é mediar acesso a dado sensível preservando utilidade e
> rastreabilidade.

**Ganho:** conecta o trabalho à agenda ativa da orientadora sem distorcer o
escopo nem inventar contribuição.

---

## 2. O que NÃO fazer

| Anti-padrão | Por quê |
|---|---|
| Citar VANT/UAV como se o trabalho fosse do domínio | O trabalho não é sobre veículos aéreos. Citação decorativa é detectável e prejudica |
| Citar a tese de doutorado dela (2004) sem uso real | Referência de cortesia. Conhecer sim; citar só se o texto usar o conceito |
| Inserir todas as citações acima | Cinco inserções bem argumentadas > quinze decorativas. P1 e P5 são as de maior retorno |
| Alegar continuidade de linha de pesquisa | O trabalho é adjacente, não continuação. Enquadrar como adjacência honesta |

---

## 3. Preparação para a arguição

Perguntas prováveis, dada a especialidade dela:

1. **"Quantas sessões? Qual o intervalo de confiança? Como controlou o
   ambiente?"** — resposta pronta em `EXECUCAO-DEFINITIVA.md`. **Só é
   defensável depois da execução definitiva com k≥5.** Esta é a pergunta mais
   provável da banca inteira.
2. **"Por que p95 e não só média?"** — cauda importa em latência percebida;
   precedente na literatura de avaliação de desempenho do próprio grupo.
3. **"O que exatamente o *microbenchmark* não mede?"** — Tabela de metodologia
   já delimita: não mede rede de longa distância, inferência em nuvem, decisão
   humana nem utilidade de tarefa.
4. **"Isso é comparável a quê?"** — não há linha de base comparativa; o
   protocolo de dois braços está declarado como trabalho futuro. **Assumir a
   limitação, não improvisar.**
5. **"Mascarar PII resolve LGPD?"** — não, e o texto afirma isso em sete pontos.
   Resposta direta: mascaramento é controle técnico; anonimização é qualificação
   jurídica que depende de risco de reidentificação no contexto.
6. **"Por que Rust?"** — segurança de memória reduz classes de vulnerabilidade
   em código que manipula segredo; há citação do NSA no texto.

---

## 4. Ação imediata sobre o `paper.tex`

- [x] Conferir as referências inseridas contra DOI/editor/PDF
- [x] P1: inserir a citação JNCA 2016 na justificativa do §3.9
- [x] P5: inserir o enquadramento de governança de dados na introdução
- [x] P2 e P4: inserir somente onde o argumento existente é reforçado
- [x] P3: avaliar e rejeitar a inserção — o artigo ICUAS avalia classificadores
      IDS contra ataques e conjuntos de dados, não uma bateria pré-especificada
      de chamadas MCP; a analogia metodológica seria excessiva
- [x] Acrescentar os `\bibitem` correspondentes, seguindo o padrão ABNT do
      arquivo
- [x] Recompilar e confirmar zero citações indefinidas
