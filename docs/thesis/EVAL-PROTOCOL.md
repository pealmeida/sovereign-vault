# Protocolo pré-registrado de avaliação em dois braços

## Estado

Este é um protocolo prospectivo. Hoje existe somente parte do Braço A: o
microbenchmark local de `vault.read` e a bateria finita de sondas de gateway em
`apps/thesis-eval`. Não existe adaptador de nuvem, telemetria fim a fim,
baseline cloud-direct, estudo humano ou resultado comparativo a reportar.

## Objetivo e hipótese operacional

Comparar, com o mesmo corpus sintético, conjunto de tarefas e modelo fixado, o
efeito da mediação pelo gateway local sobre latência fim a fim, utilidade,
exposição não autorizada, mascaramento de PII, custo e falhas. O protocolo não
pressupõe superioridade de nenhum braço; estima diferenças acompanhadas de
incerteza.

## Materiais e controles comuns

- Corpus: exclusivamente sintético e aprovado antes da coleta; sem segredos,
  dados pessoais, contas, chaves ou registros de usuários reais.
- Tarefas e prompts: conjunto pareado, versionado e pré-registrado. Cada tarefa
  tem critérios objetivos de sucesso e uma lista de campos que não podem ser
  revelados.
- Modelo: mesmo provedor, família, identificador/versão e parâmetros nos dois
  braços. Registrar região, data/hora, temperatura, `seed` quando disponível,
  limite de tokens, ferramentas e configuração de retenção.
- Rede: registrar local, conexão, RTT, perdas e janelas de execução; alternar a
  ordem dos braços dentro de cada par para reduzir efeito de tempo.

## Braços

| Braço | Condição |
|---|---|
| A — gateway local | O modelo acessa o corpus apenas por MCP através do Sovereign Vault, com contêineres, escopos e modos predefinidos. Registrar modo, decisão de aprovação/OTP, auditoria e saídas mascaradas. |
| B — cloud-direct | O mesmo modelo/versão recebe o mesmo material sintético por caminho de armazenamento/contexto em nuvem, sem o gateway. A política de baseline deve ser documentada e realmente disponibilizar o material que o Braço A pode reter ou mascarar. |

## Desfechos pré-especificados

1. Latência fim a fim por tarefa, com fronteiras de cronômetro explicitadas.
2. Sucesso/qualidade da tarefa por rubricagem pré-definida, preferencialmente
   com avaliador cego ao braço.
3. Divulgação não autorizada: presença de cada campo protegido na saída, nos
   tool calls e nos logs de telemetria permitidos.
4. Precisão e revocação de PII para as categorias com rótulo no corpus.
5. Custo de API, tokens, falhas de rede e erros de ferramenta.
6. Para APPROVAL/OTP: tempo de decisão humana (mediana, p95, timeout, negação
   e abandono), separado da latência interna do gateway.

## Extensões pós-peer-review da avaliação de segurança

- Incluir sondas de exfiltração no modo DIRECT, deixando explícito que leituras
  permitidas nesse modo retornam dados sem consentimento por projeto.
- Executar uma bateria separada contra o controlador desktop real
  `ApprovalState`, além da bateria WS que usa a política simulada `HitlPolicy`.
- Executar pelo menos $k\geq3$ sessões independentes; reportar IC de 95% por
  bootstrap e pré-definir a regra de `warmup` e descarte.
- Para cada sonda, registrar resposta JSON-RPC, classe de resposta/erro, evento
  de auditoria esperado e observado, e veredito. Falhas de transporte ou
  pareamento devem ser separadas de bloqueios de política, caminho ou escopo.

## Coleta, governança e ética

Executar somente com dados sintéticos. Desabilitar ou documentar retenção,
treinamento e registro do provedor conforme a configuração disponível no dia.
Guardar prompts, respostas e telemetria em repositório controlado; remover
identificadores operacionais desnecessários. Qualquer mudança de modelo,
versão, região, corpus, prompt, política de retenção ou modo de consentimento
cria uma nova execução versionada, e não deve ser combinada silenciosamente com
a anterior. Pesquisa com participantes para consentimento humano requer a
aprovação institucional aplicável antes de coleta.

## Plano estatístico

Cada par tarefa--semente/caso é executado nos dois braços; a unidade principal é
a diferença pareada A--B. Relatar número de pares válidos, exclusões e motivo.
Para latência e custo, apresentar mediana, p95, diferença pareada e IC de 95%
por bootstrap pareado. Para desfechos binários, relatar numerador/denominador e
IC de 95% apropriado; para precisão/recall, relatar matriz de confusão por
categoria e IC por reamostragem. Não interpretar ausência de significância como
equivalência. Falhas e timeouts permanecem como desfechos, sem descarte ad hoc.
O tamanho amostral e o número de repetições serão definidos antes da execução
com base em efeito mínimo de interesse e orçamento de API; para a bateria de
segurança, o mínimo pós-revisão é $k\geq3$ sessões independentes.

## Reprodutibilidade e reporte

Para cada rodada, registrar commit, comando, perfil, SO/kernel, CPU, RAM,
armazenamento, `rustc`, fornecedor/modelo/versão/região, parâmetros, condições
de rede, data/hora, checksums do corpus e dos CSVs. Publicar agregados e
artefatos sintéticos que não contrariem contratos de provedor. Os resultados
atuais de `target/thesis-eval` devem continuar rotulados como microbenchmark
sintético local do Braço A, não como comparação de nuvem.
