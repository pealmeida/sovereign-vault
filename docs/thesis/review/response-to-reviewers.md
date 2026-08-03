# Resposta consolidada aos pareceristas — segunda revisão

## Síntese editorial

Os pareceres registraram um veredito de **1 major-revision (R3)** e **4
accept-with-revisions (R1, R2, R4 e R5)**. Os temas validados por mais de um
parecer foram: fronteira entre política HITL simulada e controlador desktop real;
escopo não medido no microbenchmark stdio; definição do estimando de latência;
caráter preliminar de uma única sessão; e limites de PII/LGPD. Não foram
criados resultados, medições ou referências novos.

## R1 — sistemas, segurança e método

1. **[ACEITO]** A custódia foi corrigida em §3.6.1: KEK por frase-secreta/Argon2id ou chaveiro do SO, DEK versionada envolvida em `keyring.svault` e uma única DEK ativa.
2. **[ACEITO]** §3.9.1 e a Tabela de metodologia agora identificam o stdio como validação de parâmetros/caminho, sem resolução de agente nem escopo; `enforce_scopes` não é cronometrado ali.
3. **[ACEITO]** §§3.9.2 e 4.3 delimitam 10/10 a WS + escopo + caminho + `HitlPolicy` simulada, sem atribuição ao controlador desktop; o registro causal por sonda e a execução com `ApprovalState` foram incluídos como futuro em `EVAL-PROTOCOL.md`.
4. **[ACEITO]** §3.9.1 redefine a Eq.~\eqref{eq:e2e} como uma única chamada MCP instrumentada, com timestamps, exclusões e ida/volta disjuntas; declara que ainda não foi medida.
5. **[ACEITO]** Todas as tabelas e equações de `paper.tex` receberam `\label{}`; referências manuais foram substituídas por `\ref{}`/`\eqref{}`.
6. **[ACEITO]** §3.6.3 corrige as faixas de evidência de trânsito/assinatura para `transit.rs:245-330,368-392` e `sv-mcp/src/lib.rs:1715-1740`.
7. **[PARCIAL — futuro]** §§4.1--4.3 e o Apêndice reclassificam os CSVs como execução preliminar e deixam armazenamento/energia a finalizar; a geração e versionamento automático de `run-metadata.json` permanece trabalho futuro.

## R2 — metodologia DSR e estatística

1. **[ACEITO]** §3.9.1 remove a medição implícita de escopo no stdio e declara que esse custo não foi medido.
2. **[ACEITO]** §§3.9.2, 4.1 e 4.3 retiram a alegação de mediação desktop da bateria simulada; o protocolo futuro exige separar falha de transporte de bloqueio de política.
3. **[ACEITO]** A Eq.~\eqref{eq:e2e} em §3.9.1 foi operacionalizada para uma chamada MCP, não para tarefa agêntica multi-volta.
4. **[ACEITO]** §§3.3 e 3.9 posicionam explicitamente a avaliação como artificial+somativa e o estudo futuro como naturalística+somativa, com teto de generalização.
5. **[ACEITO]** Capítulo 4 e Apêndice registram uma sessão sem IC como preliminar; `EVAL-PROTOCOL.md` fixa futuro mínimo de $k\geq3$, IC bootstrap de 95% e regra de `warmup`/descarte.
6. **[ACEITO]** §3.4 reconhece o traço retrospectivo de Peffers e aponta ADRs da correção NATIVE e das sondas A9/A10 como ciclo construir--avaliar.
7. **[PARCIAL — futuro]** O ciclo de rigor permanece fundamentado nas fontes já usadas; a ampliação bibliográfica específica para metodologia de avaliação de segurança e medição de PII não foi introduzida nesta revisão editorial.

Observações menores: a limitação do modelo de March--Smith permanece declarada em §3.5; a ressalva de AutoAllow/espera humana foi reforçada em §3.9.1 e §4.2; e referências de tabelas foram corrigidas.

## R3 — segurança de agentes e modelo de ameaça

1. **[ACEITO]** §§3.9.2 e 4.3 limitam a bateria à política `HitlPolicy` simulada e excluem o controlador desktop real de suas alegações; a execução com `ApprovalState` é **ACEITO-PARA-TRABALHO-FUTURO** em `EVAL-PROTOCOL.md`.
2. **[ACEITO]** A caixa “Modelo de ameaça e limites” (§3.7) inclui roubo de token como fora de escopo, recomenda 0600/chaveiro futuro e exclui atacante adaptativo da bateria única.
3. **[ACEITO — CORRIGIDO]** A revisão de código revelou o P0 de apagamento de escopos e o oráculo modeless de assinatura/decifragem/corretagem. A correção preserva os escopos persistidos e bloqueia essas operações em modo headless, direcionando-as ao desktop; o commit a ser criado é `fix(headless): preserve agent scopes and deny modeless crypto/broker operations`. O aviso de §3.6.3 registra o achado e a correção, sem cunhar CVE literal.
4. **[PARCIAL — futuro]** §3.7 exclui explicitamente DIRECT da garantia de mediação humana; sondas de exfiltração DIRECT e uma execução com `ApprovalState` são **ACEITO-PARA-TRABALHO-FUTURO** em `EVAL-PROTOCOL.md`, sem resultados fabricados.
5. **[ACEITO]** Resumo, §3.6.3 e Tabela~\ref{tab:fronteira-evidencia} informam a limitação LGPD, o exemplo “João Silva, Rua X, CEP 12345-678” e a lista de campos não detectados.

Observações menores: o risco de oráculo foi elevado ao aviso de segurança; $k\geq3$ sessões e IC bootstrap são **ACEITO-PARA-TRABALHO-FUTURO** em `EVAL-PROTOCOL.md`, enquanto a limitação de sessão única está em §§4.1--4.3; e §3.6.4 já esclarece que rollback integral do diretório de auditoria não é detectável sem âncora externa.

## R4 — sistemas Rust e criptografia aplicada

1. **[ACEITO — CORRIGIDO]** A alegação de que o headless mantém escopos foi inicialmente refutada: `apps/cli/src/serve.rs` retornava `scopes: Vec::new()` e `crates/sv-mcp/src/lib.rs:1854-1857` trata escopo vazio como `Ok(())`, isto é, acesso total. O achado foi corrigido no commit a ser criado `fix(headless): preserve agent scopes and deny modeless crypto/broker operations`: o autenticador agora converte os escopos persistidos para `ResolvedAgent`, sem sintetizar escopos para agentes genuinamente sem restrição.
2. **[ACEITO]** §§3.9.1 e 4.2 qualificam os ~14--35 µs de APPROVAL/OTP sob AutoAllow como piso mecânico; a espera humana de produção é externa e tipicamente em segundos.

Pontos menores:

1. **[ACEITO]** §2.5 descreve `ring` como dependência transitiva via `reqwest`/`rustls`, não dependência FFI direta.
2. **[ACEITO]** §3.6.3 declara que a zeroização ponta-a-ponta da semente Ed25519 também depende da disciplina do armazenamento em `sv-core`.
3. **[PARCIAL — futuro]** A limitação de conteúdo binário ANONYMIZED não recebeu nova alegação experimental nesta rodada; a futura avaliação de PII permanece limitada a dados sintéticos e detectores explicitamente enumerados.
4. **[PARCIAL — futuro]** O limite de recuperação de commit interrompido não foi elevado a resultado experimental nesta revisão; a fronteira de rollback sem âncora externa permanece em §3.6.4.

## R5 — privacidade e LGPD

1. **[ACEITO]** Resumo e §3.6.3 agora afirmam que nome+endereço podem manter identificabilidade sob o Art.~5º da LGPD, mesmo com CPF/CNPJ mascarados, e excluem documentos com risco realista de vinculação.
2. **[ACEITO]** A Tabela~\ref{tab:fronteira-evidencia} lista explicitamente RG, CEP, nomes, endereços, datas de nascimento e telefones sem formatação como NÃO detectados.
3. **[PARCIAL — futuro]** O registro por sonda de resposta/erro e evento de auditoria esperado/observado foi incluído em `EVAL-PROTOCOL.md`; a instrumentação específica da negação de conteúdo não UTF-8 permanece para a execução futura.
4. **[ACEITO]** §4.4 mantém a expansão e medição de PII brasileiro, incluindo RG, CEP, nomes e endereços, como trabalho futuro.
