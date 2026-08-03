# R1 — revisão adversarial (sistemas, segurança e método)

## Veredito: ACEITAR COM REVISÕES

A revisão eliminou as alegações mais amplas do texto anterior, mas os pontos
abaixo ainda impedem que a evidência seja descrita como medição de escopos, de
mediação desktop ou de latência fim a fim.

1. **[MAIOR] — §3.6.1, l. 143: a descrição de custódia e a citação são imprecisas.** `XChaCha20-Poly1305` e Argon2id são implementados, mas a DEK não fica "em chaveiro". A DEK fica envolvida no arquivo `keyring.svault`; no modo `Passphrase`, a KEK é derivada por Argon2id, e no modo alternativo `OsKeychain` é a **KEK** que fica no chaveiro do SO (`crates/sv-core/src/lib.rs:372-447,485-515`; `crates/sv-core/src/keyring.rs:206-282`; `crates/sv-crypto/src/lib.rs:92-103,149-193`). A referência atual a dois arquivos sem linhas também não permite verificar a frase. **Correção:** substituir por “conteúdo sob XChaCha20-Poly1305; DEKs versionadas são envolvidas em `keyring.svault` sob uma KEK, derivada por Argon2id no modo de senha ou mantida no chaveiro do SO no modo correspondente”, com as linhas acima.

2. **[MAIOR] — §3.7, l. 161; §3.9.1, l. 189--194: o microbenchmark não mede autenticação nem verificação real de escopo.** O harness de latência chama `serve_stdio` (`apps/thesis-eval/src/main.rs:437-440,477-500`). Esse transporte entra em `PairState::AlreadyPaired(None)` (`crates/sv-mcp/src/lib.rs:721-739`); `call_tool` só chama `enforce_scopes` quando existe um agente resolvido (`crates/sv-mcp/src/lib.rs:1033-1050`). Portanto “o fluxo de solicitações” não é universal e a célula “Medido: validação/escopo” é falsa para os CSVs. **Correção:** restringir l. 161 ao caminho WebSocket desktop autenticado; trocar “validação/escopo” por “validação (sem agente/escopo no stdio)” na tabela; medir o custo de escopo em um benchmark WS autenticado separado antes de o reportar.

3. **[MAIOR] — §3.9.2, l. 201; §4, l. 258--280: a bateria não identifica a causa do bloqueio e não exercita o controlador desktop.** Ela injeta `HitlPolicy`, uma réplica de teste que nega operações que exigiriam UI (`apps/thesis-eval/src/main.rs:135-145,664-669`), não a UI/controle desktop. Além disso, o harness contabiliza falha de transporte ou pareamento como “blocked” (`apps/thesis-eval/src/main.rs:789-804`) e o CSV não preserva resposta/erro/controle que causou cada negativa. Assim, 10/10 prova somente que as dez execuções não produziram sucesso; não atribui cada bloqueio a escopo, caminho ou consentimento. **Correção:** chamá-la de teste de integração via WebSocket com política HITL simulada; registrar por sonda a resposta JSON-RPC, classe/causa de erro e evento de auditoria esperado; separar falhas de transporte e adicionar uma execução contra o controlador desktop (ou não alegar mediação desktop nesta bateria).

4. **[MAIOR] — §3.9.1, l. 177--182: a segunda equação continua sem fronteira operacional.** `T_{e2e}` é chamado de “experiência fim a fim”, mas não especifica se é uma chamada de ferramenta ou uma tarefa agêntica; para uma tarefa real faltam serialização/filas do cliente, planejamento do modelo e potencialmente múltiplas voltas ferramenta--modelo. Os nomes `T_{cliente\leftrightarrow WAN}` e `T_{rede\ resposta}` também se sobrepõem semanticamente. A ressalva de não mensuração é correta, mas não torna a decomposição mensurável/reprodutível. **Correção:** renomear para latência fim a fim de *uma chamada MCP* e definir timestamps/exclusões, ou modelar uma tarefa com número de voltas e termos de cliente/orquestração explicitamente instrumentados. Não usar a equação para inferir experiência do usuário antes disso.

5. **[MAIOR] — §4, l. 229 e 255: referência cruzada manual errada.** Há uma tabela no Capítulo 3 (l. 184) e duas tabelas antes da tabela de latência no Capítulo 4 (l. 211 e 231). “Tabela 3.2” não pode designar a tabela de l. 231 sob a numeração automática do `abntex2` (e mudará ao inserir tabelas). Não há `\label`/`\ref` para nenhuma tabela; os únicos `\label`s são das equações. **Correção:** pôr `\label{tab:microbenchmark-latencia}` imediatamente após a legenda e usar `Tabela~\ref{tab:microbenchmark-latencia}` nos dois locais; aplicar o mesmo padrão às demais tabelas. Isto remove a referência errada e acompanha renumeração automática.

6. **[MENOR] — §3.6.3, l. 153: citação de operações criptográficas está incompleta/deslocada.** `crates/sv-mcp/src/lib.rs:1729-1740` cobre somente assinatura; cifra/decifra estão em 1715--1727. `crates/sv-core/src/transit.rs:368-392` mostra o armazenamento da semente de assinatura, não o não-retorno das chaves simétricas de trânsito (que está em `transit.rs:282-330`). A conclusão substantiva é compatível com o código, mas a evidência citada não sustenta toda a frase. **Correção:** substituir pelas faixas `transit.rs:245-330,368-392` e `sv-mcp/src/lib.rs:1715-1740`, e manter a qualificação de que texto decifrado/assinatura podem constituir oráculos.

7. **[MENOR] — Apêndice, l. 288--297: reprodutibilidade ainda é incompleta para microbenchmark.** Os três hashes, o commit e os valores da tabela de latência são consistentes com os CSVs versionados, mas o próprio texto deixa armazenamento e modo de energia como “to be recorded on final run”. Não há manifesto por execução que ligue automaticamente host, kernel/distribuição, afinidade/governador, perfil, comando e hashes. **Correção:** gerar e versionar um `run-metadata.json` junto aos CSVs e, até a coleta final, marcar os números como execução de desenvolvimento/provisória, não “figuras representativas”.

## O que está correto

A auditoria confirmou: 17 ferramentas-base e 3 de broker (20 quando habilitado);
os quatro modos desktop e a exclusão de headless da garantia; exatamente sete
categorias heurísticas de PII; cadeia HMAC-SHA256 com checkpoint e limitação de
rollback; e os valores/hashes dos três CSVs. O texto agora limita adequadamente
RAG, isolamento de SO, nuvem, decisão humana e taxa geral de prompt injection.
Não há `\\ref` indefinido no fonte (somente as duas equações têm rótulo) nem
pacote evidentemente ausente para os ambientes usados; porém não há uma
instalação LaTeX/`abntex2` disponível neste ambiente para confirmar compilação.
