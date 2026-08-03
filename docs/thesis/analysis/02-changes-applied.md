# Mudanças aplicadas na versão revisada

`paper.tex` é a versão revisada. Esta tabela faz a ponte entre as recomendações
aceitas e o local exato de sua aplicação; referências a caminho de código na
redação são evidência de implementação, não novas alegações experimentais.

| Recomendação | Aplicação em `paper.tex` | Resumo da edição |
|---|---|---|
| P0.1 | §§1.3, 2.5, 3.7, 3.8 | RQ3 passou a tratar de autenticação, escopos, consentimento e auditoria; declara ausência de isolamento de SO. |
| P0.2 | §§2.5, 3.6.4, 3.8 | Segurança Rust limitada ao código próprio sem `unsafe`; removida comparação Tauri--Electron e alegação de sandbox independente. |
| P0.3 | §§3.6.3, 3.7 | ``Nunca exposta'' tornou-se não retorno de bytes de chave; documenta oráculo, consentimento opaco e exclusão do headless. |
| P0.4 | §3.6.3 e §4.1 | Troca mascaramento genérico pelas sete categorias e declara RG/CEP/nomes/endereços/telefones sem formatação fora da cobertura. |
| P0.5 | §3.6.4 | Auditoria descrita como cadeia HMAC-SHA256 e checkpoint local; sem promessa de append-only/anti-rollback. |
| P0.6 | §§1.4, 3.7 | Caixa de modelo de ameaça de usuário/máquina únicos, gateway desbloqueado, adversário MCP e exclusões explícitas. |
| P1.1 | §3.9.1 | Equação única substituída por `T_gateway` condicional e `T_e2e` independente; espera humana é distribuição. |
| P1.2 | §§3.9.1, 4.2 e Apêndice A | Tabela de metodologia, N=1.000, AutoAllow, dados sintéticos e proveniência/checksums. |
| P1.3 | §§3.9.2, 4.3 | Resultado adversarial delimitado a 10 sondas e 2 controles em uma execução; sem taxa de prompt injection. |
| P1.4 | §§1.4.2, 3.9.3; `EVAL-PROTOCOL.md` | Objetivo 4 adota a opção A honesta; protocolo Arm A/Arm B é futuro, não evidência concluída. |
| P1.5 | §§1.3, 1.4, 2.1, 2.3, 3.5, 3.10 | RQ1 e escopo limitados a segredos/credenciais nomeados; RAG/índice/embeddings são ADR-0012 futuro. |
| P2.1 | §4.1 | Tabela de fronteira separa alegações sustentadas e qualificações obrigatórias. |
| P2.2 | §§4.2--4.3 | Reporta apenas CSV/MD reais: DIRECT, ANONYMIZED, AutoAllow e 10/10, 2/2, com limites. |
| P2.3 | §§3.6.2--3.6.3 | Inventário corrigido para 17+3; semântica DIRECT/APPROVAL/OTP/ANONYMIZED e ZKP/NATIVE reservados/rejeitados. |
| P2, futuro 1 | §4.4 | Preservar escopos headless e exigir aprovação fail-closed para operações sem modo. |
| P2, futuro 2 | §4.4 | Vincular consentimento criptográfico a chave, payload, semântica, destinatário e agente. |
| P2, futuro 3 | §4.4 | Avaliar hierarquia por contêiner ou segmentação lógica e controles de SO. |
| P2, futuro 4 | §4.4 | Medir e expandir detectores PII brasileiros. |
| P2, futuro 5 | §4.4 | Adicionar âncora externa à auditoria. |
| P2, futuro 6 | §4.4 e §3.9.3 | Executar dois braços em nuvem e estudo de consentimento humano. |
| Achado novo: perda de escopo headless | §§3.6.3, 3.7, 4.4 | Modo headless excluído de alegações de menor privilégio e recebe remediação futura explícita. |
| Achado novo: bypass headless em cripto/broker | §§3.6.3, 3.7, 4.4 | Não atribui mediação humana ao headless; prevê fail-closed antes de uso seguro. |
| Achado novo: consentimento cripto opaco | §§3.6.3, 3.7, 4.4 | Declara falta de `key_ref`/identidade verificável do payload e risco de oráculo. |

## Segunda revisão (pós-peer-review)

| Edição | Seções/artefato | Aplicação |
|---|---|---|
| A | §§3.9.2, 4.1 e 4.3 | A bateria 10/10 passou a ser descrita como transporte WS, escopo, caminho e `HitlPolicy` simulada; não mede o controlador desktop real. |
| B | §3.9.1 | O caminho stdio foi delimitado como validação de parâmetros/caminho, sem resolução de agente ou escopo; o custo de `enforce_scopes` ficou explicitamente não medido no microbenchmark. |
| C | §§3.9.1, 4.1--4.3 | Tabelas e equações receberam rótulos; referências manuais de tabela foram substituídas por `\ref{}`. |
| D | §3.6.3 e §4.4 | Inserido aviso destacado sobre escopos vazios e oráculo de assinatura/decifragem no headless, com proibição de implantação até correção e remediação referenciada. |
| E | §3.7 | Caixa de ameaça expandida para roubo de token, atacante adaptativo e exfiltração deliberada por DIRECT. |
| F | Resumo, §3.6.3 e §4.1 | Limitação LGPD reforçada, com exemplo de nome/endereço/CEP e lista explícita de PII não detectado. |
| G | §3.9.1, Eq.~`eq:e2e` | `T_e2e` passou a estimar uma única chamada MCP instrumentada, com fronteiras, exclusões e transporte de ida/volta disjuntos; continua não medido. |
| H | §§3.3 e 3.9 | Posicionamento FEDS: evidência atual artificial+somativa; dois braços futuros naturalística+somativa; teto de generalização declarado. |
| I | §§4.1--4.3 e Apêndice | Resultados passaram a ser execução preliminar de desenvolvimento (uma sessão, sem IC); requisitos de $k\geq3$, bootstrap e `warmup`/descarte foram declarados; campos de host/energia ficaram a finalizar. |
| J | §§3.9.1 e 4.2 | Valores APPROVAL/OTP sob AutoAllow foram qualificados como piso mecânico; espera humana de produção é externa e tipicamente em segundos. |
| K | §§2.5 e 3.6.3 | `ring` foi descrita como transitiva via `reqwest`/`rustls`; zeroização da semente Ed25519 passou a depender também da disciplina do chamador em `sv-core`. |
| L | §3.6.1 | Custódia corrigida para KEK por frase-secreta/Argon2id ou chaveiro do SO, DEK versionada envolvida e uma única DEK ativa. |
| M | §3.4 | Traço de Peffers declarado parcialmente retrospectivo; ADRs da correção NATIVE e sondas A9/A10 apresentados como ciclo construir--avaliar. |
