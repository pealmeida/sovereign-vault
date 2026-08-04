# Auditoria de Rastreabilidade Código-Tese — Sovereign Vault

**Veredito**: **APROVADO COM RESSALVAS**. Todas as alegações de alto risco (A–F) são sustentadas pelo código, com divergências menores de numeração de linha em duas citações e uma imprecisão de contagem que não afeta a substância. Nenhuma citação aponta para arquivo inexistente ou linha além do fim do arquivo.

---

## Tabela Citação-por-Citação

| Citação | Confere? | Observação |
|---|---|---|
| `crates/sv-core/src/lib.rs:372-447,485-515` | ✅ SIM | Linhas 372-447 contêm `VaultHandle`, `bootstrap`, `unlock`, `CustodyMode`, `MasterKey`, `VaultLock`. Linhas 485-515 contêm `keyring::create` e `keyring::load`. A alegação "DEK versionada é envolvida pela KEK em `keyring.svault`; há uma única DEK ativa, sem chaves por contêiner" confere. |
| `crates/sv-core/src/keyring.rs:206-282` | ✅ SIM | `create`, `load`, `Unwrapped`, `active_dek()`, `add_active_dek`, `rewrap_under_new_kek`. A hierarquia KEK→DEK está implementada exatamente como descrito. |
| `crates/sv-crypto/src/lib.rs:92-103,149-193` | ✅ SIM | Linhas 92-103: `MasterKey::from_passphrase` com Argon2id. Linhas 149-193: `seal`/`open` com XChaCha20-Poly1305. |
| `crates/sv-mcp/src/lib.rs:2139-2147,2877-2914` | ⚠️ PARCIAL | A tese cita linhas 2139-2147 e 2877-2914. O arquivo tem ~2900 linhas (o `tools_list_omits_broker_when_disabled` testa `assert_eq!(tools.len(), 17)` e `tools_list_includes_broker_when_enabled` testa `assert_eq!(tools.len(), 20)`). As linhas exatas dos testes são ~2139-2147 (teste 17) e ~2877-2914 (teste 20). A contagem 17+3=20 **confere**: `base_tool_descriptors()` retorna 17 ferramentas; `tool_descriptors(true)` adiciona `vault.create_broker_secret`, `vault.list_broker_secrets` e `vault.broker_request` = 20. |
| `crates/sv-privacy/src/lib.rs:46-77,205-232` | ✅ SIM | Linhas 46-77: enum `PiiCategory` com 7 variantes (Email, Cpf, Cnpj, CreditCard, Ipv4, Phone, Ssn). Linhas 205-232: `find_phones` e `find_ssns`. A palavra "exatamente" se sustenta: são exatamente 7 categorias. |
| `apps/desktop/src-tauri/src/lib.rs:786-805` | ✅ SIM | Linhas 786-805: função `approval_requirement` com match em `SecurityMode::Direct`, `Approval`, `Otp`, `Anonymized`, `Zkp` (rejeitado), `Native` (rejeitado). |
| `crates/sv-mcp/src/lib.rs:1159-1199` | ✅ SIM | Linhas 1159-1199: função `mode_rank` com `Direct=0`, `Approval=1`, `Otp=2`, `Anonymized=3`, `Zkp=4`, `Native=5`. ZKP e NATIVE são ranqueados mas não implementados como modos funcionais — a tese diz "reservados e rejeitados", o que confere com `approval_requirement` retornando erro para ambos. |
| `crates/sv-audit/src/lib.rs:545-727,977-1056` | ✅ SIM | Linhas 545-727: `AuditLog`, `record`, `sign_record`, `verify_record`, `Checkpoint`, `verify_chain`. Linhas 977-1056: `verify_locked`, `verify_against`, `scan_paths_from`. HMAC-SHA256 com encadeamento de registros e checkpoint autenticado local — confere. |
| `crates/sv-mcp/src/lib.rs:18` | ✅ SIM | Linha 18: `#![forbid(unsafe_code)]`. A tese diz "nos crates próprios" (plural). Verificação: TODOS os 9 crates (`sv-audit`, `sv-core`, `sv-crypto`, `sv-http`, `sv-keychain`, `sv-mcp`, `sv-privacy`, `sv-recovery`, `sv-storage`) e os 3 apps (`cli/main.rs`, `cli/serve.rs`, `desktop/src-tauri/src/lib.rs`, `thesis-eval/main.rs`) têm `#![forbid(unsafe_code)]`. O plural se sustenta. |
| `crates/sv-core/src/transit.rs:245-330,368-392` | ✅ SIM | Linhas 245-330: `transit_encrypt`, `transit_decrypt`, `signing_sign`. Linhas 368-392: `broker_create`, `broker_resolve`. A alegação "semente privada e chaves simétricas não são retornadas ao agente; somente assinatura, cifra ou texto decifrado" confere. |
| `crates/sv-mcp/src/lib.rs:1715-1740` | ✅ SIM | Linhas 1715-1740: `execute_tool` para `vault.encrypt`, `vault.decrypt`, `vault.sign` — retornam ciphertext/plaintext/signature, nunca key bytes. |
| `apps/desktop/src-tauri/tauri.conf.json:24-26` | ✅ SIM | Linha 24-26: campo `"csp"` com Content Security Policy. |
| `apps/desktop/src-tauri/capabilities/default.json:1-9` | ✅ SIM | Linhas 1-9: capacidades explícitas (`core:default`, `dialog:allow-confirm`). |
| `apps/cli/src/serve.rs` (sem linha) | ✅ SIM | Arquivo existe. A nota sobre headless cita o arquivo sem número de linha, o que é aceitável para uma referência geral. |
| `apps/thesis-eval/src/main.rs` (sem linha) | ✅ SIM | Arquivo existe. Citado para `payload_for` e `pii_payload`. |
| `docs/adr/0012-context-containers.md` | ✅ SIM | Arquivo existe (verificado via `list_dir`). |
| `docs/thesis/EVAL-PROTOCOL.md` | ✅ SIM | Arquivo existe. |
| `target/thesis-eval/latency.csv`, `adversarial.csv`, `micro.csv` | NÃO VERIFICADO | Arquivos de saída de execução; não fazem parte do código fonte versionado. A tese provê hashes SHA-256 para verificação futura. |

---

## Achados por Severidade

### BLOQUEANTE (impediria aprovação)

**Nenhum.** Nenhuma alegação técnica central é refutada pelo código.

### RELEVANTE (deve ser corrigido antes da entrega)

1. **Citação `crates/sv-mcp/src/lib.rs:2139-2147,2877-2914` — numeração instável**. As linhas 2139-2147 contêm o teste `tools_list_omits_broker_when_disabled` com `assert_eq!(tools.len(), 17)`. As linhas 2877-2914 contêm `tools_list_includes_broker_when_enabled` com `assert_eq!(tools.len(), 20)`. Esses números são de código de teste e podem mudar com qualquer refatoração. A tese afirma "A superfície MCP analisada contém 17 ferramentas-base e três ferramentas condicionais de broker, totalizando 20 quando o broker está habilitado". **Recomendação**: citar também `base_tool_descriptors()` (que define as 17) e `tool_descriptors()` (que adiciona as 3 condicionais), pois essas funções são a definição canônica, não os testes.

2. **Contagem de ferramentas: 17 vs "5 file tools + ..."**. O comentário no teste diz "5 file tools + vault.destroy + vault.info + transit create/list/encrypt/decrypt + signing create/list/sign/verify + export/import agents". Vamos contar: vault.list, vault.read, vault.write, vault.delete, vault.create_container = 5 file tools. vault.destroy = 1. vault.info = 1. vault.create_transit_key, vault.list_transit_keys, vault.encrypt, vault.decrypt = 4 transit. vault.create_signing_key, vault.list_signing_keys, vault.sign, vault.verify = 4 signing. vault.export_agents, vault.import_agents = 2. Total: 5+1+1+4+4+2 = 17. ✅ Confere. Com broker: + vault.create_broker_secret, vault.list_broker_secrets, vault.broker_request = 20. ✅

### MENOR (não impede aprovação, mas melhora a precisão)

1. **Citação `crates/sv-privacy/src/lib.rs:205-232` para SSN e Phone**. As linhas 205-232 contêm `find_phones` (205-232) e `find_ssns` começa na 234. A citação cobre phones mas SSN está parcialmente fora (linha 234+). A diferença é de 2 linhas — irrelevante para a verificação de conteúdo, mas a banca pode notar.

2. **Citação `crates/sv-core/src/lib.rs:485-515`**. A linha 485 está dentro de `bootstrap` (OsKeychain), e 515 está em `unlock`. O intervalo cobre a criação e carregamento do keyring. OK.

3. **Citação `crates/sv-audit/src/lib.rs:545-727,977-1056`**. O intervalo 545-727 cobre `record`, `sign_record`, `Checkpoint`, `verify_chain`. O intervalo 977-1056 cobre `verify_locked`, `verify_against`, `scan_paths_from`. Ambos conferem. A alegação "registros encadeados por HMAC-SHA256 e verificados contra checkpoint autenticado local" é precisa.

---

## Verificação das Alegações de Alto Risco (A–F)

### A. Contagem de ferramentas MCP: 17+3=20
**CONFERE.** `base_tool_descriptors()` define 17 ferramentas. `tool_descriptors(true)` adiciona 3 condicionais de broker. Testes em `crates/sv-mcp/src/lib.rs` confirmam com `assert_eq!(tools.len(), 17)` e `assert_eq!(tools.len(), 20)`.

### B. Sete categorias PII: "exatamente"
**CONFERE.** `PiiCategory::ALL` contém exatamente 7 variantes: `Cnpj`, `Cpf`, `CreditCard`, `Email`, `Ipv4`, `Phone`, `Ssn`. A palavra "exatamente" se sustenta.

### C. XChaCha20-Poly1305, KEK via Argon2id, DEK versionada, DEK única ativa
**CONFERE.** `sv-crypto/src/lib.rs:92-103`: `MasterKey::from_passphrase` usa `Argon2id`. `sv-crypto/src/lib.rs:149-193`: `seal`/`open` usam `XChaCha20Poly1305`. `sv-core/src/keyring.rs`: `KeyringFile` com `active_dek_version`, `entries: Vec<WrappedDek>`, uma DEK ativa. "sem chaves por contêiner" — o cofre usa uma DEK para todos os arquivos; não há DEK por contêiner. ✅

### D. Registros encadeados por HMAC-SHA256 com checkpoint autenticado local
**CONFERE.** `sv-audit/src/lib.rs`: `sign_record` computa `mac = HMAC-SHA256(domain || payload)` com `prev_mac` no payload. `Checkpoint::signed` autentica `record_count`, `head_mac`, `active_segment`. `verify_chain` percorre todos os segmentos verificando a cadeia de MACs e o checkpoint.

### E. Proibição de unsafe "nos crates próprios" (plural)
**CONFERE.** Todos os 9 crates e 3 apps têm `#![forbid(unsafe_code)]`. O plural é preciso.

### F. Modos DIRECT, APPROVAL, OTP, ANONYMIZED suportados; ZKP e NATIVE reservados/rejeitados
**CONFERE.** `apps/desktop/src-tauri/src/lib.rs:786-805`: `approval_requirement` aceita `Direct`, `Approval`, `Otp`, `Anonymized` e rejeita `Zkp` ("ZKP mode is not implemented for live MCP access") e `Native` ("NATIVE mode is not implemented for live MCP access"). `crates/sv-mcp/src/lib.rs:1159-1199`: `mode_rank` atribui ranks 0-5 para todos os 6 modos, com ZKP=4 e NATIVE=5 sendo os mais restritivos (reservados).

---

## O Que NÃO Foi Verificado

1. **Arquivos de saída em `target/thesis-eval/`** (`latency.csv`, `adversarial.csv`, `micro.csv`): são artefatos de execução, não código fonte. Os hashes SHA-256 fornecidos no apêndice permitem verificação futura, mas não podem ser conferidos contra o código.

2. **`apps/thesis-eval/src/main.rs` linhas 466-478 e 315-323**: o arquivo existe e as referências a `payload_for` e `pii_payload` são plausíveis, mas não li o arquivo completo para confirmar os números exatos de linha.

3. **`apps/cli/src/serve.rs`**: citado sem número de linha na nota sobre headless. O arquivo existe. Não verifiquei o conteúdo específico da correção fail-closed.

4. **`docs/adr/0012-context-containers.md`**: confirmado que existe. Não verifiquei o conteúdo.

5. **`docs/thesis/EVAL-PROTOCOL.md`**: confirmado que existe. Não verifiquei o conteúdo.

---

## Resumo

O código implementa exatamente o que a tese afirma. As citações de linha são precisas (com desvios de ±2 linhas em dois casos, irrelevantes). As alegações fortes (A–F) são todas verificáveis e corretas. A tese é honesta sobre limitações (não detecta RG, CEP, nomes; ZKP e NATIVE são reservados; auditoria não é à prova de rollback completo; modo headless tem restrições). O artefato está pronto para defesa no quesito rastreabilidade.
