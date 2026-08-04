# R11 — Revisão de Segurança / Ameaças (GLM-5.1)

**Revisor:** R11 — ângulo: segurança/ameaças.
**Pergunta central:** *que caminho quebra um invariante que o paper afirma?*
**Veredito de uma linha:** Nenhum caminho quebra invariante afirmada — as afirmações de segurança são sustentadas pelo código e as qualificações são deliberadas e consistentes entre svnotas, Cap. 5 e código; os achados abaixo são de clareza/especificidade, não de correção, e nenhum é bloqueante.

---

## Síntese das seis frentes

| Frente | Veredito |
|---|---|
| 1. svnota headless (`nota:headless`) vs. `apps/cli/src/serve.rs` | **Fiel**, com sub‑enuciação das capacidades permitidas (R2). |
| 2. Auditoria: evidência de adulteração/remoção/truncamento vs. checkpoint; não‑resistência a rollback sem âncora externa | **Bate** com `crates/sv-audit` (M3). |
| 3. Semente/chaves simétricas não retornadas + limitação de oráculo/transparência de consentimento | **Correto** e qualificado (M4). |
| 4. Bateria adversarial (12 sondas, `HitlPolicy` simulada, WS autenticado, erro de transporte = bloqueio) | **Precisa**, sem veredito enganoso (M2). |
| 5. Modelo de ameaça consistente entre svnota, Cap. 5 e código | **Consistente**; fronteira stdio/WS sub‑enunciada (R1). |
| 6. Alegação de segurança sem suporte no código ou qualificação faltante | Nenhuma encontrada; o caminho stdio é a fronteira mais próxima, mas está qualificada e coberta pelo modelo de ameaça (R1). |

---

## Achados por severidade

### BLOQUEANTE
*Nenhum.*

### RELEVANTE

**R1 — Fronteira "escopos só no WebSocket" não é enunciada como controle de segurança, apenas como escopo de medição.**
O caminho `serve_stdio` opera com `PairState::AlreadyPaired(None)` (`crates/sv-mcp/src/lib.rs:1003`); `enforce_scopes` só é invocado quando `agent = Some(...)` (`lib.rs:1303`). Logo, **qualquer chamada stdio — não apenas a do microbenchmark — dispensa pairing, resolução de agente e escopos**, e a sequência da Figura 2 (autenticação → validação → escopo) não se aplica nesse transporte. O paper qualifica isto corretamente, mas ancora a qualificação no *contexto de medição* (Tabela 2, eq 1: "o transporte usa `PairState::AlreadyPaired(None)`, portanto não há resolução de agente nem aplicação de escopo nesse caminho"), e não como uma asserção de segurança.
Isso **não quebra invariante** porque o modelo de ameaça coloca "processos sob a mesma conta do usuário" fora do limite e a bateria/resultado 10/10 referem‑se explicitamente ao "gateway desktop WebSocket" (svnota do modelo de ameaça; QP3). Mas a separação lógica "escopos valem exclusivamente no WS autenticado; spawn do binário em stdio equivale a acesso local direto (fora de escopo)" não é dita *in terminis*, deixando ao leitor a inferência.
*Recomendação:* adicionar uma frase (na svnota do modelo de ameaça ou no rodapé da Figura 2) afirmando que `enforce_scopes`, pairing e consentimento aplicam‑se **somente** ao transporte WebSocket autenticado, e que iniciar o binário em modo stdio equivale a acesso local direto — já fora do limite avaliado. Não remover a qualificação existente.

**R2 — A svnota headless é fiel, mas enumera capacidades por sub‑enuciação.**
A svnota (`nota:headless`) afirma: "preserva os escopos persistidos do agente ao autenticá‑lo e recusa, em modo *headless*, operações *modeless* que portam ou usam segredos (cifra de trânsito, decifragem, assinatura e corretagem), de forma *fail‑closed* [...] o *headless* mantém leituras e escritas DIRECT ordinárias". Verificação em `apps/cli/src/serve.rs`:
- `HeadlessAuthenticator::authenticate` retorna `ResolvedAgent { scopes: resolve_scopes(&record.scopes)? }` — **preserva escopos persistidos** ✓;
- `HeadlessAuthenticator::new` rejeita `record.scopes.is_empty()` — **recusa agente sem escopo** ✓;
- `is_headless_allowed_action` exclui `Encrypt, Decrypt, Sign, CreateTransitKey, CreateSigningKey, CreateBrokerSecret, ListBrokerSecrets, Broker, ExportAgents, ImportAgents` — **recusa operações modeless que portam/usam segredos**, *fail‑closed* ✓;
- `headless_allows_container_mode` permite só `Direct`, nega `Approval/Otp/Anonymized/Zkp/Native` e `None` — **fail‑closed** ✓.

A asserção de **segurança** está correta. O desvio é de enumeração: o controlador também permite `CreateContainer`/`DestroyContainer` (modo `Direct`), `DeleteFile`, `ListContainers`, `ListFiles`, `VaultInfo`, `Verify`, `ListTransitKeys`, `ListSigningKeys` (estes dois últimos retornam apenas *metadata*, sem bytes de chave). "leituras e escritas DIRECT ordinárias" é verdade, mas não‑exaustivo; um leitor apressado pode ler como "somente read/write".
*Recomendação:* opcionalmente, trocar "leituras e escritas DIRECT" por "operações de contêiner DIRECT e de metadados (listagem, `vault.info`, `verify`, listagem de chaves como *metadata*)", mantendo o foco na invariante de segurança (segredos *modeless* bloqueados). Não alterar a afirmação de segurança.

### MENOR

**M1 — Comparação de `agent_id` não constante‑tempo no autenticador headless.**
`HeadlessAuthenticator::authenticate` compara `agent_id` com `agent_id != Some(self.agent_id.as_str())` (variável) enquanto o `token` usa `subtle::ConstantTimeEq` (`ct_eq`). Como `agent_id` (`ag_<hex>`) não é secreto, o vazamento de *timing* é desprezível; a assimetria, porém, pode confundir um leitor de segurança. Sem impacto no veredito.

**M2 — Bateria adversarial caracterizada com precisão; nenhum veredito enganoso.**
Confirmado em `apps/thesis-eval/src/main.rs`: 12 sondas pré‑especificadas (A1–A10 ataques, C1–C2 controles); a bateria usa o transporte WebSocket com `.with_access_controller(Arc::new(HitlPolicy))` (`main.rs:809`), ou seja, **`HitlPolicy` simulada e não o controlador desktop real `ApprovalState`**; `run_probe` trata erro de transporte/pareamento como bloqueio (`blocked = match run_probe(...) { Ok(r) => …, Err(_) => true }`, `main.rs:932‑936`). O microbenchmark, por sua vez, usa `AutoAllow` (`main.rs:480‑490`) sobre stdio. O texto qualifica explicitamente "valida somente transporte WebSocket, escopo, validação de caminho e aplicação de política HITL simulada", coerente com o código. **O 10/10 + 2/2 não é enganoso** porque o veredito esperado é declarado antes da execução e o qualificador limita a validade externa às negativas enumeradas.

**M3 — Auditoria: a alegação de evidência de adulteração e a não‑resistência a rollback batem com `sv-audit`.**
O comentário de cabeçalho de `crates/sv-audit/src/lib.rs:1‑16` afirma textualmente que o checkpoint "detects selective modification or deletion relative to that checkpoint, but it cannot detect rollback of a [...] snapshot rollback requires anchoring the checkpoint head in external trusted [...]". Há testes diretos: `suffix_truncation_is_detected_by_checkpoint` (`lib.rs:1684`), `checkpoint_edit_is_authenticated` (`lib.rs:1796`), `checkpoint_deletion_and_malformed_checkpoint_fail_closed` (`lib.rs:1715`). A afirmação do paper — "evidência de adulteração, remoção e truncamento em relação ao *checkpoint* presente. Não é prova de armazenamento *append‑only* resistente a *rollback*" — corresponde fielmente. ✓

**M4 — Semente/chaves simétricas não retornadas; limitação de oráculo e transparência de consentimento qualificadas.**
Em `execute_tool` (`sv-mcp`): `vault.encrypt`→somente `ciphertext_b64`; `vault.decrypt`→`plaintext_b64` (sem chave); `vault.sign`→`signature_b64` + `public_key_b64` (sem semente); `vault.list_transit_keys`→nome+versão; `vault.list_signing_keys`→nome+versão+`public_key_b64`; `vault.create_broker_secret`/`broker_request`→o `BrokerOutcome` exclui secret e cabeçalho injetado por contrato do trait. A `authorization_context` (digest SHA‑256 *domain‑separated*, excluindo só `otp`) é computada mas o paper **não alega** autorização vinculada — pelo contrário, qualifica: "não fornece autorização vinculada à chave/uso nem [...] descrição verificável do conteúdo a assinar ou decifrar [...] não elimina risco de uso como oráculo". Tudo correto e qualificado. ✓

---

## Resposta direta à pergunta central

**Não há caminho que quebre invariante afirmada.** As invariantes de segurança do paper são, todas, cercadas por qualificações que correspondem ao código:

- "não retorna bytes de chave/semente" → sustentado (`execute_tool`, `BrokerOutcome`);
- "auditoria dá evidência de adulteração/remoção/truncamento vs. checkpoint, mas não resiste a rollback sem âncora externa" → sustentado (`sv-audit` cabeçalho + testes);
- "escopos e consentimento reduzem acessos laterais *no gateway desktop WebSocket*, modelo de usuário/máquina único" → sustentado (bateria em WS com `HitlPolicy`); o caminho stdio sem escopo é a fronteira mais próxima, mas está dentro do modelo de ameaça (mesmo usuário = fora de escopo) e é qualificado no contexto de medição.

O único ponto de tensão residual (R1) é de **clareza de fronteira**, não de quebra: a qualificação do stdio sem escopo aparece como nota de medição, e não como asserção explícita de que *escopos/pairing/consentimento valem exclusivamente no WS*. Recomenda‑se uma frase de esclarecimento, sem remover nenhuma qualificação existente.
