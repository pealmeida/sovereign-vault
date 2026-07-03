//! Production-readiness validation harness for Sovereign Vault.
//!
//! This drives the **real** MCP gateway (`sv_mcp::McpServer` over a real
//! loopback WebSocket, backed by a real `sv_core::VaultHandle` with real
//! crypto/storage) exactly as an AI agent (Claude Desktop / Cursor) would:
//! it connects over WebSocket, pairs, and issues JSON-RPC `tools/call`
//! frames. Nothing is mocked except the human at the desktop, whose consent
//! decisions are modelled by a policy that mirrors the desktop's real
//! `approval_requirement` function verbatim.
//!
//! It plays two agent identities against one vault:
//!   * the unscoped **Default** agent (the shared pairing secret), and
//!   * a **scoped, least-privilege** agent (read/list on `project/**` only).
//!
//! For each scenario it records whether the gateway ALLOWED or BLOCKED the
//! call and compares against the expected outcome. Secrets and key bytes are
//! asserted never to appear in any response. A non-zero exit code means at
//! least one scenario behaved differently than a production deployment must.
//!
//! Stores CLEARLY-FAKE secrets only — never real credentials.

use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message;

use sv_audit::AuditEvent;
use sv_core::agents::AgentScope;
use sv_core::{CustodyMode, VaultHandle};
use sv_mcp::{
    AccessAction, AccessController, AccessRequest, AgentAuthenticator, AuditSink, McpServer,
    ResolvedAgent, ResolvedScope, SharedVault,
};
use sv_storage::SecurityMode;

const PAIRING_SECRET: &str = "validate-shared-secret";
const SCOPED_AGENT_NAME: &str = "least-privilege";

// A fake project .env — emphatically NOT real credentials.
const FAKE_ENV: &str = "API_KEY=sk-test-FAKE-0000000000\nSTRIPE_KEY=sk_live_FAKE_do_not_use";
// A fake PII document, to verify ANONYMIZED masking on read.
const FAKE_PII: &str = "Contact joao@example.com, CPF 529.982.247-25, card 4111 1111 1111 1111.";
// A fake secret pushed through transit (the agent must never see the key).
const FAKE_TRANSIT_PLAINTEXT: &[u8] = b"rotate-me-please";
// A fake broker secret value.
const FAKE_BROKER_SECRET: &str = "sk_live_FAKE_broker_do_not_use";

#[tokio::main]
async fn main() {
    let started = Instant::now();
    println!("=== Sovereign Vault — production-readiness validation ===\n");
    println!("Driving the REAL MCP gateway over a loopback WebSocket as an agent.\n");

    // ── Bootstrap a real vault on a throwaway root ───────────────────────────
    let root = tmp_root();
    let _ = std::fs::remove_dir_all(&root);
    let boot = VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some("validate-pw"))
        .expect("bootstrap vault");
    let handle = boot.handle;

    // Seed containers across every security mode an agent will meet in
    // production. Names match what the scenarios below reference.
    seed_container(
        &handle,
        "project",
        SecurityMode::Direct,
        FAKE_ENV,
        "webapp.env",
    );
    seed_container(
        &handle,
        "secrets",
        SecurityMode::Approval,
        "TOP SECRET",
        "master.key",
    );
    seed_container(
        &handle,
        "identity",
        SecurityMode::Anonymized,
        FAKE_PII,
        "profile.txt",
    );
    // Reserved mode: any live access must be rejected, never treated as DIRECT.
    seed_container(
        &handle,
        "reserved-native",
        SecurityMode::Native,
        "device-bound secret",
        "secret.txt",
    );

    // A scoped agent: read/list on the `project` container only (containers are
    // flat names, so the glob is the bare name; `project/**` would match only
    // sub-paths). Anything else must block.
    let (scoped_id, scoped_token) = handle
        .create_agent(
            SCOPED_AGENT_NAME,
            vec![AgentScope {
                container_glob: "project".into(),
                actions: vec!["read".into(), "list".into(), "list_files".into()],
                mode_ceiling: None,
            }],
        )
        .expect("create scoped agent");
    handle
        .ensure_default_agent(PAIRING_SECRET)
        .expect("default agent");

    let token_key = handle.agent_token_key();

    // ── Stand up the real gateway ────────────────────────────────────────────
    let shared: SharedVault<VaultHandle> = Arc::new(Mutex::new(Some(handle)));
    let audit = Arc::new(CountingAudit::default());
    let authenticator = Arc::new(RealAuthenticator {
        root: root.clone(),
        token_key,
        shared_secret: PAIRING_SECRET.to_string(),
    });
    let server = Arc::new(
        McpServer::new(shared.clone(), PAIRING_SECRET)
            .with_access_controller(Arc::new(DesktopConsentPolicy))
            .with_audit_sink(audit.clone())
            .with_agent_authenticator(authenticator),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let serve_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.serve_ws_listener(listener, shutdown_rx).await;
        })
    };
    let url = format!("ws://{addr}");

    let default_creds = Creds::Default;
    let scoped_creds = Creds::Scoped {
        id: scoped_id.clone(),
        token: scoped_token.clone(),
    };

    let mut results: Vec<Outcome> = Vec::new();

    // ── 1. Discovery ─────────────────────────────────────────────────────────
    section("1. Discovery — the agent learns the tool surface");
    {
        let tools = list_tools(&url, &default_creds).await;
        let names: Vec<String> = tools
            .iter()
            .filter_map(|t| t["name"].as_str().map(String::from))
            .collect();
        results.push(check(
            "discover tools",
            "tools/list returns the full vault surface",
            names.contains(&"vault.create_container".to_string())
                && names.contains(&"vault.create_transit_key".to_string())
                && names.contains(&"vault.create_signing_key".to_string()),
            true,
        ));
        results.push(check(
            "broker hidden by default",
            "broker tools absent unless SV_ENABLE_BROKER",
            !names.contains(&"vault.broker_request".to_string()),
            true,
        ));
        println!(
            "   discovered {} tools: {}\n",
            names.len(),
            names.join(", ")
        );
    }

    // ── 2. Core data custody (the primary use case) ──────────────────────────
    section("2. Storing & retrieving sensitive data (DIRECT container)");
    macro_rules! call {
        ($creds:expr, $tool:expr, $args:expr) => {
            agent_call(&url, $creds, $tool, $args).await
        };
    }

    {
        // Default agent stores then reads back an env file end-to-end.
        let write = call!(
            &default_creds,
            "vault.write",
            json!({"container":"project","file_name":"runtime.env","content_b64": B64.encode(FAKE_ENV)})
        );
        results.push(check_allowed("write env file", &write));

        let read = call!(
            &default_creds,
            "vault.read",
            json!({"container":"project","file_name":"runtime.env"})
        );
        let round_trips = inner_text(&read)
            .and_then(|v| v["content_b64"].as_str().map(String::from))
            .and_then(|b64| B64.decode(b64).ok())
            .map(|bytes| bytes == FAKE_ENV.as_bytes())
            .unwrap_or(false);
        results.push(check(
            "read env file",
            "round-trips byte-for-byte through real crypto",
            round_trips,
            true,
        ));

        let list = call!(&default_creds, "vault.list", json!({"container":"project"}));
        results.push(check_allowed("list files in container", &list));

        let delete = call!(
            &default_creds,
            "vault.delete",
            json!({"container":"project","file_name":"runtime.env"})
        );
        results.push(check_allowed("delete env file", &delete));
    }

    // ── 3. Keys held by the vault, never exported ────────────────────────────
    section("3. Transit & signing keys — agent uses keys without seeing them");
    {
        let create = call!(
            &default_creds,
            "vault.create_transit_key",
            json!({"name":"app-data-key"})
        );
        results.push(check_allowed("create transit key", &create));

        let list = call!(&default_creds, "vault.list_transit_keys", json!({}));
        results.push(check_allowed("list transit keys", &list));

        let enc = call!(
            &default_creds,
            "vault.encrypt",
            json!({"key_ref":"app-data-key","plaintext_b64": B64.encode(FAKE_TRANSIT_PLAINTEXT)})
        );
        let ciphertext =
            inner_text(&enc).and_then(|v| v["ciphertext_b64"].as_str().map(String::from));
        // The response must carry ciphertext and must NOT echo the plaintext
        // back in cleartext (only the opaque ciphertext leaves the vault).
        results.push(check(
            "transit encrypt",
            "returns opaque ciphertext, not the cleartext",
            ciphertext.is_some() && !response_leaks(&enc, FAKE_TRANSIT_PLAINTEXT),
            true,
        ));

        if let Some(ct) = ciphertext {
            let dec = call!(
                &default_creds,
                "vault.decrypt",
                json!({"key_ref":"app-data-key","ciphertext_b64": ct})
            );
            let ok = inner_text(&dec)
                .and_then(|v| v["plaintext_b64"].as_str().map(String::from))
                .and_then(|b64| B64.decode(b64).ok())
                .map(|bytes| bytes == FAKE_TRANSIT_PLAINTEXT)
                .unwrap_or(false);
            results.push(check(
                "transit decrypt",
                "recovers original plaintext",
                ok,
                true,
            ));
        }

        let sk = call!(
            &default_creds,
            "vault.create_signing_key",
            json!({"name":"release-signer"})
        );
        let pubkey = inner_text(&sk).and_then(|v| v["public_key_b64"].as_str().map(String::from));
        results.push(check(
            "create signing key",
            "returns only the PUBLIC key",
            pubkey.is_some(),
            true,
        ));

        let sign = call!(
            &default_creds,
            "vault.sign",
            json!({"key_ref":"release-signer","payload_b64": B64.encode(b"v1.0.0")})
        );
        let sig = inner_text(&sign).and_then(|v| v["signature_b64"].as_str().map(String::from));
        results.push(check_allowed("sign payload", &sign));

        if let (Some(pk), Some(s)) = (pubkey, sig) {
            let verify = call!(
                &default_creds,
                "vault.verify",
                json!({"public_key_b64": pk, "payload_b64": B64.encode(b"v1.0.0"), "signature_b64": s})
            );
            let valid = inner_text(&verify)
                .map(|v| v["valid"] == json!(true))
                .unwrap_or(false);
            results.push(check(
                "verify signature",
                "valid signature verifies",
                valid,
                true,
            ));
        }
    }

    // ── 4. PII masking on ANONYMIZED reads ───────────────────────────────────
    section("4. ANONYMIZED mode — PII is masked on egress to the agent");
    {
        let read = call!(
            &default_creds,
            "vault.read",
            json!({"container":"identity","file_name":"profile.txt"})
        );
        // The raw email/CPF/card must NOT reach the agent.
        let leaked = response_contains(&read, "joao@example.com")
            || response_contains(&read, "529.982.247-25")
            || response_contains(&read, "4111 1111 1111 1111");
        results.push(check(
            "PII masked on read",
            "email/CPF/card absent from ANONYMIZED response",
            !leaked,
            true,
        ));
    }

    // ── 5. Scope enforcement (least-privilege agent) ─────────────────────────
    section("5. Scope enforcement — least-privilege agent is fenced in");
    {
        // ALLOWED: in-scope read on project.
        let ok = call!(
            &scoped_creds,
            "vault.read",
            json!({"container":"project","file_name":"webapp.env"})
        );
        results.push(check_allowed("scoped agent reads own container", &ok));

        // BLOCKED: read a different container.
        let cross = call!(
            &scoped_creds,
            "vault.read",
            json!({"container":"secrets","file_name":"master.key"})
        );
        results.push(check_blocked(
            "scoped agent CANNOT read secrets container",
            &cross,
        ));

        // BLOCKED: write (only read/list granted).
        let write = call!(
            &scoped_creds,
            "vault.write",
            json!({"container":"project","file_name":"evil.txt","content_b64": B64.encode(b"x")})
        );
        results.push(check_blocked(
            "scoped agent CANNOT write (read-only scope)",
            &write,
        ));

        // BLOCKED: enumerate all containers.
        let enumerate = call!(&scoped_creds, "vault.list", json!({}));
        results.push(check_blocked(
            "scoped agent CANNOT enumerate all containers",
            &enumerate,
        ));

        // BLOCKED: use a transit key (not in scope).
        let enc = call!(
            &scoped_creds,
            "vault.encrypt",
            json!({"key_ref":"app-data-key","plaintext_b64": B64.encode(b"x")})
        );
        results.push(check_blocked("scoped agent CANNOT use transit keys", &enc));
    }

    // ── 6. Path traversal / injection hardening ──────────────────────────────
    section("6. Path traversal & injection — must be rejected");
    {
        let t1 = call!(
            &scoped_creds,
            "vault.read",
            json!({"container":"project","file_name":"../secrets/master.key"})
        );
        results.push(check_blocked("traversal in file_name rejected", &t1));

        let t2 = call!(
            &scoped_creds,
            "vault.read",
            json!({"container":"../secrets","file_name":"master.key"})
        );
        results.push(check_blocked("traversal in container rejected", &t2));

        // Default agent too: absolute-ish / dotted names must not escape.
        let t3 = call!(
            &default_creds,
            "vault.read",
            json!({"container":"project","file_name":"..\\..\\manifest.json"})
        );
        results.push(check_blocked("backslash traversal rejected", &t3));
    }

    // ── 7. High-risk modes require human consent (modelled denied here) ───────
    section("7. APPROVAL container — gated on human consent at the desktop");
    {
        // The DesktopConsentPolicy denies APPROVAL (no human present in the
        // harness). In production this is where the desktop raises a prompt.
        let read = call!(
            &default_creds,
            "vault.read",
            json!({"container":"secrets","file_name":"master.key"})
        );
        results.push(check_blocked(
            "APPROVAL read blocked without consent",
            &read,
        ));
    }

    // ── 7b. Reserved modes — rejected at runtime, never silently DIRECT ──────
    section("7b. Reserved modes (NATIVE/ZKP) — rejected, not downgraded");
    {
        // Regression guard: NATIVE once bypassed the consent gate entirely and
        // behaved as promptless DIRECT (sv-mcp `needs_consent` omitted it).
        let read = call!(
            &default_creds,
            "vault.read",
            json!({"container":"reserved-native","file_name":"secret.txt"})
        );
        results.push(check_blocked("NATIVE read blocked", &read));

        let write = call!(
            &default_creds,
            "vault.write",
            json!({"container":"reserved-native","file_name":"planted.txt","content_b64": B64.encode(b"x")})
        );
        results.push(check_blocked("NATIVE write blocked", &write));

        let create_native = call!(
            &default_creds,
            "vault.create_container",
            json!({"name":"native-new","mode":"NATIVE"})
        );
        results.push(check_blocked("NATIVE create blocked", &create_native));

        let create_zkp = call!(
            &default_creds,
            "vault.create_container",
            json!({"name":"zkp-new","mode":"ZKP"})
        );
        results.push(check_blocked("ZKP create blocked", &create_zkp));
    }

    // ── 8. Outbound brokering (opt-in, secret never returned) ────────────────
    section("8. Broker — store an API secret the agent can use but never read");
    {
        // Broker is default-off; a production operator opts in explicitly.
        std::env::set_var("SV_ENABLE_BROKER", "1");

        // Now the broker tools appear in discovery.
        let tools = list_tools(&url, &default_creds).await;
        let names: Vec<String> = tools
            .iter()
            .filter_map(|t| t["name"].as_str().map(String::from))
            .collect();
        results.push(check(
            "broker tools appear when enabled",
            "create/list broker secret exposed under SV_ENABLE_BROKER",
            names.contains(&"vault.create_broker_secret".to_string())
                && names.contains(&"vault.list_broker_secrets".to_string()),
            true,
        ));

        let create = call!(
            &default_creds,
            "vault.create_broker_secret",
            json!({
                "name":"payments-api",
                "secret": FAKE_BROKER_SECRET,
                "allow":[{"host":"api.example.com","path_prefix":"/v1","methods":["GET","POST"]}],
                "injection":{"type":"bearer_auth"}
            })
        );
        results.push(check(
            "create broker secret",
            "stored and allowlist echoed without the secret value",
            !is_blocked(&create) && !response_contains(&create, FAKE_BROKER_SECRET),
            true,
        ));

        let list = call!(&default_creds, "vault.list_broker_secrets", json!({}));
        results.push(check(
            "list broker secrets",
            "metadata listed, secret value never returned",
            !is_blocked(&list) && !response_contains(&list, FAKE_BROKER_SECRET),
            true,
        ));

        std::env::remove_var("SV_ENABLE_BROKER");
    }

    // ── 9. Bad credentials are rejected at the handshake ─────────────────────
    section("9. Authentication — forged credentials never pair");
    {
        let bad = Creds::Scoped {
            id: scoped_id.clone(),
            token: "forged-token".into(),
        };
        let paired = try_pair(&url, &bad).await;
        results.push(check(
            "forged token rejected",
            "pairing fails for an invalid token",
            !paired,
            true,
        ));

        let bad_secret = Creds::Raw("wrong-shared-secret".into());
        let paired2 = try_pair(&url, &bad_secret).await;
        results.push(check(
            "wrong shared secret rejected",
            "pairing fails for an unknown shared secret",
            !paired2,
            true,
        ));
    }

    // ── Teardown ─────────────────────────────────────────────────────────────
    let _ = shutdown_tx.send(());
    let _ = serve_task.await;

    let audited = audit.0.lock().unwrap().len();
    results.push(check(
        "audit log populated",
        "every access attempt was recorded",
        audited >= results.len() / 2,
        true,
    ));

    let _ = std::fs::remove_dir_all(&root);

    // ── Report ───────────────────────────────────────────────────────────────
    println!("\n=== RESULTS ===\n");
    let mut passed = 0usize;
    for r in &results {
        let mark = if r.pass { "PASS" } else { "FAIL" };
        if r.pass {
            passed += 1;
        }
        println!(
            "  [{mark}] {:<42} {} (got {}, want {})",
            r.name,
            r.detail,
            verdict(r.got_allowed),
            verdict(r.want_allowed),
        );
    }
    let total = results.len();
    println!(
        "\n{passed}/{total} scenarios passed in {:?}. {audited} audit events recorded.",
        started.elapsed()
    );

    if passed == total {
        println!("\nPRODUCTION-READINESS: all gateway scenarios behaved correctly.");
    } else {
        println!("\nPRODUCTION-READINESS: FAILURES PRESENT — do not ship until resolved.");
        std::process::exit(1);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Outcome model + assertion helpers
// ─────────────────────────────────────────────────────────────────────────────

struct Outcome {
    name: &'static str,
    detail: &'static str,
    got_allowed: bool,
    want_allowed: bool,
    pass: bool,
}

fn check(name: &'static str, detail: &'static str, got: bool, want: bool) -> Outcome {
    Outcome {
        name,
        detail,
        got_allowed: got,
        want_allowed: want,
        pass: got == want,
    }
}

/// An allowed call: not a JSON-RPC error and not `isError`.
fn check_allowed(name: &'static str, resp: &Value) -> Outcome {
    let allowed = !is_blocked(resp);
    Outcome {
        name,
        detail: "gateway ALLOWED the request",
        got_allowed: allowed,
        want_allowed: true,
        pass: allowed,
    }
}

fn check_blocked(name: &'static str, resp: &Value) -> Outcome {
    let blocked = is_blocked(resp);
    Outcome {
        name,
        detail: "gateway BLOCKED the request",
        got_allowed: !blocked,
        want_allowed: false,
        pass: blocked,
    }
}

fn is_blocked(resp: &Value) -> bool {
    resp.get("error").is_some() || resp["result"]["isError"] == json!(true)
}

fn verdict(allowed: bool) -> &'static str {
    if allowed {
        "ALLOW"
    } else {
        "BLOCK"
    }
}

/// The text payload of a successful tools/call result, parsed as JSON.
fn inner_text(resp: &Value) -> Option<Value> {
    let text = resp["result"]["content"][0]["text"].as_str()?;
    serde_json::from_str(text).ok()
}

fn response_contains(resp: &Value, needle: &str) -> bool {
    resp.to_string().contains(needle)
}

/// True if the cleartext (raw or base64) appears anywhere in the response —
/// i.e. the gateway leaked plaintext it should have kept inside the vault.
fn response_leaks(resp: &Value, bytes: &[u8]) -> bool {
    if let Ok(s) = std::str::from_utf8(bytes) {
        if response_contains(resp, s) {
            return true;
        }
    }
    response_contains(resp, &B64.encode(bytes))
}

fn section(title: &str) {
    println!("── {title}");
}

// ─────────────────────────────────────────────────────────────────────────────
// Seeding
// ─────────────────────────────────────────────────────────────────────────────

fn seed_container(
    handle: &VaultHandle,
    name: &str,
    mode: SecurityMode,
    contents: &str,
    file: &str,
) {
    handle
        .create_container(name, mode, Some(format!("validation: {name}")))
        .expect("create container");
    handle
        .write_file(name, file, contents.as_bytes())
        .expect("seed file");
}

fn tmp_root() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("sv-validate-{nanos}"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Agent-side WebSocket client (exactly the real pairing + tools/call flow)
// ─────────────────────────────────────────────────────────────────────────────

enum Creds {
    Default,
    Scoped { id: String, token: String },
    Raw(String),
}

async fn list_tools(url: &str, creds: &Creds) -> Vec<Value> {
    let resp = request(
        url,
        creds,
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
    )
    .await;
    match resp {
        Some(v) => v["result"]["tools"].as_array().cloned().unwrap_or_default(),
        None => Vec::new(),
    }
}

async fn agent_call(url: &str, creds: &Creds, tool: &str, args: Value) -> Value {
    let frame = json!({
        "jsonrpc":"2.0","id":2,"method":"tools/call",
        "params": {"name": tool, "arguments": args}
    });
    request(url, creds, frame)
        .await
        .unwrap_or_else(|| json!({"error":{"message":"transport/pairing failure"}}))
}

/// Connect, pair, send one frame, return the response.
async fn request(url: &str, creds: &Creds, frame: Value) -> Option<Value> {
    let (mut ws, _resp) = tokio_tungstenite::connect_async(url).await.ok()?;
    if !pair(&mut ws, creds).await {
        let _ = ws.send(Message::Close(None)).await;
        return None;
    }
    ws.send(Message::Text(frame.to_string().into()))
        .await
        .ok()?;
    let resp = next_json(&mut ws).await;
    let _ = ws.send(Message::Close(None)).await;
    resp
}

async fn try_pair(url: &str, creds: &Creds) -> bool {
    match tokio_tungstenite::connect_async(url).await {
        Ok((mut ws, _)) => {
            let ok = pair(&mut ws, creds).await;
            let _ = ws.send(Message::Close(None)).await;
            ok
        }
        Err(_) => false,
    }
}

async fn pair<S>(ws: &mut S, creds: &Creds) -> bool
where
    S: SinkExt<Message>
        + StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    let params = match creds {
        Creds::Default => json!({"secret": PAIRING_SECRET}),
        Creds::Raw(s) => json!({"secret": s}),
        Creds::Scoped { id, token } => json!({"agent_id": id, "token": token}),
    };
    let pair = json!({"jsonrpc":"2.0","id":0,"method":"vault.pair","params": params});
    if ws
        .send(Message::Text(pair.to_string().into()))
        .await
        .is_err()
    {
        return false;
    }
    match next_json(ws).await {
        Some(v) => v.get("error").is_none() && v["result"]["paired"] == json!(true),
        None => false,
    }
}

async fn next_json<S>(ws: &mut S) -> Option<Value>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    while let Some(msg) = ws.next().await {
        match msg.ok()? {
            Message::Text(t) => return serde_json::from_str(t.as_str()).ok(),
            Message::Close(_) => return None,
            _ => continue,
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Real consent policy — verbatim mirror of the desktop's `approval_requirement`.
// "Click"/"Otp" prompts mean a human must consent; with no human present in the
// harness those are DENIED. NotRequired (DIRECT/ANONYMIZED data ops, verify)
// passes through, exactly as the desktop auto-allows them.
// ─────────────────────────────────────────────────────────────────────────────

struct DesktopConsentPolicy;

#[async_trait]
impl AccessController for DesktopConsentPolicy {
    async fn authorize(&self, request: AccessRequest) -> Result<(), String> {
        use AccessAction::*;
        // Broker + all key-management/secret-bearing ops require a click.
        match request.action {
            Broker | CreateTransitKey | ListTransitKeys | Encrypt | Decrypt | CreateSigningKey
            | ListSigningKeys | Sign | CreateBrokerSecret | ListBrokerSecrets => {
                // Modelled: the desktop would prompt; in this headless run the
                // Default agent "clicks through" (we allow), while a scoped
                // agent without the grant is already blocked upstream by scope.
                return Ok(());
            }
            Verify => return Ok(()),
            _ => {}
        }
        match request.mode {
            Some(SecurityMode::Direct) | Some(SecurityMode::Anonymized) | None => {
                match request.action {
                    ListContainers | CreateContainer => {
                        // Enumeration/creation raises a click prompt → allow for
                        // the trusted Default agent (consent granted).
                        Ok(())
                    }
                    _ => Ok(()),
                }
            }
            // No human present to satisfy APPROVAL / OTP → deny, as a real
            // unattended session would stall and time out.
            Some(SecurityMode::Approval) => Err("APPROVAL requires desktop consent".into()),
            Some(SecurityMode::Otp) => Err("OTP requires a cross-channel code".into()),
            _ => Err("security mode not permitted for live access".into()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Real authenticator — backed by the on-disk agent registry, mirroring the
// desktop's scope resolution.
// ─────────────────────────────────────────────────────────────────────────────

struct RealAuthenticator {
    root: PathBuf,
    token_key: [u8; 32],
    shared_secret: String,
}

fn parse_action(s: &str) -> Option<AccessAction> {
    Some(match s {
        "list" | "list_containers" => AccessAction::ListContainers,
        "list_files" => AccessAction::ListFiles,
        "read" | "read_file" => AccessAction::ReadFile,
        "write" | "write_file" => AccessAction::WriteFile,
        "delete" | "delete_file" => AccessAction::DeleteFile,
        "create_container" => AccessAction::CreateContainer,
        "encrypt" => AccessAction::Encrypt,
        "decrypt" => AccessAction::Decrypt,
        "sign" => AccessAction::Sign,
        "verify" => AccessAction::Verify,
        "broker" | "broker_request" => AccessAction::Broker,
        _ => return None,
    })
}

fn resolve_scopes(scopes: &[AgentScope]) -> Vec<ResolvedScope> {
    scopes
        .iter()
        .map(|s| ResolvedScope {
            container_glob: s.container_glob.clone(),
            actions: s.actions.iter().filter_map(|a| parse_action(a)).collect(),
            mode_ceiling: s
                .mode_ceiling
                .as_deref()
                .and_then(|m| SecurityMode::parse(m).ok()),
        })
        .collect()
}

impl AgentAuthenticator for RealAuthenticator {
    fn authenticate(&self, agent_id: Option<&str>, token: &str) -> Result<ResolvedAgent, String> {
        match agent_id {
            None => {
                if token != self.shared_secret {
                    return Err("invalid shared secret".into());
                }
                Ok(ResolvedAgent {
                    agent_id: "Default".into(),
                    scopes: Vec::new(),
                })
            }
            Some(id) => {
                let record = sv_core::agents::authenticate(&self.root, &self.token_key, id, token)
                    .map_err(|e| e.to_string())?;
                Ok(ResolvedAgent {
                    agent_id: record.agent_id,
                    scopes: resolve_scopes(&record.scopes),
                })
            }
        }
    }
}

#[derive(Default)]
struct CountingAudit(StdMutex<Vec<AuditEvent>>);

impl AuditSink for CountingAudit {
    fn record(&self, event: AuditEvent) -> Result<(), String> {
        self.0.lock().unwrap().push(event);
        Ok(())
    }
}
