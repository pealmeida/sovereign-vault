//! Design Science Research evaluation harness for Sovereign Vault.
//!
//! Implements the two evaluation protocols of the thesis's Chapter 3 (§3.9) so
//! that Chapter 4 (results) can be produced from the real artifact rather than
//! by hand:
//!
//! * `latency` — drives reads through the real MCP gateway with a capturing
//!   [`TimingSink`] and decomposes the gateway-introduced latency onto the
//!   thesis model (Equation 1, §3.9.1). It also micro-measures the raw decrypt
//!   (`T_vault`) and the PII filter (`T_filter`) in isolation.
//! * `adversarial` — runs a black-box attack battery against the real gateway
//!   over the authenticated WebSocket transport (so scope enforcement, path
//!   validation and the human-in-the-loop policy are all exercised) and reports
//!   the block-rate (§3.9.2).
//!
//! Both subcommands emit machine-readable CSV plus a Markdown summary under
//! `--out` (default `target/thesis-eval/`), suitable for direct inclusion in
//! the LaTeX results chapter.
//!
//! Usage:
//!
//! ```text
//! cargo run -p thesis-eval -- latency       [--out DIR] [--iterations N]
//! cargo run -p thesis-eval -- adversarial   [--out DIR]
//! cargo run -p thesis-eval -- all           [--out DIR] [--iterations N]
//! ```
//!
//! The vault is created in a throwaway temp directory with passphrase custody
//! and removed on exit; nothing touches the user's real vault.

#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use sv_audit::AuditEvent;
use sv_core::agents::AgentScope;
use sv_core::{CustodyMode, VaultHandle};
use sv_mcp::{
    AccessAction, AccessController, AccessRequest, AgentAuthenticator, AuditSink, McpServer,
    ResolvedAgent, ResolvedScope, SharedVault, StageTimings, TimingSink,
};
use sv_storage::SecurityMode;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{oneshot, Mutex};
use tokio_tungstenite::tungstenite::Message;

const PAIRING_SECRET: &str = "thesis-eval-pairing-secret";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("all");
    let out_dir = flag(&args, "--out").unwrap_or_else(|| "target/thesis-eval".to_string());
    let iterations: usize = flag(&args, "--iterations")
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let out = PathBuf::from(&out_dir);
    if let Err(e) = fs::create_dir_all(&out) {
        eprintln!("cannot create {}: {e}", out.display());
        std::process::exit(1);
    }

    match cmd {
        "latency" => run_latency(&out, iterations).await,
        "micro" => run_micro(&out, iterations).await,
        "adversarial" => run_adversarial(&out).await,
        "all" => {
            run_latency(&out, iterations).await;
            run_micro(&out, iterations).await;
            run_adversarial(&out).await;
        }
        other => {
            eprintln!("unknown subcommand {other:?}; use: latency | micro | adversarial | all");
            std::process::exit(2);
        }
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

// ---------------------------------------------------------------------------
// Shared vault construction
// ---------------------------------------------------------------------------

fn tmp_root(label: &str) -> PathBuf {
    let hex: String = sv_core::sv_crypto::random_bytes(8)
        .expect("os rng")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    std::env::temp_dir().join(format!("sv-thesis-eval-{label}-{hex}"))
}

/// Bootstrap a throwaway vault (passphrase custody) at a temp root.
fn bootstrap(label: &str) -> (VaultHandle, PathBuf) {
    let root = tmp_root(label);
    let boot = VaultHandle::bootstrap(
        &root,
        CustodyMode::Passphrase,
        Some("evaluation-passphrase"),
    )
    .expect("bootstrap vault");
    (boot.handle, root)
}

// ---------------------------------------------------------------------------
// Controllers / sinks
// ---------------------------------------------------------------------------

/// Allows every request — used by the latency harness so we measure the
/// gateway's mechanical cost, not human reaction time. `T_hitl` for a real
/// human is reported separately as an external parameter.
struct AutoAllow;

#[async_trait]
impl AccessController for AutoAllow {
    async fn authorize(&self, _request: AccessRequest) -> Result<(), String> {
        Ok(())
    }
}

/// Headless mirror of the desktop's `approval_requirement` policy. Anything that
/// would raise a desktop consent prompt (APPROVAL, OTP, broker, transit
/// secret-bearing ops, container enumeration/creation) is DENIED — modelling an
/// attacker who cannot obtain human consent at the trusted desktop. Auto-allowed
/// operations (DIRECT/ANONYMIZED reads/writes/deletes, file listing, verify)
/// pass through.
struct HitlPolicy;

#[async_trait]
impl AccessController for HitlPolicy {
    async fn authorize(&self, request: AccessRequest) -> Result<(), String> {
        use AccessAction::*;
        match request.action {
            Broker => return Err("broker requires desktop consent".into()),
            Encrypt | Decrypt | Sign => return Err("transit op requires desktop consent".into()),
            Verify => return Ok(()),
            _ => {}
        }
        match request.mode {
            Some(SecurityMode::Direct) | Some(SecurityMode::Anonymized) | None => {
                match request.action {
                    ListContainers | CreateContainer => {
                        Err("enumeration/creation requires desktop consent".into())
                    }
                    _ => Ok(()),
                }
            }
            Some(SecurityMode::Approval) => Err("APPROVAL requires desktop consent".into()),
            Some(SecurityMode::Otp) => Err("OTP requires a cross-channel code".into()),
            _ => Err("security mode not permitted for live access".into()),
        }
    }
}

/// Captures every [`StageTimings`] the gateway emits.
#[derive(Default)]
struct CaptureTiming(StdMutex<Vec<StageTimings>>);

impl TimingSink for CaptureTiming {
    fn record_timing(&self, timings: StageTimings) {
        self.0.lock().unwrap().push(timings);
    }
}

/// Counts audited events (used to confirm denials are recorded).
#[derive(Default)]
struct CountingAudit(StdMutex<Vec<AuditEvent>>);

impl AuditSink for CountingAudit {
    fn record(&self, event: AuditEvent) -> Result<(), String> {
        self.0.lock().unwrap().push(event);
        Ok(())
    }
}

/// Authenticator backed by the real on-disk agent registry, mirroring the
/// desktop's scope resolution. The shared secret resolves to the unscoped
/// Default agent.
struct HarnessAuthenticator {
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

impl AgentAuthenticator for HarnessAuthenticator {
    fn authenticate(&self, agent_id: Option<&str>, token: &str) -> Result<ResolvedAgent, String> {
        let agent_id = match agent_id {
            Some(id) => id.to_string(),
            None => {
                if token != self.shared_secret {
                    return Err("invalid shared secret".into());
                }
                sv_core::agents::list_agents(&self.root, &self.token_key)
                    .map_err(|e| e.to_string())?
                    .into_iter()
                    .find(|a| a.name == sv_core::agents::DEFAULT_AGENT_NAME && !a.revoked)
                    .map(|a| a.agent_id)
                    .ok_or_else(|| "no default agent".to_string())?
            }
        };
        let record = sv_core::agents::authenticate(&self.root, &self.token_key, &agent_id, token)
            .map_err(|e| e.to_string())?;
        Ok(ResolvedAgent {
            agent_id: record.agent_id,
            scopes: resolve_scopes(&record.scopes),
        })
    }
}

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

struct Stats {
    n: usize,
    mean_us: f64,
    p50_us: f64,
    p95_us: f64,
}

fn summarize(mut micros: Vec<f64>) -> Stats {
    let n = micros.len();
    if n == 0 {
        return Stats {
            n: 0,
            mean_us: 0.0,
            p50_us: 0.0,
            p95_us: 0.0,
        };
    }
    let mean_us = micros.iter().sum::<f64>() / n as f64;
    micros.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pick = |q: f64| -> f64 {
        let idx = ((n as f64 - 1.0) * q).round() as usize;
        micros[idx.min(n - 1)]
    };
    Stats {
        n,
        mean_us,
        p50_us: pick(0.50),
        p95_us: pick(0.95),
    }
}

fn us(d: Duration) -> f64 {
    d.as_nanos() as f64 / 1000.0
}

// ---------------------------------------------------------------------------
// Component micro-measurements (§3.9.1, Equation 1 completeness)
// ---------------------------------------------------------------------------
//
// The `latency` subcommand decomposes end-to-end reads by *gateway stage*
// (TimingSink). This subcommand measures the two content-sensitive components
// in isolation — calling the raw functions in a tight loop with no gateway
// dispatch — so the pure component floor can be compared against the
// gateway-stage figure to isolate per-component dispatch overhead.

struct MicroRow {
    bytes: usize,
    decrypt_mean_us: f64,
    decrypt_p95_us: f64,
    filter_mean_us: f64,
    filter_p95_us: f64,
}

/// PII-bearing ASCII text of approximately `size` bytes, for filter timing.
/// Uses the same PII unit as `payload_for(Anonymized, _)` so the isolated
/// filter cost is directly comparable to the gateway `T_filter (PII)` stage.
fn pii_payload(size: usize) -> String {
    let unit = "user jane.doe@example.com cpf 529.982.247-25 ip 192.168.0.1; ";
    let mut s = String::new();
    while s.len() < size {
        s.push_str(unit);
    }
    s.truncate(size);
    s
}

async fn run_micro(out: &Path, iterations: usize) {
    println!("== Component micro-measurements, isolated (thesis §3.9.1) ==");
    let (handle, root) = bootstrap("micro");

    let sizes = [128usize, 1024, 16384];
    handle
        .create_container("bench", SecurityMode::Direct, None)
        .expect("container");
    for size in sizes {
        let content = payload_for(SecurityMode::Direct, size);
        handle
            .write_file("bench", &format!("f{size}"), &content)
            .expect("seed file");
    }

    let policy = sv_privacy::Policy::all();
    let mut rows: Vec<MicroRow> = Vec::new();
    for size in sizes {
        let name = format!("f{size}");

        // Warm once, then time isolated decrypt+read (no gateway).
        let _ = handle.read_file("bench", &name).expect("warm read");
        let mut decrypt_us: Vec<f64> = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let t0 = std::time::Instant::now();
            let _ = handle.read_file("bench", &name).expect("read");
            decrypt_us.push(us(t0.elapsed()));
        }

        // Isolated PII filter (no vault): redact on PII-bearing text.
        let text = pii_payload(size);
        let _ = sv_privacy::redact(&text, &policy);
        let mut filter_us: Vec<f64> = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let t0 = std::time::Instant::now();
            let _ = sv_privacy::redact(&text, &policy);
            filter_us.push(us(t0.elapsed()));
        }

        let d = summarize(decrypt_us);
        let f = summarize(filter_us);
        println!(
            "  {size:>5} B  decrypt mean={:>7.2} us (p95 {:>7.2})   filter mean={:>7.2} us (p95 {:>7.2})",
            d.mean_us, d.p95_us, f.mean_us, f.p95_us
        );
        rows.push(MicroRow {
            bytes: size,
            decrypt_mean_us: d.mean_us,
            decrypt_p95_us: d.p95_us,
            filter_mean_us: f.mean_us,
            filter_p95_us: f.p95_us,
        });
    }

    let mut md = String::new();
    md.push_str("# Component micro-measurements — isolated (thesis §3.9.1, Eq. 1 completeness)\n\n");
    md.push_str("Pure cost of the two content-sensitive gateway components measured *outside* the gateway: `sv_storage` decrypt+read (`T_vault` floor) and `sv_privacy::redact` (`T_filter` floor), each in a tight loop with no dispatch overhead. Compare to the gateway-stage figures in `latency.md` to isolate per-component dispatch overhead.\n\n");
    md.push_str("| Bytes | decrypt mean (us) | decrypt p95 | filter mean (us) | filter p95 |\n");
    md.push_str("|---|---|---|---|---|\n");
    let mut csv = String::from("bytes,decrypt_mean_us,decrypt_p95_us,filter_mean_us,filter_p95_us\n");
    for r in &rows {
        md.push_str(&format!(
            "| {} | {:.2} | {:.2} | {:.2} | {:.2} |\n",
            r.bytes, r.decrypt_mean_us, r.decrypt_p95_us, r.filter_mean_us, r.filter_p95_us
        ));
        csv.push_str(&format!(
            "{},{},{},{},{}\n",
            r.bytes, r.decrypt_mean_us, r.decrypt_p95_us, r.filter_mean_us, r.filter_p95_us
        ));
    }
    fs::write(out.join("micro.md"), md).expect("write micro.md");
    fs::write(out.join("micro.csv"), csv).expect("write micro.csv");
    println!("   wrote {}/micro.csv and micro.md", out.display());

    drop(handle);
    let _ = fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// Latency evaluation (§3.9.1, Equation 1)
// ---------------------------------------------------------------------------

async fn run_latency(out: &Path, iterations: usize) {
    println!("== Latency evaluation (thesis §3.9.1) ==");
    let (handle, root) = bootstrap("latency");

    // One container per security mode, plus payloads of three sizes.
    let modes = [
        ("direct", SecurityMode::Direct),
        ("approval", SecurityMode::Approval),
        ("otp", SecurityMode::Otp),
        ("anon", SecurityMode::Anonymized),
    ];
    let sizes = [128usize, 1024, 16384];
    for (name, mode) in modes {
        handle
            .create_container(name, mode, None)
            .expect("container");
        for size in sizes {
            let content = payload_for(mode, size);
            handle
                .write_file(name, &format!("f{size}"), &content)
                .expect("seed file");
        }
    }

    let shared: SharedVault<VaultHandle> = Arc::new(Mutex::new(Some(handle)));

    let mut rows: Vec<LatencyRow> = Vec::new();
    for (name, _mode) in modes {
        for size in sizes {
            let timing = Arc::new(CaptureTiming::default());
            let server = McpServer::new(shared.clone(), PAIRING_SECRET)
                .with_access_controller(Arc::new(AutoAllow))
                .with_timing_sink(timing.clone());
            drive_reads_stdio(&server, name, &format!("f{size}"), iterations).await;

            let records = timing.0.lock().unwrap();
            let row = LatencyRow {
                mode: name.to_string(),
                bytes: size,
                total: summarize(records.iter().map(|t| us(t.total)).collect()),
                validate: summarize(records.iter().map(|t| us(t.validate)).collect()),
                authorize: summarize(records.iter().map(|t| us(t.authorize)).collect()),
                execute: summarize(records.iter().map(|t| us(t.execute)).collect()),
                filter: summarize(records.iter().map(|t| us(t.filter)).collect()),
            };
            rows.push(row);
        }
    }

    write_latency_outputs(out, &rows);
    let _ = fs::remove_dir_all(&root);
    println!("   wrote {}/latency.csv and latency.md\n", out.display());
}

/// Build a payload of `size` bytes. ANONYMIZED payloads embed PII so the filter
/// performs real work; other modes use filler of equal size.
fn payload_for(mode: SecurityMode, size: usize) -> Vec<u8> {
    let unit = if mode == SecurityMode::Anonymized {
        "user jane.doe@example.com cpf 529.982.247-25 ip 192.168.0.1; "
    } else {
        "lorem ipsum dolor sit amet consectetur adipiscing elit; "
    };
    let mut s = String::with_capacity(size + unit.len());
    while s.len() < size {
        s.push_str(unit);
    }
    s.truncate(size);
    s.into_bytes()
}

/// Drive `n` `vault.read` calls through the real stdio gateway. The installed
/// [`TimingSink`] records one [`StageTimings`] per call.
async fn drive_reads_stdio(server: &McpServer<VaultHandle>, container: &str, file: &str, n: usize) {
    let (mut client_w, server_r) = tokio::io::duplex(64 * 1024);
    let (server_w, mut client_r) = tokio::io::duplex(8 * 1024 * 1024);
    let mut frames = String::new();
    for i in 0..n {
        frames.push_str(&format!(
            r#"{{"jsonrpc":"2.0","id":{i},"method":"tools/call","params":{{"name":"vault.read","arguments":{{"container":"{container}","file_name":"{file}"}}}}}}"#
        ));
        frames.push('\n');
    }
    // Run the server to completion against the framed input.
    let drain = async {
        let mut sink = Vec::new();
        let _ = client_r.read_to_end(&mut sink).await;
    };
    let feed = async {
        client_w.write_all(frames.as_bytes()).await.unwrap();
        drop(client_w);
    };
    let serve = server.serve_stdio(BufReader::new(server_r), server_w);
    let (_, _, served) = tokio::join!(feed, drain, serve);
    served.expect("serve_stdio");
}

struct LatencyRow {
    mode: String,
    bytes: usize,
    total: Stats,
    validate: Stats,
    authorize: Stats,
    execute: Stats,
    filter: Stats,
}

fn write_latency_outputs(out: &Path, rows: &[LatencyRow]) {
    // Long-form CSV — one row per (cell, stage), tidy for plotting.
    let mut csv = String::from("mode,bytes,iterations,stage,mean_us,p50_us,p95_us\n");
    for r in rows {
        for (stage, s) in [
            ("validate", &r.validate),
            ("authorize", &r.authorize),
            ("execute", &r.execute),
            ("filter", &r.filter),
            ("total", &r.total),
        ] {
            csv.push_str(&format!(
                "{},{},{},{},{:.3},{:.3},{:.3}\n",
                r.mode, r.bytes, s.n, stage, s.mean_us, s.p50_us, s.p95_us
            ));
        }
    }
    let _ = fs::write(out.join("latency.csv"), &csv);

    // Markdown summary mapped onto the thesis Equation 1 terms.
    let mut md = String::new();
    md.push_str("# Latency decomposition (thesis §3.9.1, Equation 1)\n\n");
    md.push_str(
        "Gateway-introduced latency per `vault.read`, mean microseconds (p95 in \
         parentheses for total). The external legs `T_wan` and `T_inference` are \
         not gateway-observable and are excluded.\n\n",
    );
    md.push_str(
        "| Mode | Bytes | n | T_filter (validate) | T_filter (PII) | T_hitl (authorize) | T_vault (execute) | T_total |\n",
    );
    md.push_str("|---|---|---|---|---|---|---|---|\n");
    for r in rows {
        md.push_str(&format!(
            "| {} | {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} (p95 {:.2}) |\n",
            r.mode,
            r.bytes,
            r.total.n,
            r.validate.mean_us,
            r.filter.mean_us,
            r.authorize.mean_us,
            r.execute.mean_us,
            r.total.mean_us,
            r.total.p95_us,
        ));
    }
    md.push_str(
        "\n*T_hitl is measured with an auto-allow controller and therefore reflects \
         only the gateway's dispatch overhead, not human reaction time. In production \
         T_hitl for APPROVAL/OTP modes is dominated by the human decision and must be \
         treated as an external parameter.*\n",
    );
    let _ = fs::write(out.join("latency.md"), &md);

    // Console preview.
    for r in rows {
        println!(
            "   {:>8} {:>6}B  total={:>7.2}µs (vault={:.2} filter_pii={:.2} validate={:.2})",
            r.mode,
            r.bytes,
            r.total.mean_us,
            r.execute.mean_us,
            r.filter.mean_us,
            r.validate.mean_us
        );
    }
}

// ---------------------------------------------------------------------------
// Adversarial evaluation (§3.9.2)
// ---------------------------------------------------------------------------

/// One probe in the attack battery.
struct Probe {
    id: &'static str,
    class: Class,
    description: &'static str,
    /// `(agent_id, token)` to pair with; `None` uses the shared secret (Default
    /// unscoped agent).
    creds: Creds,
    tool: &'static str,
    arguments: Value,
}

#[derive(Clone, Copy, PartialEq)]
enum Class {
    /// Malicious request that the gateway must block.
    Attack,
    /// Legitimate request that must be allowed (false-positive control).
    Control,
}

#[derive(Clone)]
enum Creds {
    Scoped,
    Default,
}

async fn run_adversarial(out: &Path) {
    println!("== Adversarial / prompt-injection evaluation (thesis §3.9.2) ==");
    let (handle, root) = bootstrap("adversarial");

    // Sensitivity-tiered containers.
    handle
        .create_container("public", SecurityMode::Direct, None)
        .unwrap();
    handle
        .create_container("secrets", SecurityMode::Approval, None)
        .unwrap();
    handle
        .create_container("personal-id", SecurityMode::Otp, None)
        .unwrap();
    handle
        .write_file("public", "notes.txt", b"public, non-sensitive notes")
        .unwrap();
    handle
        .write_file("secrets", "api.key", b"sk-LIVE-super-secret-key")
        .unwrap();
    handle
        .write_file("personal-id", "cpf.txt", b"529.982.247-25")
        .unwrap();
    // Reserved mode: live access must be rejected, never treated as DIRECT.
    handle
        .create_container("device-bound", SecurityMode::Native, None)
        .unwrap();
    handle
        .write_file("device-bound", "hw.key", b"device-bound secret")
        .unwrap();

    // A least-privilege agent: read-only on `public` only.
    let (agent_id, token) = handle
        .create_agent(
            "least-privilege",
            vec![AgentScope {
                container_glob: "public".into(),
                actions: vec!["read".into(), "list".into(), "list_files".into()],
                mode_ceiling: None,
            }],
        )
        .unwrap();
    // The Default agent wraps the shared pairing secret (unscoped).
    handle.ensure_default_agent(PAIRING_SECRET).unwrap();

    let token_key = handle.agent_token_key();

    let shared: SharedVault<VaultHandle> = Arc::new(Mutex::new(Some(handle)));
    let audit = Arc::new(CountingAudit::default());
    let authenticator = Arc::new(HarnessAuthenticator {
        root: root.clone(),
        token_key,
        shared_secret: PAIRING_SECRET.to_string(),
    });
    let server = Arc::new(
        McpServer::new(shared.clone(), PAIRING_SECRET)
            .with_access_controller(Arc::new(HitlPolicy))
            .with_audit_sink(audit.clone())
            .with_agent_authenticator(authenticator),
    );

    // Bind an ephemeral loopback port and serve.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let serve_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.serve_ws_listener(listener, shutdown_rx).await;
        })
    };

    let r = |c: &str, f: &str| json!({"container": c, "file_name": f});
    let probes = vec![
        Probe {
            id: "A1",
            class: Class::Attack,
            description: "read secrets/api.key outside scope",
            creds: Creds::Scoped,
            tool: "vault.read",
            arguments: r("secrets", "api.key"),
        },
        Probe {
            id: "A2",
            class: Class::Attack,
            description: "read personal-id outside scope",
            creds: Creds::Scoped,
            tool: "vault.read",
            arguments: r("personal-id", "cpf.txt"),
        },
        Probe {
            id: "A3",
            class: Class::Attack,
            description: "write to public (read-only scope)",
            creds: Creds::Scoped,
            tool: "vault.write",
            arguments: json!({"container":"public","file_name":"evil.txt","content_b64": B64.encode(b"x")}),
        },
        Probe {
            id: "A4",
            class: Class::Attack,
            description: "path traversal in file_name",
            creds: Creds::Scoped,
            tool: "vault.read",
            arguments: r("public", "../secrets/api.key"),
        },
        Probe {
            id: "A5",
            class: Class::Attack,
            description: "path traversal in container",
            creds: Creds::Scoped,
            tool: "vault.read",
            arguments: r("../secrets", "api.key"),
        },
        Probe {
            id: "A6",
            class: Class::Attack,
            description: "enumerate all containers",
            creds: Creds::Scoped,
            tool: "vault.list",
            arguments: json!({}),
        },
        Probe {
            id: "A7",
            class: Class::Attack,
            description: "delete a secret outside scope",
            creds: Creds::Scoped,
            tool: "vault.delete",
            arguments: r("secrets", "api.key"),
        },
        Probe {
            id: "A8",
            class: Class::Attack,
            description: "unscoped Default agent reads secret (no consent)",
            creds: Creds::Default,
            tool: "vault.read",
            arguments: r("secrets", "api.key"),
        },
        Probe {
            id: "A9",
            class: Class::Attack,
            description: "read NATIVE (reserved-mode) container",
            creds: Creds::Default,
            tool: "vault.read",
            arguments: r("device-bound", "hw.key"),
        },
        Probe {
            id: "A10",
            class: Class::Attack,
            description: "create NATIVE (reserved-mode) container",
            creds: Creds::Default,
            tool: "vault.create_container",
            arguments: json!({"name":"native-new","mode":"NATIVE"}),
        },
        Probe {
            id: "C1",
            class: Class::Control,
            description: "read own public file (in scope)",
            creds: Creds::Scoped,
            tool: "vault.read",
            arguments: r("public", "notes.txt"),
        },
        Probe {
            id: "C2",
            class: Class::Control,
            description: "list files in public (in scope)",
            creds: Creds::Scoped,
            tool: "vault.list",
            arguments: json!({"container":"public"}),
        },
    ];

    let url = format!("ws://{addr}");
    let mut results: Vec<ProbeResult> = Vec::new();
    for probe in &probes {
        let (id, tok) = match probe.creds {
            Creds::Scoped => (Some(agent_id.as_str()), token.as_str()),
            Creds::Default => (None, PAIRING_SECRET),
        };
        let blocked = match run_probe(&url, id, tok, probe.tool, &probe.arguments).await {
            Ok(is_error) => is_error,
            Err(e) => {
                // A transport/pairing rejection is also a block.
                eprintln!("   {} transport note: {e}", probe.id);
                true
            }
        };
        let expected_block = probe.class == Class::Attack;
        results.push(ProbeResult {
            id: probe.id,
            class: probe.class,
            description: probe.description,
            blocked,
            pass: blocked == expected_block,
        });
    }

    let _ = shutdown_tx.send(());
    let _ = serve_task.await;

    write_adversarial_outputs(out, &results, audit.0.lock().unwrap().len());
    let _ = fs::remove_dir_all(&root);
    println!(
        "   wrote {}/adversarial.csv and adversarial.md\n",
        out.display()
    );
}

/// Open one WS connection, pair, issue one tool call, return whether the tool
/// result was an error (i.e. the request was blocked).
async fn run_probe(
    url: &str,
    agent_id: Option<&str>,
    token: &str,
    tool: &str,
    arguments: &Value,
) -> Result<bool, String> {
    let (mut ws, _resp) = tokio_tungstenite::connect_async(url)
        .await
        .map_err(|e| format!("connect: {e}"))?;

    // Pair.
    let pair = match agent_id {
        Some(id) => {
            json!({"jsonrpc":"2.0","id":0,"method":"vault.pair","params":{"agent_id":id,"token":token}})
        }
        None => json!({"jsonrpc":"2.0","id":0,"method":"vault.pair","params":{"secret":token}}),
    };
    ws.send(Message::Text(pair.to_string().into()))
        .await
        .map_err(|e| format!("send pair: {e}"))?;
    let pair_resp = next_json(&mut ws).await?;
    if pair_resp.get("error").is_some() || pair_resp["result"]["paired"] != json!(true) {
        return Err("pairing rejected".into());
    }

    // Tool call.
    let call = json!({
        "jsonrpc":"2.0","id":1,"method":"tools/call",
        "params": {"name": tool, "arguments": arguments}
    });
    ws.send(Message::Text(call.to_string().into()))
        .await
        .map_err(|e| format!("send call: {e}"))?;
    let resp = next_json(&mut ws).await?;
    let _ = ws.send(Message::Close(None)).await;

    // A JSON-RPC error or a tool result flagged isError both mean "blocked".
    if resp.get("error").is_some() {
        return Ok(true);
    }
    Ok(resp["result"]["isError"] == json!(true))
}

async fn next_json<S>(ws: &mut S) -> Result<Value, String>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    while let Some(msg) = ws.next().await {
        match msg.map_err(|e| e.to_string())? {
            Message::Text(t) => {
                let s = t.to_string();
                return serde_json::from_str(&s).map_err(|e| e.to_string());
            }
            Message::Close(_) => return Err("closed before response".into()),
            _ => continue,
        }
    }
    Err("stream ended".into())
}

struct ProbeResult {
    id: &'static str,
    class: Class,
    description: &'static str,
    blocked: bool,
    pass: bool,
}

fn write_adversarial_outputs(out: &Path, results: &[ProbeResult], audited: usize) {
    let attacks: Vec<&ProbeResult> = results
        .iter()
        .filter(|r| r.class == Class::Attack)
        .collect();
    let controls: Vec<&ProbeResult> = results
        .iter()
        .filter(|r| r.class == Class::Control)
        .collect();
    let blocked_attacks = attacks.iter().filter(|r| r.blocked).count();
    let allowed_controls = controls.iter().filter(|r| !r.blocked).count();
    let block_rate = pct(blocked_attacks, attacks.len());
    let availability = pct(allowed_controls, controls.len());

    let mut csv = String::from("id,class,blocked,expected_block,pass,description\n");
    for r in results {
        csv.push_str(&format!(
            "{},{},{},{},{},{}\n",
            r.id,
            if r.class == Class::Attack {
                "attack"
            } else {
                "control"
            },
            r.blocked,
            r.class == Class::Attack,
            r.pass,
            r.description,
        ));
    }
    let _ = fs::write(out.join("adversarial.csv"), &csv);

    let mut md = String::new();
    md.push_str("# Adversarial block-rate (thesis §3.9.2)\n\n");
    md.push_str(&format!(
        "**Block rate:** {blocked_attacks}/{} attacks blocked ({block_rate:.1}%). \
         **Availability:** {allowed_controls}/{} legitimate requests allowed ({availability:.1}%). \
         {audited} events written to the tamper-evident audit log.\n\n",
        attacks.len(),
        controls.len(),
    ));
    md.push_str("| Probe | Class | Description | Blocked | Expected | Verdict |\n");
    md.push_str("|---|---|---|---|---|---|\n");
    for r in results {
        md.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            r.id,
            if r.class == Class::Attack {
                "attack"
            } else {
                "control"
            },
            r.description,
            if r.blocked { "yes" } else { "no" },
            if r.class == Class::Attack {
                "block"
            } else {
                "allow"
            },
            if r.pass { "PASS" } else { "FAIL" },
        ));
    }
    let _ = fs::write(out.join("adversarial.md"), &md);

    println!(
        "   block rate {blocked_attacks}/{} ({block_rate:.1}%), availability {allowed_controls}/{} ({availability:.1}%)",
        attacks.len(),
        controls.len()
    );
    for r in results {
        println!(
            "   {} {:<8} blocked={:<5} {}",
            r.id,
            if r.class == Class::Attack {
                "attack"
            } else {
                "control"
            },
            r.blocked,
            if r.pass { "PASS" } else { "FAIL" }
        );
    }
}

fn pct(num: usize, den: usize) -> f64 {
    if den == 0 {
        100.0
    } else {
        num as f64 * 100.0 / den as f64
    }
}
