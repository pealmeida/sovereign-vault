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
//! cargo run -p thesis-eval -- latency       [--out DIR] [--iterations N] [--warmup N] [--seed N]
//! cargo run -p thesis-eval -- micro         [--out DIR] [--iterations N] [--warmup N]
//! cargo run -p thesis-eval -- adversarial   [--out DIR]
//! cargo run -p thesis-eval -- all           [--out DIR] [--iterations N] [--warmup N] [--seed N]
//! ```
//!
//! `--warmup N` is an override above a floor of one discarded call, not an
//! absolute count: the microbenchmark always performs one legacy priming read
//! per size, so `--warmup 0` (and the absent flag) still discards that single
//! call. Any `N >= 1` discards exactly `N`. The latency arm discards its warmup
//! on a server built without a `TimingSink`, so discarded calls never reach the
//! measurement buffer.
//!
//! The vault is created in a throwaway temp directory with passphrase custody
//! and removed on exit; nothing touches the user's real vault.

#![forbid(unsafe_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
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
    let warmup: usize = flag(&args, "--warmup")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let seed: Option<u64> = flag(&args, "--seed").and_then(|s| s.parse().ok());
    let session = flag(&args, "--session").unwrap_or_else(|| "s0".to_string());
    let protocol = flag(&args, "--protocol").unwrap_or_else(|| "legacy".to_string());
    let out = PathBuf::from(&out_dir);
    if let Err(e) = fs::create_dir_all(&out) {
        eprintln!("cannot create {}: {e}", out.display());
        std::process::exit(1);
    }

    match cmd {
        "latency" => run_latency(&out, iterations, warmup, seed, &session, &protocol).await,
        "micro" => run_micro(&out, iterations, warmup).await,
        "adversarial" => run_adversarial(&out).await,
        "enforce_scopes" => run_enforce_scopes(&out, iterations, warmup, &session).await,
        "pii" => run_pii(&out),
        "headless_probes" => run_headless_probes(&out).await,
        "all" => {
            run_latency(&out, iterations, warmup, seed, &session, &protocol).await;
            run_micro(&out, iterations, warmup).await;
            run_adversarial(&out).await;
        }
        other => {
            eprintln!(
                "unknown subcommand {other:?}; use: latency | micro | adversarial | enforce_scopes | all"
            );
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
    p99_us: f64,
    /// Bootstrap 95% CI on the *median*, resampled with replacement from this
    /// session's own `n` timed calls (session remains the independent unit
    /// for cross-session inference — see `docs/thesis/evidence/aggregate.py`;
    /// this is a within-session precision estimate, not a substitute for it).
    ci95_lo_us: f64,
    ci95_hi_us: f64,
}

fn summarize(micros: Vec<f64>) -> Stats {
    summarize_seeded(micros, 0)
}

/// Same as [`summarize`] plus p99 and a bootstrap CI on the median. `seed`
/// only drives the bootstrap resampling (deterministic, auditable), never the
/// measured values themselves.
fn summarize_seeded(mut micros: Vec<f64>, seed: u64) -> Stats {
    let n = micros.len();
    if n == 0 {
        return Stats {
            n: 0,
            mean_us: 0.0,
            p50_us: 0.0,
            p95_us: 0.0,
            p99_us: 0.0,
            ci95_lo_us: 0.0,
            ci95_hi_us: 0.0,
        };
    }
    let mean_us = micros.iter().sum::<f64>() / n as f64;
    micros.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pick = |v: &[f64], q: f64| -> f64 {
        let idx = ((v.len() as f64 - 1.0) * q).round() as usize;
        v[idx.min(v.len() - 1)]
    };
    let (ci95_lo_us, ci95_hi_us) = bootstrap_median_ci(&micros, seed);
    Stats {
        n,
        mean_us,
        p50_us: pick(&micros, 0.50),
        p95_us: pick(&micros, 0.95),
        p99_us: pick(&micros, 0.99),
        ci95_lo_us,
        ci95_hi_us,
    }
}

/// Percentile-bootstrap 95% CI on the median of an already-sorted sample,
/// resampling with replacement B=2000 times. Uses the existing [`XorShift64`]
/// generator so no `rand` dependency is needed for this deterministic op.
fn bootstrap_median_ci(sorted: &[f64], seed: u64) -> (f64, f64) {
    const B: usize = 2000;
    let n = sorted.len();
    if n == 0 {
        return (0.0, 0.0);
    }
    let mut rng = XorShift64::new(seed ^ 0xC1A0_DA7A_5EED_u64 ^ n as u64);
    let mut medians: Vec<f64> = Vec::with_capacity(B);
    let mut resample = vec![0.0f64; n];
    for _ in 0..B {
        for slot in resample.iter_mut() {
            let idx = (rng.next_u64() % n as u64) as usize;
            *slot = sorted[idx];
        }
        resample.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let idx = ((n as f64 - 1.0) * 0.50).round() as usize;
        medians.push(resample[idx.min(n - 1)]);
    }
    medians.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let at = |q: f64| -> f64 {
        let idx = ((medians.len() as f64 - 1.0) * q).round() as usize;
        medians[idx.min(medians.len() - 1)]
    };
    (at(0.025), at(0.975))
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

async fn run_micro(out: &Path, iterations: usize, warmup: usize) {
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

        // Preserve the legacy one-shot priming read for the default (`--warmup`
        // absent or zero) path. When requested, `warmup` instead controls the
        // exact number of discarded calls before the measured loop.
        for _ in 0..micro_warmup_iterations(warmup) {
            let _ = handle.read_file("bench", &name).expect("warm read");
        }
        let decrypt_us = measure_iterations(iterations, || {
            let t0 = std::time::Instant::now();
            let _ = handle.read_file("bench", &name).expect("read");
            us(t0.elapsed())
        });

        // Isolated PII filter (no vault): redact on PII-bearing text.
        let text = pii_payload(size);
        for _ in 0..micro_warmup_iterations(warmup) {
            let _ = sv_privacy::redact(&text, &policy);
        }
        let filter_us = measure_iterations(iterations, || {
            let t0 = std::time::Instant::now();
            let _ = sv_privacy::redact(&text, &policy);
            us(t0.elapsed())
        });

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
    md.push_str(
        "# Component micro-measurements — isolated (thesis §3.9.1, Eq. 1 completeness)\n\n",
    );
    md.push_str("Pure cost of the two content-sensitive gateway components measured *outside* the gateway: `sv_storage` decrypt+read (`T_vault` floor) and `sv_privacy::redact` (`T_filter` floor), each in a tight loop with no dispatch overhead. Compare to the gateway-stage figures in `latency.md` to isolate per-component dispatch overhead.\n\n");
    md.push_str("| Bytes | decrypt mean (us) | decrypt p95 | filter mean (us) | filter p95 |\n");
    md.push_str("|---|---|---|---|---|\n");
    let mut csv =
        String::from("bytes,decrypt_mean_us,decrypt_p95_us,filter_mean_us,filter_p95_us\n");
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
    write_micro_metadata(out, &rows, warmup);
    println!("   wrote {}/micro.csv and micro.md", out.display());

    drop(handle);
    let _ = fs::remove_dir_all(&root);
}

/// Emits a companion CSV only when `--warmup` changes the microbenchmark.
/// Keeping metadata separate preserves the legacy `micro.csv` schema for the
/// default invocation while making the effective discarded count auditable.
fn write_micro_metadata(out: &Path, rows: &[MicroRow], warmup: usize) {
    if warmup == 0 {
        return;
    }
    let mut csv = String::from("bytes,warmup\n");
    for row in rows {
        csv.push_str(&format!("{},{}\n", row.bytes, warmup));
    }
    fs::write(out.join("micro-metadata.csv"), csv).expect("write micro-metadata.csv");
}

fn micro_warmup_iterations(warmup: usize) -> usize {
    if warmup == 0 {
        1
    } else {
        warmup
    }
}

fn measure_iterations<T>(iterations: usize, mut operation: impl FnMut() -> T) -> Vec<T> {
    (0..iterations).map(|_| operation()).collect()
}

// ---------------------------------------------------------------------------
// Latency evaluation (§3.9.1, Equation 1)
// ---------------------------------------------------------------------------

async fn run_latency(
    out: &Path,
    iterations: usize,
    warmup: usize,
    seed: Option<u64>,
    session: &str,
    protocol: &str,
) {
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
    for (execution_order, cell) in latency_cells(seed).into_iter().enumerate() {
        let timing = Arc::new(CaptureTiming::default());
        if warmup > 0 {
            // This server intentionally has no TimingSink: the exact same
            // gateway call and payload are exercised, but discarded calls
            // cannot enter the measurements' capture buffer.
            let warmup_server = McpServer::new(shared.clone(), PAIRING_SECRET)
                .with_access_controller(Arc::new(AutoAllow));
            drive_reads_stdio(
                &warmup_server,
                cell.name,
                &format!("f{}", cell.bytes),
                warmup,
            )
            .await;
        }
        let server = McpServer::new(shared.clone(), PAIRING_SECRET)
            .with_access_controller(Arc::new(AutoAllow))
            .with_timing_sink(timing.clone());
        drive_reads_stdio(&server, cell.name, &format!("f{}", cell.bytes), iterations).await;

        let records = timing.0.lock().unwrap();
        let cell_seed = seed.unwrap_or(0) ^ (cell.bytes as u64) ^ (execution_order as u64) << 32;
        let row = LatencyRow {
            mode: cell.name.to_string(),
            bytes: cell.bytes,
            warmup,
            seed,
            execution_order,
            total: summarize_seeded(records.iter().map(|t| us(t.total)).collect(), cell_seed),
            validate: summarize(records.iter().map(|t| us(t.validate)).collect()),
            authorize: summarize(records.iter().map(|t| us(t.authorize)).collect()),
            execute: summarize(records.iter().map(|t| us(t.execute)).collect()),
            filter: summarize(records.iter().map(|t| us(t.filter)).collect()),
        };
        rows.push(row);
    }

    write_latency_outputs(out, &rows);
    write_latency_v2(out, &rows, protocol, session);
    let _ = fs::remove_dir_all(&root);
    println!("   wrote {}/latency.csv and latency.md\n", out.display());
}

/// Payload-size label matching the thesis's three fixed sizes.
fn payload_label(bytes: usize) -> String {
    match bytes {
        128 => "128B".to_string(),
        1024 => "1KiB".to_string(),
        16384 => "16KiB".to_string(),
        other => format!("{other}B"),
    }
}

/// Per-session, per-cell row for the corrected-protocol evidence set
/// (docs/thesis/EVAL-PROTOCOL.md extension, reviewer items E1/E2). One row
/// per (mode, payload); `ci95_*` bounds the *median* (`p50_us`), bootstrapped
/// within this session's own `n` calls.
fn write_latency_v2(out: &Path, rows: &[LatencyRow], protocol: &str, session: &str) {
    let mut csv = String::from(
        "protocol,session,mode,payload,bytes,n,warmup_n,order_index,mean_us,p50_us,p95_us,p99_us,ci95_lo_us,ci95_hi_us\n",
    );
    for r in rows {
        let s = &r.total;
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{:.3},{:.3},{:.3},{:.3},{:.3},{:.3}\n",
            protocol,
            session,
            r.mode,
            payload_label(r.bytes),
            r.bytes,
            s.n,
            r.warmup,
            r.execution_order,
            s.mean_us,
            s.p50_us,
            s.p95_us,
            s.p99_us,
            s.ci95_lo_us,
            s.ci95_hi_us,
        ));
    }
    let _ = fs::write(out.join("latency_v2.csv"), &csv);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LatencyCell {
    name: &'static str,
    bytes: usize,
}

fn latency_cells(seed: Option<u64>) -> Vec<LatencyCell> {
    let modes = ["direct", "approval", "otp", "anon"];
    let sizes = [128usize, 1024, 16384];
    let mut cells = Vec::with_capacity(modes.len() * sizes.len());
    for name in modes {
        for bytes in sizes {
            cells.push(LatencyCell { name, bytes });
        }
    }
    if let Some(seed) = seed {
        shuffle_cells(&mut cells, seed);
    }
    cells
}

/// A compact non-cryptographic xorshift64 generator for the optional execution
/// order shuffle. `cargo tree` exposes `rand` only transitively (and at several
/// versions), so declaring it directly would add a manifest dependency solely
/// for this small deterministic operation. This implementation is deliberately
/// local and auditable; it never affects payloads, measured calls, or data.
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        // xorshift's all-zero state is absorbing; preserve a distinct,
        // deterministic shuffle for the valid CLI seed zero.
        Self {
            state: if seed == 0 {
                0x9e37_79b9_7f4a_7c15
            } else {
                seed
            },
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }
}

fn shuffle_cells(cells: &mut [LatencyCell], seed: u64) {
    let mut rng = XorShift64::new(seed);
    for i in (1..cells.len()).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        cells.swap(i, j);
    }
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
    warmup: usize,
    seed: Option<u64>,
    execution_order: usize,
    total: Stats,
    validate: Stats,
    authorize: Stats,
    execute: Stats,
    filter: Stats,
}

/// Writes the legacy long-form latency CSV and, when either optional flag is
/// active, a companion metadata CSV. Separating metadata preserves the default
/// `latency.csv` schema while retaining warmup, seed, and execution order.
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

    write_latency_metadata(out, rows);

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

fn write_latency_metadata(out: &Path, rows: &[LatencyRow]) {
    let Some(first) = rows.first() else {
        return;
    };
    if first.warmup == 0 && first.seed.is_none() {
        return;
    }
    let mut csv = String::from("mode,bytes,warmup,seed,execution_order\n");
    for row in rows {
        csv.push_str(&format!(
            "{},{},{},{},{}\n",
            row.mode,
            row.bytes,
            row.warmup,
            row.seed
                .map_or_else(|| "none".to_string(), |seed| seed.to_string()),
            row.execution_order,
        ));
    }
    let _ = fs::write(out.join("latency-metadata.csv"), csv);
}

// ---------------------------------------------------------------------------
// enforce_scopes on the authenticated WS path (reviewer item 5 / E3)
// ---------------------------------------------------------------------------
//
// The stdio path used by `run_latency` never resolves an agent, so
// `enforce_scopes` (crates/sv-mcp/src/lib.rs) is never invoked there — that is
// the exact gap reviewer item 5 flags (thesis §4.1). This measures the real
// authenticated WebSocket path, which does resolve an agent and does run
// `enforce_scopes`, and decomposes it by scope-set size.
//
// `enforce_scopes` short-circuits to `Ok(())` when `agent.scopes.is_empty()`
// (see sv-mcp), so the unscoped agent is not a code-level bypass — it is the
// same function, real code, taking its cheapest branch. A literal bypass
// (skipping the `if let Some(agent)` check) was intentionally not built: the
// task's hard constraint is not to modify the gateway to make a measurement
// easier, and this comparison does not require it.

/// One (scope_set_size, creds) arm of the WS enforcement decomposition.
struct ScopeArm {
    label: &'static str,
    scope_set_size: usize,
    creds: Option<(String, String)>,
}

async fn run_enforce_scopes(out: &Path, iterations: usize, warmup: usize, session: &str) {
    println!("== enforce_scopes on the authenticated WS path (reviewer item 5) ==");
    let (handle, root) = bootstrap("enforce_scopes");
    handle
        .create_container("bench", SecurityMode::Direct, None)
        .expect("container");
    let sizes = [128usize, 1024, 16384];
    for size in sizes {
        let content = payload_for(SecurityMode::Direct, size);
        handle
            .write_file("bench", &format!("f{size}"), &content)
            .expect("seed file");
    }

    // Small scope set: exactly one scope, matching immediately.
    let (small_id, small_token) = handle
        .create_agent(
            "scope-small",
            vec![AgentScope {
                container_glob: "bench".into(),
                actions: vec!["read".into()],
                mode_ceiling: None,
            }],
        )
        .expect("agent");

    // Large scope set: 19 non-matching decoys plus the matching scope LAST,
    // so `enforce_scopes`'s linear scan pays its worst case for this request.
    let mut large_scopes: Vec<AgentScope> = (0..19)
        .map(|i| AgentScope {
            container_glob: format!("decoy-{i}"),
            actions: vec!["read".into()],
            mode_ceiling: None,
        })
        .collect();
    large_scopes.push(AgentScope {
        container_glob: "bench".into(),
        actions: vec!["read".into()],
        mode_ceiling: None,
    });
    let (large_id, large_token) = handle
        .create_agent("scope-large", large_scopes)
        .expect("agent");

    handle.ensure_default_agent(PAIRING_SECRET).expect("default agent");
    let token_key = handle.agent_token_key();

    let shared: SharedVault<VaultHandle> = Arc::new(Mutex::new(Some(handle)));
    let timing = Arc::new(CaptureTiming::default());
    let authenticator = Arc::new(HarnessAuthenticator {
        root: root.clone(),
        token_key,
        shared_secret: PAIRING_SECRET.to_string(),
    });
    let server = Arc::new(
        McpServer::new(shared.clone(), PAIRING_SECRET)
            .with_access_controller(Arc::new(AutoAllow))
            .with_timing_sink(timing.clone())
            .with_agent_authenticator(authenticator),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let serve_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let _ = server.serve_ws_listener(listener, shutdown_rx).await;
        })
    };
    let url = format!("ws://{addr}");

    let arms = [
        ScopeArm {
            label: "scope_0_unscoped",
            scope_set_size: 0,
            creds: None,
        },
        ScopeArm {
            label: "scope_1_small",
            scope_set_size: 1,
            creds: Some((small_id.clone(), small_token.clone())),
        },
        ScopeArm {
            label: "scope_20_large",
            scope_set_size: 20,
            creds: Some((large_id.clone(), large_token.clone())),
        },
    ];

    let mut rows: Vec<EnforceScopesRow> = Vec::new();
    for (order_index, arm) in arms.iter().enumerate() {
        for &size in &sizes {
            let file = format!("f{size}");
            let creds = arm.creds.as_ref().map(|(a, b)| (a.as_str(), b.as_str()));
            if warmup > 0 {
                ws_drive_reads(&url, creds, "bench", &file, warmup).await;
                timing.0.lock().unwrap().clear();
            } else {
                timing.0.lock().unwrap().clear();
            }
            ws_drive_reads(&url, creds, "bench", &file, iterations).await;
            let records: Vec<StageTimings> = timing.0.lock().unwrap().drain(..).collect();
            let cell_seed = 0xE5C0_9E5_u64 ^ (arm.scope_set_size as u64) ^ (size as u64) << 16;
            rows.push(EnforceScopesRow {
                label: arm.label,
                scope_set_size: arm.scope_set_size,
                bytes: size,
                total: summarize_seeded(records.iter().map(|t| us(t.total)).collect(), cell_seed),
                validate: summarize(records.iter().map(|t| us(t.validate)).collect()),
                authorize: summarize(records.iter().map(|t| us(t.authorize)).collect()),
                execute: summarize(records.iter().map(|t| us(t.execute)).collect()),
                filter: summarize(records.iter().map(|t| us(t.filter)).collect()),
                order_index,
            });
        }
    }

    let _ = shutdown_tx.send(());
    let _ = serve_task.await;

    write_enforce_scopes_outputs(out, &rows, session, iterations, warmup);
    let _ = fs::remove_dir_all(&root);
    println!(
        "   wrote {}/enforce_scopes.csv and enforce_scopes_stages.csv\n",
        out.display()
    );
}

/// Pair once, then drive `n` sequential `vault.read` calls over one
/// authenticated WS connection — the real network stack, not the in-process
/// stdio duplex `run_latency` uses.
async fn ws_drive_reads(url: &str, creds: Option<(&str, &str)>, container: &str, file: &str, n: usize) {
    let (mut ws, _resp) = tokio_tungstenite::connect_async(url)
        .await
        .expect("ws connect");
    let pair = match creds {
        Some((id, tok)) => {
            json!({"jsonrpc":"2.0","id":0,"method":"vault.pair","params":{"agent_id":id,"token":tok}})
        }
        None => json!({"jsonrpc":"2.0","id":0,"method":"vault.pair","params":{"secret":PAIRING_SECRET}}),
    };
    ws.send(Message::Text(pair.to_string().into()))
        .await
        .expect("send pair");
    let resp = next_json(&mut ws).await.expect("pair response");
    assert_eq!(resp["result"]["paired"], json!(true), "pairing failed: {resp}");

    for i in 0..n {
        let call = json!({
            "jsonrpc":"2.0","id":i+1,"method":"tools/call",
            "params": {"name": "vault.read", "arguments": {"container": container, "file_name": file}}
        });
        ws.send(Message::Text(call.to_string().into()))
            .await
            .expect("send call");
        let resp = next_json(&mut ws).await.expect("call response");
        assert!(
            resp.get("error").is_none() && resp["result"]["isError"] != json!(true),
            "call failed: {resp}"
        );
    }
    let _ = ws.send(Message::Close(None)).await;
}

struct EnforceScopesRow {
    label: &'static str,
    scope_set_size: usize,
    bytes: usize,
    total: Stats,
    validate: Stats,
    authorize: Stats,
    execute: Stats,
    filter: Stats,
    order_index: usize,
}

fn write_enforce_scopes_outputs(
    out: &Path,
    rows: &[EnforceScopesRow],
    session: &str,
    iterations: usize,
    warmup: usize,
) {
    // Primary schema (docs/thesis §8): delta vs the scope_0_unscoped floor at
    // the same payload, paired within this session.
    let mut csv = String::from(
        "path,scope_set_size,mode,payload,n,k,median_us,ci95_lo_us,ci95_hi_us,delta_vs_bypass_us,delta_ci95_lo,delta_ci95_hi\n",
    );
    for r in rows {
        let floor = rows
            .iter()
            .find(|f| f.scope_set_size == 0 && f.bytes == r.bytes)
            .map(|f| f.total.p50_us)
            .unwrap_or(0.0);
        let delta = r.total.p50_us - floor;
        csv.push_str(&format!(
            "ws_authenticated,{},direct,{},{},{},{:.3},{:.3},{:.3},{:.3},,\n",
            r.scope_set_size,
            payload_label(r.bytes),
            iterations,
            1,
            r.total.p50_us,
            r.total.ci95_lo_us,
            r.total.ci95_hi_us,
            delta,
        ));
    }
    let _ = fs::write(out.join("enforce_scopes.csv"), &csv);

    // Stage decomposition companion — not in the fixed filename list but
    // needed to answer "which stages could you isolate" (§5, E3).
    let mut stages_csv = String::from(
        "session,label,scope_set_size,payload,bytes,order_index,stage,n,mean_us,p50_us,p95_us,p99_us\n",
    );
    for r in rows {
        for (stage, s) in [
            ("validate_plus_scope_check", &r.validate),
            ("authorize_hitl", &r.authorize),
            ("execute_vault", &r.execute),
            ("filter_pii", &r.filter),
            ("total", &r.total),
        ] {
            stages_csv.push_str(&format!(
                "{},{},{},{},{},{},{},{},{:.3},{:.3},{:.3},{:.3}\n",
                session,
                r.label,
                r.scope_set_size,
                payload_label(r.bytes),
                r.bytes,
                r.order_index,
                stage,
                s.n,
                s.mean_us,
                s.p50_us,
                s.p95_us,
                s.p99_us,
            ));
        }
    }
    let _ = fs::write(out.join("enforce_scopes_stages.csv"), &stages_csv);

    for r in rows {
        println!(
            "   {:<18} {:>6}B  total_p50={:>7.3}us (validate+scope={:.3} authorize={:.3} execute={:.3} filter={:.3})",
            r.label, r.bytes, r.total.p50_us, r.validate.p50_us, r.authorize.p50_us, r.execute.p50_us, r.filter.p50_us
        );
    }
    let _ = warmup; // recorded via run-metadata.json (collect-metadata.sh), not per-row here
}

// ---------------------------------------------------------------------------
// PII filter characterization against the real sv-privacy crate (E4)
// ---------------------------------------------------------------------------
//
// Calls `sv_privacy::scan`/`redact` directly — no vault, no gateway. All
// generated identifiers are synthetic: CPF/CNPJ/card numbers are randomly
// generated digits passed through the *same public, standard* check-digit
// algorithms sv-privacy itself validates against (CPF/CNPJ have no official
// reserved-test range; this mirrors the fixed synthetic CPF the harness
// already uses elsewhere in this file). Card numbers use the recognized
// 400000 test BIN. Email uses RFC 2606 reserved domains. IPv4 uses RFC 1918
// ranges. Phone uses the NANP 555-01XX fictional-use block. SSN uses the
// 900-999 area range the SSA states it will never issue.

fn pii_luhn_check_digit(prefix: &[u8]) -> u8 {
    // Compute the trailing digit that makes `prefix + digit` Luhn-valid.
    let mut sum = 0u32;
    let mut double = true; // the check digit itself is never doubled
    for &d in prefix.iter().rev() {
        let mut v = d as u32;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    ((10 - (sum % 10)) % 10) as u8
}

fn pii_cpf_check_digits(base: &[u8; 9]) -> (u8, u8) {
    let check = |data: &[u8], start_weight: usize| -> u8 {
        let sum: usize = data
            .iter()
            .enumerate()
            .map(|(k, &d)| d as usize * (start_weight - k))
            .sum();
        let r = (sum * 10) % 11;
        if r == 10 {
            0
        } else {
            r as u8
        }
    };
    let d1 = check(base, 10);
    let mut with_d1 = base.to_vec();
    with_d1.push(d1);
    let d2 = check(&with_d1, 11);
    (d1, d2)
}

fn pii_cnpj_check_digits(base: &[u8; 12]) -> (u8, u8) {
    let weights1 = [5usize, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let digit = |data: &[u8], weights: &[usize]| -> u8 {
        let sum: usize = data.iter().zip(weights).map(|(&d, &w)| d as usize * w).sum();
        let r = sum % 11;
        if r < 2 {
            0
        } else {
            (11 - r) as u8
        }
    };
    let d1 = digit(base, &weights1);
    let mut with_d1 = base.to_vec();
    with_d1.push(d1);
    let weights2 = [6usize, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
    let d2 = digit(&with_d1, &weights2);
    (d1, d2)
}

fn pii_gen_cpf(rng: &mut XorShift64, punct: &str) -> String {
    let mut base = [0u8; 9];
    for slot in base.iter_mut() {
        *slot = (rng.next_u64() % 10) as u8;
    }
    if base.iter().all(|&x| x == base[0]) {
        base[0] = (base[0] + 1) % 10;
    }
    let (d1, d2) = pii_cpf_check_digits(&base);
    let digits: Vec<u8> = base.iter().copied().chain([d1, d2]).collect();
    match punct {
        "canonical" => format!(
            "{}{}{}.{}{}{}.{}{}{}-{}{}",
            digits[0], digits[1], digits[2], digits[3], digits[4], digits[5], digits[6],
            digits[7], digits[8], digits[9], digits[10]
        ),
        "bare" => digits.iter().map(|d| d.to_string()).collect(),
        "spaced" => digits
            .iter()
            .map(|d| d.to_string())
            .collect::<Vec<_>>()
            .join(" "),
        "slashed" => format!(
            "{}{}{}/{}{}{}/{}{}{}-{}{}",
            digits[0], digits[1], digits[2], digits[3], digits[4], digits[5], digits[6],
            digits[7], digits[8], digits[9], digits[10]
        ),
        _ => unreachable!(),
    }
}

fn pii_gen_cnpj(rng: &mut XorShift64, punct: &str) -> String {
    let mut base = [0u8; 12];
    for slot in base.iter_mut() {
        *slot = (rng.next_u64() % 10) as u8;
    }
    if base.iter().all(|&x| x == base[0]) {
        base[0] = (base[0] + 1) % 10;
    }
    let (d1, d2) = pii_cnpj_check_digits(&base);
    let digits: Vec<u8> = base.iter().copied().chain([d1, d2]).collect();
    let s = |i: usize| digits[i].to_string();
    match punct {
        "canonical" => format!(
            "{}{}.{}{}{}.{}{}{}/{}{}{}{}-{}{}",
            s(0), s(1), s(2), s(3), s(4), s(5), s(6), s(7), s(8), s(9), s(10), s(11), s(12), s(13)
        ),
        "bare" => digits.iter().map(|d| d.to_string()).collect(),
        "spaced" => digits
            .iter()
            .map(|d| d.to_string())
            .collect::<Vec<_>>()
            .join(" "),
        _ => unreachable!(),
    }
}

fn pii_gen_card(rng: &mut XorShift64, punct: &str) -> String {
    // Recognized 400000 test BIN + 9 random digits + Luhn check digit = 16.
    let mut prefix = vec![4u8, 0, 0, 0, 0, 0];
    for _ in 0..9 {
        prefix.push((rng.next_u64() % 10) as u8);
    }
    let check = pii_luhn_check_digit(&prefix);
    let digits: Vec<u8> = prefix.into_iter().chain([check]).collect();
    let groups: Vec<String> = digits
        .chunks(4)
        .map(|c| c.iter().map(|d| d.to_string()).collect::<String>())
        .collect();
    match punct {
        "canonical" => groups.join("-"),
        "spaced" => groups.join(" "),
        "bare" => digits.iter().map(|d| d.to_string()).collect(),
        "dotted" => groups.join("."),
        _ => unreachable!(),
    }
}

fn pii_gen_email(rng: &mut XorShift64, variant: &str) -> String {
    let domains = ["example.com", "example.org", "example.net"];
    let domain = domains[(rng.next_u64() % 3) as usize];
    let local = format!("user{}", rng.next_u64() % 100000);
    match variant {
        "canonical" => format!("{local}@{domain}"),
        "plus_tag" => format!("{local}+tag{}@{domain}", rng.next_u64() % 100),
        "spaced" => {
            let d = domain.replace('.', " . ");
            format!("{local} @ {d}")
        }
        "obfuscated" => {
            let d = domain.replace('.', "[dot]");
            format!("{local}[at]{d}")
        }
        _ => unreachable!(),
    }
}

fn pii_gen_ipv4(rng: &mut XorShift64, variant: &str) -> String {
    // RFC 1918 private ranges only.
    let block = rng.next_u64() % 3;
    let (a, b_range): (u8, (u8, u8)) = match block {
        0 => (10, (0, 255)),
        1 => (172, (16, 31)),
        _ => (192, (168, 168)),
    };
    let b = if b_range.0 == b_range.1 {
        b_range.0
    } else {
        b_range.0 + (rng.next_u64() % (b_range.1 as u64 - b_range.0 as u64 + 1)) as u8
    };
    let c = (rng.next_u64() % 256) as u8;
    let d = (rng.next_u64() % 254 + 1) as u8;
    match variant {
        "canonical" => format!("{a}.{b}.{c}.{d}"),
        "leading_zero" => format!("{a:03}.{b:03}.{c:03}.{d:03}"),
        "spaced" => format!("{a} . {b} . {c} . {d}"),
        "cidr_suffix" => format!("{a}.{b}.{c}.{d}/24"),
        _ => unreachable!(),
    }
}

fn pii_gen_phone(rng: &mut XorShift64, variant: &str) -> String {
    // NANP fictional-use block: any area code, exchange 555, subscriber 01XX.
    let area = 200 + (rng.next_u64() % 700) as u32; // avoid 0/1 leading area codes
    let sub = 100 + (rng.next_u64() % 100) as u32; // 0100-0199
    match variant {
        "canonical" => format!("({area}) 555-01{:02}", sub % 100),
        "international_br" => format!("+55 11 555-01{:02}", sub % 100),
        "bare" => format!("{area}5550{:03}", 100 + sub % 100),
        "dotted_no_symbol" => format!("{area}.555.01{:02}", sub % 100),
        _ => unreachable!(),
    }
}

fn pii_gen_ssn(rng: &mut XorShift64, variant: &str) -> String {
    // Area 900-999: SSA states these will never be issued.
    let area = 900 + (rng.next_u64() % 100) as u32;
    let group = 1 + (rng.next_u64() % 99) as u32;
    let serial = 1 + (rng.next_u64() % 9999) as u32;
    match variant {
        "canonical" => format!("{area:03}-{group:02}-{serial:04}"),
        "bare" => format!("{area:03}{group:02}{serial:04}"),
        "spaced" => format!("{area:03} {group:02} {serial:04}"),
        "dotted" => format!("{area:03}.{group:02}.{serial:04}"),
        _ => unreachable!(),
    }
}

/// Synthetic examples for categories sv-privacy has NO detector for (the
/// thesis's admitted gaps): RG, CEP, full name, address, birth date,
/// unformatted phone (covered separately above as a *format* variant, but
/// also included here since the thesis lists it among the gaps).
fn pii_gen_gap(rng: &mut XorShift64, category: &str) -> String {
    match category {
        "rg" => format!("{}.{}.{}-{}",
            10 + rng.next_u64() % 90, 100 + rng.next_u64() % 900, 100 + rng.next_u64() % 900,
            (b'0' + (rng.next_u64() % 10) as u8) as char),
        "cep" => format!("{:05}-{:03}", rng.next_u64() % 100000, rng.next_u64() % 1000),
        "full_name" => {
            let first = ["Ana", "Bruno", "Carla", "Diego", "Elisa", "Fabio"][(rng.next_u64() % 6) as usize];
            let last = ["Teste", "Exemplo", "Fictício", "Amostra", "Sintético"][(rng.next_u64() % 5) as usize];
            format!("{first} {last}")
        }
        "address" => format!(
            "Rua Fictícia {}, {} - Bairro Teste",
            rng.next_u64() % 9999, rng.next_u64() % 999
        ),
        "birth_date" => format!(
            "{:02}/{:02}/{}",
            1 + rng.next_u64() % 28, 1 + rng.next_u64() % 12, 1950 + rng.next_u64() % 60
        ),
        "phone_unformatted" => format!("55{:07}", rng.next_u64() % 10000000),
        _ => unreachable!(),
    }
}

fn pii_covered_categories() -> [(&'static str, sv_privacy::PiiCategory); 7] {
    use sv_privacy::PiiCategory::*;
    [
        ("email", Email),
        ("cpf", Cpf),
        ("cnpj", Cnpj),
        ("credit_card", CreditCard),
        ("ipv4", Ipv4),
        ("phone", Phone),
        ("ssn", Ssn),
    ]
}

fn pii_gen_canonical(rng: &mut XorShift64, category: &str) -> String {
    match category {
        "email" => pii_gen_email(rng, "canonical"),
        "cpf" => pii_gen_cpf(rng, "canonical"),
        "cnpj" => pii_gen_cnpj(rng, "canonical"),
        "credit_card" => pii_gen_card(rng, "canonical"),
        "ipv4" => pii_gen_ipv4(rng, "canonical"),
        "phone" => pii_gen_phone(rng, "canonical"),
        "ssn" => pii_gen_ssn(rng, "canonical"),
        _ => unreachable!(),
    }
}

/// Neutral, PII-free filler sentence for false-positive testing.
fn pii_filler_sentence(rng: &mut XorShift64) -> String {
    let words = [
        "o", "sistema", "processa", "dados", "locais", "sem", "enviar", "conteúdo", "para",
        "servidores", "externos", "durante", "a", "execução", "normal", "das", "tarefas",
        "solicitadas", "pelo", "agente", "de", "forma", "auditável", "e", "reversível",
    ];
    (0..12)
        .map(|_| words[(rng.next_u64() % words.len() as u64) as usize])
        .collect::<Vec<_>>()
        .join(" ")
}

fn run_pii(out: &Path) {
    println!("== PII filter characterization against real sv-privacy (E4) ==");
    let mut rng = XorShift64::new(0xF11_7E57);

    // (a) Category recall + false-positive rate.
    let mut recall_csv = String::from("category,covered,n,detected,recall,fp_on_filler,filler_trials\n");
    for (label, expected) in pii_covered_categories() {
        let mut detected = 0;
        const N: usize = 200;
        for _ in 0..N {
            let item = pii_gen_canonical(&mut rng, label);
            let text = format!("Contact record: {item} please process.");
            let findings = sv_privacy::scan(&text, &sv_privacy::Policy::all());
            if findings.iter().any(|f| f.category == expected) {
                detected += 1;
            }
        }
        // False positives: how often filler text (no PII) trips *any* detector.
        let mut fp = 0;
        const FILLER_N: usize = 500;
        for _ in 0..FILLER_N {
            let text = pii_filler_sentence(&mut rng);
            let findings = sv_privacy::scan(&text, &sv_privacy::Policy::all());
            if !findings.is_empty() {
                fp += 1;
            }
        }
        recall_csv.push_str(&format!(
            "{label},true,{N},{detected},{:.4},{fp},{FILLER_N}\n",
            detected as f64 / N as f64
        ));
        println!("  [covered] {label:<12} recall={detected}/{N}  fp_on_filler={fp}/{FILLER_N}");
    }

    // Gap categories: the thesis's 6 admitted gaps. No detector exists, so
    // recall is 0 by construction; we confirm that and check for accidental
    // cross-category false positives (collateral detections).
    let gap_categories = ["rg", "cep", "full_name", "address", "birth_date", "phone_unformatted"];
    for label in gap_categories {
        let mut detected = 0;
        let mut collateral = 0;
        const N: usize = 200;
        for _ in 0..N {
            let item = pii_gen_gap(&mut rng, label);
            let text = format!("Contact record: {item} please process.");
            let findings = sv_privacy::scan(&text, &sv_privacy::Policy::all());
            // "detected" would mean some detector fired ON the inserted span;
            // approximate by checking whether the item substring is still
            // present verbatim in the redaction output (i.e. untouched).
            let redaction = sv_privacy::redact(&text, &sv_privacy::Policy::all());
            if !redaction.output.contains(&item) {
                detected += 1; // something masked part of our inserted span
            }
            if !findings.is_empty() {
                collateral += 1;
            }
        }
        recall_csv.push_str(&format!(
            "{label},false,{N},{detected},{:.4},{collateral},{N}\n",
            detected as f64 / N as f64
        ));
        println!("  [gap]     {label:<18} recall={detected}/{N}  collateral_findings={collateral}/{N}");
    }
    fs::write(out.join("pii_filter_characterization.csv"), &recall_csv)
        .expect("write pii_filter_characterization.csv");

    // (b) Format robustness.
    let variant_sets: &[(&str, &[&str])] = &[
        ("cpf", &["canonical", "bare", "spaced", "slashed"]),
        ("cnpj", &["canonical", "bare", "spaced"]),
        ("credit_card", &["canonical", "spaced", "bare", "dotted"]),
        ("email", &["canonical", "plus_tag", "spaced", "obfuscated"]),
        ("ipv4", &["canonical", "leading_zero", "spaced", "cidr_suffix"]),
        ("phone", &["canonical", "international_br", "bare", "dotted_no_symbol"]),
        ("ssn", &["canonical", "bare", "spaced", "dotted"]),
    ];
    let mut format_csv = String::from("category,variant,n,detected,detect_rate\n");
    for (category, variants) in variant_sets {
        let expected = pii_covered_categories()
            .into_iter()
            .find(|(l, _)| l == category)
            .unwrap()
            .1;
        for variant in *variants {
            const N: usize = 60;
            let mut detected = 0;
            for _ in 0..N {
                let item = match *category {
                    "cpf" => pii_gen_cpf(&mut rng, variant),
                    "cnpj" => pii_gen_cnpj(&mut rng, variant),
                    "credit_card" => pii_gen_card(&mut rng, variant),
                    "email" => pii_gen_email(&mut rng, variant),
                    "ipv4" => pii_gen_ipv4(&mut rng, variant),
                    "phone" => pii_gen_phone(&mut rng, variant),
                    "ssn" => pii_gen_ssn(&mut rng, variant),
                    _ => unreachable!(),
                };
                let text = format!("Contact record: {item} please process.");
                let findings = sv_privacy::scan(&text, &sv_privacy::Policy::all());
                if findings.iter().any(|f| f.category == expected) {
                    detected += 1;
                }
            }
            format_csv.push_str(&format!(
                "{category},{variant},{N},{detected},{:.4}\n",
                detected as f64 / N as f64
            ));
            println!("  [format]  {category:<12} {variant:<18} {detected}/{N}");
        }
    }
    fs::write(out.join("pii_format_robustness.csv"), &format_csv)
        .expect("write pii_format_robustness.csv");

    // (c) Cost decomposition: size x density grid.
    let sizes = [128usize, 1024, 4096, 16384, 65536];
    let densities = [0.0f64, 0.25, 0.5, 0.75, 1.0];
    let pii_unit = "user jane.doe@example.com cpf 529.982.247-25 ip 192.168.0.1; ";
    let filler_unit = "lorem ipsum dolor sit amet consectetur adipiscing elit sed; ";
    let mut cost_csv = String::from("bytes,density,n,mean_us,p50_us\n");
    const COST_N: usize = 50;
    for &size in &sizes {
        for &density in &densities {
            let mut text = String::with_capacity(size + 64);
            while text.len() < size {
                let roll = (rng.next_u64() % 1000) as f64 / 1000.0;
                if roll < density {
                    text.push_str(pii_unit);
                } else {
                    text.push_str(filler_unit);
                }
            }
            text.truncate(size);
            let policy = sv_privacy::Policy::all();
            let times: Vec<f64> = (0..COST_N)
                .map(|_| {
                    let t0 = std::time::Instant::now();
                    let _ = sv_privacy::redact(&text, &policy);
                    us(t0.elapsed())
                })
                .collect();
            let stats = summarize(times);
            cost_csv.push_str(&format!(
                "{size},{density},{COST_N},{:.4},{:.4}\n",
                stats.mean_us, stats.p50_us
            ));
        }
    }
    fs::write(out.join("pii_cost_size_x_density.csv"), &cost_csv)
        .expect("write pii_cost_size_x_density.csv");
    println!("   wrote {}/pii_*.csv\n", out.display());
}

// ---------------------------------------------------------------------------
// Headless fail-closed probe battery, against the REAL headless CLI (E5)
// ---------------------------------------------------------------------------
//
// `run_adversarial`'s `HitlPolicy` is a hand-written mirror of the desktop's
// consent policy (its own doc comment says so) — it is not the real headless
// fail-closed path the thesis's reviewer item 5 asks about. That real path
// is `apps/cli/src/serve.rs`'s `HeadlessAccessController`
// (`is_headless_allowed_action`, lines ~246-261): an explicit ALLOWLIST, not
// a denylist. `apps/cli` has no library target, so this battery does not
// import that function — it spawns the real `sovereign-vault serve` binary
// as a subprocess and drives probes over its real authenticated WebSocket
// port, so the policy under test is the actual compiled artifact, not a
// reimplementation of it.

struct HeadlessProbe {
    id: &'static str,
    /// Name used in the thesis briefing's provisional reconstruction, for
    /// the required name-reconciliation (§7). `None` = no provisional name
    /// existed (this probe covers a gap found while reading the real code).
    provisional_name: Option<&'static str>,
    real_tool: &'static str,
    class: Class,
    expected_verdict: &'static str,
    arguments: Value,
}

async fn run_headless_probes(out: &Path) {
    println!("== Headless fail-closed probe battery vs. the real CLI (E5) ==");
    let bin = PathBuf::from("target/release/sovereign-vault");
    if !bin.exists() {
        let msg = "NÃO MEDIDO: target/release/sovereign-vault not built (run `cargo build --release -p sovereign-vault` first)";
        eprintln!("{msg}");
        fs::write(out.join("headless_probes_status.txt"), msg).ok();
        return;
    }

    let (handle, root) = bootstrap("headless-probes");
    handle
        .create_container("bench", SecurityMode::Direct, None)
        .expect("container");
    handle
        .write_file("bench", "f1", b"direct content")
        .expect("seed file");
    handle
        .create_container("anon-bench", SecurityMode::Anonymized, None)
        .expect("container");
    handle
        .write_file("anon-bench", "f1", b"user jane.doe@example.com")
        .expect("seed file");

    // One scope granting EVERY action on every container: the point of this
    // battery is to isolate the access-controller's own allowlist, not scope
    // enforcement (already covered by E3 and by the A1-A10 battery).
    let all_actions = [
        "list", "list_files", "read", "write", "delete", "create_container", "destroy",
        "create_transit_key", "list_transit_keys", "encrypt", "decrypt", "create_signing_key",
        "list_signing_keys", "sign", "verify", "create_broker_secret", "list_broker_secrets",
        "broker", "vault_info", "export_agents", "import_agents",
    ];
    let (agent_id, token) = handle
        .create_agent(
            "headless-probe-agent",
            vec![AgentScope {
                container_glob: "*".into(),
                actions: all_actions.iter().map(|s| s.to_string()).collect(),
                mode_ceiling: None,
            }],
        )
        .expect("agent");

    let audit_key = handle.audit_hmac_key();

    // A real Ed25519 keypair for the C3 (`vault.verify`) control, so a
    // legitimate call succeeds instead of erroring on a malformed key —
    // which would misclassify an ALLOWED call as blocked.
    let (secret, public) = sv_core::sv_crypto::ed25519_generate().expect("ed25519 keygen");
    let message = b"headless-probe-c3";
    let signature = sv_core::sv_crypto::ed25519_sign(&secret, message).expect("sign");

    let scratch = std::env::temp_dir().join(format!("sv-headless-probes-{}", std::process::id()));
    fs::create_dir_all(&scratch).expect("scratch dir");
    let pass_file = scratch.join("passphrase");
    let token_file = scratch.join("agent-token");
    fs::write(&pass_file, "evaluation-passphrase").expect("write passphrase file");
    fs::write(&token_file, &token).expect("write token file");
    fs::set_permissions(&pass_file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600)).unwrap();

    // Release the in-process lock before the subprocess opens the same root.
    drop(handle);

    let ws_port = free_port();
    let http_port = free_port();

    let mut child = tokio::process::Command::new(&bin)
        .arg("serve")
        .arg("--root")
        .arg(&root)
        .arg("--passphrase-file")
        .arg(&pass_file)
        .arg("--bind")
        .arg(format!("127.0.0.1:{ws_port}"))
        .arg("--http-bind")
        .arg(format!("127.0.0.1:{http_port}"))
        .arg("--agent-id")
        .arg(&agent_id)
        .arg("--agent-token-file")
        .arg(&token_file)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn sovereign-vault serve");

    let url = format!("ws://127.0.0.1:{ws_port}");
    let mut connected = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if tokio_tungstenite::connect_async(&url).await.is_ok() {
            connected = true;
            break;
        }
    }
    if !connected {
        let _ = child.kill().await;
        let msg = "NÃO MEDIDO: sovereign-vault serve did not bind the WS port within 5s";
        eprintln!("{msg}");
        fs::write(out.join("headless_probes_status.txt"), msg).ok();
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&scratch);
        return;
    }

    let r_verify = json!({
        "public_key_b64": B64.encode(public),
        "payload_b64": B64.encode(message),
        "signature_b64": B64.encode(signature),
    });
    let probes = vec![
        HeadlessProbe { id: "A11", provisional_name: Some("transit.decrypt"), real_tool: "vault.decrypt", class: Class::Attack, expected_verdict: "BLOCKED", arguments: json!({"key_ref":"missing-key","ciphertext_b64":"AAAA"}) },
        HeadlessProbe { id: "A12", provisional_name: Some("signing.sign"), real_tool: "vault.sign", class: Class::Attack, expected_verdict: "BLOCKED", arguments: json!({"key_ref":"missing-key","payload_b64":"AAAA"}) },
        HeadlessProbe { id: "A13", provisional_name: Some("transit.encrypt"), real_tool: "vault.encrypt", class: Class::Attack, expected_verdict: "BLOCKED", arguments: json!({"key_ref":"missing-key","plaintext_b64":"AAAA"}) },
        HeadlessProbe { id: "A14", provisional_name: Some("broker.issue"), real_tool: "vault.create_broker_secret", class: Class::Attack, expected_verdict: "BLOCKED", arguments: json!({"name":"probe-secret","secret":"x","allow":[{"host":"example.com","path_prefix":"/","methods":["GET"]}]}) },
        HeadlessProbe { id: "A15", provisional_name: Some("broker.exchange"), real_tool: "vault.broker_request", class: Class::Attack, expected_verdict: "BLOCKED", arguments: json!({"secret_ref":"nonexistent","method":"GET","url":"https://example.com/"}) },
        HeadlessProbe { id: "A16", provisional_name: None, real_tool: "vault.create_signing_key", class: Class::Attack, expected_verdict: "BLOCKED", arguments: json!({"name":"probe-signing-key"}) },
        HeadlessProbe { id: "A17", provisional_name: None, real_tool: "vault.create_transit_key", class: Class::Attack, expected_verdict: "BLOCKED", arguments: json!({"name":"probe-transit-key"}) },
        HeadlessProbe { id: "A18", provisional_name: None, real_tool: "vault.export_agents", class: Class::Attack, expected_verdict: "BLOCKED", arguments: json!({}) },
        HeadlessProbe { id: "A19", provisional_name: None, real_tool: "vault.import_agents", class: Class::Attack, expected_verdict: "BLOCKED", arguments: json!({"envelope":{"version":1,"exported_at":0,"agents":[]}}) },
        HeadlessProbe { id: "A20", provisional_name: None, real_tool: "vault.list_broker_secrets", class: Class::Attack, expected_verdict: "BLOCKED", arguments: json!({}) },
        HeadlessProbe { id: "C3", provisional_name: None, real_tool: "vault.verify", class: Class::Control, expected_verdict: "ALLOWED", arguments: r_verify },
        HeadlessProbe { id: "C4", provisional_name: None, real_tool: "vault.info", class: Class::Control, expected_verdict: "ALLOWED", arguments: json!({}) },
    ];

    let mut results: Vec<(String, bool, bool, bool)> = Vec::new(); // (id, blocked, transport_error, pass)
    for probe in &probes {
        let outcome = run_probe(&url, Some(agent_id.as_str()), &token, probe.real_tool, &probe.arguments).await;
        let transport_error = matches!(outcome, ProbeOutcome::TransportError(_));
        let blocked = matches!(outcome, ProbeOutcome::Blocked | ProbeOutcome::TransportError(_));
        let expected_block = probe.expected_verdict == "BLOCKED";
        let pass = !transport_error && blocked == expected_block;
        results.push((probe.id.to_string(), blocked, transport_error, pass));
    }

    let _ = child.kill().await;
    let _ = child.wait().await;

    // Verify the real HMAC audit chain now that the subprocess has exited.
    let (chain_ok, chain_entries, chain_reason) = match sv_audit::AuditLog::open(&root, audit_key) {
        Ok(log) => match log.verify_chain() {
            Ok(report) => (report.ok, report.entries, report.reason.unwrap_or_default()),
            Err(e) => (false, 0, e.to_string()),
        },
        Err(e) => (false, 0, e.to_string()),
    };

    write_headless_probes_outputs(out, &probes, &results, chain_ok, chain_entries, &chain_reason);
    let _ = fs::remove_dir_all(&root);
    let _ = fs::remove_dir_all(&scratch);
    println!("   wrote {}/headless_probes.csv\n", out.display());
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().unwrap().port()
}

fn write_headless_probes_outputs(
    out: &Path,
    probes: &[HeadlessProbe],
    results: &[(String, bool, bool, bool)],
    chain_ok: bool,
    chain_entries: usize,
    chain_reason: &str,
) {
    let mut csv = String::from(
        "id,provisional_name,real_tool,class,expected_verdict,observed_verdict,transport_error,pass,audit_chain_ok,audit_chain_entries,audit_chain_reason\n",
    );
    for (probe, (id, blocked, transport_error, pass)) in probes.iter().zip(results) {
        debug_assert_eq!(probe.id, id);
        let observed = if *transport_error {
            "TRANSPORT_ERROR"
        } else if *blocked {
            "BLOCKED"
        } else {
            "ALLOWED"
        };
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},\"{}\"\n",
            id,
            probe.provisional_name.unwrap_or("n/a"),
            probe.real_tool,
            if probe.class == Class::Attack { "attack" } else { "control" },
            probe.expected_verdict,
            observed,
            transport_error,
            pass,
            chain_ok,
            chain_entries,
            chain_reason.replace('"', "'"),
        ));
        println!(
            "   {id:<4} {:<28} expected={:<8} observed={:<8} {}",
            probe.real_tool,
            probe.expected_verdict,
            observed,
            if *pass { "MATCH" } else { "*** MISMATCH ***" },
        );
    }
    let _ = fs::write(out.join("headless_probes.csv"), &csv);
    println!("   audit chain ok={chain_ok} entries={chain_entries} reason={chain_reason:?}");
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
        let outcome = run_probe(&url, id, tok, probe.tool, &probe.arguments).await;
        // A transport failure is infrastructure noise, not a policy decision: it
        // is recorded separately so the aggregator can exclude it from both the
        // block rate and the availability rate instead of silently inflating
        // either one (see docs/thesis/evidence/aggregate.py).
        let transport_error = match &outcome {
            ProbeOutcome::TransportError(e) => {
                eprintln!("   {} transport error: {e}", probe.id);
                true
            }
            _ => false,
        };
        let blocked = matches!(
            outcome,
            ProbeOutcome::Blocked | ProbeOutcome::TransportError(_)
        );
        let expected_block = probe.class == Class::Attack;
        results.push(ProbeResult {
            id: probe.id,
            class: probe.class,
            description: probe.description,
            blocked,
            transport_error,
            pass: !transport_error && blocked == expected_block,
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

/// Outcome of one probe, separating policy decisions from infrastructure noise.
///
/// `Blocked` and `Allowed` are verdicts the server produced; `TransportError`
/// means the exchange never reached a verdict (connect, send or stream
/// failure). Conflating the third case with `Blocked` — as the harness did
/// before — makes a flaky socket look like a working control.
enum ProbeOutcome {
    Blocked,
    Allowed,
    TransportError(String),
}

/// Open one WS connection, pair, issue one tool call, and classify the result.
///
/// A pairing rejection is a policy decision (the server refused the
/// credentials), so it maps to `Blocked`, not to `TransportError`.
async fn run_probe(
    url: &str,
    agent_id: Option<&str>,
    token: &str,
    tool: &str,
    arguments: &Value,
) -> ProbeOutcome {
    macro_rules! transport {
        ($e:expr, $ctx:literal) => {
            match $e {
                Ok(v) => v,
                Err(e) => return ProbeOutcome::TransportError(format!("{}: {e}", $ctx)),
            }
        };
    }

    let (mut ws, _resp) = transport!(tokio_tungstenite::connect_async(url).await, "connect");

    // Pair.
    let pair = match agent_id {
        Some(id) => {
            json!({"jsonrpc":"2.0","id":0,"method":"vault.pair","params":{"agent_id":id,"token":token}})
        }
        None => json!({"jsonrpc":"2.0","id":0,"method":"vault.pair","params":{"secret":token}}),
    };
    transport!(
        ws.send(Message::Text(pair.to_string().into())).await,
        "send pair"
    );
    let pair_resp = transport!(next_json(&mut ws).await, "pair response");
    if pair_resp.get("error").is_some() || pair_resp["result"]["paired"] != json!(true) {
        // The server answered and refused: a policy block, not a transport fault.
        return ProbeOutcome::Blocked;
    }

    // Tool call.
    let call = json!({
        "jsonrpc":"2.0","id":1,"method":"tools/call",
        "params": {"name": tool, "arguments": arguments}
    });
    transport!(
        ws.send(Message::Text(call.to_string().into())).await,
        "send call"
    );
    let resp = transport!(next_json(&mut ws).await, "call response");
    let _ = ws.send(Message::Close(None)).await;

    // A JSON-RPC error or a tool result flagged isError both mean "blocked".
    if resp.get("error").is_some() || resp["result"]["isError"] == json!(true) {
        return ProbeOutcome::Blocked;
    }
    ProbeOutcome::Allowed
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
    /// The exchange never reached a server verdict. Excluded from both rates.
    transport_error: bool,
    pass: bool,
}

/// Counts behind the two reported rates, with transport failures set aside.
struct AdversarialTally {
    blocked_attacks: usize,
    attack_trials: usize,
    allowed_controls: usize,
    control_trials: usize,
    transport_errors: usize,
}

/// Probes that failed in transport carry no policy information, so they are
/// dropped from the numerator *and* the denominator of both rates and reported
/// separately as infrastructure failures.
fn tally_adversarial(results: &[ProbeResult]) -> AdversarialTally {
    let attacks: Vec<&ProbeResult> = results
        .iter()
        .filter(|r| r.class == Class::Attack && !r.transport_error)
        .collect();
    let controls: Vec<&ProbeResult> = results
        .iter()
        .filter(|r| r.class == Class::Control && !r.transport_error)
        .collect();
    AdversarialTally {
        blocked_attacks: attacks.iter().filter(|r| r.blocked).count(),
        attack_trials: attacks.len(),
        allowed_controls: controls.iter().filter(|r| !r.blocked).count(),
        control_trials: controls.len(),
        transport_errors: results.iter().filter(|r| r.transport_error).count(),
    }
}

fn write_adversarial_outputs(out: &Path, results: &[ProbeResult], audited: usize) {
    let tally = tally_adversarial(results);
    let transport_errors = tally.transport_errors;
    let blocked_attacks = tally.blocked_attacks;
    let allowed_controls = tally.allowed_controls;
    let block_rate = pct(blocked_attacks, tally.attack_trials);
    let availability = pct(allowed_controls, tally.control_trials);

    let mut csv =
        String::from("id,class,blocked,transport_error,expected_block,pass,description\n");
    for r in results {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            r.id,
            if r.class == Class::Attack {
                "attack"
            } else {
                "control"
            },
            r.blocked,
            r.transport_error,
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
         **Transport errors (excluded from both rates):** {transport_errors}. \
         {audited} events written to the tamper-evident audit log.\n\n",
        tally.attack_trials, tally.control_trials,
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
            if r.transport_error {
                "n/a (transport)"
            } else if r.blocked {
                "yes"
            } else {
                "no"
            },
            if r.class == Class::Attack {
                "block"
            } else {
                "allow"
            },
            if r.transport_error {
                "TRANSPORT ERROR"
            } else if r.pass {
                "PASS"
            } else {
                "FAIL"
            },
        ));
    }
    let _ = fs::write(out.join("adversarial.md"), &md);

    println!(
        "   block rate {blocked_attacks}/{} ({block_rate:.1}%), availability {allowed_controls}/{} ({availability:.1}%), transport errors {transport_errors}",
        tally.attack_trials,
        tally.control_trials
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
            if r.transport_error {
                "TRANSPORT ERROR"
            } else if r.pass {
                "PASS"
            } else {
                "FAIL"
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_seed_preserves_the_original_cell_order() {
        let order: Vec<(&str, usize)> = latency_cells(None)
            .into_iter()
            .map(|cell| (cell.name, cell.bytes))
            .collect();
        assert_eq!(
            order,
            vec![
                ("direct", 128),
                ("direct", 1024),
                ("direct", 16384),
                ("approval", 128),
                ("approval", 1024),
                ("approval", 16384),
                ("otp", 128),
                ("otp", 1024),
                ("otp", 16384),
                ("anon", 128),
                ("anon", 1024),
                ("anon", 16384),
            ]
        );
    }

    #[test]
    fn same_seed_has_the_same_order_and_different_seed_changes_it() {
        let first = latency_cells(Some(42));
        assert_eq!(first, latency_cells(Some(42)));
        assert_ne!(first, latency_cells(Some(43)));
    }

    #[test]
    fn zero_warmup_keeps_the_measured_iteration_count() {
        let iterations = 20;
        let mut calls = 0;
        let measured = measure_iterations(iterations, || {
            calls += 1;
        });
        assert_eq!(measured.len(), iterations);
        assert_eq!(calls, iterations);
        assert_eq!(micro_warmup_iterations(0), 1);
    }

    #[test]
    fn warmup_is_an_override_above_a_floor_of_one_discarded_call() {
        // `--warmup 0` and an absent flag share the legacy one-shot priming
        // read; any explicit N >= 1 discards exactly N.
        assert_eq!(micro_warmup_iterations(0), 1);
        assert_eq!(micro_warmup_iterations(1), 1);
        assert_eq!(micro_warmup_iterations(200), 200);
    }

    fn probe_result(
        id: &'static str,
        class: Class,
        blocked: bool,
        transport_error: bool,
    ) -> ProbeResult {
        ProbeResult {
            id,
            class,
            description: "fixture",
            blocked,
            transport_error,
            pass: !transport_error,
        }
    }

    #[test]
    fn transport_errors_leave_both_rates_untouched() {
        let clean = vec![
            probe_result("A1", Class::Attack, true, false),
            probe_result("A2", Class::Attack, true, false),
            probe_result("C1", Class::Control, false, false),
        ];
        // Same battery plus one attack and one control that never reached a
        // server verdict.
        let noisy = vec![
            probe_result("A1", Class::Attack, true, false),
            probe_result("A2", Class::Attack, true, false),
            probe_result("C1", Class::Control, false, false),
            probe_result("A3", Class::Attack, true, true),
            probe_result("C2", Class::Control, true, true),
        ];

        let base = tally_adversarial(&clean);
        let with_noise = tally_adversarial(&noisy);

        assert_eq!(base.transport_errors, 0);
        assert_eq!(with_noise.transport_errors, 2);
        // Excluded from numerator *and* denominator of both rates.
        assert_eq!(with_noise.attack_trials, base.attack_trials);
        assert_eq!(with_noise.blocked_attacks, base.blocked_attacks);
        assert_eq!(with_noise.control_trials, base.control_trials);
        assert_eq!(with_noise.allowed_controls, base.allowed_controls);
        assert_eq!(
            pct(with_noise.blocked_attacks, with_noise.attack_trials),
            100.0
        );
        assert_eq!(
            pct(with_noise.allowed_controls, with_noise.control_trials),
            100.0
        );
    }
}
