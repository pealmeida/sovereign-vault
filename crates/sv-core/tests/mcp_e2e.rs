//! End-to-end test of the real agent data path: a live `VaultHandle` wrapped
//! in `McpServer`, driven over `serve_stdio` exactly as the `mcp-stdio` proxy
//! does, proving an agent can write and read real (encrypted-on-disk) data.

use std::path::PathBuf;
use std::sync::Arc;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use sv_core::sv_mcp::{McpServer, SharedVault};
use sv_core::sv_storage::SecurityMode;
use sv_core::{CustodyMode, VaultHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

fn tmp_dir(label: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let hex: String = sv_core::sv_crypto::random_bytes(8)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    p.push(format!("sv-core-mcpe2e-{label}-{hex}"));
    p
}

#[tokio::test]
async fn agent_writes_and_reads_real_vault_over_mcp_stdio() {
    let root = tmp_dir("rw");
    let boot = VaultHandle::bootstrap(&root, CustodyMode::Passphrase, Some("pw")).unwrap();
    boot.handle
        .create_container("notes", SecurityMode::Direct, None)
        .unwrap();

    let shared: SharedVault<VaultHandle> = Arc::new(Mutex::new(Some(boot.handle)));
    let server = McpServer::new(shared, "test-secret");

    // Two duplex pipes: client->server (server reads) and server->client.
    let (mut client_w, server_r) = tokio::io::duplex(16 * 1024);
    let (server_w, mut client_r) = tokio::io::duplex(16 * 1024);

    let task = tokio::spawn(async move {
        let _ = server.serve_stdio(BufReader::new(server_r), server_w).await;
    });

    let payload = B64.encode(b"my-production-api-key");
    let write = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"vault.write","arguments":{{"container":"notes","file_name":"key.txt","content_b64":"{payload}"}}}}}}"#
    );
    let read = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault.read","arguments":{"container":"notes","file_name":"key.txt"}}}"#;
    client_w
        .write_all(format!("{write}\n{read}\n").as_bytes())
        .await
        .unwrap();
    drop(client_w); // EOF ends serve_stdio

    let mut out = String::new();
    client_r.read_to_string(&mut out).await.unwrap();
    task.await.unwrap();

    // The read response must round-trip the exact plaintext (base64).
    assert!(
        out.contains(&payload),
        "vault.read did not return the written plaintext.\noutput: {out}"
    );
    // And the plaintext must NOT be sitting unencrypted on disk.
    let blob = std::fs::read(root.join("notes").join("key.txt.svault")).unwrap();
    assert!(
        !blob
            .windows(b"my-production-api-key".len())
            .any(|w| w == b"my-production-api-key"),
        "plaintext found in the on-disk blob"
    );

    let _ = std::fs::remove_dir_all(&root);
}
