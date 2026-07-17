use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::codec::{FramedRead, LinesCodec};

const VAULT_HTTP: &str = "http://127.0.0.1:9943";
const VAULT_WS: &str = "ws://127.0.0.1:9944";
const MAX_STDIO_FRAME_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
enum PairingMode {
    SharedSecret(String),
    Agent { agent_id: String, token: String },
}

pub async fn run_mcp_stdio() -> Result<(), String> {
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let pairing = match pairing_mode_from_env()? {
        Some(mode) => mode,
        None => PairingMode::SharedSecret(fetch_pairing_secret().await.map_err(|e| {
            format!(
                "Sovereign Vault is not running or not unlocked. \
                 Open the desktop app and unlock your vault first. ({e})"
            )
        })?),
    };

    let (ws, _resp) = tokio_tungstenite::connect_async(VAULT_WS)
        .await
        .map_err(|e| format!("connect {VAULT_WS}: {e}"))?;
    let (mut sink, mut source) = ws.split();

    let pair_req = pairing_request(&pairing);
    sink.send(Message::Text(pair_req.to_string().into()))
        .await
        .map_err(|e| format!("send pair: {e}"))?;
    match source.next().await {
        Some(Ok(Message::Text(t))) => {
            let v: Value =
                serde_json::from_str(&t).map_err(|e| format!("malformed pair response: {e}"))?;
            if v.get("error").is_some() || v.get("result").and_then(|r| r.get("paired")).is_none() {
                return Err(format!("pairing rejected: {t}"));
            }
        }
        Some(Ok(other)) => return Err(format!("unexpected pair frame: {other:?}")),
        Some(Err(e)) => return Err(format!("ws error during pair: {e}")),
        None => return Err("ws closed during pair".into()),
    }

    let mut lines = FramedRead::new(
        tokio::io::stdin(),
        LinesCodec::new_with_max_length(MAX_STDIO_FRAME_BYTES),
    );
    let mut stdout = tokio::io::stdout();

    loop {
        tokio::select! {
            line = lines.next() => {
                match line {
                    Some(Ok(l)) => {
                        let l = l.trim();
                        if l.is_empty() {
                            continue;
                        }
                        if let Err(e) = sink.send(Message::Text(l.to_string().into())).await {
                            return Err(format!("ws send: {e}"));
                        }
                    }
                    None => {
                        let _ = sink.send(Message::Close(None)).await;
                        return Ok(());
                    }
                    Some(Err(e)) => return Err(format!("stdin frame rejected: {e}")),
                }
            }
            msg = source.next() => {
                match msg {
                    Some(Ok(Message::Text(t))) => {
                        if !is_supported_frame(&t) {
                            continue;
                        }
                        stdout.write_all(t.as_bytes()).await.map_err(|e| e.to_string())?;
                        stdout.write_all(b"\n").await.map_err(|e| e.to_string())?;
                        stdout.flush().await.map_err(|e| e.to_string())?;
                    }
                    Some(Ok(Message::Binary(b))) => {
                        if let Ok(t) = String::from_utf8(b.to_vec()) {
                            if is_supported_frame(&t) {
                                stdout.write_all(t.as_bytes()).await.map_err(|e| e.to_string())?;
                                stdout.write_all(b"\n").await.map_err(|e| e.to_string())?;
                                stdout.flush().await.map_err(|e| e.to_string())?;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Ok(_)) => continue,
                    Some(Err(e)) => return Err(format!("ws recv: {e}")),
                }
            }
        }
    }
}

fn pairing_mode_from_env() -> Result<Option<PairingMode>, String> {
    pairing_mode_from_lookup(|key| std::env::var(key).ok())
}

fn pairing_mode_from_lookup<F>(lookup: F) -> Result<Option<PairingMode>, String>
where
    F: Fn(&str) -> Option<String>,
{
    let agent_id = lookup("SV_AGENT_ID")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let token = lookup("SV_PAIRING_TOKEN")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    match (agent_id, token) {
        (Some(agent_id), Some(token)) => Ok(Some(PairingMode::Agent { agent_id, token })),
        (Some(_), None) => Err("SV_AGENT_ID requires SV_PAIRING_TOKEN".into()),
        (None, Some(secret)) => Ok(Some(PairingMode::SharedSecret(secret))),
        (None, None) => Ok(None),
    }
}

fn pairing_request(mode: &PairingMode) -> Value {
    match mode {
        PairingMode::SharedSecret(secret) => json!({
            "jsonrpc": "2.0",
            "id": "pair",
            "method": "vault.pair",
            "params": { "secret": secret }
        }),
        PairingMode::Agent { agent_id, token } => json!({
            "jsonrpc": "2.0",
            "id": "pair",
            "method": "vault.pair",
            "params": { "agent_id": agent_id, "token": token }
        }),
    }
}

fn is_supported_frame(text: &str) -> bool {
    let v: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if v.get("id").is_some() {
        return true;
    }
    match v.get("method").and_then(|m| m.as_str()) {
        Some(m) => m.starts_with("notifications/"),
        None => false,
    }
}

async fn fetch_pairing_secret() -> Result<String, String> {
    let url = format!("{VAULT_HTTP}/.well-known/mcp-pairing");
    let resp = reqwest::get(&url).await.map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    let body: Value = resp.json().await.map_err(|e| e.to_string())?;
    body.get("secret")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "no `secret` field in pairing response".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_env_none_falls_back_to_http_secret() {
        let mode = pairing_mode_from_lookup(|_| None).unwrap();
        assert_eq!(mode, None);
    }

    #[test]
    fn pairing_env_token_without_agent_uses_shared_secret_mode() {
        let mode = pairing_mode_from_lookup(|key| match key {
            "SV_PAIRING_TOKEN" => Some("tok".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(mode, Some(PairingMode::SharedSecret("tok".into())));
    }

    #[test]
    fn pairing_env_agent_and_token_use_agent_mode() {
        let mode = pairing_mode_from_lookup(|key| match key {
            "SV_AGENT_ID" => Some("ag_1".into()),
            "SV_PAIRING_TOKEN" => Some("tok".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(
            mode,
            Some(PairingMode::Agent {
                agent_id: "ag_1".into(),
                token: "tok".into(),
            })
        );
    }

    #[test]
    fn pairing_env_agent_without_token_is_rejected() {
        let error = pairing_mode_from_lookup(|key| match key {
            "SV_AGENT_ID" => Some("ag_1".into()),
            _ => None,
        })
        .unwrap_err();
        assert!(error.contains("SV_AGENT_ID requires SV_PAIRING_TOKEN"));
    }

    #[test]
    fn pairing_request_uses_agent_fields() {
        let request = pairing_request(&PairingMode::Agent {
            agent_id: "ag_1".into(),
            token: "tok".into(),
        });
        assert_eq!(request["params"]["agent_id"], "ag_1");
        assert_eq!(request["params"]["token"], "tok");
        assert!(request["params"].get("secret").is_none());
    }

    #[tokio::test]
    async fn stdio_rejects_oversized_request_frame() {
        let input = vec![b'x'; MAX_STDIO_FRAME_BYTES + 1];
        let mut frames = FramedRead::new(
            input.as_slice(),
            LinesCodec::new_with_max_length(MAX_STDIO_FRAME_BYTES),
        );

        assert!(matches!(frames.next().await, Some(Err(_))));
    }
}
