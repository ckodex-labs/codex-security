use anyhow::{bail, Result};
use std::path::PathBuf;

const STATE_DIR_ENV: &str = "CODEX_SECURITY_STATE_DIR";
const CREDENTIAL_FILE: &str = "credential.json";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredCredential {
    pub auth_method: String,
    pub api_key_hash: String,
    pub created_at: String,
}

pub fn credential_path() -> Result<PathBuf> {
    let state_dir = std::env::var(STATE_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(".codex-security"))
                .unwrap_or_else(|_| PathBuf::from("/tmp/.codex-security"))
        });
    Ok(state_dir.join(CREDENTIAL_FILE))
}

pub fn store_credential(auth_method: &str, api_key: &str) -> Result<()> {
    let path = credential_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let hash = hash_api_key(api_key);
    let credential = StoredCredential {
        auth_method: auth_method.to_string(),
        api_key_hash: hash,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let json = serde_json::to_string_pretty(&credential)?;
    std::fs::write(&path, json)?;
    Ok(())
}

pub fn load_credential() -> Result<Option<StoredCredential>> {
    let path = credential_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)?;
    let credential: StoredCredential = serde_json::from_str(&content)?;
    Ok(Some(credential))
}

pub fn ensure_credential(auth_method: &str) -> Result<()> {
    match auth_method {
        "chatgpt" => {
            if std::env::var("CODEX_AUTH_METHOD").unwrap_or_default() != "chatgpt" {
                bail!(
                    "ChatGPT authentication requires CODEX_AUTH_METHOD=chatgpt to be set"
                );
            }
        }
        "api-key" => {
            if std::env::var("CODEX_API_KEY").is_err() && std::env::var("OPENAI_API_KEY").is_err() {
                bail!(
                    "API key authentication requires CODEX_API_KEY or OPENAI_API_KEY to be set"
                );
            }
        }
        other => bail!("Unknown auth method: {}", other),
    }

    let key = std::env::var("CODEX_API_KEY")
        .or_else(|_| std::env::var("OPENAI_API_KEY"))
        .unwrap_or_default();
    if !key.is_empty() {
        store_credential(auth_method, &key)?;
    }

    Ok(())
}

fn hash_api_key(key: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, key.as_bytes());
    hex::encode(digest.as_ref())
}