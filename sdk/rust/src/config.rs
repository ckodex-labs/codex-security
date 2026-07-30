use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct SdkConfig {
    pub api_endpoint: String,
    pub api_key: String,
    pub auth_method: AuthMethod,
}

#[derive(Debug, Clone, Deserialize)]
pub enum AuthMethod {
    ApiKey,
    Chatgpt,
}

impl SdkConfig {
    pub fn from_env() -> Result<Self> {
        let api_endpoint = std::env::var("CODEX_API_ENDPOINT")
            .unwrap_or_else(|_| "https://api.codex.openai.com/v1".to_string());
        let api_key = std::env::var("CODEX_API_KEY")
            .or_else(|_| std::env::var("OPENAI_API_KEY"))
            .expect("CODEX_API_KEY or OPENAI_API_KEY must be set");
        let auth_method = if std::env::var("CODEX_AUTH_METHOD").unwrap_or_default() == "chatgpt" {
            AuthMethod::Chatgpt
        } else {
            AuthMethod::ApiKey
        };
        Ok(Self {
            api_endpoint,
            api_key,
            auth_method,
        })
    }
}