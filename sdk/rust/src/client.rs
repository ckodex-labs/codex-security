use crate::config::SdkConfig;
use crate::error::SdkError;
use crate::scan;
use anyhow::Result;
use std::time::Duration;

pub fn build_http_client() -> Result<reqwest::Client> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(5)
        .danger_accept_invalid_certs(false)
        .build()
        .map_err(|e| SdkError::Internal(e.into()))?;
    Ok(client)
}

pub struct CodexSecurityClient {
    config: SdkConfig,
    client: reqwest::Client,
}

impl CodexSecurityClient {
    pub fn new(config: SdkConfig) -> Result<Self> {
        let http_client = build_http_client()?;
        Ok(Self {
            config,
            client: http_client,
        })
    }

    pub async fn run(&self, target: &str) -> Result<crate::model::ScanResult> {
        let result = scan::execute_scan(&self.config, target, None, "medium").await?;
        Ok(result)
    }

    pub async fn run_with_options(
        &self,
        target: &str,
        model: Option<&str>,
        effort: &str,
    ) -> Result<crate::model::ScanResult> {
        let result = scan::execute_scan(&self.config, target, model, effort).await?;
        Ok(result)
    }
}