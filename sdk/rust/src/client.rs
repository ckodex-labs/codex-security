use crate::config::SdkConfig;
use crate::error::SdkError;
use crate::model::ScanResult;
use anyhow::Result;

pub struct CodexSecurityClient {
    config: SdkConfig,
    client: reqwest::Client,
}

impl CodexSecurityClient {
    pub fn new(config: SdkConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()?;
        Ok(Self { config, client })
    }

    pub async fn run(&self, target: &str) -> Result<ScanResult> {
        let response = self
            .client
            .post(&self.config.api_endpoint)
            .bearer_auth(&self.config.api_key)
            .json(&serde_json::json!({ "target": target }))
            .send()
            .await?;

        let result: ScanResult = response.json().await?;
        Ok(result)
    }
}