use crate::client::CodexSecurityClient;
use crate::config::SdkConfig;
use crate::error::SdkError;
use crate::model::ScanResult;
use anyhow::Result;

pub async fn execute_scan(config: SdkConfig, target: &str) -> Result<ScanResult> {
    let client = CodexSecurityClient::new(config)?;
    client.run(target).await.map_err(SdkError::from)
}