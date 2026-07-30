use crate::client::CodexSecurityClient;
use crate::config::SdkConfig;
use crate::error::SdkError;
use crate::model::ScanResult;

pub async fn execute_scan(config: SdkConfig, target: &str) -> Result<ScanResult, SdkError> {
    let client = CodexSecurityClient::new(config)?;
    match client.run(target).await {
        Ok(result) => Ok(result),
        Err(e) => Err(SdkError::ScanError(e.to_string())),
    }
}