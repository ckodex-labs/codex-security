use crate::config::SdkConfig;
use crate::error::SdkError;
use crate::model::ScanResult;
use crate::parser::{EnrichedScanResult, ParsedScanResponse};
use crate::target::prepare_target;
use anyhow::Result;
use std::time::Duration;

const MAX_RETRIES: usize = 3;
const RETRY_DELAY_MS: u64 = 1000;

pub async fn execute_scan(
    config: &SdkConfig,
    target: &str,
    model: Option<&str>,
    effort: &str,
) -> Result<ScanResult, SdkError> {
    let target = prepare_target(target).map_err(|e| SdkError::ScanError(e.to_string()))?;

    let client = crate::client::build_http_client()?;

    let mut request_body = serde_json::json!({
        "target": target.normalized,
        "effort": effort,
    });

    if let Some(model_name) = model {
        request_body["model"] = serde_json::json!(model_name);
    }

    let mut last_error = None;

    for attempt in 1..=MAX_RETRIES {
        match send_scan_request(&client, config, &request_body).await {
            Ok(result) => return Ok(result),
            Err(e) => {
                last_error = Some(e.to_string());
                if attempt < MAX_RETRIES {
                    let delay = RETRY_DELAY_MS * attempt as u64;
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
            }
        }
    }

    Err(SdkError::ScanError(format!(
        "Scan failed after {} attempts: {}",
        MAX_RETRIES,
        last_error.unwrap_or_default()
    )))
}

pub async fn execute_enriched_scan(
    config: &SdkConfig,
    target: &str,
    model: Option<&str>,
    effort: &str,
) -> Result<EnrichedScanResult, SdkError> {
    let target = prepare_target(target).map_err(|e| SdkError::ScanError(e.to_string()))?;

    let client = crate::client::build_http_client()?;

    let mut request_body = serde_json::json!({
        "target": target.normalized,
        "effort": effort,
    });

    if let Some(model_name) = model {
        request_body["model"] = serde_json::json!(model_name);
    }

    let mut last_error = None;

    for attempt in 1..=MAX_RETRIES {
        match send_scan_request(&client, config, &request_body).await {
            Ok(result) => {
                let parsed = ParsedScanResponse::parse(&serde_json::to_string(&result).unwrap())
                    .map_err(|e| SdkError::ScanError(e.to_string()))?;
                let enriched = EnrichedScanResult::from_response(parsed, target.clone())
                    .map_err(|e| SdkError::ScanError(e.to_string()))?;
                return Ok(enriched);
            }
            Err(e) => {
                last_error = Some(e.to_string());
                if attempt < MAX_RETRIES {
                    let delay = RETRY_DELAY_MS * attempt as u64;
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                }
            }
        }
    }

    Err(SdkError::ScanError(format!(
        "Scan failed after {} attempts: {}",
        MAX_RETRIES,
        last_error.unwrap_or_default()
    )))
}

async fn send_scan_request(
    client: &reqwest::Client,
    config: &SdkConfig,
    body: &serde_json::Value,
) -> Result<ScanResult, SdkError> {
    let response = client
        .post(&config.api_endpoint)
        .bearer_auth(&config.api_key)
        .json(body)
        .send()
        .await
        .map_err(|e| SdkError::ScanError(e.to_string()))?;

    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| SdkError::ScanError(e.to_string()))?;

    if !status.is_success() {
        return Err(SdkError::ScanError(format!(
            "HTTP {} - {}",
            status.as_u16(),
            text
        )));
    }

    let result: ScanResult =
        serde_json::from_str(&text).map_err(|e| SdkError::ScanError(e.to_string()))?;
    Ok(result)
}
