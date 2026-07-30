use crate::error::SdkError;
use crate::model::{Finding, FindingSummary, ScanResult, ScanStatus, Severity};
use crate::proof::{generate_receipt, sign_receipt, DecisionTrace, PolicyResult};
use crate::target::ScanTarget;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedScanResponse {
    pub report_path: String,
    pub findings: Vec<Finding>,
    pub status: ScanStatus,
    pub metadata: ResponseMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseMetadata {
    pub model: Option<String>,
    pub effort: String,
    pub duration_ms: u64,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedScanResult {
    pub scan_result: ScanResult,
    pub decision_trace: DecisionTrace,
    pub target: ScanTarget,
}

impl ParsedScanResponse {
    pub fn parse(text: &str) -> Result<Self> {
        let response: RawScanResponse = serde_json::from_str(text)
            .map_err(|e| SdkError::ScanError(format!("Failed to parse scan response: {}", e)))?;

        let findings = response
            .findings
            .into_iter()
            .map(|raw| Finding {
                id: raw.id,
                severity: parse_severity(&raw.severity),
                title: raw.title,
                description: raw.description.unwrap_or_default(),
                location: raw.location,
            })
            .collect();

        let status = parse_status(&response.status);

        Ok(Self {
            report_path: response.report_path,
            findings,
            status,
            metadata: {
                let raw_meta = response.metadata;
                ResponseMetadata {
                    model: raw_meta.as_ref().and_then(|m| m.model.clone()),
                    effort: raw_meta
                        .as_ref()
                        .and_then(|m| m.effort.clone())
                        .unwrap_or_default(),
                    duration_ms: raw_meta.as_ref().and_then(|m| m.duration_ms).unwrap_or(0),
                    generated_at: raw_meta.and_then(|m| m.generated_at).unwrap_or_else(|| {
                        SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs()
                            .to_string()
                    }),
                }
            },
        })
    }

    pub fn into_scan_result(self) -> ScanResult {
        ScanResult {
            report_path: self.report_path,
            findings: self.findings,
            status: self.status,
        }
    }
}

impl EnrichedScanResult {
    pub fn from_response(mut response: ParsedScanResponse, target: ScanTarget) -> Result<Self> {
        let findings: Vec<FindingSummary> = response
            .findings
            .iter()
            .map(|f| FindingSummary {
                id: f.id.clone(),
                severity: format!("{:?}", f.severity),
                title: f.title.clone(),
                location: f.location.clone(),
            })
            .collect();

        let metadata = response.metadata.clone();
        let gate = format!(
            "target={};effort={};model={}",
            target.display_name(),
            metadata.effort,
            metadata.model.unwrap_or_default()
        );

        let mut trace = generate_receipt(&findings, &gate)?;
        sign_receipt(&mut trace)?;

        Ok(Self {
            scan_result: response.into_scan_result(),
            decision_trace: trace,
            target,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawScanResponse {
    report_path: String,
    findings: Vec<RawFinding>,
    status: String,
    metadata: Option<RawMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawFinding {
    id: String,
    severity: String,
    title: String,
    description: Option<String>,
    location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RawMetadata {
    model: Option<String>,
    effort: Option<String>,
    duration_ms: Option<u64>,
    generated_at: Option<String>,
}

fn parse_severity(raw: &str) -> Severity {
    match raw.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Medium,
    }
}

fn parse_status(raw: &str) -> ScanStatus {
    match raw.to_lowercase().as_str() {
        "complete" | "completed" => ScanStatus::Complete,
        "running" | "in_progress" => ScanStatus::Running,
        _ => ScanStatus::Failed,
    }
}
