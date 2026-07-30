use anyhow::Result;
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct DecisionTrace {
    pub receipt_id: String,
    pub findings: Vec<String>,
    pub policy_result: PolicyResult,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyResult {
    pub passed: bool,
    pub gate: String,
    pub evidence_url: Option<String>,
}

pub fn generate_receipt(findings: &[String], gate: &str) -> Result<DecisionTrace> {
    Ok(DecisionTrace {
        receipt_id: Uuid::new_v4().to_string(),
        findings: findings.to_vec(),
        policy_result: PolicyResult {
            passed: findings.is_empty(),
            gate: gate.to_string(),
            evidence_url: None,
        },
    })
}