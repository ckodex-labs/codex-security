use anyhow::Result;
use std::collections::HashMap;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub struct DecisionTrace {
    pub receipt_id: String,
    pub findings: Vec<crate::model::FindingSummary>,
    pub policy_result: PolicyResult,
    pub timestamp: String,
    pub evidence: EvidenceBundle,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub struct PolicyResult {
    pub passed: bool,
    pub gate: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub struct EvidenceBundle {
    pub artifacts: Vec<String>,
    pub checksums: HashMap<String, String>,
    pub signature: Option<String>,
}

#[allow(dead_code)]
pub fn generate_receipt(
    findings: &[crate::model::FindingSummary],
    gate: &str,
) -> Result<DecisionTrace> {
    let receipt_id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().to_rfc3339();

    let passed = findings.is_empty();
    let reason = if passed {
        None
    } else {
        Some(format!(
            "{} findings detected at gate {}",
            findings.len(),
            gate
        ))
    };

    let artifacts = collect_artifacts()?;
    let checksums = compute_checksums(&artifacts)?;

    Ok(DecisionTrace {
        receipt_id,
        findings: findings.to_vec(),
        policy_result: PolicyResult {
            passed,
            gate: gate.to_string(),
            reason,
        },
        timestamp,
        evidence: EvidenceBundle {
            artifacts,
            checksums,
            signature: None,
        },
    })
}

#[allow(dead_code)]
pub fn sign_receipt(receipt: &mut DecisionTrace) -> Result<()> {
    let json = serde_json::to_string(&receipt)?;
    let digest = ring::digest::digest(&ring::digest::SHA256, json.as_bytes());
    let proof_hash = hex::encode(digest.as_ref());
    receipt.evidence.signature = Some(proof_hash);
    Ok(())
}

#[allow(dead_code)]
pub fn collect_artifacts() -> Result<Vec<String>> {
    let mut artifacts = Vec::new();

    if let Ok(cwd) = std::env::current_dir() {
        artifacts.push(cwd.display().to_string());
    }

    if let Ok(home) = std::env::var("HOME") {
        artifacts.push(home);
    }

    Ok(artifacts)
}

#[allow(dead_code)]
pub fn compute_checksums(artifacts: &[String]) -> Result<HashMap<String, String>> {
    let mut checksums = HashMap::new();
    for artifact in artifacts {
        let digest = ring::digest::digest(&ring::digest::SHA256, artifact.as_bytes());
        checksums.insert(artifact.clone(), hex::encode(digest.as_ref()));
    }
    Ok(checksums)
}

#[allow(dead_code)]
pub fn load_or_generate_receipt(receipt_path: Option<&str>) -> Result<DecisionTrace> {
    match receipt_path {
        Some(path) => {
            let content = std::fs::read_to_string(path)?;
            let trace: DecisionTrace = serde_json::from_str(&content)?;
            Ok(trace)
        }
        None => {
            let empty_findings: Vec<crate::model::FindingSummary> = Vec::new();
            let mut trace = generate_receipt(&empty_findings, "default")?;
            sign_receipt(&mut trace)?;
            Ok(trace)
        }
    }
}
