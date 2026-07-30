use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub report_path: String,
    pub findings: Vec<Finding>,
    pub status: ScanStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub location: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScanStatus {
    Running,
    Complete,
    Failed,
}
