use crate::proof::DecisionTrace;
use crate::target::ScanTarget;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

const HISTORY_FILE: &str = "scan-history.json";
const DEFAULT_HISTORY_DIR: &str = ".codex-security";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: String,
    pub target: ScanTarget,
    pub result_status: String,
    pub findings_count: usize,
    pub completed_at: String,
    pub trace: Option<DecisionTrace>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistory {
    pub records: Vec<ScanRecord>,
}

impl ScanHistory {
    pub fn load() -> Result<Self> {
        let path = history_path()?;
        if !path.exists() {
            return Ok(Self {
                records: Vec::new(),
            });
        }

        let content = fs::read_to_string(&path)?;
        let history: ScanHistory = serde_json::from_str(&content)?;
        Ok(history)
    }

    pub fn save(&self) -> Result<()> {
        let path = history_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, json)?;
        Ok(())
    }

    pub fn add_record(&mut self, record: ScanRecord) {
        self.records.push(record);
    }

    pub fn latest(&self) -> Option<&ScanRecord> {
        self.records.last()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

pub fn record_scan(
    target: ScanTarget,
    result_status: String,
    findings_count: usize,
    trace: Option<DecisionTrace>,
) -> Result<ScanRecord> {
    let mut history = ScanHistory::load()?;

    let record = ScanRecord {
        id: uuid::Uuid::new_v4().to_string(),
        target,
        result_status,
        findings_count,
        completed_at: SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs().to_string())
            .unwrap_or_default(),
        trace,
    };

    history.add_record(record.clone());
    history.save()?;

    Ok(record)
}

pub fn history_path() -> Result<PathBuf> {
    let state_dir = std::env::var("CODEX_SECURITY_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            std::env::var("HOME")
                .map(|h| PathBuf::from(h).join(DEFAULT_HISTORY_DIR))
                .unwrap_or_else(|_| PathBuf::from("/tmp").join(DEFAULT_HISTORY_DIR))
        });
    Ok(state_dir.join(HISTORY_FILE))
}
