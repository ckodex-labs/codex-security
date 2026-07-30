use codex_security_sdk::history::{record_scan, ScanHistory, ScanRecord};
use codex_security_sdk::target;
use tempfile::TempDir;

#[test]
fn test_scan_history_empty() {
    let history = ScanHistory::load().unwrap();
    assert!(history.is_empty());
}

#[test]
fn test_scan_history_add_and_latest() {
    let temp = TempDir::new().unwrap();
    std::env::set_var("CODEX_SECURITY_STATE_DIR", temp.path());

    let target = target::prepare_target(temp.path().to_str().unwrap()).unwrap();
    let mut history = ScanHistory::load().unwrap();
    history.add_record(ScanRecord {
        id: "1".into(),
        target,
        result_status: "complete".into(),
        findings_count: 0,
        completed_at: "1".into(),
        trace: None,
    });
    history.save().unwrap();

    let loaded = ScanHistory::load().unwrap();
    assert_eq!(loaded.len(), 1);
    assert!(loaded.latest().is_some());

    std::env::remove_var("CODEX_SECURITY_STATE_DIR");
}

#[test]
fn test_scan_history_record_roundtrip() {
    let temp = TempDir::new().unwrap();
    std::env::set_var("CODEX_SECURITY_STATE_DIR", temp.path());

    let target = target::prepare_target(temp.path().to_str().unwrap()).unwrap();
    let record = record_scan(target, "complete".into(), 3, None).unwrap();
    assert_eq!(record.findings_count, 3);
    assert_eq!(record.result_status, "complete");

    std::env::remove_var("CODEX_SECURITY_STATE_DIR");
}
