use codex_security_sdk::parser::{EnrichedScanResult, ParsedScanResponse};

#[test]
fn test_parse_valid_response() {
    let json = r#"{
        "report_path": "/tmp/report.json",
        "findings": [
            {
                "id": "1",
                "severity": "high",
                "title": "Test finding",
                "description": "A test",
                "location": "src/main.rs"
            }
        ],
        "status": "complete",
        "metadata": {
            "model": "gpt-5.6-terra",
            "effort": "high",
            "duration_ms": 1500,
            "generated_at": "1"
        }
    }"#;

    let parsed = ParsedScanResponse::parse(json).unwrap();
    assert_eq!(parsed.report_path, "/tmp/report.json");
    assert_eq!(parsed.findings.len(), 1);
    assert_eq!(parsed.findings[0].id, "1");
}

#[test]
fn test_parse_response_no_metadata() {
    let json = r#"{
        "report_path": "/tmp/report.json",
        "findings": [],
        "status": "complete"
    }"#;

    let parsed = ParsedScanResponse::parse(json).unwrap();
    assert!(parsed.findings.is_empty());
    assert_eq!(parsed.metadata.effort, "");
}

#[test]
fn test_parse_response_invalid_json() {
    let json = "not valid json";
    assert!(ParsedScanResponse::parse(json).is_err());
}

#[test]
fn test_enriched_from_response() {
    let json = r#"{
        "report_path": "/tmp/report.json",
        "findings": [],
        "status": "complete",
        "metadata": {
            "effort": "medium",
            "model": "gpt-5.6-terra"
        }
    }"#;

    let parsed = ParsedScanResponse::parse(json).unwrap();
    let target = codex_security_sdk::target::ScanTarget {
        path: std::path::PathBuf::from("/tmp/test"),
        exists: true,
        is_file: true,
        is_dir: false,
        normalized: "/tmp/test".into(),
    };

    let enriched = EnrichedScanResult::from_response(parsed, target).unwrap();
    assert_eq!(enriched.scan_result.report_path, "/tmp/report.json");
    assert!(!enriched.decision_trace.receipt_id.is_empty());
}
