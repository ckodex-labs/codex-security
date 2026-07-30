use codex_security_sdk::config;
use codex_security_sdk::credential;
use codex_security_sdk::model;
use codex_security_sdk::proof;
use codex_security_sdk::scan;
use codex_security_sdk::SdkConfig;
use std::collections::HashMap;
use tempfile::TempDir;

fn with_env<K, V>(key: K, value: V) -> Option<String>
where
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
{
    let prev = std::env::var(key.as_ref()).ok();
    std::env::remove_var(key.as_ref());
    if !value.as_ref().is_empty() {
        std::env::set_var(key, value);
    }
    prev
}

#[test]
fn test_config_from_env_missing_key() {
    let prev_api = with_env("CODEX_API_KEY", "");
    let prev_openai = with_env("OPENAI_API_KEY", "");
    assert!(SdkConfig::from_env().is_err());
    if let Some(v) = prev_api {
        std::env::set_var("CODEX_API_KEY", v);
    }
    if let Some(v) = prev_openai {
        std::env::set_var("OPENAI_API_KEY", v);
    }
}

#[test]
fn test_client_constructable() {
    let prev = with_env("CODEX_API_KEY", "test-key");
    let cfg = SdkConfig::from_env().unwrap();
    let _client = codex_security_sdk::client::CodexSecurityClient::new(cfg).unwrap();
    if prev.is_some() {
        std::env::set_var("CODEX_API_KEY", prev.unwrap());
    } else {
        std::env::remove_var("CODEX_API_KEY");
    }
}

#[test]
fn test_finding_summary_constructed() {
    let summary = model::FindingSummary {
        id: "1".into(),
        severity: "high".into(),
        title: "test".into(),
        location: "src/main.rs".into(),
    };
    assert_eq!(summary.id, "1");
}

#[test]
fn test_decision_trace_constructed() {
    let summary = model::FindingSummary {
        id: "1".into(),
        severity: "high".into(),
        title: "test".into(),
        location: "src/main.rs".into(),
    };
    let trace = proof::generate_receipt(&[summary], "default").unwrap();
    assert!(!trace.receipt_id.is_empty());
}

#[test]
fn test_policy_result_constructed() {
    let result = proof::PolicyResult {
        passed: true,
        gate: "default".into(),
        reason: None,
    };
    assert!(result.passed);
}

#[test]
fn test_evidence_bundle_constructed() {
    let bundle = proof::EvidenceBundle {
        artifacts: vec!["/tmp".into()],
        checksums: HashMap::new(),
        signature: None,
    };
    assert_eq!(bundle.artifacts.len(), 1);
}

#[test]
fn test_generate_and_sign_receipt() {
    let summary = model::FindingSummary {
        id: "1".into(),
        severity: "high".into(),
        title: "test".into(),
        location: "src/main.rs".into(),
    };
    let mut trace = proof::generate_receipt(&[summary], "default").unwrap();
    proof::sign_receipt(&mut trace).unwrap();
    assert!(trace.evidence.signature.is_some());
}

#[test]
fn test_load_or_generate_receipt() {
    let trace = proof::load_or_generate_receipt(None).unwrap();
    assert!(!trace.receipt_id.is_empty());
}

#[test]
fn test_collect_artifacts() {
    let artifacts = proof::collect_artifacts().unwrap();
    assert!(!artifacts.is_empty());
}

#[test]
fn test_compute_checksums() {
    let artifacts = vec!["test".into()];
    let checksums = proof::compute_checksums(&artifacts).unwrap();
    assert!(checksums.contains_key("test"));
}

#[test]
fn test_credential_roundtrip() {
    let temp = TempDir::new().unwrap();
    let prev_dir = with_env("CODEX_SECURITY_STATE_DIR", temp.path());
    let prev_key = with_env("CODEX_API_KEY", "secret");
    credential::ensure_credential("api-key").unwrap();
    let stored = credential::load_credential().unwrap();
    assert!(stored.is_some());
    assert_eq!(stored.unwrap().auth_method, "api-key");
    if let Some(v) = prev_dir {
        std::env::set_var("CODEX_SECURITY_STATE_DIR", v);
    } else {
        std::env::remove_var("CODEX_SECURITY_STATE_DIR");
    }
    if let Some(v) = prev_key {
        std::env::set_var("CODEX_API_KEY", v);
    } else {
        std::env::remove_var("CODEX_API_KEY");
    }
}

#[test]
fn test_credential_path_override() {
    let temp = TempDir::new().unwrap();
    let prev_dir = with_env("CODEX_SECURITY_STATE_DIR", temp.path());
    let prev_home = with_env("HOME", "/tmp/fake-home");
    let path = credential::credential_path().unwrap();
    assert!(path
        .to_string_lossy()
        .starts_with(temp.path().to_string_lossy().as_ref()));
    if let Some(v) = prev_dir {
        std::env::set_var("CODEX_SECURITY_STATE_DIR", v);
    } else {
        std::env::remove_var("CODEX_SECURITY_STATE_DIR");
    }
    if let Some(v) = prev_home {
        std::env::set_var("HOME", v);
    } else {
        std::env::remove_var("HOME");
    }
}
