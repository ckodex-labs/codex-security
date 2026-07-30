use codex_security_sdk::target;
use tempfile::TempDir;

#[test]
fn test_prepare_target_file() {
    let temp = TempDir::new().unwrap();
    let file_path = temp.path().join("test.txt");
    std::fs::write(&file_path, b"hello").unwrap();

    let target = target::prepare_target(file_path.to_str().unwrap()).unwrap();
    assert!(target.exists);
    assert!(target.is_file);
    assert!(!target.is_dir);
}

#[test]
fn test_prepare_target_dir() {
    let temp = TempDir::new().unwrap();
    let target = target::prepare_target(temp.path().to_str().unwrap()).unwrap();
    assert!(target.exists);
    assert!(!target.is_file);
    assert!(target.is_dir);
}

#[test]
fn test_prepare_target_missing() {
    let result = target::prepare_target("/nonexistent/path/12345");
    assert!(result.is_err());
}

#[test]
fn test_target_display_name() {
    let temp = TempDir::new().unwrap();
    let target = target::prepare_target(temp.path().to_str().unwrap()).unwrap();
    assert!(!target.display_name().is_empty());
}
