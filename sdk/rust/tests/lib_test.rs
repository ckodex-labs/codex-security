#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_from_env_missing_key() {
        std::env::remove_var("CODEX_API_KEY");
        std::env::remove_var("OPENAI_API_KEY");
        assert!(SdkConfig::from_env().is_err());
    }
}