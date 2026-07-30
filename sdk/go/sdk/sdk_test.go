package sdk

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		apiKeyEnv   string
		endpointEnv string
		wantKey     string
		wantErr     bool
	}{
		{
			name:      "CODEX_API_KEY set",
			apiKeyEnv: "test-key",
			wantKey:   "test-key",
			wantErr:   false,
		},
		{
			name:      "missing key",
			apiKeyEnv: "",
			wantKey:   "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Unsetenv("CODEX_API_KEY")
			os.Unsetenv("OPENAI_API_KEY")
			defer func() {
				os.Unsetenv("CODEX_API_KEY")
				os.Unsetenv("OPENAI_API_KEY")
				os.Unsetenv("CODEX_API_ENDPOINT")
			}()

			if tt.apiKeyEnv != "" {
				os.Setenv("CODEX_API_KEY", tt.apiKeyEnv)
			}
			if tt.endpointEnv != "" {
				os.Setenv("CODEX_API_ENDPOINT", tt.endpointEnv)
			}

			config, err := LoadConfig()
			if tt.wantErr && err == nil {
				t.Error("expected error but got none")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.wantErr && config.APIKey != tt.wantKey {
				t.Errorf("expected API key %q, got %q", tt.wantKey, config.APIKey)
			}
		})
	}
}

func TestIsEnvSet(t *testing.T) {
	if IsEnvSet("CODEX_SECURITY_TEST_VAR_12345") {
		t.Error("expected env var to not be set")
	}

	os.Setenv("CODEX_SECURITY_TEST_VAR_12345", "1")
	if !IsEnvSet("CODEX_SECURITY_TEST_VAR_12345") {
		t.Error("expected env var to be set")
	}
	os.Unsetenv("CODEX_SECURITY_TEST_VAR_12345")
}

func TestRequireEnv(t *testing.T) {
	if _, err := RequireEnv("CODEX_SECURITY_TEST_VAR_12345"); err == nil {
		t.Error("expected error for missing env var")
	}

	os.Setenv("CODEX_SECURITY_TEST_VAR_12345", "value")
	value, err := RequireEnv("CODEX_SECURITY_TEST_VAR_12345")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "value" {
		t.Errorf("expected 'value', got %q", value)
	}
	os.Unsetenv("CODEX_SECURITY_TEST_VAR_12345")
}
