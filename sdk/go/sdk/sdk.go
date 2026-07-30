package sdk

import (
	"fmt"
	"os"
)

type ConfigError string

func (e ConfigError) Error() string {
	return string(e)
}

type SDKConfig struct {
	APIKey      string
	APIEndpoint string
}

func LoadConfig() (SDKConfig, error) {
	apiKey := os.Getenv("CODEX_API_KEY")
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}
	if apiKey == "" {
		return SDKConfig{}, ConfigError("CODEX_API_KEY or OPENAI_API_KEY must be set")
	}

	endpoint := os.Getenv("CODEX_API_ENDPOINT")
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1"
	}

	return SDKConfig{
		APIKey:      apiKey,
		APIEndpoint: endpoint,
	}, nil
}

type ScanResult struct {
	ReportPath string `json:"report_path"`
	Findings   []Finding
	Status     string `json:"status"`
}

type Finding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location"`
}

type DecisionTrace struct {
	ReceiptID string `json:"receipt_id"`
	Gate      string `json:"gate"`
	Policy    string `json:"policy"`
	Findings  []FindingSummary
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

type FindingSummary struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Lcation  string `json:"location"`
}

type Credential struct {
	AuthMethod string `json:"auth_method"`
	CreatedAt  string `json:"created_at"`
}

func IsEnvSet(key string) bool {
	_, ok := os.LookupEnv(key)
	return ok
}

func RequireEnv(key string) (string, error) {
	value, ok := os.LookupEnv(key)
	if !ok || value == "" {
		return "", fmt.Errorf("%s must be set", key)
	}
	return value, nil
}
