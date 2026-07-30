package sdk

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var (
	ErrHistoryNotFound = fmt.Errorf("scan history not found")
)

type ScanRecord struct {
	ID            string         `json:"id"`
	Target        Target         `json:"target"`
	ResultStatus  string         `json:"result_status"`
	FindingsCount int            `json:"findings_count"`
	CompletedAt   string         `json:"completed_at"`
	Trace         *DecisionTrace `json:"trace,omitempty"`
}

type ScanHistory struct {
	Records []ScanRecord `json:"records"`
}

func (h *ScanHistory) AddRecord(record ScanRecord) {
	h.Records = append(h.Records, record)
}

func (h *ScanHistory) Latest() *ScanRecord {
	if len(h.Records) == 0 {
		return nil
	}
	return &h.Records[len(h.Records)-1]
}

func (h *ScanHistory) Len() int {
	return len(h.Records)
}

func (h *ScanHistory) IsEmpty() bool {
	return len(h.Records) == 0
}

func LoadHistory() (*ScanHistory, error) {
	path, err := historyPath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &ScanHistory{Records: []ScanRecord{}}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read history: %w", err)
	}

	var history ScanHistory
	if err := json.Unmarshal(data, &history); err != nil {
		return nil, fmt.Errorf("failed to parse history: %w", err)
	}

	return &history, nil
}

func (h *ScanHistory) Save() error {
	path, err := historyPath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("failed to create history directory: %w", err)
	}

	data, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal history: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write history: %w", err)
	}

	return nil
}

func RecordScan(target Target, resultStatus string, findingsCount int, trace *DecisionTrace) (*ScanRecord, error) {
	history, err := LoadHistory()
	if err != nil {
		return nil, err
	}

	id, err := generateID()
	if err != nil {
		return nil, err
	}

	record := ScanRecord{
		ID:            id,
		Target:        target,
		ResultStatus:  resultStatus,
		FindingsCount: findingsCount,
		CompletedAt:   time.Now().Format(time.RFC3339),
		Trace:         trace,
	}

	history.AddRecord(record)
	if err := history.Save(); err != nil {
		return nil, err
	}

	return &record, nil
}

type Target struct {
	Path       string
	Exists     bool
	IsFile     bool
	IsDir      bool
	Normalized string
}

func PrepareTarget(target string) (Target, error) {
	info, err := os.Stat(target)
	exists := err == nil

	if exists {
		return Target{
			Path:       target,
			Exists:     true,
			IsFile:     info.Mode().IsRegular(),
			IsDir:      info.IsDir(),
			Normalized: target,
		}, nil
	}

	return Target{}, fmt.Errorf("scan target does not exist: %s", target)
}

func historyPath() (string, error) {
	stateDir := os.Getenv("CODEX_SECURITY_STATE_DIR")
	if stateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get home directory: %w", err)
		}
		stateDir = home + "/.codex-security"
	}
	return filepath.Join(stateDir, "scan-history.json"), nil
}
