package sdk

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

type ProofError string

func (e ProofError) Error() string {
	return string(e)
}

func GenerateReceipt(findings []FindingSummary, gate string) (DecisionTrace, error) {
	if gate == "" {
		return DecisionTrace{}, ProofError("gate is required")
	}

	receiptID, err := generateID()
	if err != nil {
		return DecisionTrace{}, err
	}

	return DecisionTrace{
		ReceiptID: receiptID,
		Gate:      gate,
		Policy:    "default",
		Findings:  findings,
	}, nil
}

func SignReceipt(trace *DecisionTrace) error {
	if trace == nil {
		return ProofError("trace is nil")
	}

	keyID, privateKey, err := loadOrGenerateSigningKey()
	if err != nil {
		return err
	}

	message, err := marshalReceiptForSigning(trace)
	if err != nil {
		return err
	}

	signature, err := privateKey.Sign(rand.Reader, []byte(message), crypto.Hash(0))
	if err != nil {
		return ProofError(err.Error())
	}

	trace.KeyID = keyID
	trace.Signature = hex.EncodeToString(signature)
	return nil
}

func loadOrGenerateSigningKey() (string, ed25519.PrivateKey, error) {
	stateDir := os.Getenv("CODEX_SECURITY_STATE_DIR")
	if stateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		stateDir = home + "/.codex-security"
	}

	keyPath := stateDir + "/proof.key"
	if _, err := os.Stat(keyPath); err == nil {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return "", nil, fmt.Errorf("failed to read key file: %w", err)
		}
		keyID, keyHex, ok := parseKeyFile(data)
		if !ok {
			return "", nil, ProofError("invalid key file format")
		}
		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil {
			return "", nil, fmt.Errorf("failed to decode key: %w", err)
		}
		return keyID, ed25519.PrivateKey(keyBytes), nil
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate key: %w", err)
	}

	keyID, err := generateID()
	if err != nil {
		return "", nil, err
	}

	keyHex := hex.EncodeToString(privateKey)
	keyFile := fmt.Sprintf("key=%s\nprivate_key=%s\n", keyID, keyHex)
	if err := os.WriteFile(keyPath, []byte(keyFile), 0600); err != nil {
		return "", nil, fmt.Errorf("failed to write key file: %w", err)
	}

	return keyID, privateKey, nil
}

func generateID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate id: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func marshalReceiptForSigning(trace *DecisionTrace) (string, error) {
	return fmt.Sprintf("receipt=%s\nkey=%s\nsignature=%s\n",
		trace.ReceiptID, trace.KeyID, trace.Signature), nil
}

func parseKeyFile(data []byte) (string, string, bool) {
	var keyID, keyHex string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "key=") {
			keyID = strings.TrimPrefix(line, "key=")
		}
		if strings.HasPrefix(line, "private_key=") {
			keyHex = strings.TrimPrefix(line, "private_key=")
		}
	}
	return keyID, keyHex, keyID != "" && keyHex != ""
}

func VerifyReceipt(trace DecisionTrace) error {
	if trace.KeyID == "" || trace.Signature == "" {
		return ProofError("missing signature or key id")
	}

	stateDir := os.Getenv("CODEX_SECURITY_STATE_DIR")
	if stateDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		stateDir = home + "/.codex-security"
	}

	keyPath := stateDir + "/proof.key"
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key file: %w", err)
	}

	_, keyHex, ok := parseKeyFile(data)
	if !ok {
		return ProofError("invalid key file format")
	}

	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("failed to decode key: %w", err)
	}

	publicKey := ed25519.PublicKey(keyBytes[32:])
	signature, err := hex.DecodeString(trace.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	message, err := marshalReceiptForSigning(&trace)
	if err != nil {
		return err
	}

	if !ed25519.Verify(publicKey, []byte(message), signature) {
		return ProofError("invalid signature")
	}

	return nil
}
