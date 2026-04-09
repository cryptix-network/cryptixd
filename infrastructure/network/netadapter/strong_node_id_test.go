package netadapter

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateStrongNodeID(t *testing.T) {
	tempDir := t.TempDir()

	first, err := loadOrCreateStrongNodeID(tempDir)
	if err != nil {
		t.Fatalf("loadOrCreateStrongNodeID unexpectedly failed: %s", err)
	}
	if len(first) != strongNodeIDHexLen {
		t.Fatalf("unexpected strong-node ID length: got %d expected %d", len(first), strongNodeIDHexLen)
	}

	second, err := loadOrCreateStrongNodeID(tempDir)
	if err != nil {
		t.Fatalf("loadOrCreateStrongNodeID unexpectedly failed on second call: %s", err)
	}
	if second != first {
		t.Fatalf("expected strong-node ID to persist across loads")
	}
}

func TestNormalizeStrongNodeIDHex(t *testing.T) {
	valid := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	normalized, ok := normalizeStrongNodeIDHex(valid)
	if !ok {
		t.Fatalf("expected valid strong-node ID")
	}
	if normalized != valid {
		t.Fatalf("unexpected normalization result")
	}

	if _, ok = normalizeStrongNodeIDHex("invalid-id"); ok {
		t.Fatalf("expected invalid strong-node ID to be rejected")
	}
}

func TestLoadStrongNodeIDInvalidFile(t *testing.T) {
	tempDir := t.TempDir()
	identityFile := filepath.Join(tempDir, strongNodeIDFilename)
	if err := os.WriteFile(identityFile, []byte(`{"schema_version":1,"static_id":"zz"}`), 0o600); err != nil {
		t.Fatalf("failed writing identity fixture: %s", err)
	}

	if _, err := loadStrongNodeID(identityFile); err == nil {
		t.Fatalf("expected invalid strong-node identity file to fail")
	}
}
