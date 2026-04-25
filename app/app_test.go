package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cryptix-network/cryptixd/infrastructure/config"
)

func TestRemoveDatabaseRemovesRuntimeState(t *testing.T) {
	appDir := t.TempDir()
	cfg := &config.Config{Flags: &config.Flags{AppDir: appDir}}

	for _, dirname := range resetStateDirnames {
		stateDir := filepath.Join(appDir, dirname)
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			t.Fatalf("MkdirAll(%s): %s", stateDir, err)
		}
		if err := os.WriteFile(filepath.Join(stateDir, "state"), []byte("state"), 0o600); err != nil {
			t.Fatalf("WriteFile(%s): %s", stateDir, err)
		}
	}

	logDir := filepath.Join(appDir, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(logs): %s", err)
	}

	if err := removeDatabase(cfg); err != nil {
		t.Fatalf("removeDatabase: %s", err)
	}

	for _, dirname := range resetStateDirnames {
		stateDir := filepath.Join(appDir, dirname)
		if _, err := os.Stat(stateDir); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be removed, got err=%v", stateDir, err)
		}
	}
	if _, err := os.Stat(logDir); err != nil {
		t.Fatalf("expected logs directory to be kept: %s", err)
	}
}
