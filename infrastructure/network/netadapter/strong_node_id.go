package netadapter

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

const (
	strongNodeIDSchemaVersion = 1
	strongNodeIDDirName       = "strong-nodes"
	strongNodeIDFilename      = "go_strong_node_identity.json"
	strongNodeIDFileMaxBytes  = 16 * 1024
	strongNodeIDHexLen        = 64
)

type strongNodeIdentityDisk struct {
	SchemaVersion uint32 `json:"schema_version"`
	StaticID      string `json:"static_id"`
}

func loadOrCreateStrongNodeID(appDir string) (string, error) {
	strongNodeIDDir := filepath.Join(appDir, strongNodeIDDirName)
	if err := os.MkdirAll(strongNodeIDDir, 0o700); err != nil {
		return "", errors.Wrap(err, "failed creating strong-node identity directory")
	}

	identityFile := filepath.Join(strongNodeIDDir, strongNodeIDFilename)
	staticID, err := loadStrongNodeID(identityFile)
	if err == nil {
		return staticID, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		log.Warnf("Failed loading persisted strong-node ID from %s: %s. Regenerating a new one.", identityFile, err)
	}

	staticID, err = generateStrongNodeID()
	if err != nil {
		return "", errors.Wrap(err, "failed generating strong-node ID")
	}
	if err = persistStrongNodeID(identityFile, staticID); err != nil {
		return "", errors.Wrap(err, "failed persisting strong-node ID")
	}
	return staticID, nil
}

func loadStrongNodeID(identityFile string) (string, error) {
	raw, err := os.ReadFile(identityFile)
	if err != nil {
		return "", err
	}
	if len(raw) > strongNodeIDFileMaxBytes {
		return "", errors.Errorf("strong-node identity file exceeded max size of %d bytes", strongNodeIDFileMaxBytes)
	}

	var disk strongNodeIdentityDisk
	if err := json.Unmarshal(raw, &disk); err != nil {
		return "", errors.Wrap(err, "invalid strong-node identity JSON")
	}
	if disk.SchemaVersion != strongNodeIDSchemaVersion {
		return "", errors.Errorf("unsupported strong-node identity schema version %d", disk.SchemaVersion)
	}

	staticID, ok := normalizeStrongNodeIDHex(disk.StaticID)
	if !ok {
		return "", errors.New("invalid strong-node ID encoding in identity file")
	}
	return staticID, nil
}

func persistStrongNodeID(identityFile, staticID string) error {
	tmpFile := identityFile + ".tmp"
	disk := strongNodeIdentityDisk{
		SchemaVersion: strongNodeIDSchemaVersion,
		StaticID:      staticID,
	}

	serialized, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}
	serialized = append(serialized, '\n')

	if err = os.WriteFile(tmpFile, serialized, 0o600); err != nil {
		return err
	}

	if err = os.Rename(tmpFile, identityFile); err != nil {
		_ = os.Remove(tmpFile)
		return err
	}
	return nil
}

func generateStrongNodeID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func normalizeStrongNodeIDHex(candidate string) (string, bool) {
	cleaned := strings.ToLower(strings.TrimSpace(candidate))
	if len(cleaned) != strongNodeIDHexLen {
		return "", false
	}
	if _, err := hex.DecodeString(cleaned); err != nil {
		return "", false
	}
	return cleaned, true
}
