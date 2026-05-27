package blockrelay

import (
	"testing"
	"time"

	"github.com/cryptix-network/cryptixd/infrastructure/config"
)

func TestAtomicP2PAuditDAALagMatchesStableRustRendezvousPolicy(t *testing.T) {
	if atomicP2PAuditDAALag != 60 {
		t.Fatalf("atomicP2PAuditDAALag = %d, want 60", atomicP2PAuditDAALag)
	}
}

func TestAtomicP2PAuditDefaultIntervalIsThreeMinutes(t *testing.T) {
	cfg := config.DefaultConfig()
	if got := atomicP2PAuditIntervalFromConfig(cfg); got != 3*time.Minute {
		t.Fatalf("atomicP2PAuditIntervalFromConfig(default) = %s, want 3m", got)
	}
}

func TestAtomicP2PAuditIntervalOverride(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.AtomicHealthAuditIntervalMinutes = 7
	if got := atomicP2PAuditIntervalFromConfig(cfg); got != 7*time.Minute {
		t.Fatalf("atomicP2PAuditIntervalFromConfig(7) = %s, want 7m", got)
	}
}

func TestAtomicP2PAuditCanBeDisabled(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.DisableAtomicHealthAudit = true
	if atomicP2PAuditEnabled(cfg) {
		t.Fatalf("atomicP2PAuditEnabled returned true with DisableAtomicHealthAudit")
	}
}
