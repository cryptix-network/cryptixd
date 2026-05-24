package mempool

import (
	"testing"
	"time"

	"github.com/cryptix-network/cryptixd/domain/dagconfig"
)

func TestDefaultConfigAtomicExpiryIsFixedDAA(t *testing.T) {
	oneBPS := DefaultConfig(&dagconfig.Params{TargetTimePerBlock: time.Second})
	tenBPS := DefaultConfig(&dagconfig.Params{TargetTimePerBlock: 100 * time.Millisecond})

	if oneBPS.AtomicTransactionExpireIntervalDAAScore != defaultAtomicTransactionExpireIntervalDAA {
		t.Fatalf("1 BPS atomic expiry DAA: got %d, want %d",
			oneBPS.AtomicTransactionExpireIntervalDAAScore, defaultAtomicTransactionExpireIntervalDAA)
	}
	if tenBPS.AtomicTransactionExpireIntervalDAAScore != defaultAtomicTransactionExpireIntervalDAA {
		t.Fatalf("10 BPS atomic expiry DAA: got %d, want %d",
			tenBPS.AtomicTransactionExpireIntervalDAAScore, defaultAtomicTransactionExpireIntervalDAA)
	}
	if oneBPS.AtomicTransactionTotalExpireIntervalDAAScore != defaultAtomicTransactionTotalExpireIntervalDAA {
		t.Fatalf("1 BPS atomic total expiry DAA: got %d, want %d",
			oneBPS.AtomicTransactionTotalExpireIntervalDAAScore, defaultAtomicTransactionTotalExpireIntervalDAA)
	}
	if tenBPS.AtomicTransactionTotalExpireIntervalDAAScore != defaultAtomicTransactionTotalExpireIntervalDAA {
		t.Fatalf("10 BPS atomic total expiry DAA: got %d, want %d",
			tenBPS.AtomicTransactionTotalExpireIntervalDAAScore, defaultAtomicTransactionTotalExpireIntervalDAA)
	}
	if tenBPS.TransactionExpireScanIntervalDAAScore != defaultTransactionExpireScanIntervalSeconds*10 {
		t.Fatalf("10 BPS scan interval DAA: got %d, want %d",
			tenBPS.TransactionExpireScanIntervalDAAScore, defaultTransactionExpireScanIntervalSeconds*10)
	}
}
