package atomicstate

import (
	"math"
	"testing"
)

func TestCalculateTradeFeeUsesDeterministicIntegerFloor(t *testing.T) {
	tests := []struct {
		name     string
		amount   uint64
		feeBPS   uint16
		expected uint64
	}{
		{name: "one sompi rounds to zero", amount: 1, feeBPS: 1000, expected: 0},
		{name: "three point three three percent small odd fee", amount: 100, feeBPS: 333, expected: 3},
		{name: "three point three three percent below denominator", amount: 9_999, feeBPS: 333, expected: 332},
		{name: "three point three three percent above denominator", amount: 10_001, feeBPS: 333, expected: 333},
		{name: "three point three three percent common trade", amount: 1_000_000, feeBPS: 333, expected: 33_300},
		{name: "three point three three percent uneven decimal", amount: 12_345_678, feeBPS: 333, expected: 411_111},
		{name: "max amount ten percent", amount: math.MaxUint64, feeBPS: 1000, expected: 1_844_674_407_370_955_161},
		{name: "max amount three point three three percent", amount: math.MaxUint64, feeBPS: 333, expected: 614_276_577_654_528_068},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fee, err := calculateTradeFee(test.amount, test.feeBPS)
			if err != nil {
				t.Fatalf("calculateTradeFee returned error: %v", err)
			}
			if fee != test.expected {
				t.Fatalf("fee mismatch: got %d want %d", fee, test.expected)
			}
		})
	}
}

func TestApplyFeeToPoolSplitsOneAndTwoRecipientsDeterministically(t *testing.T) {
	tests := []struct {
		name           string
		recipientCount int
		feeTrade       uint64
		wantTotal      uint64
		wantRecipient0 uint64
		wantRecipient1 uint64
	}{
		{name: "zero fee leaves one recipient unchanged", recipientCount: 1, feeTrade: 0, wantTotal: 0, wantRecipient0: 0},
		{name: "one recipient receives all", recipientCount: 1, feeTrade: 333, wantTotal: 333, wantRecipient0: 333},
		{name: "two recipients split even fee equally", recipientCount: 2, feeTrade: 33_300, wantTotal: 33_300, wantRecipient0: 16_650, wantRecipient1: 16_650},
		{name: "two recipients put odd remainder on canonical second recipient", recipientCount: 2, feeTrade: 333, wantTotal: 333, wantRecipient0: 166, wantRecipient1: 167},
		{name: "two recipients tiny odd fee", recipientCount: 2, feeTrade: 3, wantTotal: 3, wantRecipient0: 1, wantRecipient1: 2},
		{name: "two recipients max rounded fee stays exact", recipientCount: 2, feeTrade: 1_844_674_407_370_955_161, wantTotal: 1_844_674_407_370_955_161, wantRecipient0: 922_337_203_685_477_580, wantRecipient1: 922_337_203_685_477_581},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recipients := make([]LiquidityFeeRecipientState, test.recipientCount)
			var total uint64
			if err := applyFeeToPool(recipients, &total, test.feeTrade); err != nil {
				t.Fatalf("applyFeeToPool returned error: %v", err)
			}

			if total != test.wantTotal {
				t.Fatalf("total mismatch: got %d want %d", total, test.wantTotal)
			}
			if test.recipientCount > 0 && recipients[0].UnclaimedSompi != test.wantRecipient0 {
				t.Fatalf("recipient0 mismatch: got %d want %d", recipients[0].UnclaimedSompi, test.wantRecipient0)
			}
			if test.recipientCount > 1 && recipients[1].UnclaimedSompi != test.wantRecipient1 {
				t.Fatalf("recipient1 mismatch: got %d want %d", recipients[1].UnclaimedSompi, test.wantRecipient1)
			}
			if test.recipientCount == 2 && recipients[0].UnclaimedSompi+recipients[1].UnclaimedSompi != total {
				t.Fatalf("recipient sum mismatch: recipients=%d total=%d",
					recipients[0].UnclaimedSompi+recipients[1].UnclaimedSompi, total)
			}
		})
	}
}

func TestApplyFeeToPoolRepeatedRoundingIsStable(t *testing.T) {
	fees := []uint64{0, 1, 3, 332, 333, 999, 33_300, 411_111, 614_276_577_654_528_068}
	recipients := make([]LiquidityFeeRecipientState, 2)
	var total, expected0, expected1 uint64

	for _, feeTrade := range fees {
		if err := applyFeeToPool(recipients, &total, feeTrade); err != nil {
			t.Fatalf("applyFeeToPool(%d) returned error: %v", feeTrade, err)
		}
		if feeTrade == 0 {
			continue
		}
		expected0 += feeTrade / 2
		expected1 += feeTrade - feeTrade/2
	}

	if recipients[0].UnclaimedSompi != expected0 {
		t.Fatalf("recipient0 mismatch after sequence: got %d want %d", recipients[0].UnclaimedSompi, expected0)
	}
	if recipients[1].UnclaimedSompi != expected1 {
		t.Fatalf("recipient1 mismatch after sequence: got %d want %d", recipients[1].UnclaimedSompi, expected1)
	}
	if total != expected0+expected1 {
		t.Fatalf("total mismatch after sequence: total=%d recipients=%d", total, expected0+expected1)
	}
}
