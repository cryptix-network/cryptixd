package antifraud

import "testing"

func TestShouldDisconnectOnConsecutiveMismatch(t *testing.T) {
	streak := 0
	for i := 0; i < modeMismatchThreshold-1; i++ {
		if shouldDisconnectOnConsecutiveMismatch(&streak, true) {
			t.Fatalf("unexpected disconnect before threshold at iteration %d", i)
		}
	}
	if streak != modeMismatchThreshold-1 {
		t.Fatalf("unexpected streak value: got %d expected %d", streak, modeMismatchThreshold-1)
	}
	if !shouldDisconnectOnConsecutiveMismatch(&streak, true) {
		t.Fatalf("expected disconnect at threshold")
	}
}

func TestShouldDisconnectOnConsecutiveMismatchResetsAfterHealthyTick(t *testing.T) {
	streak := 0
	if shouldDisconnectOnConsecutiveMismatch(&streak, true) {
		t.Fatalf("unexpected disconnect on first mismatch")
	}
	if shouldDisconnectOnConsecutiveMismatch(&streak, false) {
		t.Fatalf("healthy tick must not trigger disconnect")
	}
	if streak != 0 {
		t.Fatalf("expected streak reset after healthy tick, got %d", streak)
	}
}
