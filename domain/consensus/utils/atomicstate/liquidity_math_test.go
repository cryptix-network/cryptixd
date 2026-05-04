package atomicstate

import (
	"strings"
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus/utils/constants"
)

func buyWithGrossForTest(realTokenReserves Uint128, virtualCPayReserves uint64, virtualTokenReserves Uint128, grossIn uint64, feeBPS uint16) (uint64, uint64, Uint128, Uint128, uint64, Uint128, error) {
	fee, err := calculateTradeFee(grossIn, feeBPS)
	if err != nil {
		return 0, 0, Uint128{}, Uint128{}, 0, Uint128{}, err
	}
	net := grossIn - fee
	tokenOut, newRealTokenReserves, newVirtualCPayReserves, newVirtualTokenReserves, err :=
		cpmmBuy(realTokenReserves, virtualCPayReserves, virtualTokenReserves, net)
	return fee, net, tokenOut, newRealTokenReserves, newVirtualCPayReserves, newVirtualTokenReserves, err
}

func buyAcceptedForTest(realTokenReserves Uint128, virtualCPayReserves uint64, virtualTokenReserves Uint128, grossIn uint64, feeBPS uint16) bool {
	fee, err := calculateTradeFee(grossIn, feeBPS)
	if err != nil || grossIn < fee {
		return false
	}
	_, _, _, _, err = cpmmBuy(realTokenReserves, virtualCPayReserves, virtualTokenReserves, grossIn-fee)
	return err == nil
}

func maxBuyInSompiForTest(realTokenReserves Uint128, virtualCPayReserves uint64, virtualTokenReserves Uint128, feeBPS uint16) uint64 {
	tokenOut, ok := realTokenReserves.Sub(Uint128FromUint64(minRealTokenReserve))
	if !ok || tokenOut.IsZero() {
		return 0
	}
	max, err := minGrossInputForTokenOut(realTokenReserves, virtualCPayReserves, virtualTokenReserves, tokenOut, feeBPS)
	if err != nil {
		panic(err)
	}
	return max
}

func TestCPMMBuyStopsBeforeFinalRealToken(t *testing.T) {
	tokenOut, remaining, _, _, err := cpmmBuy(Uint128FromUint64(2), 1_000, Uint128FromUint64(2), 1_000)
	if err != nil {
		t.Fatalf("buy failed: %v", err)
	}
	if tokenOut.Compare(Uint128FromUint64(1)) != 0 {
		t.Fatalf("unexpected tokenOut: got %s, want 1", tokenOut.Big().String())
	}
	if remaining.Compare(Uint128FromUint64(minRealTokenReserve)) != 0 {
		t.Fatalf("unexpected real token reserve: got %s, want 1", remaining.Big().String())
	}
}

func TestCPMMBuyRejectsFinalTokenDrain(t *testing.T) {
	_, _, _, _, err := cpmmBuy(Uint128FromUint64(2), 1_000, Uint128FromUint64(3), 2_000)
	if err == nil {
		t.Fatal("expected final token drain to fail")
	}
	if !strings.Contains(err.Error(), "drain final real token") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCPMMSellRejectsGrossReserveBreachEvenWhenNetPayoutWouldFit(t *testing.T) {
	grossOut := uint64(1_000)
	fee, err := calculateTradeFee(grossOut, 1_000)
	if err != nil {
		t.Fatalf("fee failed: %v", err)
	}
	cpayOut := grossOut - fee
	if !(grossOut > 1_000-minCPayReserve && cpayOut <= 1_000-minCPayReserve) {
		t.Fatalf("test setup invalid: gross=%d cpayOut=%d", grossOut, cpayOut)
	}
	_, _, _, _, err = cpmmSell(1_000, 2_000, Uint128FromUint64(1), Uint128FromUint64(1))
	if err == nil {
		t.Fatal("expected gross floor breach to fail")
	}
	if !strings.Contains(err.Error(), "drain final real sompi") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSplitSellRoundTripDoesNotExtractRoundingProfit(t *testing.T) {
	buyInput := uint64(7)
	tokenOut, _, virtualCPay, virtualTokens, err := cpmmBuy(Uint128FromUint64(4), 2, Uint128FromUint64(4), buyInput)
	if err != nil {
		t.Fatalf("buy failed: %v", err)
	}
	tokenOut64, ok := tokenOut.Uint64()
	if !ok {
		t.Fatalf("tokenOut too large: %s", tokenOut.Big().String())
	}
	if tokenOut64 != 3 {
		t.Fatalf("tokenOut got %d want 3", tokenOut64)
	}

	realCPay := virtualCPay
	totalGrossOut := uint64(0)
	for sold := uint64(0); sold < tokenOut64; sold++ {
		grossOut, nextRealCPay, nextVirtualCPay, nextVirtualTokens, err := cpmmSell(
			realCPay,
			virtualCPay,
			virtualTokens,
			Uint128FromUint64(1),
		)
		if err != nil {
			t.Fatalf("sell %d failed: %v", sold, err)
		}
		totalGrossOut, ok = checkedAddUint64(totalGrossOut, grossOut)
		if !ok {
			t.Fatal("total gross out overflow")
		}
		realCPay = nextRealCPay
		virtualCPay = nextVirtualCPay
		virtualTokens = nextVirtualTokens
	}
	if totalGrossOut > buyInput {
		t.Fatalf("split sell extracted rounding profit: buy=%d sell=%d", buyInput, totalGrossOut)
	}
}

func FuzzCPMMBuyThenSplitSellDoesNotExtractRoundingProfit(f *testing.F) {
	f.Add(uint64(4), uint64(2), uint64(4), uint64(7))
	f.Add(uint64(1_000_000), uint64(initialVirtualCPayReserves), uint64(initialVirtualTokenReserve), uint64(10*constants.SompiPerCryptix))
	f.Add(uint64(777_777), uint64(1_234_567_890_123), uint64(987_654), uint64(987_654_321))

	f.Fuzz(func(t *testing.T, realTokenSeed uint64, virtualCPaySeed uint64, virtualTokenSeed uint64, cpayInSeed uint64) {
		realTokenReserves := Uint128FromUint64(2 + realTokenSeed%10_000)
		virtualCPayReserves := uint64(1 + virtualCPaySeed%1_000_000_000_000)
		virtualTokenReserves := Uint128FromUint64(2 + virtualTokenSeed%20_000)
		cpayIn := uint64(1 + cpayInSeed%1_000_000_000)

		tokenOut, _, virtualCPay, virtualTokens, err := cpmmBuy(realTokenReserves, virtualCPayReserves, virtualTokenReserves, cpayIn)
		if err != nil {
			return
		}
		tokenOut64, ok := tokenOut.Uint64()
		if !ok || tokenOut64 == 0 || tokenOut64 > 256 {
			return
		}

		realCPay := virtualCPay
		totalGrossOut := uint64(0)
		for sold := uint64(0); sold < tokenOut64; sold++ {
			grossOut, nextRealCPay, nextVirtualCPay, nextVirtualTokens, err := cpmmSell(
				realCPay,
				virtualCPay,
				virtualTokens,
				Uint128FromUint64(1),
			)
			if err != nil {
				return
			}
			totalGrossOut, ok = checkedAddUint64(totalGrossOut, grossOut)
			if !ok {
				t.Fatal("total gross out overflow")
			}
			realCPay = nextRealCPay
			virtualCPay = nextVirtualCPay
			virtualTokens = nextVirtualTokens
		}

		if totalGrossOut > cpayIn {
			t.Fatalf("split sell extracted rounding profit: buy=%d sell=%d tokenOut=%d", cpayIn, totalGrossOut, tokenOut64)
		}
	})
}

func TestInitialVirtualTokenReservesScaleWithSupply(t *testing.T) {
	tests := []struct {
		maxSupply uint64
		expected  uint64
	}{
		{minLiquidityTokenSupplyRaw, 120_000},
		{liquidityTokenSupplyRaw, 1_200_000},
		{maxLiquidityTokenSupplyRaw, 12_000_000},
	}
	for _, test := range tests {
		got, err := initialVirtualTokenReservesForMaxSupply(Uint128FromUint64(test.maxSupply))
		if err != nil {
			t.Fatalf("maxSupply %d failed: %v", test.maxSupply, err)
		}
		if got.Compare(Uint128FromUint64(test.expected)) != 0 {
			t.Fatalf("maxSupply %d got %s want %d", test.maxSupply, got.Big().String(), test.expected)
		}
	}
	if _, err := initialVirtualTokenReservesForMaxSupply(Uint128FromUint64(minLiquidityTokenSupplyRaw - 1)); err == nil {
		t.Fatal("expected below-min supply to fail")
	}
	if _, err := initialVirtualTokenReservesForMaxSupply(Uint128FromUint64(maxLiquidityTokenSupplyRaw + 1)); err == nil {
		t.Fatal("expected above-max supply to fail")
	}
}

func TestAggressiveModeUsesSmallerVirtualReserves(t *testing.T) {
	virtualCPay, err := initialVirtualCPayReservesForMode(liquidityCurveModeAggressive)
	if err != nil {
		t.Fatalf("aggressive virtual cpay failed: %v", err)
	}
	if virtualCPay != aggressiveVirtualCPayReserve {
		t.Fatalf("aggressive virtual cpay got %d want %d", virtualCPay, aggressiveVirtualCPayReserve)
	}
	tests := []struct {
		maxSupply uint64
		expected  uint64
	}{
		{minLiquidityTokenSupplyRaw, 105_000},
		{liquidityTokenSupplyRaw, 1_050_000},
		{maxLiquidityTokenSupplyRaw, 10_500_000},
	}
	for _, test := range tests {
		got, err := initialVirtualTokenReservesForMaxSupplyAndMode(Uint128FromUint64(test.maxSupply), liquidityCurveModeAggressive)
		if err != nil {
			t.Fatalf("maxSupply %d failed: %v", test.maxSupply, err)
		}
		if got.Compare(Uint128FromUint64(test.expected)) != 0 {
			t.Fatalf("maxSupply %d got %s want %d", test.maxSupply, got.Big().String(), test.expected)
		}
	}
	if err := validateLiquidityCurveMode(99); err == nil {
		t.Fatal("expected invalid curve mode to fail")
	}
}

func TestIndividualModeUsesStrictIntegerCurveParams(t *testing.T) {
	if err := validateLiquidityCurveParameters(liquidityCurveModeIndividual, aggressiveVirtualCPayReserve, 10_500); err != nil {
		t.Fatalf("valid individual params failed: %v", err)
	}
	if err := validateLiquidityCurveParameters(liquidityCurveModeIndividual, individualMaxVirtualCPay, 20_000); err != nil {
		t.Fatalf("valid individual max params failed: %v", err)
	}
	virtualCPay, err := initialVirtualCPayReservesForCurve(liquidityCurveModeIndividual, aggressiveVirtualCPayReserve)
	if err != nil {
		t.Fatalf("individual virtual cpay failed: %v", err)
	}
	if virtualCPay != aggressiveVirtualCPayReserve {
		t.Fatalf("individual virtual cpay got %d want %d", virtualCPay, aggressiveVirtualCPayReserve)
	}
	virtualTokens, err := initialVirtualTokenReservesForMaxSupplyAndCurve(Uint128FromUint64(liquidityTokenSupplyRaw), liquidityCurveModeIndividual, 10_500)
	if err != nil {
		t.Fatalf("individual virtual tokens failed: %v", err)
	}
	if virtualTokens.Compare(Uint128FromUint64(1_050_000)) != 0 {
		t.Fatalf("individual virtual tokens got %s want 1050000", virtualTokens.Big().String())
	}
	if err := validateLiquidityCurveParameters(liquidityCurveModeBasic, aggressiveVirtualCPayReserve, 10_500); err == nil {
		t.Fatal("expected non-individual mode with individual params to fail")
	}
	if err := validateLiquidityCurveParameters(liquidityCurveModeIndividual, individualMinVirtualCPay+1, 10_500); err == nil {
		t.Fatal("expected fixed CPAY step violation to fail")
	}
	if err := validateLiquidityCurveParameters(liquidityCurveModeIndividual, aggressiveVirtualCPayReserve, 10_550); err == nil {
		t.Fatal("expected multiplier step violation to fail")
	}
}

func TestIndividualModeTradeVectorsAreExactAcrossRange(t *testing.T) {
	buyTests := []struct {
		name                  string
		maxSupply             uint64
		fixedCPay             uint64
		multiplierBPS         uint16
		grossIn               uint64
		feeBPS                uint16
		expectedFee           uint64
		expectedNet           uint64
		expectedTokenOut      uint64
		expectedRealTokens    uint64
		expectedVirtualCPay   uint64
		expectedVirtualTokens uint64
	}{
		{"individual_min_buy_1000_cpay_100bps", liquidityTokenSupplyRaw, individualMinVirtualCPay, 10_100, 1_000 * constants.SompiPerCryptix, 100, 1_000_000_000, 99_000_000_000, 998, 999_002, 100_099_000_000_000, 1_009_002},
		{"individual_default_buy_1000_cpay_100bps", liquidityTokenSupplyRaw, aggressiveVirtualCPayReserve, 10_500, 1_000 * constants.SompiPerCryptix, 100, 1_000_000_000, 99_000_000_000, 519, 999_481, 200_099_000_000_000, 1_049_481},
		{"individual_max_buy_1000_cpay_100bps", liquidityTokenSupplyRaw, individualMaxVirtualCPay, 20_000, 1_000 * constants.SompiPerCryptix, 100, 1_000_000_000, 99_000_000_000, 247, 999_753, 800_099_000_000_000, 1_999_753},
		{"individual_custom_buy_12345_cpay_40bps", 5_000_000, 330_000_000_000_000, 14_600, 12_345 * constants.SompiPerCryptix, 40, 4_938_000_000, 1_229_562_000_000, 27_098, 4_972_902, 331_229_562_000_000, 7_272_902},
	}
	for _, test := range buyTests {
		virtualCPay, err := initialVirtualCPayReservesForCurve(liquidityCurveModeIndividual, test.fixedCPay)
		if err != nil {
			t.Fatalf("%s virtual cpay failed: %v", test.name, err)
		}
		virtualTokens, err := initialVirtualTokenReservesForMaxSupplyAndCurve(Uint128FromUint64(test.maxSupply), liquidityCurveModeIndividual, test.multiplierBPS)
		if err != nil {
			t.Fatalf("%s virtual tokens failed: %v", test.name, err)
		}
		fee, net, tokenOut, realTokens, newVirtualCPay, newVirtualTokens, err := buyWithGrossForTest(
			Uint128FromUint64(test.maxSupply),
			virtualCPay,
			virtualTokens,
			test.grossIn,
			test.feeBPS,
		)
		if err != nil {
			t.Fatalf("%s failed: %v", test.name, err)
		}
		if fee != test.expectedFee || net != test.expectedNet || newVirtualCPay != test.expectedVirtualCPay {
			t.Fatalf("%s mismatch fee/net/vcpay: got %d/%d/%d", test.name, fee, net, newVirtualCPay)
		}
		if tokenOut.Compare(Uint128FromUint64(test.expectedTokenOut)) != 0 {
			t.Fatalf("%s tokenOut got %s want %d", test.name, tokenOut.Big().String(), test.expectedTokenOut)
		}
		if realTokens.Compare(Uint128FromUint64(test.expectedRealTokens)) != 0 {
			t.Fatalf("%s real tokens got %s want %d", test.name, realTokens.Big().String(), test.expectedRealTokens)
		}
		if newVirtualTokens.Compare(Uint128FromUint64(test.expectedVirtualTokens)) != 0 {
			t.Fatalf("%s virtual tokens got %s want %d", test.name, newVirtualTokens.Big().String(), test.expectedVirtualTokens)
		}
	}

	sellTests := []struct {
		name                  string
		realCPay              uint64
		virtualCPay           uint64
		virtualTokens         uint64
		tokenIn               uint64
		feeBPS                uint16
		expectedGrossOut      uint64
		expectedFee           uint64
		expectedCPayOut       uint64
		expectedRealCPay      uint64
		expectedVirtualCPay   uint64
		expectedVirtualTokens uint64
	}{
		{"individual_min_sell_250_tokens_100bps", 99_100_000_000, 100_099_000_000_000, 1_009_002, 250, 100, 24_795_343_482, 247_953_434, 24_547_390_048, 74_304_656_518, 100_074_204_656_518, 1_009_252},
		{"individual_max_sell_247_tokens_100bps", 99_100_000_000, 800_099_000_000_000, 1_999_753, 247, 100, 98_812_226_500, 988_122_265, 97_824_104_235, 287_773_500, 800_000_187_773_500, 2_000_000},
		{"individual_custom_sell_7777_tokens_40bps", 1_229_662_000_000, 331_229_562_000_000, 7_272_902, 7_777, 40, 353_809_349_879, 1_415_237_399, 352_394_112_480, 875_852_650_121, 330_875_752_650_121, 7_280_679},
	}
	for _, test := range sellTests {
		grossOut, realCPay, virtualCPay, virtualTokens, err := cpmmSell(
			test.realCPay,
			test.virtualCPay,
			Uint128FromUint64(test.virtualTokens),
			Uint128FromUint64(test.tokenIn),
		)
		if err != nil {
			t.Fatalf("%s failed: %v", test.name, err)
		}
		fee, err := calculateTradeFee(grossOut, test.feeBPS)
		if err != nil {
			t.Fatalf("%s fee failed: %v", test.name, err)
		}
		cpayOut := grossOut - fee
		if grossOut != test.expectedGrossOut || fee != test.expectedFee || cpayOut != test.expectedCPayOut {
			t.Fatalf("%s payout mismatch: got gross=%d fee=%d out=%d", test.name, grossOut, fee, cpayOut)
		}
		if realCPay != test.expectedRealCPay || virtualCPay != test.expectedVirtualCPay {
			t.Fatalf("%s reserve mismatch: got real=%d virtual=%d", test.name, realCPay, virtualCPay)
		}
		if virtualTokens.Compare(Uint128FromUint64(test.expectedVirtualTokens)) != 0 {
			t.Fatalf("%s virtual tokens got %s want %d", test.name, virtualTokens.Big().String(), test.expectedVirtualTokens)
		}
	}
}

func TestMinGrossInputForTokenOutRemovesIntegerOverpay(t *testing.T) {
	budget := uint64(10 * constants.SompiPerCryptix)
	tokenOut, _, _, _, err := cpmmBuy(
		Uint128FromUint64(liquidityTokenSupplyRaw),
		initialVirtualCPayReserves,
		Uint128FromUint64(initialVirtualTokenReserve),
		budget,
	)
	if err != nil {
		t.Fatalf("budget buy failed: %v", err)
	}
	if tokenOut.Compare(Uint128FromUint64(4)) != 0 {
		t.Fatalf("budget tokenOut got %s want 4", tokenOut.Big().String())
	}
	canonical, err := minGrossInputForTokenOut(
		Uint128FromUint64(liquidityTokenSupplyRaw),
		initialVirtualCPayReserves,
		Uint128FromUint64(initialVirtualTokenReserve),
		tokenOut,
		0,
	)
	if err != nil {
		t.Fatalf("canonical input failed: %v", err)
	}
	if canonical != 833_336_112 {
		t.Fatalf("canonical input got %d want 833336112", canonical)
	}
	if canonical >= budget {
		t.Fatalf("canonical input should be below budget: canonical=%d budget=%d", canonical, budget)
	}
	previousTokenOut, _, _, _, err := cpmmBuy(
		Uint128FromUint64(liquidityTokenSupplyRaw),
		initialVirtualCPayReserves,
		Uint128FromUint64(initialVirtualTokenReserve),
		canonical-1,
	)
	if err != nil {
		t.Fatalf("previous buy failed: %v", err)
	}
	if previousTokenOut.Compare(Uint128FromUint64(3)) != 0 {
		t.Fatalf("previous tokenOut got %s want 3", previousTokenOut.Big().String())
	}
}

func TestMinGrossInputForTokenOutAccountsForFeeFlooring(t *testing.T) {
	budget := uint64(1_000 * constants.SompiPerCryptix)
	feeBPS := uint16(100)
	fee, err := calculateTradeFee(budget, feeBPS)
	if err != nil {
		t.Fatalf("fee failed: %v", err)
	}
	tokenOut, _, _, _, err := cpmmBuy(
		Uint128FromUint64(liquidityTokenSupplyRaw),
		initialVirtualCPayReserves,
		Uint128FromUint64(initialVirtualTokenReserve),
		budget-fee,
	)
	if err != nil {
		t.Fatalf("budget buy failed: %v", err)
	}
	canonical, err := minGrossInputForTokenOut(
		Uint128FromUint64(liquidityTokenSupplyRaw),
		initialVirtualCPayReserves,
		Uint128FromUint64(initialVirtualTokenReserve),
		tokenOut,
		feeBPS,
	)
	if err != nil {
		t.Fatalf("canonical input failed: %v", err)
	}
	if canonical >= budget {
		t.Fatalf("canonical input should be below budget: canonical=%d budget=%d", canonical, budget)
	}
	canonicalFee, err := calculateTradeFee(canonical, feeBPS)
	if err != nil {
		t.Fatalf("canonical fee failed: %v", err)
	}
	canonicalTokenOut, _, _, _, err := cpmmBuy(
		Uint128FromUint64(liquidityTokenSupplyRaw),
		initialVirtualCPayReserves,
		Uint128FromUint64(initialVirtualTokenReserve),
		canonical-canonicalFee,
	)
	if err != nil {
		t.Fatalf("canonical buy failed: %v", err)
	}
	if canonicalTokenOut.Compare(tokenOut) != 0 {
		t.Fatalf("canonical tokenOut got %s want %s", canonicalTokenOut.Big().String(), tokenOut.Big().String())
	}
}

func TestInitialNoFeeBuyShape(t *testing.T) {
	_, _, _, _, err := cpmmBuy(
		Uint128FromUint64(liquidityTokenSupplyRaw),
		initialVirtualCPayReserves,
		Uint128FromUint64(initialVirtualTokenReserve),
		constants.SompiPerCryptix,
	)
	if err == nil || !strings.Contains(err.Error(), "zero token_out") {
		t.Fatalf("expected 1 CPAY to produce deterministic zero-output error, got %v", err)
	}
	_, _, _, _, err = cpmmBuy(
		Uint128FromUint64(liquidityTokenSupplyRaw),
		initialVirtualCPayReserves,
		Uint128FromUint64(initialVirtualTokenReserve),
		2*constants.SompiPerCryptix,
	)
	if err == nil || !strings.Contains(err.Error(), "zero token_out") {
		t.Fatalf("expected 2 CPAY to produce deterministic zero-output error, got %v", err)
	}

	tests := []struct {
		cpay     uint64
		expected uint64
	}{
		{5, 2},
		{10, 4},
		{50, 23},
		{100, 47},
		{500, 239},
		{1_000, 479},
		{5_000, 2_395},
		{10_000, 4_780},
		{100_000, 46_153},
		{500_000, 200_000},
		{1_000_000, 342_857},
		{2_500_000, 600_000},
	}
	for _, test := range tests {
		tokenOut, _, _, _, err := cpmmBuy(
			Uint128FromUint64(liquidityTokenSupplyRaw),
			initialVirtualCPayReserves,
			Uint128FromUint64(initialVirtualTokenReserve),
			test.cpay*constants.SompiPerCryptix,
		)
		if err != nil {
			t.Fatalf("%d CPAY failed: %v", test.cpay, err)
		}
		if tokenOut.Compare(Uint128FromUint64(test.expected)) != 0 {
			t.Fatalf("%d CPAY tokenOut got %s want %d", test.cpay, tokenOut.Big().String(), test.expected)
		}
	}
}

func TestSameCPayBuyIsSupplyPercentageStable(t *testing.T) {
	minPPM := uint64(^uint64(0))
	maxPPM := uint64(0)
	for _, maxSupply := range []uint64{minLiquidityTokenSupplyRaw, liquidityTokenSupplyRaw, maxLiquidityTokenSupplyRaw} {
		virtualTokens, err := initialVirtualTokenReservesForMaxSupply(Uint128FromUint64(maxSupply))
		if err != nil {
			t.Fatalf("virtual tokens failed: %v", err)
		}
		tokenOut, _, _, _, err := cpmmBuy(
			Uint128FromUint64(maxSupply),
			initialVirtualCPayReserves,
			virtualTokens,
			1_000*constants.SompiPerCryptix,
		)
		if err != nil {
			t.Fatalf("buy failed for maxSupply %d: %v", maxSupply, err)
		}
		tokenOut64, ok := tokenOut.Uint64()
		if !ok {
			t.Fatalf("tokenOut too large: %s", tokenOut.Big().String())
		}
		ppm := tokenOut64 * 1_000_000 / maxSupply
		if ppm < minPPM {
			minPPM = ppm
		}
		if ppm > maxPPM {
			maxPPM = ppm
		}
	}
	if maxPPM-minPPM > 10 {
		t.Fatalf("scaled curve drift too high: minPPM=%d maxPPM=%d", minPPM, maxPPM)
	}
}

func TestRustGoDeterminismBuyVectorsAreExact(t *testing.T) {
	tests := []struct {
		name                     string
		realTokenReserves        Uint128
		virtualCPayReserves      uint64
		virtualTokenReserves     Uint128
		grossIn                  uint64
		feeBPS                   uint16
		expectedFee              uint64
		expectedNet              uint64
		expectedTokenOut         uint64
		expectedRealTokens       uint64
		expectedVirtualCPay      uint64
		expectedVirtualTokenRest uint64
	}{
		{"initial_buy_10_cpay_no_fee", Uint128FromUint64(liquidityTokenSupplyRaw), initialVirtualCPayReserves, Uint128FromUint64(initialVirtualTokenReserve), 10 * constants.SompiPerCryptix, 0, 0, 10 * constants.SompiPerCryptix, 4, 999_996, 250_001_000_000_000, 1_199_996},
		{"initial_buy_1000_cpay_100bps", Uint128FromUint64(liquidityTokenSupplyRaw), initialVirtualCPayReserves, Uint128FromUint64(initialVirtualTokenReserve), 1_000 * constants.SompiPerCryptix, 100, 1_000_000_000, 99_000_000_000, 475, 999_525, 250_099_000_000_000, 1_199_525},
		{"aggressive_initial_buy_1000_cpay_100bps", Uint128FromUint64(liquidityTokenSupplyRaw), aggressiveVirtualCPayReserve, Uint128FromUint64(aggressiveVirtualTokenReserve), 1_000 * constants.SompiPerCryptix, 100, 1_000_000_000, 99_000_000_000, 519, 999_481, 200_099_000_000_000, 1_049_481},
		{"custom_buy_fee_250bps", Uint128FromUint64(777_777), 1_234_567_890_123, Uint128FromUint64(987_654), 987_654_321, 250, 24_691_358, 962_962_963, 769, 777_008, 1_235_530_853_086, 986_885},
		{"near_inventory_buy_exact_one", Uint128FromUint64(2), 1_000, Uint128FromUint64(2), 1_000, 0, 0, 1_000, 1, 1, 2_000, 1},
	}
	for _, test := range tests {
		fee, net, tokenOut, realTokens, virtualCPay, virtualTokens, err := buyWithGrossForTest(
			test.realTokenReserves,
			test.virtualCPayReserves,
			test.virtualTokenReserves,
			test.grossIn,
			test.feeBPS,
		)
		if err != nil {
			t.Fatalf("%s failed: %v", test.name, err)
		}
		if fee != test.expectedFee || net != test.expectedNet || virtualCPay != test.expectedVirtualCPay {
			t.Fatalf("%s mismatch fee/net/vcpay: got %d/%d/%d", test.name, fee, net, virtualCPay)
		}
		if tokenOut.Compare(Uint128FromUint64(test.expectedTokenOut)) != 0 {
			t.Fatalf("%s tokenOut got %s want %d", test.name, tokenOut.Big().String(), test.expectedTokenOut)
		}
		if realTokens.Compare(Uint128FromUint64(test.expectedRealTokens)) != 0 {
			t.Fatalf("%s real tokens got %s want %d", test.name, realTokens.Big().String(), test.expectedRealTokens)
		}
		if virtualTokens.Compare(Uint128FromUint64(test.expectedVirtualTokenRest)) != 0 {
			t.Fatalf("%s virtual tokens got %s want %d", test.name, virtualTokens.Big().String(), test.expectedVirtualTokenRest)
		}
	}
}

func TestRustGoDeterminismSellVectorsAreExact(t *testing.T) {
	tests := []struct {
		name                string
		realCPayReserves    uint64
		virtualCPayReserves uint64
		virtualTokenReserve Uint128
		tokenIn             Uint128
		feeBPS              uint16
		expectedGrossOut    uint64
		expectedFee         uint64
		expectedCPayOut     uint64
		expectedRealCPay    uint64
		expectedVirtualCPay uint64
		expectedVirtualTok  uint64
	}{
		{"sell_initialish_100_100bps", 99_100_000_000, 250_099_000_000_000, Uint128FromUint64(1_199_525), Uint128FromUint64(100), 100, 20_848_098_364, 208_480_983, 20_639_617_381, 78_251_901_636, 250_078_151_901_636, 1_199_625},
		{"sell_custom_250bps", 20_000_000_000, 987_654_321_000, Uint128FromUint64(876_543), Uint128FromUint64(12_345), 250, 13_716_680_383, 342_917_009, 13_373_763_374, 6_283_319_617, 973_937_640_617, 888_888},
		{"sell_big_1000bps", 50_000_000_000_000, 1_234_567_890_123, Uint128FromUint64(987_654), Uint128FromUint64(500_000), 1_000, 414_937_845_131, 41_493_784_513, 373_444_060_618, 49_585_062_154_869, 819_630_044_992, 1_487_654},
	}
	for _, test := range tests {
		grossOut, realCPay, virtualCPay, virtualTokens, err := cpmmSell(
			test.realCPayReserves,
			test.virtualCPayReserves,
			test.virtualTokenReserve,
			test.tokenIn,
		)
		if err != nil {
			t.Fatalf("%s failed: %v", test.name, err)
		}
		fee, err := calculateTradeFee(grossOut, test.feeBPS)
		if err != nil {
			t.Fatalf("%s fee failed: %v", test.name, err)
		}
		cpayOut := grossOut - fee
		if grossOut != test.expectedGrossOut || fee != test.expectedFee || cpayOut != test.expectedCPayOut {
			t.Fatalf("%s payout mismatch: got gross=%d fee=%d out=%d", test.name, grossOut, fee, cpayOut)
		}
		if realCPay != test.expectedRealCPay || virtualCPay != test.expectedVirtualCPay {
			t.Fatalf("%s reserve mismatch: got real=%d virtual=%d", test.name, realCPay, virtualCPay)
		}
		if virtualTokens.Compare(Uint128FromUint64(test.expectedVirtualTok)) != 0 {
			t.Fatalf("%s virtual tokens got %s want %d", test.name, virtualTokens.Big().String(), test.expectedVirtualTok)
		}
	}
}

func TestMaxBuyInSompiIsGrossAndEnforcesExactBoundary(t *testing.T) {
	tests := []struct {
		realTokenReserves    Uint128
		virtualCPayReserves  uint64
		virtualTokenReserves Uint128
		feeBPS               uint16
		expectedMax          uint64
	}{
		{Uint128FromUint64(liquidityTokenSupplyRaw), initialVirtualCPayReserves, Uint128FromUint64(initialVirtualTokenReserve), 0, 1_249_992_500_037_500},
		{Uint128FromUint64(liquidityTokenSupplyRaw), initialVirtualCPayReserves, Uint128FromUint64(initialVirtualTokenReserve), 100, 1_262_618_686_906_565},
		{Uint128FromUint64(500_000), 1_234_567_890_123, Uint128FromUint64(987_654), 250, 1_298_275_363_323},
	}
	for _, test := range tests {
		max := maxBuyInSompiForTest(test.realTokenReserves, test.virtualCPayReserves, test.virtualTokenReserves, test.feeBPS)
		if max != test.expectedMax {
			t.Fatalf("max buy got %d want %d", max, test.expectedMax)
		}
		if !buyAcceptedForTest(test.realTokenReserves, test.virtualCPayReserves, test.virtualTokenReserves, max, test.feeBPS) {
			t.Fatalf("max buy %d should be accepted", max)
		}
		fee, err := calculateTradeFee(max, test.feeBPS)
		if err != nil {
			t.Fatalf("fee failed: %v", err)
		}
		tokenOut, realTokens, _, _, err := cpmmBuy(test.realTokenReserves, test.virtualCPayReserves, test.virtualTokenReserves, max-fee)
		if err != nil {
			t.Fatalf("max buy should quote: %v", err)
		}
		if realTokens.Compare(Uint128FromUint64(minRealTokenReserve)) != 0 {
			t.Fatalf("max buy real tokens got %s want %d", realTokens.Big().String(), minRealTokenReserve)
		}
		over := max + 1
		overFee, err := calculateTradeFee(over, test.feeBPS)
		if err != nil {
			t.Fatalf("over fee failed: %v", err)
		}
		if overTokenOut, _, _, _, err := cpmmBuy(test.realTokenReserves, test.virtualCPayReserves, test.virtualTokenReserves, over-overFee); err == nil {
			if overTokenOut.Compare(tokenOut) != 0 {
				t.Fatalf("over tokenOut got %s want %s", overTokenOut.Big().String(), tokenOut.Big().String())
			}
			canonical, err := minGrossInputForTokenOut(test.realTokenReserves, test.virtualCPayReserves, test.virtualTokenReserves, overTokenOut, test.feeBPS)
			if err != nil {
				t.Fatalf("over canonical failed: %v", err)
			}
			if canonical == over {
				t.Fatalf("max buy + 1 should not be canonical")
			}
		}
	}
}

func TestDeterministicStressPreservesReserveFloorsAndVaultAccounting(t *testing.T) {
	realCPay := uint64(initialRealCPayReserves)
	realTokens := Uint128FromUint64(liquidityTokenSupplyRaw)
	virtualCPay := uint64(initialVirtualCPayReserves)
	virtualTokens := Uint128FromUint64(initialVirtualTokenReserve)
	circulating := Uint128FromUint64(0)
	unclaimedFees := uint64(0)
	vaultValue := realCPay
	feeSchedule := []uint16{0, 10, 100, 250, 1_000}
	seed := uint64(0xC0FFEE1234567890)

	for step := 0; step < 2_000; step++ {
		seed = seed*6364136223846793005 + 1442695040888963407
		feeBPS := feeSchedule[step%len(feeSchedule)]
		preferBuy := step%4 != 3 || circulating.IsZero()
		if preferBuy {
			maxBuy := maxBuyInSompiForTest(realTokens, virtualCPay, virtualTokens, feeBPS)
			if maxBuy == 0 {
				continue
			}
			cap := uint64(10 * constants.SompiPerCryptix)
			if maxBuy < cap {
				cap = maxBuy
			}
			grossIn := uint64(1) + seed%cap
			fee, net, tokenOut, nextRealTokens, nextVirtualCPay, nextVirtualTokens, err :=
				buyWithGrossForTest(realTokens, virtualCPay, virtualTokens, grossIn, feeBPS)
			if err != nil {
				continue
			}
			realCPay += net
			realTokens = nextRealTokens
			virtualCPay = nextVirtualCPay
			virtualTokens = nextVirtualTokens
			var ok bool
			circulating, ok = circulating.Add(tokenOut)
			if !ok {
				t.Fatal("circulating overflow")
			}
			unclaimedFees += fee
			vaultValue += grossIn
		} else {
			maxSell := circulating
			if maxSell.Compare(Uint128FromUint64(10_000)) > 0 {
				maxSell = Uint128FromUint64(10_000)
			}
			if maxSell.IsZero() {
				continue
			}
			tokenIn := Uint128FromUint64(1 + seed%maxSell.Big().Uint64())
			grossOut, nextRealCPay, nextVirtualCPay, nextVirtualTokens, err := cpmmSell(realCPay, virtualCPay, virtualTokens, tokenIn)
			if err != nil {
				continue
			}
			fee, err := calculateTradeFee(grossOut, feeBPS)
			if err != nil {
				t.Fatalf("fee failed: %v", err)
			}
			cpayOut := grossOut - fee
			if cpayOut == 0 {
				continue
			}
			realCPay = nextRealCPay
			var ok bool
			realTokens, ok = realTokens.Add(tokenIn)
			if !ok {
				t.Fatal("real token overflow")
			}
			virtualCPay = nextVirtualCPay
			virtualTokens = nextVirtualTokens
			circulating, ok = circulating.Sub(tokenIn)
			if !ok {
				t.Fatal("circulating underflow")
			}
			unclaimedFees += fee
			vaultValue -= cpayOut
		}

		total, ok := circulating.Add(realTokens)
		if !ok || total.Compare(Uint128FromUint64(liquidityTokenSupplyRaw)) != 0 {
			t.Fatalf("supply invariant failed at step %d", step)
		}
		if realTokens.Compare(Uint128FromUint64(minRealTokenReserve)) < 0 {
			t.Fatalf("real token floor breached at step %d", step)
		}
		if realCPay < minCPayReserve {
			t.Fatalf("real CPAY floor breached at step %d", step)
		}
		if virtualCPay == 0 || virtualTokens.IsZero() {
			t.Fatalf("virtual reserve zero at step %d", step)
		}
		if vaultValue != realCPay+unclaimedFees {
			t.Fatalf("vault accounting failed at step %d: vault=%d real=%d fees=%d", step, vaultValue, realCPay, unclaimedFees)
		}
	}
}
