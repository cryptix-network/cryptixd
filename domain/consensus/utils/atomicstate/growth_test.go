package atomicstate

import (
	"strings"
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
)

func TestEstimateStateGrowthForTransferMatchesRustAccounting(t *testing.T) {
	ownerScript := testOwnerScript(0xD1)
	ownerID := mustOwnerIDFromScript(t, ownerScript)
	assetID := bytes32(0xD2)
	toOwnerID := bytes32(0xD3)
	state := testTransferState(ownerID, assetID, 10)

	tx := testTransferTx(ownerScript, 0xD4, testTransferPayload(1, assetID, toOwnerID, Uint128FromUint64(3)))
	growth, err := EstimateStateGrowthForTransaction(tx, 1, 0, state)
	if err != nil {
		t.Fatalf("EstimateStateGrowthForTransaction failed: %s", err)
	}

	if growth.NewNonceKeys != 1 {
		t.Fatalf("new nonce keys got %d want 1", growth.NewNonceKeys)
	}
	if growth.NewBalanceKeys != 1 {
		t.Fatalf("new balance keys got %d want 1", growth.NewBalanceKeys)
	}
	if growth.NewAssets != 0 || growth.NewPools != 0 || growth.NewAnchorOwnerKeys != 0 {
		t.Fatalf("unexpected transfer growth: %+v", growth)
	}
}

func TestValidateAndApplyTransactionWithGrowthRejectsBeforeMutation(t *testing.T) {
	ownerScript := testOwnerScript(0xD5)
	ownerID := mustOwnerIDFromScript(t, ownerScript)
	assetID := bytes32(0xD6)
	toOwnerID := bytes32(0xD7)
	state := testTransferState(ownerID, assetID, 10)
	tx := testTransferTx(ownerScript, 0xD8, testTransferPayload(1, assetID, toOwnerID, Uint128FromUint64(3)))

	err := ValidateAndApplyTransactionWithGrowth(tx, 1, 0, state, &BlockStateGrowth{}, StateGrowthLimits{
		MaxNewAssets:          1,
		MaxNewBalanceKeys:     0,
		MaxNewNonceKeys:       1,
		MaxNewPools:           1,
		MaxNewAnchorOwnerKeys: 1,
	})
	if err == nil || !strings.Contains(err.Error(), "new balance keys") {
		t.Fatalf("got error %v, want new balance keys growth rejection", err)
	}
	if _, ok := state.NextNonces[AssetNonceKey(ownerID, assetID)]; ok {
		t.Fatalf("nonce inserted after rejected growth")
	}
	if got := state.Balances[BalanceKey{AssetID: assetID, OwnerID: toOwnerID}]; !got.IsZero() {
		t.Fatalf("receiver balance inserted after rejected growth: %s", got.Big().String())
	}
}

func TestBlockStateGrowthEnforcesAnchorOwnerLimitAcrossTransactions(t *testing.T) {
	state := NewState()
	growth := &BlockStateGrowth{}
	limits := StateGrowthLimits{
		MaxNewAssets:          1,
		MaxNewBalanceKeys:     1,
		MaxNewNonceKeys:       1,
		MaxNewPools:           1,
		MaxNewAnchorOwnerKeys: 1,
	}

	first := anchorOnlyTx(testOwnerScript(0xE1))
	if err := ValidateAndApplyTransactionWithGrowth(first, 0, 1, state, growth, limits); err != nil {
		t.Fatalf("first anchor tx failed: %s", err)
	}

	second := anchorOnlyTx(testOwnerScript(0xE2))
	err := ValidateAndApplyTransactionWithGrowth(second, 0, 1, state, growth, limits)
	if err == nil || !strings.Contains(err.Error(), "new anchor owner keys") {
		t.Fatalf("got error %v, want new anchor owner keys growth rejection", err)
	}
	if got := growth.Used().NewAnchorOwnerKeys; got != 1 {
		t.Fatalf("committed anchor owner growth got %d want 1", got)
	}
}

func anchorOnlyTx(scriptPublicKey *externalapi.ScriptPublicKey) *externalapi.DomainTransaction {
	return &externalapi.DomainTransaction{
		Version: 1,
		Outputs: []*externalapi.DomainTransactionOutput{
			{Value: 1, ScriptPublicKey: scriptPublicKey},
		},
	}
}
