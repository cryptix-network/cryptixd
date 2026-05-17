package atomicstate

import (
	"fmt"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
)

// StateGrowthLimits are consensus limits for new persistent CAT state keys per block.
type StateGrowthLimits struct {
	MaxNewAssets          uint64
	MaxNewBalanceKeys     uint64
	MaxNewNonceKeys       uint64
	MaxNewPools           uint64
	MaxNewAnchorOwnerKeys uint64
}

// StateGrowth is the per-transaction estimate of newly-created CAT state keys.
type StateGrowth struct {
	NewAssets          uint64
	NewBalanceKeys     uint64
	NewNonceKeys       uint64
	NewPools           uint64
	NewAnchorOwnerKeys uint64
}

// BlockStateGrowth tracks already-accepted CAT state growth for one block.
type BlockStateGrowth struct {
	used StateGrowth
}

// Used returns the cumulative state growth already committed for the block.
func (growth *BlockStateGrowth) Used() StateGrowth {
	if growth == nil {
		return StateGrowth{}
	}
	return growth.used
}

// EnsureCanAdd validates that adding delta would stay within the block limits.
func (growth *BlockStateGrowth) EnsureCanAdd(delta StateGrowth, limits StateGrowthLimits) error {
	if growth == nil {
		return nil
	}
	if exceedsLimit(growth.used.NewAssets, delta.NewAssets, limits.MaxNewAssets) {
		return fmt.Errorf("atomic state growth limit exceeded for new assets: current=%d delta=%d limit=%d",
			growth.used.NewAssets, delta.NewAssets, limits.MaxNewAssets)
	}
	if exceedsLimit(growth.used.NewBalanceKeys, delta.NewBalanceKeys, limits.MaxNewBalanceKeys) {
		return fmt.Errorf("atomic state growth limit exceeded for new balance keys: current=%d delta=%d limit=%d",
			growth.used.NewBalanceKeys, delta.NewBalanceKeys, limits.MaxNewBalanceKeys)
	}
	if exceedsLimit(growth.used.NewNonceKeys, delta.NewNonceKeys, limits.MaxNewNonceKeys) {
		return fmt.Errorf("atomic state growth limit exceeded for new nonce keys: current=%d delta=%d limit=%d",
			growth.used.NewNonceKeys, delta.NewNonceKeys, limits.MaxNewNonceKeys)
	}
	if exceedsLimit(growth.used.NewPools, delta.NewPools, limits.MaxNewPools) {
		return fmt.Errorf("atomic state growth limit exceeded for new liquidity pools: current=%d delta=%d limit=%d",
			growth.used.NewPools, delta.NewPools, limits.MaxNewPools)
	}
	if exceedsLimit(growth.used.NewAnchorOwnerKeys, delta.NewAnchorOwnerKeys, limits.MaxNewAnchorOwnerKeys) {
		return fmt.Errorf("atomic state growth limit exceeded for new anchor owner keys: current=%d delta=%d limit=%d",
			growth.used.NewAnchorOwnerKeys, delta.NewAnchorOwnerKeys, limits.MaxNewAnchorOwnerKeys)
	}
	return nil
}

// Commit adds a successfully-applied transaction delta to the block growth counter.
func (growth *BlockStateGrowth) Commit(delta StateGrowth) {
	if growth == nil {
		return
	}
	growth.used.NewAssets += delta.NewAssets
	growth.used.NewBalanceKeys += delta.NewBalanceKeys
	growth.used.NewNonceKeys += delta.NewNonceKeys
	growth.used.NewPools += delta.NewPools
	growth.used.NewAnchorOwnerKeys += delta.NewAnchorOwnerKeys
}

func exceedsLimit(current, delta, limit uint64) bool {
	return delta > limit || current > limit-delta
}

// ValidateAndApplyTransactionWithGrowth enforces per-block CAT state-growth limits before applying a transaction.
func ValidateAndApplyTransactionWithGrowth(
	tx *externalapi.DomainTransaction,
	povDAAScore uint64,
	payloadHFActivationDAAScore uint64,
	state *State,
	growth *BlockStateGrowth,
	limits StateGrowthLimits,
) error {
	delta, err := EstimateStateGrowthForTransaction(tx, povDAAScore, payloadHFActivationDAAScore, state)
	if err != nil {
		return err
	}
	if err := growth.EnsureCanAdd(delta, limits); err != nil {
		return err
	}
	if err := ValidateAndApplyTransaction(tx, povDAAScore, payloadHFActivationDAAScore, state); err != nil {
		return err
	}
	growth.Commit(delta)
	return nil
}

// EstimateStateGrowthForTransaction mirrors rusty-cryptix Atomic state-growth accounting.
func EstimateStateGrowthForTransaction(
	tx *externalapi.DomainTransaction,
	povDAAScore uint64,
	payloadHFActivationDAAScore uint64,
	state *State,
) (StateGrowth, error) {
	if state == nil {
		return StateGrowth{}, fmt.Errorf("nil atomic state")
	}

	var growth StateGrowth
	seenAnchorOwners := make(map[[externalapi.DomainHashSize]byte]struct{})
	for _, output := range tx.Outputs {
		ownerID, ok := OwnerIDFromScript(output.ScriptPublicKey)
		if !ok {
			continue
		}
		if _, exists := state.AnchorCounts[ownerID]; exists {
			continue
		}
		if _, counted := seenAnchorOwners[ownerID]; counted {
			continue
		}
		seenAnchorOwners[ownerID] = struct{}{}
		growth.NewAnchorOwnerKeys++
	}

	payloadHFActive := povDAAScore >= payloadHFActivationDAAScore
	if !payloadHFActive || !subnetworks.IsPayload(tx.SubnetworkID) || len(tx.Payload) == 0 {
		return growth, nil
	}

	parsedPayload, err := ParsePayload(tx.Payload)
	if err != nil {
		return growth, err
	}
	if parsedPayload == nil {
		return growth, nil
	}

	ownerID, err := resolveOwnerFromPopulatedTx(tx, parsedPayload.AuthInputIndex)
	if err != nil {
		return growth, err
	}
	nonceKey := nonceKeyForOp(ownerID, parsedPayload.Op)
	if _, ok := state.NextNonces[nonceKey]; !ok {
		growth.NewNonceKeys = 1
	}

	txIDBytes := *consensushashing.TransactionID(tx).ByteArray()
	switch op := parsedPayload.Op.(type) {
	case CreateAssetOp:
		if _, ok := state.Assets[txIDBytes]; !ok {
			growth.NewAssets = 1
		}
	case CreateAssetWithMintOp:
		if _, ok := state.Assets[txIDBytes]; !ok {
			growth.NewAssets = 1
		}
		if !op.InitialMintAmount.IsZero() {
			key := BalanceKey{AssetID: txIDBytes, OwnerID: op.InitialMintToOwnerID}
			if _, ok := state.Balances[key]; !ok {
				growth.NewBalanceKeys++
			}
		}
	case CreateLiquidityAssetOp:
		if _, ok := state.Assets[txIDBytes]; !ok {
			growth.NewAssets = 1
			growth.NewPools = 1
		}
		if op.LaunchBuySompi > 0 {
			key := BalanceKey{AssetID: txIDBytes, OwnerID: ownerID}
			if _, ok := state.Balances[key]; !ok {
				growth.NewBalanceKeys++
			}
		}
	case TransferOp:
		if op.Amount.IsZero() {
			break
		}
		fromKey := BalanceKey{AssetID: op.AssetID, OwnerID: ownerID}
		toKey := BalanceKey{AssetID: op.AssetID, OwnerID: op.ToOwnerID}
		if fromKey != toKey {
			if _, ok := state.Balances[toKey]; !ok {
				growth.NewBalanceKeys++
			}
		}
	case MintOp:
		if op.Amount.IsZero() {
			break
		}
		key := BalanceKey{AssetID: op.AssetID, OwnerID: op.ToOwnerID}
		if _, ok := state.Balances[key]; !ok {
			growth.NewBalanceKeys++
		}
	case BuyLiquidityExactInOp:
		key := BalanceKey{AssetID: op.AssetID, OwnerID: ownerID}
		if _, ok := state.Balances[key]; !ok {
			growth.NewBalanceKeys++
		}
	}

	return growth, nil
}
