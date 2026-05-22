package mempool

import (
	"fmt"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
)

type atomicMempoolSlotKind byte

const (
	atomicMempoolSlotKindNonce atomicMempoolSlotKind = iota
	atomicMempoolSlotKindLiquidityPool
)

type atomicMempoolSlot struct {
	kind      atomicMempoolSlotKind
	nonceKey  atomicstate.NonceKey
	nonce     uint64
	assetID   [externalapi.DomainHashSize]byte
	poolNonce uint64
}

func (slot atomicMempoolSlot) String() string {
	switch slot.kind {
	case atomicMempoolSlotKindNonce:
		scope := "owner"
		if slot.nonceKey.ScopeKind == atomicstate.NonceScopeAsset {
			scope = fmt.Sprintf("asset:%x", slot.nonceKey.ScopeID)
		}
		return fmt.Sprintf("nonce:%s:%x:%d", scope, slot.nonceKey.OwnerID, slot.nonce)
	case atomicMempoolSlotKindLiquidityPool:
		return fmt.Sprintf("liquidity-pool:%x:%d", slot.assetID, slot.poolNonce)
	default:
		return fmt.Sprintf("unknown:%d", slot.kind)
	}
}

func atomicMempoolSlots(transaction *externalapi.DomainTransaction) ([]atomicMempoolSlot, error) {
	if transaction == nil || !subnetworks.IsPayload(transaction.SubnetworkID) {
		return nil, nil
	}

	parsed, err := atomicstate.ParsePayload(transaction.Payload)
	if err != nil {
		return nil, transactionRuleError(RejectInvalid, fmt.Sprintf("invalid CAT payload: %s", err))
	}
	if parsed == nil {
		return nil, nil
	}

	authInputIndex := int(parsed.AuthInputIndex)
	if authInputIndex >= len(transaction.Inputs) {
		return nil, transactionRuleError(RejectInvalid, fmt.Sprintf(
			"CAT auth input index %d out of bounds for %d inputs", parsed.AuthInputIndex, len(transaction.Inputs)))
	}

	authInput := transaction.Inputs[authInputIndex]
	if authInput == nil || authInput.UTXOEntry == nil {
		return nil, transactionRuleError(RejectBadOrphan, fmt.Sprintf(
			"CAT auth input %d has no UTXO entry", parsed.AuthInputIndex))
	}

	ownerID, ok := atomicstate.OwnerIDFromScript(authInput.UTXOEntry.ScriptPublicKey())
	if !ok {
		return nil, transactionRuleError(RejectInvalid, "CAT auth input has unsupported owner script")
	}

	nonceKey, liquidityAssetID, liquidityPoolNonce, hasLiquidityPoolSlot, ok := atomicPayloadSlots(parsed, ownerID)
	if !ok {
		return nil, transactionRuleError(RejectInvalid, "unknown CAT payload op")
	}

	slots := []atomicMempoolSlot{{
		kind:     atomicMempoolSlotKindNonce,
		nonceKey: nonceKey,
		nonce:    parsed.Nonce,
	}}

	if hasLiquidityPoolSlot {
		slots = append(slots, atomicMempoolSlot{
			kind:      atomicMempoolSlotKindLiquidityPool,
			assetID:   liquidityAssetID,
			poolNonce: liquidityPoolNonce,
		})
	}

	return slots, nil
}

func isCATTransaction(transaction *externalapi.DomainTransaction) bool {
	return transaction != nil &&
		subnetworks.IsPayload(transaction.SubnetworkID) &&
		len(transaction.Payload) >= 3 &&
		string(transaction.Payload[:3]) == "CAT"
}

func atomicMempoolDebugSummary(transaction *externalapi.DomainTransaction) string {
	if !isCATTransaction(transaction) {
		return "cat=false"
	}

	if len(transaction.Payload) <= len("CAT")+1 {
		return "cat=true op=truncated"
	}

	var opLabel string
	switch transaction.Payload[len("CAT")+1] {
	case 0:
		opLabel = "create_asset"
	case 1:
		opLabel = "transfer"
	case 2:
		opLabel = "mint"
	case 3:
		opLabel = "burn"
	case 4:
		opLabel = "create_asset_with_mint"
	case 5:
		opLabel = "create_liquidity_asset"
	case 6:
		opLabel = "buy_liquidity_exact_in"
	case 7:
		opLabel = "sell_liquidity_exact_in"
	case 8:
		opLabel = "claim_liquidity_fees"
	default:
		return fmt.Sprintf("cat=true op=unsupported(%d)", transaction.Payload[len("CAT")+1])
	}

	slot, ok, err := atomicMempoolLiquidityPoolSlot(transaction)
	liquiditySlot := "none"
	if err != nil {
		liquiditySlot = fmt.Sprintf("parse_error=%s", err)
	} else if ok {
		liquiditySlot = slot.String()
	}
	return fmt.Sprintf("cat=true op=%s liquidity_slot=%s", opLabel, liquiditySlot)
}

func atomicMempoolLiquidityPoolSlot(transaction *externalapi.DomainTransaction) (atomicMempoolSlot, bool, error) {
	if transaction == nil || !subnetworks.IsPayload(transaction.SubnetworkID) {
		return atomicMempoolSlot{}, false, nil
	}

	parsed, err := atomicstate.ParsePayload(transaction.Payload)
	if err != nil {
		return atomicMempoolSlot{}, false, fmt.Errorf("invalid CAT payload: %s", err)
	}
	if parsed == nil {
		return atomicMempoolSlot{}, false, nil
	}

	switch op := parsed.Op.(type) {
	case atomicstate.BuyLiquidityExactInOp:
		return atomicMempoolSlot{
			kind:      atomicMempoolSlotKindLiquidityPool,
			assetID:   op.AssetID,
			poolNonce: op.ExpectedPoolNonce,
		}, true, nil
	case atomicstate.SellLiquidityExactInOp:
		return atomicMempoolSlot{
			kind:      atomicMempoolSlotKindLiquidityPool,
			assetID:   op.AssetID,
			poolNonce: op.ExpectedPoolNonce,
		}, true, nil
	case atomicstate.ClaimLiquidityFeesOp:
		return atomicMempoolSlot{
			kind:      atomicMempoolSlotKindLiquidityPool,
			assetID:   op.AssetID,
			poolNonce: op.ExpectedPoolNonce,
		}, true, nil
	default:
		return atomicMempoolSlot{}, false, nil
	}
}

func atomicPayloadSlots(parsed *atomicstate.ParsedPayload, ownerID [externalapi.DomainHashSize]byte) (
	nonceKey atomicstate.NonceKey,
	liquidityAssetID [externalapi.DomainHashSize]byte,
	liquidityPoolNonce uint64,
	hasLiquidityPoolSlot bool,
	ok bool,
) {
	switch op := parsed.Op.(type) {
	case atomicstate.CreateAssetOp, atomicstate.CreateAssetWithMintOp, atomicstate.CreateLiquidityAssetOp:
		return atomicstate.OwnerNonceKey(ownerID), [externalapi.DomainHashSize]byte{}, 0, false, true
	case atomicstate.TransferOp:
		return atomicstate.AssetNonceKey(ownerID, op.AssetID), [externalapi.DomainHashSize]byte{}, 0, false, true
	case atomicstate.MintOp:
		return atomicstate.AssetNonceKey(ownerID, op.AssetID), [externalapi.DomainHashSize]byte{}, 0, false, true
	case atomicstate.BurnOp:
		return atomicstate.AssetNonceKey(ownerID, op.AssetID), [externalapi.DomainHashSize]byte{}, 0, false, true
	case atomicstate.BuyLiquidityExactInOp:
		return atomicstate.AssetNonceKey(ownerID, op.AssetID), op.AssetID, op.ExpectedPoolNonce, true, true
	case atomicstate.SellLiquidityExactInOp:
		return atomicstate.AssetNonceKey(ownerID, op.AssetID), op.AssetID, op.ExpectedPoolNonce, true, true
	case atomicstate.ClaimLiquidityFeesOp:
		return atomicstate.AssetNonceKey(ownerID, op.AssetID), op.AssetID, op.ExpectedPoolNonce, true, true
	default:
		return atomicstate.NonceKey{}, [externalapi.DomainHashSize]byte{}, 0, false, false
	}
}
