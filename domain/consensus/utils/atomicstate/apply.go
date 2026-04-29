package atomicstate

import (
	"fmt"
	"math"
	"math/big"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/constants"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/txscript"
)

const (
	liquidityMinPayoutSompi = uint64(1)
	curveFloorToken         = uint64(1)
)

const liquidityVaultTy txscript.ScriptClass = 4

type vaultTransition struct {
	inputValue  uint64
	outputIndex uint32
	outputValue uint64
}

func ValidateAndApplyTransaction(tx *externalapi.DomainTransaction, povDAAScore uint64, payloadHFActivationDAAScore uint64, state *State) error {
	if state == nil {
		return fmt.Errorf("nil atomic state")
	}
	payloadHFActive := povDAAScore >= payloadHFActivationDAAScore
	liquidityVaultOutputCount := 0
	for _, output := range tx.Outputs {
		if scriptClass(output.ScriptPublicKey) == liquidityVaultTy {
			liquidityVaultOutputCount++
		}
	}
	spentVaultInputs, err := collectSpentLiquidityVaultInputs(tx, state)
	if err != nil {
		return err
	}

	if !payloadHFActive || !subnetworks.IsPayload(tx.SubnetworkID) || len(tx.Payload) == 0 {
		if len(spentVaultInputs) != 0 || liquidityVaultOutputCount > 0 {
			return fmt.Errorf("reserved LiquidityVault scripts require a CAT liquidity payload")
		}
		applyAnchorDeltas(tx, state)
		return nil
	}

	parsedPayload, err := ParsePayload(tx.Payload)
	if err != nil {
		return err
	}
	if parsedPayload == nil {
		if len(spentVaultInputs) != 0 || liquidityVaultOutputCount > 0 {
			return fmt.Errorf("reserved LiquidityVault scripts require a CAT liquidity payload")
		}
		applyAnchorDeltas(tx, state)
		return nil
	}

	ownerID, err := resolveOwnerFromPopulatedTx(tx, parsedPayload.AuthInputIndex)
	if err != nil {
		return err
	}
	expectedNonce := state.NextNonces[ownerID]
	if expectedNonce == 0 {
		expectedNonce = 1
	}
	if parsedPayload.Nonce != expectedNonce {
		return fmt.Errorf("nonce baseline violation for owner `%x`: expected `%d`, got `%d`", ownerID, expectedNonce, parsedPayload.Nonce)
	}

	if len(spentVaultInputs) != 0 {
		switch parsedPayload.Op.(type) {
		case BuyLiquidityExactInOp, SellLiquidityExactInOp, ClaimLiquidityFeesOp:
		default:
			return fmt.Errorf("spending a LiquidityVault input is only valid for buy/sell/claim liquidity ops")
		}
	}
	if liquidityVaultOutputCount > 0 && !opAllowsLiquidityVaultOutput(parsedPayload.Op) {
		return fmt.Errorf("creating a LiquidityVault output is only valid for create/buy/sell/claim liquidity ops")
	}
	if _, ok := parsedPayload.Op.(CreateLiquidityAssetOp); ok && len(spentVaultInputs) != 0 {
		return fmt.Errorf("create-liquidity must not spend any LiquidityVault input")
	}

	if err := validateReplacementAnchor(tx, ownerID, state); err != nil {
		return err
	}

	txIDBytes := *consensushashing.TransactionID(tx).ByteArray()
	if err := applyOp(tx, txIDBytes, ownerID, parsedPayload.Op, state); err != nil {
		return err
	}

	if expectedNonce == math.MaxUint64 {
		return fmt.Errorf("nonce progression overflow for owner `%x`", ownerID)
	}
	state.NextNonces[ownerID] = expectedNonce + 1
	applyAnchorDeltas(tx, state)
	return nil
}

func opAllowsLiquidityVaultOutput(op PayloadOp) bool {
	switch op.(type) {
	case CreateLiquidityAssetOp, BuyLiquidityExactInOp, SellLiquidityExactInOp, ClaimLiquidityFeesOp:
		return true
	default:
		return false
	}
}

func liquiditySellLocked(pool LiquidityPoolState) bool {
	return pool.UnlockTargetSompi > 0 && !pool.Unlocked
}

func validateLiquidityUnlockTargetForState(unlockTargetSompi uint64) error {
	if unlockTargetSompi > constants.MaxSompi {
		return fmt.Errorf("liquidity unlock target `%d` exceeds MaxSompi `%d`", unlockTargetSompi, constants.MaxSompi)
	}
	return nil
}

func resolveOwnerFromPopulatedTx(tx *externalapi.DomainTransaction, authInputIndex uint16) ([externalapi.DomainHashSize]byte, error) {
	index := int(authInputIndex)
	if index >= len(tx.Inputs) || tx.Inputs[index].UTXOEntry == nil {
		return [externalapi.DomainHashSize]byte{}, fmt.Errorf("auth_input_index `%d` has no populated UTXO entry in contextual validation", index)
	}
	ownerID, ok := OwnerIDFromScript(tx.Inputs[index].UTXOEntry.ScriptPublicKey())
	if !ok {
		return [externalapi.DomainHashSize]byte{},
			fmt.Errorf("auth input script public key is not a supported CAT owner authorization scheme (expected PubKey, PubKeyECDSA, or ScriptHash)")
	}
	return ownerID, nil
}

func validateReplacementAnchor(tx *externalapi.DomainTransaction, ownerID [externalapi.DomainHashSize]byte, state *State) error {
	beforeCount := state.AnchorCounts[ownerID]
	spentForOwner := uint64(0)
	for _, input := range tx.Inputs {
		if input.UTXOEntry == nil {
			continue
		}
		if inputOwnerID, ok := OwnerIDFromScript(input.UTXOEntry.ScriptPublicKey()); ok && inputOwnerID == ownerID {
			if spentForOwner < math.MaxUint64 {
				spentForOwner++
			}
		}
	}
	if saturatingSub(beforeCount, spentForOwner) > 0 {
		return nil
	}
	for _, output := range tx.Outputs {
		if outputOwnerID, ok := OwnerIDFromScript(output.ScriptPublicKey); ok && outputOwnerID == ownerID {
			return nil
		}
	}
	return fmt.Errorf("auth owner would lose the final anchor UTXO without a replacement owner output")
}

func applyAnchorDeltas(tx *externalapi.DomainTransaction, state *State) {
	spentCounts := make(map[[externalapi.DomainHashSize]byte]uint64)
	for _, input := range tx.Inputs {
		if input.UTXOEntry == nil {
			continue
		}
		ownerID, ok := OwnerIDFromScript(input.UTXOEntry.ScriptPublicKey())
		if !ok {
			continue
		}
		spentCounts[ownerID]++
	}
	createdCounts := make(map[[externalapi.DomainHashSize]byte]uint64)
	for _, output := range tx.Outputs {
		ownerID, ok := OwnerIDFromScript(output.ScriptPublicKey)
		if !ok {
			continue
		}
		createdCounts[ownerID]++
	}
	owners := make(map[[externalapi.DomainHashSize]byte]struct{})
	for ownerID := range spentCounts {
		owners[ownerID] = struct{}{}
	}
	for ownerID := range createdCounts {
		owners[ownerID] = struct{}{}
	}
	for ownerID := range owners {
		oldCount := state.AnchorCounts[ownerID]
		newCount := saturatingAdd(saturatingSub(oldCount, spentCounts[ownerID]), createdCounts[ownerID])
		if newCount == 0 {
			delete(state.AnchorCounts, ownerID)
		} else {
			state.AnchorCounts[ownerID] = newCount
		}
	}
}

func applyOp(tx *externalapi.DomainTransaction, txIDBytes [externalapi.DomainHashSize]byte, ownerID [externalapi.DomainHashSize]byte, op PayloadOp, state *State) error {
	switch op := op.(type) {
	case CreateAssetOp:
		assetID := txIDBytes
		if _, ok := state.Assets[assetID]; ok {
			return fmt.Errorf("asset `%x` already exists", assetID)
		}
		return insertAssetState(state, assetID, AssetState{
			AssetClass:           AssetClassStandard,
			MintAuthorityOwnerID: op.MintAuthorityOwnerID,
			SupplyMode:           payloadSupplyModeToState(op.SupplyMode),
			MaxSupply:            op.MaxSupply,
			TotalSupply:          Uint128{},
			PlatformTag:          op.PlatformTag,
			Liquidity:            nil,
		})

	case CreateAssetWithMintOp:
		assetID := txIDBytes
		if _, ok := state.Assets[assetID]; ok {
			return fmt.Errorf("asset `%x` already exists", assetID)
		}
		supplyMode := payloadSupplyModeToState(op.SupplyMode)
		totalSupply := Uint128{}
		if !op.InitialMintAmount.IsZero() {
			if supplyMode == SupplyModeCapped && op.InitialMintAmount.Compare(op.MaxSupply) > 0 {
				return fmt.Errorf("initial mint exceeds cap for asset `%x`", assetID)
			}
			key := BalanceKey{AssetID: assetID, OwnerID: op.InitialMintToOwnerID}
			receiverAfter, ok := state.Balances[key].Add(op.InitialMintAmount)
			if !ok {
				return fmt.Errorf("balance overflow while create-and-mint asset `%x`", assetID)
			}
			state.Balances[key] = receiverAfter
			totalSupply = op.InitialMintAmount
		}
		return insertAssetState(state, assetID, AssetState{
			AssetClass:           AssetClassStandard,
			MintAuthorityOwnerID: op.MintAuthorityOwnerID,
			SupplyMode:           supplyMode,
			MaxSupply:            op.MaxSupply,
			TotalSupply:          totalSupply,
			PlatformTag:          op.PlatformTag,
			Liquidity:            nil,
		})

	case CreateLiquidityAssetOp:
		return applyCreateLiquidityAsset(tx, txIDBytes, ownerID, op, state)

	case TransferOp:
		if _, ok := state.Assets[op.AssetID]; !ok {
			return fmt.Errorf("transfer references unknown asset `%x`", op.AssetID)
		}
		fromKey := BalanceKey{AssetID: op.AssetID, OwnerID: ownerID}
		toKey := BalanceKey{AssetID: op.AssetID, OwnerID: op.ToOwnerID}
		senderBalance := state.Balances[fromKey]
		if fromKey == toKey {
			if _, ok := senderBalance.Sub(op.Amount); !ok {
				return fmt.Errorf("insufficient balance for self-transfer of asset `%x`", op.AssetID)
			}
			return nil
		}
		senderAfter, ok := senderBalance.Sub(op.Amount)
		if !ok {
			return fmt.Errorf("insufficient balance for transfer of asset `%x`", op.AssetID)
		}
		receiverAfter, ok := state.Balances[toKey].Add(op.Amount)
		if !ok {
			return fmt.Errorf("balance overflow for transfer receiver in asset `%x`", op.AssetID)
		}
		if senderAfter.IsZero() {
			delete(state.Balances, fromKey)
		} else {
			state.Balances[fromKey] = senderAfter
		}
		state.Balances[toKey] = receiverAfter
		return nil

	case MintOp:
		asset, ok := state.Assets[op.AssetID]
		if !ok {
			return fmt.Errorf("mint references unknown asset `%x`", op.AssetID)
		}
		if asset.AssetClass == AssetClassLiquidity {
			return fmt.Errorf("legacy mint is invalid for liquidity asset `%x`", op.AssetID)
		}
		if asset.MintAuthorityOwnerID != ownerID {
			return fmt.Errorf("owner `%x` is not mint authority for asset `%x`", ownerID, op.AssetID)
		}
		newTotalSupply, ok := asset.TotalSupply.Add(op.Amount)
		if !ok {
			return fmt.Errorf("supply overflow while minting asset `%x`", op.AssetID)
		}
		if asset.SupplyMode == SupplyModeCapped && newTotalSupply.Compare(asset.MaxSupply) > 0 {
			return fmt.Errorf("mint would exceed cap for asset `%x`", op.AssetID)
		}
		key := BalanceKey{AssetID: op.AssetID, OwnerID: op.ToOwnerID}
		receiverAfter, ok := state.Balances[key].Add(op.Amount)
		if !ok {
			return fmt.Errorf("balance overflow while minting asset `%x`", op.AssetID)
		}
		asset.TotalSupply = newTotalSupply
		if err := insertAssetState(state, op.AssetID, asset); err != nil {
			return err
		}
		state.Balances[key] = receiverAfter
		return nil

	case BurnOp:
		asset, ok := state.Assets[op.AssetID]
		if !ok {
			return fmt.Errorf("burn references unknown asset `%x`", op.AssetID)
		}
		if asset.AssetClass == AssetClassLiquidity {
			return fmt.Errorf("legacy burn is invalid for liquidity asset `%x`", op.AssetID)
		}
		senderKey := BalanceKey{AssetID: op.AssetID, OwnerID: ownerID}
		senderAfter, ok := state.Balances[senderKey].Sub(op.Amount)
		if !ok {
			return fmt.Errorf("insufficient balance for burn in asset `%x`", op.AssetID)
		}
		supplyAfter, ok := asset.TotalSupply.Sub(op.Amount)
		if !ok {
			return fmt.Errorf("supply underflow while burning asset `%x`", op.AssetID)
		}
		asset.TotalSupply = supplyAfter
		if err := insertAssetState(state, op.AssetID, asset); err != nil {
			return err
		}
		if senderAfter.IsZero() {
			delete(state.Balances, senderKey)
		} else {
			state.Balances[senderKey] = senderAfter
		}
		return nil

	case BuyLiquidityExactInOp:
		return applyBuyLiquidityExactIn(tx, ownerID, op, state)

	case SellLiquidityExactInOp:
		return applySellLiquidityExactIn(tx, ownerID, op, state)

	case ClaimLiquidityFeesOp:
		return applyClaimLiquidityFees(tx, ownerID, op, state)
	default:
		return fmt.Errorf("unknown atomic payload op")
	}
}

func applyCreateLiquidityAsset(tx *externalapi.DomainTransaction, assetID, ownerID [externalapi.DomainHashSize]byte, op CreateLiquidityAssetOp, state *State) error {
	if _, ok := state.Assets[assetID]; ok {
		return fmt.Errorf("asset `%x` already exists", assetID)
	}
	if err := validateLiquidityCreateParams(op.Decimals, op.MaxSupply, op.SeedReserveSompi); err != nil {
		return err
	}
	if err := validateLiquidityUnlockTargetForState(op.UnlockTargetSompi); err != nil {
		return err
	}
	vaultOutputIndex, vaultOutputValue, err := resolveCreateLiquidityVaultOutput(tx)
	if err != nil {
		return err
	}
	expectedVaultValue, ok := checkedAddUint64(op.SeedReserveSompi, op.LaunchBuySompi)
	if !ok {
		return fmt.Errorf("vault value overflow on create")
	}
	if vaultOutputValue != expectedVaultValue {
		return fmt.Errorf("create liquidity vault output mismatch: expected `%d`, got `%d`", expectedVaultValue, vaultOutputValue)
	}
	feeRecipients, err := buildFeeRecipientState(op.Recipients)
	if err != nil {
		return err
	}
	if op.FeeBPS > 0 && len(feeRecipients) == 0 {
		return fmt.Errorf("fee_bps > 0 requires at least one recipient")
	}

	remainingPoolSupply := op.MaxSupply
	curveReserveSompi := op.SeedReserveSompi
	unclaimedFeeTotalSompi := uint64(0)
	totalSupply := Uint128{}
	if op.LaunchBuySompi > 0 {
		feeTrade, err := calculateTradeFee(op.LaunchBuySompi, op.FeeBPS)
		if err != nil {
			return err
		}
		launchBuyNet, ok := checkedSubUint64(op.LaunchBuySompi, feeTrade)
		if !ok {
			return fmt.Errorf("launch buy fee underflow")
		}
		tokenOut, newRemainingPoolSupply, newCurveReserveSompi, err := cpmmBuy(remainingPoolSupply, curveReserveSompi, launchBuyNet)
		if err != nil {
			return err
		}
		if tokenOut.Compare(op.LaunchBuyMinTokenOut) < 0 {
			return fmt.Errorf("launch buy min_token_out violated")
		}
		if tokenOut.IsZero() {
			return fmt.Errorf("launch buy produced zero token_out")
		}
		remainingPoolSupply = newRemainingPoolSupply
		curveReserveSompi = newCurveReserveSompi
		if err := applyFeeToPool(feeRecipients, &unclaimedFeeTotalSompi, feeTrade); err != nil {
			return err
		}
		totalSupply = tokenOut
		receiverKey := BalanceKey{AssetID: assetID, OwnerID: ownerID}
		receiverAfter, ok := state.Balances[receiverKey].Add(tokenOut)
		if !ok {
			return fmt.Errorf("balance overflow while launch-buy minting liquidity asset `%x`", assetID)
		}
		state.Balances[receiverKey] = receiverAfter
	}

	txID := consensushashing.TransactionID(tx)
	unlocked := op.UnlockTargetSompi == 0 || curveReserveSompi >= op.UnlockTargetSompi
	asset := AssetState{
		AssetClass:           AssetClassLiquidity,
		MintAuthorityOwnerID: [externalapi.DomainHashSize]byte{},
		SupplyMode:           SupplyModeCapped,
		MaxSupply:            op.MaxSupply,
		TotalSupply:          totalSupply,
		PlatformTag:          op.PlatformTag,
		Liquidity: &LiquidityPoolState{
			PoolNonce:              1,
			RemainingPoolSupply:    remainingPoolSupply,
			CurveReserveSompi:      curveReserveSompi,
			UnclaimedFeeTotalSompi: unclaimedFeeTotalSompi,
			FeeBPS:                 op.FeeBPS,
			FeeRecipients:          feeRecipients,
			VaultOutpoint: externalapi.DomainOutpoint{
				TransactionID: *txID,
				Index:         vaultOutputIndex,
			},
			VaultValueSompi:   vaultOutputValue,
			UnlockTargetSompi: op.UnlockTargetSompi,
			Unlocked:          unlocked,
		},
	}
	if err := validateLiquidityInvariants(assetID, asset); err != nil {
		return err
	}
	return insertAssetState(state, assetID, asset)
}

func applyBuyLiquidityExactIn(tx *externalapi.DomainTransaction, ownerID [externalapi.DomainHashSize]byte, op BuyLiquidityExactInOp, state *State) error {
	asset, ok := state.Assets[op.AssetID]
	if !ok {
		return fmt.Errorf("buy references unknown asset `%x`", op.AssetID)
	}
	if asset.AssetClass != AssetClassLiquidity || asset.Liquidity == nil {
		return fmt.Errorf("buy is only valid for liquidity assets")
	}
	pool := *asset.Liquidity
	if pool.PoolNonce != op.ExpectedPoolNonce {
		return fmt.Errorf("stale liquidity nonce for asset `%x`: expected `%d`, got `%d`", op.AssetID, pool.PoolNonce, op.ExpectedPoolNonce)
	}
	vaultTransition, err := resolveLiquidityVaultTransition(tx, pool.VaultOutpoint)
	if err != nil {
		return err
	}
	vaultDelta, ok := checkedSubUint64(vaultTransition.outputValue, vaultTransition.inputValue)
	if !ok {
		return fmt.Errorf("buy requires vault_value to increase")
	}
	if vaultDelta != op.CPayInSompi {
		return fmt.Errorf("buy vault delta mismatch: expected `%d`, got `%d`", op.CPayInSompi, vaultDelta)
	}
	feeTrade, err := calculateTradeFee(op.CPayInSompi, pool.FeeBPS)
	if err != nil {
		return err
	}
	netIn, ok := checkedSubUint64(op.CPayInSompi, feeTrade)
	if !ok {
		return fmt.Errorf("buy fee underflow")
	}
	tokenOut, newRemainingPoolSupply, newCurveReserveSompi, err := cpmmBuy(pool.RemainingPoolSupply, pool.CurveReserveSompi, netIn)
	if err != nil {
		return err
	}
	if tokenOut.Compare(op.MinTokenOut) < 0 {
		return fmt.Errorf("buy min_token_out violated")
	}
	if tokenOut.IsZero() {
		return fmt.Errorf("buy produced zero token_out")
	}
	pool.RemainingPoolSupply = newRemainingPoolSupply
	pool.CurveReserveSompi = newCurveReserveSompi
	if pool.UnlockTargetSompi > 0 && pool.CurveReserveSompi >= pool.UnlockTargetSompi {
		pool.Unlocked = true
	}
	if err := applyFeeToPool(pool.FeeRecipients, &pool.UnclaimedFeeTotalSompi, feeTrade); err != nil {
		return err
	}
	pool.VaultOutpoint = externalapi.DomainOutpoint{TransactionID: *consensushashing.TransactionID(tx), Index: vaultTransition.outputIndex}
	pool.VaultValueSompi = vaultTransition.outputValue
	if pool.PoolNonce == math.MaxUint64 {
		return fmt.Errorf("pool nonce overflow")
	}
	pool.PoolNonce++

	receiverKey := BalanceKey{AssetID: op.AssetID, OwnerID: ownerID}
	receiverAfter, ok := state.Balances[receiverKey].Add(tokenOut)
	if !ok {
		return fmt.Errorf("receiver balance overflow while buying liquidity asset `%x`", op.AssetID)
	}
	state.Balances[receiverKey] = receiverAfter
	totalSupply, ok := asset.TotalSupply.Add(tokenOut)
	if !ok {
		return fmt.Errorf("total_supply overflow while buying liquidity asset `%x`", op.AssetID)
	}
	asset.TotalSupply = totalSupply
	asset.Liquidity = &pool
	if err := validateLiquidityInvariants(op.AssetID, asset); err != nil {
		return err
	}
	return insertAssetState(state, op.AssetID, asset)
}

func applySellLiquidityExactIn(tx *externalapi.DomainTransaction, ownerID [externalapi.DomainHashSize]byte, op SellLiquidityExactInOp, state *State) error {
	asset, ok := state.Assets[op.AssetID]
	if !ok {
		return fmt.Errorf("sell references unknown asset `%x`", op.AssetID)
	}
	if asset.AssetClass != AssetClassLiquidity || asset.Liquidity == nil {
		return fmt.Errorf("sell is only valid for liquidity assets")
	}
	pool := *asset.Liquidity
	if pool.PoolNonce != op.ExpectedPoolNonce {
		return fmt.Errorf("stale liquidity nonce for asset `%x`: expected `%d`, got `%d`", op.AssetID, pool.PoolNonce, op.ExpectedPoolNonce)
	}
	if liquiditySellLocked(pool) {
		return fmt.Errorf("liquidity sell locked for asset `%x` until curve reserve reaches `%d` sompi", op.AssetID, pool.UnlockTargetSompi)
	}
	senderKey := BalanceKey{AssetID: op.AssetID, OwnerID: ownerID}
	senderAfter, ok := state.Balances[senderKey].Sub(op.TokenIn)
	if !ok {
		return fmt.Errorf("insufficient balance for sell in liquidity asset `%x`", op.AssetID)
	}
	supplyAfter, ok := asset.TotalSupply.Sub(op.TokenIn)
	if !ok {
		return fmt.Errorf("total_supply underflow while selling liquidity asset `%x`", op.AssetID)
	}
	grossOut, newRemainingPoolSupply, newCurveReserveSompi, err := cpmmSell(pool.RemainingPoolSupply, pool.CurveReserveSompi, op.TokenIn)
	if err != nil {
		return err
	}
	feeTrade, err := calculateTradeFee(grossOut, pool.FeeBPS)
	if err != nil {
		return err
	}
	cpayOut, ok := checkedSubUint64(grossOut, feeTrade)
	if !ok {
		return fmt.Errorf("sell fee underflow")
	}
	if cpayOut == 0 {
		return fmt.Errorf("sell produced zero cpay_out")
	}
	if cpayOut < op.MinCPayOutSompi {
		return fmt.Errorf("sell min_cpay_out violated")
	}
	if cpayOut < liquidityMinPayoutSompi {
		return fmt.Errorf("sell payout below liquidity_min_payout_sompi")
	}
	if err := validateCurveReserveAgainstOutstandingSupply(op.AssetID, supplyAfter, newCurveReserveSompi); err != nil {
		return err
	}
	if err := validatePayoutOutput(tx, op.CPayReceiveOutputIndex, cpayOut, nil); err != nil {
		return err
	}
	vaultTransition, err := resolveLiquidityVaultTransition(tx, pool.VaultOutpoint)
	if err != nil {
		return err
	}
	vaultDelta, ok := checkedSubUint64(vaultTransition.inputValue, vaultTransition.outputValue)
	if !ok {
		return fmt.Errorf("sell requires vault_value to decrease")
	}
	if vaultDelta != cpayOut {
		return fmt.Errorf("sell vault delta mismatch: expected `%d`, got `%d`", cpayOut, vaultDelta)
	}
	pool.RemainingPoolSupply = newRemainingPoolSupply
	pool.CurveReserveSompi = newCurveReserveSompi
	if err := applyFeeToPool(pool.FeeRecipients, &pool.UnclaimedFeeTotalSompi, feeTrade); err != nil {
		return err
	}
	pool.VaultOutpoint = externalapi.DomainOutpoint{TransactionID: *consensushashing.TransactionID(tx), Index: vaultTransition.outputIndex}
	pool.VaultValueSompi = vaultTransition.outputValue
	if pool.PoolNonce == math.MaxUint64 {
		return fmt.Errorf("pool nonce overflow")
	}
	pool.PoolNonce++

	if senderAfter.IsZero() {
		delete(state.Balances, senderKey)
	} else {
		state.Balances[senderKey] = senderAfter
	}
	asset.TotalSupply = supplyAfter
	asset.Liquidity = &pool
	if err := validateLiquidityInvariants(op.AssetID, asset); err != nil {
		return err
	}
	return insertAssetState(state, op.AssetID, asset)
}

func applyClaimLiquidityFees(tx *externalapi.DomainTransaction, ownerID [externalapi.DomainHashSize]byte, op ClaimLiquidityFeesOp, state *State) error {
	asset, ok := state.Assets[op.AssetID]
	if !ok {
		return fmt.Errorf("claim references unknown asset `%x`", op.AssetID)
	}
	if asset.AssetClass != AssetClassLiquidity || asset.Liquidity == nil {
		return fmt.Errorf("claim is only valid for liquidity assets")
	}
	pool := *asset.Liquidity
	if pool.PoolNonce != op.ExpectedPoolNonce {
		return fmt.Errorf("stale liquidity nonce for asset `%x`: expected `%d`, got `%d`", op.AssetID, pool.PoolNonce, op.ExpectedPoolNonce)
	}
	if liquiditySellLocked(pool) {
		return fmt.Errorf("liquidity fee claim locked for asset `%x` until curve reserve reaches `%d` sompi", op.AssetID, pool.UnlockTargetSompi)
	}
	if op.ClaimAmountSompi < liquidityMinPayoutSompi {
		return fmt.Errorf("claim amount below liquidity_min_payout_sompi")
	}
	recipientIndex := int(op.RecipientIndex)
	if recipientIndex >= len(pool.FeeRecipients) {
		return fmt.Errorf("claim recipient_index `%d` out of range", recipientIndex)
	}
	recipientOwnerID := pool.FeeRecipients[recipientIndex].OwnerID
	recipientUnclaimed := pool.FeeRecipients[recipientIndex].UnclaimedSompi
	if recipientUnclaimed < op.ClaimAmountSompi {
		return fmt.Errorf("claim amount exceeds unclaimed recipient fees")
	}
	if ownerID != recipientOwnerID {
		return fmt.Errorf("claim caller is not the configured liquidity fee recipient")
	}
	if err := validatePayoutOutput(tx, op.ClaimReceiveOutputIndex, op.ClaimAmountSompi, &recipientOwnerID); err != nil {
		return err
	}
	vaultTransition, err := resolveLiquidityVaultTransition(tx, pool.VaultOutpoint)
	if err != nil {
		return err
	}
	vaultDelta, ok := checkedSubUint64(vaultTransition.inputValue, vaultTransition.outputValue)
	if !ok {
		return fmt.Errorf("claim requires vault_value to decrease")
	}
	if vaultDelta != op.ClaimAmountSompi {
		return fmt.Errorf("claim vault delta mismatch")
	}
	pool.FeeRecipients[recipientIndex].UnclaimedSompi = recipientUnclaimed - op.ClaimAmountSompi
	pool.UnclaimedFeeTotalSompi, ok = checkedSubUint64(pool.UnclaimedFeeTotalSompi, op.ClaimAmountSompi)
	if !ok {
		return fmt.Errorf("claim unclaimed_fee_total underflow")
	}
	pool.VaultOutpoint = externalapi.DomainOutpoint{TransactionID: *consensushashing.TransactionID(tx), Index: vaultTransition.outputIndex}
	pool.VaultValueSompi = vaultTransition.outputValue
	if pool.PoolNonce == math.MaxUint64 {
		return fmt.Errorf("pool nonce overflow")
	}
	pool.PoolNonce++
	asset.Liquidity = &pool
	if err := validateLiquidityInvariants(op.AssetID, asset); err != nil {
		return err
	}
	return insertAssetState(state, op.AssetID, asset)
}

func payloadSupplyModeToState(mode PayloadSupplyMode) SupplyMode {
	if mode == PayloadSupplyModeCapped {
		return SupplyModeCapped
	}
	return SupplyModeUncapped
}

func insertAssetState(state *State, assetID [externalapi.DomainHashSize]byte, asset AssetState) error {
	if previousAsset, ok := state.Assets[assetID]; ok && previousAsset.Liquidity != nil {
		delete(state.LiquidityVaultOutpoints, previousAsset.Liquidity.VaultOutpoint)
	}
	state.Assets[assetID] = asset.clone()
	if asset.AssetClass == AssetClassLiquidity {
		if asset.Liquidity == nil {
			return fmt.Errorf("liquidity state missing for asset `%x`", assetID)
		}
		if previousAssetID, ok := state.LiquidityVaultOutpoints[asset.Liquidity.VaultOutpoint]; ok && previousAssetID != assetID {
			return fmt.Errorf("multiple liquidity assets share vault outpoint `%s`", asset.Liquidity.VaultOutpoint)
		}
		state.LiquidityVaultOutpoints[asset.Liquidity.VaultOutpoint] = assetID
	}
	return nil
}

func collectSpentLiquidityVaultInputs(tx *externalapi.DomainTransaction, state *State) ([]externalapi.DomainOutpoint, error) {
	spent := make([]externalapi.DomainOutpoint, 0)
	for _, input := range tx.Inputs {
		if input.UTXOEntry == nil || scriptClass(input.UTXOEntry.ScriptPublicKey()) != liquidityVaultTy {
			continue
		}
		_, ok, err := findLiquidityAssetByVaultOutpoint(state, input.PreviousOutpoint)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("unknown LiquidityVault input outpoint `%s`", input.PreviousOutpoint)
		}
		spent = append(spent, input.PreviousOutpoint)
	}
	return spent, nil
}

func findLiquidityAssetByVaultOutpoint(state *State, outpoint externalapi.DomainOutpoint) ([externalapi.DomainHashSize]byte, bool, error) {
	if assetID, ok := state.LiquidityVaultOutpoints[outpoint]; ok {
		asset, ok := state.Assets[assetID]
		if !ok {
			return [externalapi.DomainHashSize]byte{}, false, fmt.Errorf("liquidity vault index references missing asset `%x`", assetID)
		}
		if asset.AssetClass != AssetClassLiquidity || asset.Liquidity == nil || !asset.Liquidity.VaultOutpoint.Equal(&outpoint) {
			return [externalapi.DomainHashSize]byte{}, false, fmt.Errorf("liquidity vault index mismatch for outpoint `%s`", outpoint)
		}
		return assetID, true, nil
	}
	var matched [externalapi.DomainHashSize]byte
	found := false
	for assetID, asset := range state.Assets {
		if asset.AssetClass != AssetClassLiquidity || asset.Liquidity == nil || !asset.Liquidity.VaultOutpoint.Equal(&outpoint) {
			continue
		}
		if found {
			return [externalapi.DomainHashSize]byte{}, false, fmt.Errorf("multiple liquidity assets share vault outpoint `%s`", outpoint)
		}
		matched = assetID
		found = true
	}
	return matched, found, nil
}

func resolveCreateLiquidityVaultOutput(tx *externalapi.DomainTransaction) (uint32, uint64, error) {
	for _, input := range tx.Inputs {
		if input.UTXOEntry != nil && scriptClass(input.UTXOEntry.ScriptPublicKey()) == liquidityVaultTy {
			return 0, 0, fmt.Errorf("create-liquidity must not spend any LiquidityVault input")
		}
	}
	found := false
	var outputIndex uint32
	var outputValue uint64
	for i, output := range tx.Outputs {
		if scriptClass(output.ScriptPublicKey) != liquidityVaultTy {
			continue
		}
		if found {
			return 0, 0, fmt.Errorf("create-liquidity must have exactly one LiquidityVault output")
		}
		if i > math.MaxUint32 {
			return 0, 0, fmt.Errorf("vault output index overflow")
		}
		outputIndex = uint32(i)
		outputValue = output.Value
		found = true
	}
	if !found {
		return 0, 0, fmt.Errorf("create-liquidity must have exactly one LiquidityVault output")
	}
	return outputIndex, outputValue, nil
}

func resolveLiquidityVaultTransition(tx *externalapi.DomainTransaction, expectedVaultOutpoint externalapi.DomainOutpoint) (vaultTransition, error) {
	foundInput := false
	inputValue := uint64(0)
	for _, input := range tx.Inputs {
		if input.UTXOEntry == nil || scriptClass(input.UTXOEntry.ScriptPublicKey()) != liquidityVaultTy {
			continue
		}
		if foundInput {
			return vaultTransition{}, fmt.Errorf("liquidity transition must have exactly one LiquidityVault input")
		}
		if !input.PreviousOutpoint.Equal(&expectedVaultOutpoint) {
			return vaultTransition{}, fmt.Errorf("liquidity vault outpoint mismatch: expected `%s`, got `%s`", expectedVaultOutpoint, input.PreviousOutpoint)
		}
		inputValue = input.UTXOEntry.Amount()
		foundInput = true
	}
	if !foundInput {
		return vaultTransition{}, fmt.Errorf("liquidity transition must have exactly one LiquidityVault input")
	}
	foundOutput := false
	outputIndex := uint32(0)
	outputValue := uint64(0)
	for i, output := range tx.Outputs {
		if scriptClass(output.ScriptPublicKey) != liquidityVaultTy {
			continue
		}
		if foundOutput {
			return vaultTransition{}, fmt.Errorf("liquidity transition must have exactly one LiquidityVault output")
		}
		if i > math.MaxUint32 {
			return vaultTransition{}, fmt.Errorf("vault output index overflow")
		}
		outputIndex = uint32(i)
		outputValue = output.Value
		foundOutput = true
	}
	if !foundOutput {
		return vaultTransition{}, fmt.Errorf("liquidity transition must have exactly one LiquidityVault output")
	}
	return vaultTransition{inputValue: inputValue, outputIndex: outputIndex, outputValue: outputValue}, nil
}

func buildFeeRecipientState(recipients []PayloadRecipientAddress) ([]LiquidityFeeRecipientState, error) {
	out := make([]LiquidityFeeRecipientState, 0, len(recipients))
	for _, recipient := range recipients {
		ownerID, ok := OwnerIDFromAddressComponents(recipient.AddressVersion, recipient.AddressPayload)
		if !ok {
			return nil, fmt.Errorf("invalid liquidity fee recipient address encoding")
		}
		out = append(out, LiquidityFeeRecipientState{
			OwnerID:        ownerID,
			AddressVersion: recipient.AddressVersion,
			AddressPayload: append([]byte(nil), recipient.AddressPayload...),
			UnclaimedSompi: 0,
		})
	}
	return out, nil
}

func applyFeeToPool(recipients []LiquidityFeeRecipientState, unclaimedFeeTotalSompi *uint64, feeTrade uint64) error {
	if feeTrade == 0 {
		return nil
	}
	nextTotal, ok := checkedAddUint64(*unclaimedFeeTotalSompi, feeTrade)
	if !ok {
		return fmt.Errorf("unclaimed_fee_total overflow")
	}
	*unclaimedFeeTotalSompi = nextTotal
	switch len(recipients) {
	case 0:
		return fmt.Errorf("fee_trade > 0 but no fee recipients are configured")
	case 1:
		next, ok := checkedAddUint64(recipients[0].UnclaimedSompi, feeTrade)
		if !ok {
			return fmt.Errorf("recipient fee overflow")
		}
		recipients[0].UnclaimedSompi = next
	case 2:
		fee0 := feeTrade / 2
		fee1 := feeTrade - fee0
		next0, ok := checkedAddUint64(recipients[0].UnclaimedSompi, fee0)
		if !ok {
			return fmt.Errorf("recipient0 fee overflow")
		}
		next1, ok := checkedAddUint64(recipients[1].UnclaimedSompi, fee1)
		if !ok {
			return fmt.Errorf("recipient1 fee overflow")
		}
		recipients[0].UnclaimedSompi = next0
		recipients[1].UnclaimedSompi = next1
	default:
		return fmt.Errorf("invalid recipient count in liquidity pool state")
	}
	return nil
}

func validateLiquidityInvariants(assetID [externalapi.DomainHashSize]byte, asset AssetState) error {
	if asset.AssetClass != AssetClassLiquidity {
		return nil
	}
	if asset.Liquidity == nil {
		return fmt.Errorf("liquidity state missing for asset `%x`", assetID)
	}
	if asset.SupplyMode != SupplyModeCapped {
		return fmt.Errorf("liquidity assets must always use capped supply mode")
	}
	pool := asset.Liquidity
	if err := validateLiquidityUnlockTargetForState(pool.UnlockTargetSompi); err != nil {
		return err
	}
	if pool.UnlockTargetSompi == 0 && !pool.Unlocked {
		return fmt.Errorf("liquidity lock disabled pools must be marked unlocked")
	}
	if pool.UnlockTargetSompi > 0 && !pool.Unlocked && pool.CurveReserveSompi >= pool.UnlockTargetSompi {
		return fmt.Errorf("liquidity lock target reached for asset `%x` but pool is still locked", assetID)
	}
	if err := validateCurveReserveAgainstOutstandingSupply(assetID, asset.TotalSupply, pool.CurveReserveSompi); err != nil {
		return err
	}
	if err := validateLiquidityCurveReachability(pool.RemainingPoolSupply, pool.CurveReserveSompi); err != nil {
		return err
	}
	expectedVault, ok := checkedAddUint64(pool.CurveReserveSompi, pool.UnclaimedFeeTotalSompi)
	if !ok {
		return fmt.Errorf("vault invariant overflow")
	}
	if pool.VaultValueSompi != expectedVault {
		return fmt.Errorf("vault invariant violation for asset `%x`", assetID)
	}
	expectedTotal, ok := asset.TotalSupply.Add(pool.RemainingPoolSupply)
	if !ok {
		return fmt.Errorf("supply invariant overflow")
	}
	if expectedTotal.Compare(asset.MaxSupply) != 0 {
		return fmt.Errorf("supply invariant violation for asset `%x`", assetID)
	}
	return nil
}

func validateCurveReserveAgainstOutstandingSupply(assetID [externalapi.DomainHashSize]byte, totalSupply Uint128, curveReserveSompi uint64) error {
	if !totalSupply.IsZero() && curveReserveSompi == 0 {
		return fmt.Errorf("curve reserve exhausted for liquidity asset `%x` while tokens remain outstanding", assetID)
	}
	return nil
}

func validateLiquidityCreateParams(decimals byte, maxSupply Uint128, seedReserveSompi uint64) error {
	if decimals != liquidityTokenDecimals {
		return fmt.Errorf("liquidity asset decimals must be `%d`", liquidityTokenDecimals)
	}
	if maxSupply.Compare(Uint128FromUint64(minLiquiditySupplyRaw)) < 0 ||
		maxSupply.Compare(Uint128FromUint64(maxLiquiditySupplyRaw)) > 0 {
		return fmt.Errorf("liquidity asset max_supply must be in `%d..=%d`", minLiquiditySupplyRaw, maxLiquiditySupplyRaw)
	}
	if seedReserveSompi < minLiquiditySeedReserve {
		return fmt.Errorf("liquidity asset seed_reserve_sompi must be at least `%d`", minLiquiditySeedReserve)
	}
	return validateLiquidityCurveReachability(maxSupply, seedReserveSompi)
}

func validateLiquidityCurveReachability(remainingPoolSupply Uint128, curveReserveSompi uint64) error {
	if remainingPoolSupply.IsZero() {
		return nil
	}
	y, ok := remainingPoolSupply.Add(Uint128FromUint64(curveFloorToken))
	if !ok {
		return fmt.Errorf("liquidity curve reachability y overflow")
	}
	requiredFinalReserve := new(big.Int).Mul(new(big.Int).SetUint64(curveReserveSompi), y.Big())
	if requiredFinalReserve.Cmp(new(big.Int).SetUint64(maxLiquidityFinalReserve)) > 0 {
		return fmt.Errorf("liquidity curve final reserve `%s` exceeds MaxSompi `%d`", requiredFinalReserve.String(), maxLiquidityFinalReserve)
	}
	return nil
}

func validatePayoutOutput(tx *externalapi.DomainTransaction, outputIndex uint16, expectedValue uint64, expectedOwnerID *[externalapi.DomainHashSize]byte) error {
	if int(outputIndex) >= len(tx.Outputs) {
		return fmt.Errorf("payout output index `%d` out of range", outputIndex)
	}
	output := tx.Outputs[outputIndex]
	if output.Value != expectedValue {
		return fmt.Errorf("payout output value mismatch at index `%d`: expected `%d`, got `%d`", outputIndex, expectedValue, output.Value)
	}
	class := scriptClass(output.ScriptPublicKey)
	if class != txscript.PubKeyTy && class != txscript.PubKeyECDSATy && class != txscript.ScriptHashTy {
		return fmt.Errorf("payout script class `%s` at index `%d` is not allowed", class, outputIndex)
	}
	if expectedOwnerID != nil {
		outputOwnerID, ok := OwnerIDFromScript(output.ScriptPublicKey)
		if !ok {
			return fmt.Errorf("payout output owner id cannot be derived")
		}
		if outputOwnerID != *expectedOwnerID {
			return fmt.Errorf("payout output owner does not match configured fee recipient")
		}
	}
	return nil
}

func calculateTradeFee(amount uint64, feeBPS uint16) (uint64, error) {
	fee := new(big.Int).Mul(new(big.Int).SetUint64(amount), new(big.Int).SetUint64(uint64(feeBPS)))
	fee.Div(fee, big.NewInt(10_000))
	if !fee.IsUint64() {
		return 0, fmt.Errorf("fee does not fit into u64")
	}
	return fee.Uint64(), nil
}

func cpmmBuy(remainingPoolSupply Uint128, curveReserveSompi uint64, cpayNetIn uint64) (Uint128, Uint128, uint64, error) {
	yBefore, ok := remainingPoolSupply.Add(Uint128FromUint64(curveFloorToken))
	if !ok {
		return Uint128{}, Uint128{}, 0, fmt.Errorf("CPMM y_before overflow")
	}
	xAfter, ok := checkedAddUint64(curveReserveSompi, cpayNetIn)
	if !ok {
		return Uint128{}, Uint128{}, 0, fmt.Errorf("CPMM x_after overflow")
	}
	if xAfter == 0 {
		return Uint128{}, Uint128{}, 0, fmt.Errorf("CPMM buy x_after cannot be zero")
	}
	k := new(big.Int).Mul(new(big.Int).SetUint64(curveReserveSompi), yBefore.Big())
	yAfterBig := ceilDivBig(k, new(big.Int).SetUint64(xAfter))
	yAfter, ok := uint128FromBig(yAfterBig)
	if !ok {
		return Uint128{}, Uint128{}, 0, fmt.Errorf("CPMM buy y_after conversion overflow")
	}
	if yAfter.IsZero() {
		return Uint128{}, Uint128{}, 0, fmt.Errorf("CPMM buy y_after cannot be zero")
	}
	if yAfter.Compare(yBefore) > 0 {
		return Uint128{}, Uint128{}, 0, fmt.Errorf("CPMM buy would increase y_after")
	}
	tokenOut, ok := yBefore.Sub(yAfter)
	if !ok {
		return Uint128{}, Uint128{}, 0, fmt.Errorf("CPMM buy token_out underflow")
	}
	if tokenOut.IsZero() {
		return Uint128{}, Uint128{}, 0, fmt.Errorf("CPMM buy produced zero token_out")
	}
	newRemainingPoolSupply, ok := yAfter.Sub(Uint128FromUint64(curveFloorToken))
	if !ok {
		return Uint128{}, Uint128{}, 0, fmt.Errorf("CPMM buy remaining supply underflow")
	}
	return tokenOut, newRemainingPoolSupply, xAfter, nil
}

func cpmmSell(remainingPoolSupply Uint128, curveReserveSompi uint64, tokenIn Uint128) (uint64, Uint128, uint64, error) {
	yBefore, ok := remainingPoolSupply.Add(Uint128FromUint64(curveFloorToken))
	if !ok {
		return 0, Uint128{}, 0, fmt.Errorf("CPMM y_before overflow")
	}
	yAfter, ok := yBefore.Add(tokenIn)
	if !ok {
		return 0, Uint128{}, 0, fmt.Errorf("CPMM y_after overflow")
	}
	if yAfter.IsZero() {
		return 0, Uint128{}, 0, fmt.Errorf("CPMM sell y_after cannot be zero")
	}
	k := new(big.Int).Mul(new(big.Int).SetUint64(curveReserveSompi), yBefore.Big())
	xAfterBig := new(big.Int).Div(k, yAfter.Big())
	if !xAfterBig.IsUint64() {
		return 0, Uint128{}, 0, fmt.Errorf("CPMM sell x_after does not fit u64")
	}
	xAfter := xAfterBig.Uint64()
	if xAfter > curveReserveSompi {
		return 0, Uint128{}, 0, fmt.Errorf("CPMM sell x_after exceeds x_before")
	}
	grossOut, ok := checkedSubUint64(curveReserveSompi, xAfter)
	if !ok {
		return 0, Uint128{}, 0, fmt.Errorf("CPMM sell gross_out underflow")
	}
	if grossOut == 0 {
		return 0, Uint128{}, 0, fmt.Errorf("CPMM sell produced zero gross_out")
	}
	newRemainingPoolSupply, ok := remainingPoolSupply.Add(tokenIn)
	if !ok {
		return 0, Uint128{}, 0, fmt.Errorf("CPMM sell remaining supply overflow")
	}
	return grossOut, newRemainingPoolSupply, xAfter, nil
}

func ceilDivBig(numerator, denominator *big.Int) *big.Int {
	quotient, remainder := new(big.Int).QuoRem(numerator, denominator, new(big.Int))
	if remainder.Sign() == 0 {
		return quotient
	}
	return quotient.Add(quotient, big.NewInt(1))
}

func checkedAddUint64(left, right uint64) (uint64, bool) {
	sum := left + right
	return sum, sum >= left
}

func checkedSubUint64(left, right uint64) (uint64, bool) {
	if left < right {
		return 0, false
	}
	return left - right, true
}

func saturatingSub(left, right uint64) uint64 {
	if left < right {
		return 0
	}
	return left - right
}

func saturatingAdd(left, right uint64) uint64 {
	if math.MaxUint64-left < right {
		return math.MaxUint64
	}
	return left + right
}
