package atomicstate

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/constants"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/txscript"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/utxo"
)

func TestNonceKeyForOpMatchesRustScopes(t *testing.T) {
	ownerID := bytes32(0xA0)
	assetID := bytes32(0xB0)

	ownerOps := []PayloadOp{
		CreateAssetOp{},
		CreateAssetWithMintOp{},
		CreateLiquidityAssetOp{},
	}
	for _, op := range ownerOps {
		if got, want := nonceKeyForOp(ownerID, op), OwnerNonceKey(ownerID); got != want {
			t.Fatalf("%T nonce key got %+v want %+v", op, got, want)
		}
	}

	assetOps := []PayloadOp{
		TransferOp{AssetID: assetID},
		MintOp{AssetID: assetID},
		BurnOp{AssetID: assetID},
		BuyLiquidityExactInOp{AssetID: assetID},
		SellLiquidityExactInOp{AssetID: assetID},
		ClaimLiquidityFeesOp{AssetID: assetID},
	}
	for _, op := range assetOps {
		if got, want := nonceKeyForOp(ownerID, op), AssetNonceKey(ownerID, assetID); got != want {
			t.Fatalf("%T nonce key got %+v want %+v", op, got, want)
		}
	}
}

func TestScopedNonceAllowsOwnerAndAssetNoncesToAdvanceIndependently(t *testing.T) {
	ownerScript := testOwnerScript(0xA1)
	ownerID := mustOwnerIDFromScript(t, ownerScript)
	assetID := bytes32(0x11)
	state := testTransferState(ownerID, assetID, 10)
	state.NextNonces[OwnerNonceKey(ownerID)] = 9

	tx := testTransferTx(ownerScript, 0x01, testTransferPayload(1, assetID, bytes32(0xC0), Uint128FromUint64(3)))
	if err := ValidateAndApplyTransaction(tx, 1, 0, state); err != nil {
		t.Fatalf("transfer with independent asset nonce failed: %s", err)
	}

	if got := state.NextNonces[OwnerNonceKey(ownerID)]; got != 9 {
		t.Fatalf("owner nonce changed unexpectedly: got %d want 9", got)
	}
	if got := state.NextNonces[AssetNonceKey(ownerID, assetID)]; got != 2 {
		t.Fatalf("asset nonce got %d want 2", got)
	}
}

func TestScopedNonceRejectsDuplicateSameOwnerAssetNonce(t *testing.T) {
	ownerScript := testOwnerScript(0xA2)
	ownerID := mustOwnerIDFromScript(t, ownerScript)
	assetID := bytes32(0x12)
	state := testTransferState(ownerID, assetID, 10)

	payload := testTransferPayload(1, assetID, bytes32(0xC1), Uint128FromUint64(2))
	if err := ValidateAndApplyTransaction(testTransferTx(ownerScript, 0x02, payload), 1, 0, state); err != nil {
		t.Fatalf("first transfer failed: %s", err)
	}
	if err := ValidateAndApplyTransaction(testTransferTx(ownerScript, 0x03, payload), 1, 0, state); err == nil || !strings.Contains(err.Error(), "nonce baseline violation") {
		t.Fatalf("duplicate transfer got error %v, want nonce baseline violation", err)
	}
	if got := state.NextNonces[AssetNonceKey(ownerID, assetID)]; got != 2 {
		t.Fatalf("asset nonce after rejected duplicate got %d want 2", got)
	}
}

func TestScopedNonceRejectsAssetNonceGapWithoutMutatingState(t *testing.T) {
	ownerScript := testOwnerScript(0xA3)
	ownerID := mustOwnerIDFromScript(t, ownerScript)
	assetID := bytes32(0x13)
	state := testTransferState(ownerID, assetID, 10)

	err := ValidateAndApplyTransaction(
		testTransferTx(ownerScript, 0x04, testTransferPayload(3, assetID, bytes32(0xC2), Uint128FromUint64(2))),
		1,
		0,
		state,
	)
	if err == nil || !strings.Contains(err.Error(), "nonce baseline violation") {
		t.Fatalf("gap transfer got error %v, want nonce baseline violation", err)
	}
	if _, ok := state.NextNonces[AssetNonceKey(ownerID, assetID)]; ok {
		t.Fatalf("asset nonce was inserted by rejected gap transaction")
	}
	if got := state.Balances[BalanceKey{AssetID: assetID, OwnerID: ownerID}]; got.Compare(Uint128FromUint64(10)) != 0 {
		t.Fatalf("owner balance mutated by rejected gap transaction: got %s", got.Big().String())
	}
}

func TestScopedNonceOverflowRejectsBeforeMutatingState(t *testing.T) {
	ownerScript := testOwnerScript(0xA7)
	ownerID := mustOwnerIDFromScript(t, ownerScript)
	assetID := bytes32(0x17)
	state := testTransferState(ownerID, assetID, 10)
	state.NextNonces[AssetNonceKey(ownerID, assetID)] = math.MaxUint64

	err := ValidateAndApplyTransaction(
		testTransferTx(ownerScript, 0x08, testTransferPayload(math.MaxUint64, assetID, bytes32(0xC7), Uint128FromUint64(2))),
		1,
		0,
		state,
	)
	if err == nil || !strings.Contains(err.Error(), "nonce progression overflow") {
		t.Fatalf("overflow transfer got error %v, want nonce progression overflow", err)
	}
	if got := state.NextNonces[AssetNonceKey(ownerID, assetID)]; got != math.MaxUint64 {
		t.Fatalf("asset nonce changed after rejected overflow: got %d", got)
	}
	if got := state.Balances[BalanceKey{AssetID: assetID, OwnerID: ownerID}]; got.Compare(Uint128FromUint64(10)) != 0 {
		t.Fatalf("owner balance mutated by rejected overflow: got %s", got.Big().String())
	}
	if got := state.Balances[BalanceKey{AssetID: assetID, OwnerID: bytes32(0xC7)}]; !got.IsZero() {
		t.Fatalf("receiver balance inserted by rejected overflow: got %s", got.Big().String())
	}
}

func TestScopedNonceAllowsSameAssetNonceForDifferentOwners(t *testing.T) {
	ownerScriptA := testOwnerScript(0xA4)
	ownerScriptB := testOwnerScript(0xA5)
	ownerIDA := mustOwnerIDFromScript(t, ownerScriptA)
	ownerIDB := mustOwnerIDFromScript(t, ownerScriptB)
	assetID := bytes32(0x14)
	state := testTransferState(ownerIDA, assetID, 10)
	state.Balances[BalanceKey{AssetID: assetID, OwnerID: ownerIDB}] = Uint128FromUint64(10)
	state.AnchorCounts[ownerIDB] = 1

	if err := ValidateAndApplyTransaction(
		testTransferTx(ownerScriptA, 0x05, testTransferPayload(1, assetID, bytes32(0xC3), Uint128FromUint64(1))),
		1,
		0,
		state,
	); err != nil {
		t.Fatalf("owner A transfer failed: %s", err)
	}
	if err := ValidateAndApplyTransaction(
		testTransferTx(ownerScriptB, 0x06, testTransferPayload(1, assetID, bytes32(0xC4), Uint128FromUint64(1))),
		1,
		0,
		state,
	); err != nil {
		t.Fatalf("owner B transfer failed: %s", err)
	}
	if got := state.NextNonces[AssetNonceKey(ownerIDA, assetID)]; got != 2 {
		t.Fatalf("owner A asset nonce got %d want 2", got)
	}
	if got := state.NextNonces[AssetNonceKey(ownerIDB, assetID)]; got != 2 {
		t.Fatalf("owner B asset nonce got %d want 2", got)
	}
}

func TestCreateAssetStoresPermanentMetadataAndCreationContext(t *testing.T) {
	ownerScript := testOwnerScript(0xB7)
	ownerID := mustOwnerIDFromScript(t, ownerScript)
	sourceHash := bytes32(0x44)
	sourceDomainHash := externalapi.NewDomainHashFromByteArray(&sourceHash)
	creationContext := NewCreationContext(sourceDomainHash, 123_450, 1_715_122_999_000)

	state := NewState()
	state.AnchorCounts[ownerID] = 1
	payload := testCreateAssetPayload(
		1,
		8,
		PayloadSupplyModeCapped,
		Uint128FromUint64(1_000_000),
		bytes32(0xA1),
		[]byte("Permanent Token"),
		[]byte("PERM"),
		[]byte("{\"keep\":true}"),
		[]byte("bridge-v1"),
	)
	tx := testTransferTx(ownerScript, 0x21, payload)
	if err := ValidateAndApplyTransactionWithCreationContext(tx, 123_500, 0, creationContext, state); err != nil {
		t.Fatalf("create asset failed: %s", err)
	}

	assetID := *consensushashing.TransactionID(tx).ByteArray()
	asset, ok := state.Assets[assetID]
	if !ok {
		t.Fatalf("created asset missing from state")
	}
	if asset.CreatorOwnerID != ownerID {
		t.Fatalf("creator owner mismatch")
	}
	if asset.Decimals != 8 || string(asset.Name) != "Permanent Token" || string(asset.Symbol) != "PERM" {
		t.Fatalf("asset permanent fields not preserved: decimals=%d name=%q symbol=%q", asset.Decimals, asset.Name, asset.Symbol)
	}
	if string(asset.Metadata) != "{\"keep\":true}" || string(asset.PlatformTag) != "bridge-v1" {
		t.Fatalf("asset metadata/platform not preserved: metadata=%q platform=%q", asset.Metadata, asset.PlatformTag)
	}
	if asset.CreatedBlockHash == nil || *asset.CreatedBlockHash != sourceHash {
		t.Fatalf("created block hash mismatch")
	}
	if asset.CreatedDAAScore == nil || *asset.CreatedDAAScore != 123_450 {
		t.Fatalf("created DAA mismatch")
	}
	if asset.CreatedAt == nil || *asset.CreatedAt != 1_715_122_999_000 {
		t.Fatalf("created timestamp mismatch")
	}
}

func TestLiquidityPoolNonceMismatchDoesNotAdvanceAssetNonce(t *testing.T) {
	ownerScript := testOwnerScript(0xA6)
	ownerID := mustOwnerIDFromScript(t, ownerScript)
	assetID := bytes32(0x15)
	state := NewState()
	state.AnchorCounts[ownerID] = 1
	state.Assets[assetID] = AssetState{
		AssetClass: AssetClassLiquidity,
		Liquidity:  &LiquidityPoolState{PoolNonce: 2},
	}

	err := ValidateAndApplyTransaction(
		testTransferTx(ownerScript, 0x07, testBuyPayload(1, assetID, 1, 100, Uint128FromUint64(1))),
		1,
		0,
		state,
	)
	if err == nil || !strings.Contains(err.Error(), "stale liquidity nonce") {
		t.Fatalf("stale pool nonce got error %v, want stale liquidity nonce", err)
	}
	if _, ok := state.NextNonces[AssetNonceKey(ownerID, assetID)]; ok {
		t.Fatalf("asset nonce advanced after rejected stale pool nonce")
	}
}

func TestLiquidityVaultOutpointMismatchDoesNotMutateState(t *testing.T) {
	ownerScript := testOwnerScript(0xA8)
	ownerID := mustOwnerIDFromScript(t, ownerScript)
	assetID := bytes32(0x18)
	otherAssetID := bytes32(0x19)
	expectedVaultTxID := externalapi.NewDomainTransactionIDFromByteArray(&[externalapi.DomainHashSize]byte{0xA1})
	otherVaultTxID := externalapi.NewDomainTransactionIDFromByteArray(&[externalapi.DomainHashSize]byte{0xA2})
	expectedVault := *externalapi.NewDomainOutpoint(expectedVaultTxID, 0)
	otherVault := *externalapi.NewDomainOutpoint(otherVaultTxID, 0)

	state := NewState()
	state.AnchorCounts[ownerID] = 1
	state.Assets[assetID] = AssetState{
		AssetClass:  AssetClassLiquidity,
		TotalSupply: Uint128FromUint64(1_000),
		Liquidity: &LiquidityPoolState{
			PoolNonce:             1,
			RealCPayReservesSompi: 1_000,
			RealTokenReserves:     Uint128FromUint64(1_000),
			VirtualCPayReserves:   1_000,
			VirtualTokenReserves:  Uint128FromUint64(1_000),
			FeeBPS:                30,
			VaultOutpoint:         expectedVault,
			VaultValueSompi:       1_000,
			Unlocked:              true,
		},
	}
	state.Assets[otherAssetID] = AssetState{
		AssetClass: AssetClassLiquidity,
		Liquidity: &LiquidityPoolState{
			PoolNonce:       1,
			VaultOutpoint:   otherVault,
			VaultValueSompi: 2_000,
		},
	}
	state.RebuildLiquidityVaultOutpointIndex()

	tx := testLiquidityBuyTxWithVaultInput(ownerScript, 0x09, assetID, otherVault, 2_000, 2_005)
	err := ValidateAndApplyTransaction(tx, 1, 0, state)
	if err == nil || !strings.Contains(err.Error(), "liquidity vault outpoint mismatch") {
		t.Fatalf("vault mismatch got error %v, want liquidity vault outpoint mismatch", err)
	}
	if _, ok := state.NextNonces[AssetNonceKey(ownerID, assetID)]; ok {
		t.Fatalf("asset nonce advanced after rejected vault mismatch")
	}
	pool := state.Assets[assetID].Liquidity
	if pool.PoolNonce != 1 || !pool.VaultOutpoint.Equal(&expectedVault) || pool.VaultValueSompi != 1_000 {
		t.Fatalf("pool mutated after rejected vault mismatch: nonce=%d vault=%s value=%d", pool.PoolNonce, pool.VaultOutpoint, pool.VaultValueSompi)
	}
}

func TestRejectedLiquidityBuyDoesNotPartiallyMintBalance(t *testing.T) {
	ownerScript := testOwnerScript(0xAA)
	ownerID := mustOwnerIDFromScript(t, ownerScript)
	assetID := bytes32(0x1A)
	vaultTxID := externalapi.NewDomainTransactionIDFromByteArray(&[externalapi.DomainHashSize]byte{0xAB})
	vaultOutpoint := *externalapi.NewDomainOutpoint(vaultTxID, 0)
	maxUint128 := Uint128{Lo: math.MaxUint64, Hi: math.MaxUint64}
	realTokenReserves := Uint128FromUint64(1_000_000)
	virtualCPayReserves := uint64(1_000_000)
	virtualTokenReserves := Uint128FromUint64(1_000_000)
	feeBPS := uint16(0)
	quoteGrossIn := uint64(10_000)
	tokenOut, _, _, _, err := cpmmBuy(realTokenReserves, virtualCPayReserves, virtualTokenReserves, quoteGrossIn)
	if err != nil {
		t.Fatalf("cpmmBuy: %v", err)
	}
	if tokenOut.IsZero() {
		t.Fatalf("test setup expected non-zero tokenOut")
	}
	canonicalIn, err := minGrossInputForTokenOut(realTokenReserves, virtualCPayReserves, virtualTokenReserves, tokenOut, feeBPS)
	if err != nil {
		t.Fatalf("minGrossInputForTokenOut: %v", err)
	}

	state := NewState()
	state.AnchorCounts[ownerID] = 1
	state.Assets[assetID] = AssetState{
		AssetClass:  AssetClassLiquidity,
		TotalSupply: maxUint128,
		MaxSupply:   maxUint128,
		Liquidity: &LiquidityPoolState{
			PoolNonce:             1,
			RealCPayReservesSompi: 1_000,
			RealTokenReserves:     realTokenReserves,
			VirtualCPayReserves:   virtualCPayReserves,
			VirtualTokenReserves:  virtualTokenReserves,
			FeeBPS:                feeBPS,
			VaultOutpoint:         vaultOutpoint,
			VaultValueSompi:       1_000,
			Unlocked:              true,
		},
	}
	state.RebuildLiquidityVaultOutpointIndex()

	tx := testLiquidityBuyTxWithVaultInput(ownerScript, 0x0A, assetID, vaultOutpoint, 1_000, 1_000+canonicalIn)
	err = ValidateAndApplyTransaction(tx, 1, 0, state)
	if err == nil || !strings.Contains(err.Error(), "total_supply overflow") {
		t.Fatalf("overflowing buy got error %v, want total_supply overflow", err)
	}
	if balance := state.Balances[BalanceKey{AssetID: assetID, OwnerID: ownerID}]; !balance.IsZero() {
		t.Fatalf("rejected buy partially minted balance %s", balance.Big())
	}
	pool := state.Assets[assetID].Liquidity
	if pool.PoolNonce != 1 || !pool.VaultOutpoint.Equal(&vaultOutpoint) || pool.VaultValueSompi != 1_000 {
		t.Fatalf("rejected buy mutated pool: nonce=%d vault=%s value=%d", pool.PoolNonce, pool.VaultOutpoint, pool.VaultValueSompi)
	}
}

func TestRejectedCreateAssetWithMintDoesNotLeavePartialAsset(t *testing.T) {
	ownerScript := testOwnerScript(0xAC)
	ownerID := mustOwnerIDFromScript(t, ownerScript)
	receiverID := bytes32(0xAD)
	state := NewState()
	state.AnchorCounts[ownerID] = 1

	payload := testCreateAssetWithMintPayload(
		1,
		8,
		PayloadSupplyModeCapped,
		Uint128FromUint64(100),
		ownerID,
		[]byte("Cap"),
		[]byte("CAP"),
		nil,
		nil,
		Uint128FromUint64(101),
		receiverID,
	)
	tx := testTransferTx(ownerScript, 0x0B, payload)
	err := ValidateAndApplyTransaction(tx, 1, 0, state)
	if err == nil || !strings.Contains(err.Error(), "initial mint exceeds cap") {
		t.Fatalf("create-mint over cap got error %v, want cap rejection", err)
	}

	assetID := *consensushashing.TransactionID(tx).ByteArray()
	if _, ok := state.Assets[assetID]; ok {
		t.Fatalf("rejected create-mint created partial asset")
	}
	if balance := state.Balances[BalanceKey{AssetID: assetID, OwnerID: receiverID}]; !balance.IsZero() {
		t.Fatalf("rejected create-mint partially minted balance %s", balance.Big())
	}
}

func testTransferState(ownerID [externalapi.DomainHashSize]byte, assetID [externalapi.DomainHashSize]byte, balance uint64) *State {
	state := NewState()
	state.AnchorCounts[ownerID] = 1
	state.Assets[assetID] = AssetState{
		AssetClass:           AssetClassStandard,
		TokenVersion:         currentStateTokenVersion,
		MintAuthorityOwnerID: bytes32(0xE0),
		SupplyMode:           SupplyModeCapped,
		MaxSupply:            Uint128FromUint64(1_000_000),
		TotalSupply:          Uint128FromUint64(1_000_000),
	}
	state.Balances[BalanceKey{AssetID: assetID, OwnerID: ownerID}] = Uint128FromUint64(balance)
	return state
}

func testTransferTx(ownerScript *externalapi.ScriptPublicKey, previousOutpointTag byte, payload []byte) *externalapi.DomainTransaction {
	previousID := bytes32(previousOutpointTag)
	return &externalapi.DomainTransaction{
		Version: 1,
		Inputs: []*externalapi.DomainTransactionInput{
			{
				PreviousOutpoint: *externalapi.NewDomainOutpoint(externalapi.NewDomainTransactionIDFromByteArray(&previousID), 0),
				UTXOEntry:        utxo.NewUTXOEntry(10, ownerScript, false, 0),
			},
		},
		Outputs: []*externalapi.DomainTransactionOutput{
			{Value: 1, ScriptPublicKey: ownerScript},
		},
		SubnetworkID: subnetworks.SubnetworkIDPayload,
		Payload:      payload,
	}
}

func testTransferPayload(nonce uint64, assetID [externalapi.DomainHashSize]byte, toOwnerID [externalapi.DomainHashSize]byte, amount Uint128) []byte {
	payload := testPayloadHeader(1, nonce)
	payload = append(payload, assetID[:]...)
	payload = append(payload, toOwnerID[:]...)
	amountBytes := amount.ToLE()
	payload = append(payload, amountBytes[:]...)
	return payload
}

func testCreateAssetPayload(nonce uint64, decimals byte, supplyMode PayloadSupplyMode, maxSupply Uint128,
	mintAuthorityOwnerID [externalapi.DomainHashSize]byte, name, symbol, metadata, platformTag []byte) []byte {

	payload := testPayloadHeader(0, nonce)
	payload = append(payload, currentTokenVersion, decimals, byte(supplyMode))
	maxSupplyBytes := maxSupply.ToLE()
	payload = append(payload, maxSupplyBytes[:]...)
	payload = append(payload, mintAuthorityOwnerID[:]...)
	payload = append(payload, byte(len(name)), byte(len(symbol)))
	var metadataLen [2]byte
	binary.LittleEndian.PutUint16(metadataLen[:], uint16(len(metadata)))
	payload = append(payload, metadataLen[:]...)
	payload = append(payload, name...)
	payload = append(payload, symbol...)
	payload = append(payload, metadata...)
	if platformTag != nil {
		payload = append(payload, byte(len(platformTag)))
		payload = append(payload, platformTag...)
	}
	return payload
}

func testCreateAssetWithMintPayload(nonce uint64, decimals byte, supplyMode PayloadSupplyMode, maxSupply Uint128,
	mintAuthorityOwnerID [externalapi.DomainHashSize]byte, name, symbol, metadata, platformTag []byte,
	initialMintAmount Uint128, initialMintToOwnerID [externalapi.DomainHashSize]byte) []byte {

	payload := testPayloadHeader(4, nonce)
	payload = append(payload, currentTokenVersion, decimals, byte(supplyMode))
	maxSupplyBytes := maxSupply.ToLE()
	payload = append(payload, maxSupplyBytes[:]...)
	payload = append(payload, mintAuthorityOwnerID[:]...)
	payload = append(payload, byte(len(name)), byte(len(symbol)))
	var metadataLen [2]byte
	binary.LittleEndian.PutUint16(metadataLen[:], uint16(len(metadata)))
	payload = append(payload, metadataLen[:]...)
	payload = append(payload, name...)
	payload = append(payload, symbol...)
	payload = append(payload, metadata...)
	initialMintBytes := initialMintAmount.ToLE()
	payload = append(payload, initialMintBytes[:]...)
	payload = append(payload, initialMintToOwnerID[:]...)
	if platformTag != nil {
		payload = append(payload, byte(len(platformTag)))
		payload = append(payload, platformTag...)
	}
	return payload
}

func testBuyPayload(nonce uint64, assetID [externalapi.DomainHashSize]byte, expectedPoolNonce uint64, cpayInSompi uint64, minTokenOut Uint128) []byte {
	payload := testPayloadHeader(6, nonce)
	payload = append(payload, assetID[:]...)
	var uint64Bytes [8]byte
	binary.LittleEndian.PutUint64(uint64Bytes[:], expectedPoolNonce)
	payload = append(payload, uint64Bytes[:]...)
	binary.LittleEndian.PutUint64(uint64Bytes[:], cpayInSompi)
	payload = append(payload, uint64Bytes[:]...)
	minTokenOutBytes := minTokenOut.ToLE()
	payload = append(payload, minTokenOutBytes[:]...)
	return payload
}

func testLiquidityBuyTxWithVaultInput(
	ownerScript *externalapi.ScriptPublicKey,
	previousOutpointTag byte,
	assetID [externalapi.DomainHashSize]byte,
	vaultOutpoint externalapi.DomainOutpoint,
	vaultInputValue uint64,
	vaultOutputValue uint64,
) *externalapi.DomainTransaction {
	ownerPreviousID := bytes32(previousOutpointTag)
	return &externalapi.DomainTransaction{
		Version: 1,
		Inputs: []*externalapi.DomainTransactionInput{
			{
				PreviousOutpoint: *externalapi.NewDomainOutpoint(externalapi.NewDomainTransactionIDFromByteArray(&ownerPreviousID), 0),
				UTXOEntry:        utxo.NewUTXOEntry(10, ownerScript, false, 0),
			},
			{
				PreviousOutpoint: vaultOutpoint,
				UTXOEntry:        utxo.NewUTXOEntry(vaultInputValue, testLiquidityVaultScript(), false, 0),
			},
		},
		Outputs: []*externalapi.DomainTransactionOutput{
			{Value: 1, ScriptPublicKey: ownerScript},
			{Value: vaultOutputValue, ScriptPublicKey: testLiquidityVaultScript()},
		},
		SubnetworkID: subnetworks.SubnetworkIDPayload,
		Payload:      testBuyPayload(1, assetID, 1, vaultOutputValue-vaultInputValue, Uint128FromUint64(1)),
	}
}

func testLiquidityVaultScript() *externalapi.ScriptPublicKey {
	return &externalapi.ScriptPublicKey{
		Script:  []byte{txscript.OpData4, 'C', 'L', 'V', '1', txscript.OpDrop, txscript.OpTrue},
		Version: constants.MaxScriptPublicKeyVersion,
	}
}

func testPayloadHeader(opcode byte, nonce uint64) []byte {
	payload := append([]byte{}, catMagic...)
	payload = append(payload, catVersion, opcode, 0)
	var authIndexBytes [2]byte
	payload = append(payload, authIndexBytes[:]...)
	var nonceBytes [8]byte
	binary.LittleEndian.PutUint64(nonceBytes[:], nonce)
	payload = append(payload, nonceBytes[:]...)
	return payload
}

func testOwnerScript(seed byte) *externalapi.ScriptPublicKey {
	script := make([]byte, 34)
	script[0] = txscript.OpData32
	for i := 1; i <= 32; i++ {
		script[i] = seed
	}
	script[33] = txscript.OpCheckSig
	return &externalapi.ScriptPublicKey{Script: script, Version: constants.MaxScriptPublicKeyVersion}
}

func mustOwnerIDFromScript(t *testing.T, scriptPublicKey *externalapi.ScriptPublicKey) [externalapi.DomainHashSize]byte {
	t.Helper()

	ownerID, ok := OwnerIDFromScript(scriptPublicKey)
	if !ok {
		t.Fatal("test owner script did not derive an owner ID")
	}
	return ownerID
}
