package atomicstate

import (
	"encoding/binary"
	"math"
	"strings"
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
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
