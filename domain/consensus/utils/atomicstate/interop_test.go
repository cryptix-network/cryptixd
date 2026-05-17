package atomicstate

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
)

type atomicInteropVector struct {
	Name                      string `json:"name"`
	StateHashHex              string `json:"state_hash_hex"`
	RawUTXOCommitmentHex      string `json:"raw_utxo_commitment_hex"`
	HeaderCommitmentPreHFHex  string `json:"header_commitment_pre_hf_hex"`
	HeaderCommitmentPostHFHex string `json:"header_commitment_post_hf_hex"`
}

func TestAtomicConsensusStateRustInteropVector(t *testing.T) {
	vector := loadAtomicInteropVector(t)
	if vector.Name != "cryptix-atomic-consensus-state-root-v2" {
		t.Fatalf("unexpected vector name %q", vector.Name)
	}

	state := atomicInteropVectorState(t)
	stateCanonicalHash := state.CanonicalHash()
	if got := hex.EncodeToString(stateCanonicalHash[:]); got != vector.StateHashHex {
		t.Fatalf("state hash mismatch\n got: %s\nwant: %s", got, vector.StateHashHex)
	}

	rawUTXOCommitment, err := externalapi.NewDomainHashFromByteSlice(mustDecodeHex(t, vector.RawUTXOCommitmentHex))
	if err != nil {
		t.Fatalf("invalid raw UTXO commitment in vector: %s", err)
	}
	stateHash := mustDecodeHash32(t, vector.StateHashHex)
	if got := HeaderCommitment(rawUTXOCommitment, stateHash, false).String(); got != vector.HeaderCommitmentPreHFHex {
		t.Fatalf("pre-HF header commitment mismatch\n got: %s\nwant: %s", got, vector.HeaderCommitmentPreHFHex)
	}
	if got := HeaderCommitment(rawUTXOCommitment, stateHash, true).String(); got != vector.HeaderCommitmentPostHFHex {
		t.Fatalf("post-HF header commitment mismatch\n got: %s\nwant: %s", got, vector.HeaderCommitmentPostHFHex)
	}
}

func TestRootOnlyAtomicStateRoundTrip(t *testing.T) {
	var stateHash [externalapi.DomainHashSize]byte
	for i := range stateHash {
		stateHash[i] = byte(i + 1)
	}

	state := NewRootOnlyState(stateHash)
	if !state.IsRootOnly() {
		t.Fatalf("expected root-only state")
	}

	stateBytes := state.CanonicalBytes()
	decoded, err := FromCanonicalBytes(stateBytes)
	if err != nil {
		t.Fatalf("FromCanonicalBytes failed: %s", err)
	}
	if !decoded.IsRootOnly() {
		t.Fatalf("expected decoded state to remain root-only")
	}
	if got := decoded.CanonicalHash(); got != stateHash {
		t.Fatalf("decoded root hash mismatch\n got: %x\nwant: %x", got, stateHash)
	}
	if got := HashCanonicalBytes(stateBytes); got != stateHash {
		t.Fatalf("root-only canonical hash mismatch\n got: %x\nwant: %x", got, stateHash)
	}

	err = ValidateAndApplyTransaction(&externalapi.DomainTransaction{}, 1, 0, decoded)
	if err == nil || !strings.Contains(err.Error(), "root-only Atomic consensus state") {
		t.Fatalf("expected root-only post-HF validation guard, got %v", err)
	}
}

func atomicInteropVectorState(t *testing.T) *State {
	t.Helper()

	standardAssetID := bytes32(0x10)
	liquidityAssetID := bytes32(0x20)

	standardTotal := uint128Words(0x0100, 12_345)
	standardBalanceA := uint128Words(0x0080, 1_000)
	standardBalanceB, ok := standardTotal.Sub(standardBalanceA)
	if !ok {
		t.Fatal("standard balance calculation underflow")
	}

	liquidityTotal := uint128Words(0x8000, 333)
	liquidityRemaining := uint128Words(0x8000, 999_667)
	liquidityMaxSupply, ok := liquidityTotal.Add(liquidityRemaining)
	if !ok {
		t.Fatal("liquidity supply calculation overflow")
	}

	feeRecipientPayloadA := repeatedBytes(0x01, 32)
	feeRecipientPayloadB := repeatedBytes(0x02, 32)
	feeRecipientOwnerA, ok := OwnerIDFromAddressComponents(0, feeRecipientPayloadA)
	if !ok {
		t.Fatal("recipient owner A derivation failed")
	}
	feeRecipientOwnerB, ok := OwnerIDFromAddressComponents(0, feeRecipientPayloadB)
	if !ok {
		t.Fatal("recipient owner B derivation failed")
	}

	vaultTransactionID := bytes32(0x77)

	state := NewState()
	state.NextNonces[OwnerNonceKey(bytes32(0x61))] = 3
	state.NextNonces[AssetNonceKey(bytes32(0x60), standardAssetID)] = 99
	state.Assets[liquidityAssetID] = AssetState{
		AssetClass:           AssetClassLiquidity,
		TokenVersion:         currentStateTokenVersion,
		MintAuthorityOwnerID: bytes32(0x00),
		SupplyMode:           SupplyModeCapped,
		MaxSupply:            liquidityMaxSupply,
		TotalSupply:          liquidityTotal,
		PlatformTag:          nil,
		Liquidity: &LiquidityPoolState{
			PoolNonce:                           17,
			CurveVersion:                        currentStateLiquidityCurveVersion,
			CurveMode:                           defaultLiquidityCurveMode,
			IndividualVirtualCPayReservesSompi:  0,
			IndividualVirtualTokenMultiplierBPS: 0,
			RealCPayReservesSompi:               123_456_789,
			RealTokenReserves:                   liquidityRemaining,
			VirtualCPayReserves:                 1_000_000_000_000,
			VirtualTokenReserves:                Uint128FromUint64(1_300_000),
			UnclaimedFeeTotalSompi:              30,
			FeeBPS:                              250,
			FeeRecipients: []LiquidityFeeRecipientState{
				{
					OwnerID:        feeRecipientOwnerA,
					AddressVersion: 0,
					AddressPayload: feeRecipientPayloadA,
					UnclaimedSompi: 10,
				},
				{
					OwnerID:        feeRecipientOwnerB,
					AddressVersion: 0,
					AddressPayload: feeRecipientPayloadB,
					UnclaimedSompi: 20,
				},
			},
			VaultOutpoint:     *externalapi.NewDomainOutpoint(externalapi.NewDomainTransactionIDFromByteArray(&vaultTransactionID), 3),
			VaultValueSompi:   123_456_819,
			UnlockTargetSompi: 0,
			Unlocked:          true,
		},
	}
	state.Assets[standardAssetID] = AssetState{
		AssetClass:           AssetClassStandard,
		TokenVersion:         currentStateTokenVersion,
		MintAuthorityOwnerID: bytes32(0xA1),
		SupplyMode:           SupplyModeCapped,
		MaxSupply:            uint128Words(0x0200, 9_999),
		TotalSupply:          standardTotal,
		PlatformTag:          nil,
	}
	state.Balances[BalanceKey{AssetID: standardAssetID, OwnerID: bytes32(0xB1)}] = standardBalanceB
	state.Balances[BalanceKey{AssetID: liquidityAssetID, OwnerID: bytes32(0xC0)}] = liquidityTotal
	state.Balances[BalanceKey{AssetID: standardAssetID, OwnerID: bytes32(0xB0)}] = standardBalanceA
	state.AnchorCounts[bytes32(0x51)] = 2
	state.AnchorCounts[bytes32(0x50)] = 9
	state.RebuildLiquidityVaultOutpointIndex()
	return state
}

func loadAtomicInteropVector(t *testing.T) atomicInteropVector {
	t.Helper()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	fixturePath := filepath.Join(filepath.Dir(filename), "..", "..", "..", "..", "docs", "atomic_consensus_state_root_v2.json")
	bytes, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read interop vector fixture: %s", err)
	}
	var vector atomicInteropVector
	if err := json.Unmarshal(bytes, &vector); err != nil {
		t.Fatalf("parse interop vector fixture: %s", err)
	}
	return vector
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()

	bytes, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex %q: %s", value, err)
	}
	return bytes
}

func mustDecodeHash32(t *testing.T, value string) [externalapi.DomainHashSize]byte {
	t.Helper()

	bytes := mustDecodeHex(t, value)
	if len(bytes) != externalapi.DomainHashSize {
		t.Fatalf("expected 32-byte hash, got %d bytes", len(bytes))
	}
	var out [externalapi.DomainHashSize]byte
	copy(out[:], bytes)
	return out
}

func bytes32(value byte) [externalapi.DomainHashSize]byte {
	var out [externalapi.DomainHashSize]byte
	for i := range out {
		out[i] = value
	}
	return out
}

func repeatedBytes(value byte, length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = value
	}
	return out
}

func uint128Words(hi uint64, lo uint64) Uint128 {
	return Uint128{Hi: hi, Lo: lo}
}
