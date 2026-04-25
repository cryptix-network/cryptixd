package atomicstate

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
)

type atomicInteropVector struct {
	Name                      string `json:"name"`
	StateCanonicalHex         string `json:"state_canonical_hex"`
	StateHashHex              string `json:"state_hash_hex"`
	RawUTXOCommitmentHex      string `json:"raw_utxo_commitment_hex"`
	HeaderCommitmentPreHFHex  string `json:"header_commitment_pre_hf_hex"`
	HeaderCommitmentPostHFHex string `json:"header_commitment_post_hf_hex"`
}

func TestAtomicConsensusStateRustInteropVector(t *testing.T) {
	vector := loadAtomicInteropVector(t)
	if vector.Name != "cryptix-atomic-consensus-state-interop-v1" {
		t.Fatalf("unexpected vector name %q", vector.Name)
	}

	state := atomicInteropVectorState(t)
	canonicalBytes := state.CanonicalBytes()
	if got := hex.EncodeToString(canonicalBytes); got != vector.StateCanonicalHex {
		t.Fatalf("canonical bytes mismatch\n got: %s\nwant: %s", got, vector.StateCanonicalHex)
	}
	stateCanonicalHash := state.CanonicalHash()
	if got := hex.EncodeToString(stateCanonicalHash[:]); got != vector.StateHashHex {
		t.Fatalf("state hash mismatch\n got: %s\nwant: %s", got, vector.StateHashHex)
	}

	vectorCanonicalBytes := mustDecodeHex(t, vector.StateCanonicalHex)
	decoded, err := FromCanonicalBytes(vectorCanonicalBytes)
	if err != nil {
		t.Fatalf("FromCanonicalBytes failed: %s", err)
	}
	if got := hex.EncodeToString(decoded.CanonicalBytes()); got != vector.StateCanonicalHex {
		t.Fatalf("decoded canonical bytes mismatch\n got: %s\nwant: %s", got, vector.StateCanonicalHex)
	}
	vectorCanonicalHash := HashCanonicalBytes(vectorCanonicalBytes)
	if got := hex.EncodeToString(vectorCanonicalHash[:]); got != vector.StateHashHex {
		t.Fatalf("HashCanonicalBytes mismatch\n got: %s\nwant: %s", got, vector.StateHashHex)
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
	state.NextNonces[bytes32(0x61)] = 3
	state.NextNonces[bytes32(0x60)] = 99
	state.Assets[liquidityAssetID] = AssetState{
		AssetClass:           AssetClassLiquidity,
		MintAuthorityOwnerID: bytes32(0x00),
		SupplyMode:           SupplyModeCapped,
		MaxSupply:            liquidityMaxSupply,
		TotalSupply:          liquidityTotal,
		Liquidity: &LiquidityPoolState{
			PoolNonce:              17,
			RemainingPoolSupply:    liquidityRemaining,
			CurveReserveSompi:      123_456_789,
			UnclaimedFeeTotalSompi: 30,
			FeeBPS:                 250,
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
			VaultOutpoint:   *externalapi.NewDomainOutpoint(externalapi.NewDomainTransactionIDFromByteArray(&vaultTransactionID), 3),
			VaultValueSompi: 123_456_819,
		},
	}
	state.Assets[standardAssetID] = AssetState{
		AssetClass:           AssetClassStandard,
		MintAuthorityOwnerID: bytes32(0xA1),
		SupplyMode:           SupplyModeCapped,
		MaxSupply:            uint128Words(0x0200, 9_999),
		TotalSupply:          standardTotal,
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
	fixturePath := filepath.Join(filepath.Dir(filename), "..", "..", "..", "..", "docs", "atomic_consensus_state_interop_v1.json")
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
