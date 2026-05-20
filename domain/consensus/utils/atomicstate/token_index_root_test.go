package atomicstate

import (
	"encoding/hex"
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
)

func TestTokenIndexHashMatchesRustGoldenVector(t *testing.T) {
	var buckets [atomicTokenRootBuckets][externalapi.DomainHashSize]byte

	assetID := tokenIndexTestBytes32(0x11)
	ownerID := tokenIndexTestBytes32(0x22)
	creatorID := tokenIndexTestBytes32(0x33)
	authorityID := tokenIndexTestBytes32(0x44)

	asset := AssetState{
		CreatorOwnerID:       creatorID,
		AssetClass:           AssetClassStandard,
		TokenVersion:         currentStateTokenVersion,
		MintAuthorityOwnerID: authorityID,
		Decimals:             8,
		SupplyMode:           SupplyModeUncapped,
		MaxSupply:            Uint128{},
		TotalSupply:          Uint128FromUint64(900),
		Name:                 []byte("Atomic"),
		Symbol:               []byte("ATM"),
		Metadata:             []byte{0xA1, 0xB2},
		PlatformTag:          nil,
		CreatedBlockHash:     nil,
		CreatedDAAScore:      nil,
		CreatedAt:            nil,
	}
	applyTokenRootLeaf(&buckets, logicalTokenAssetKey(assetID), tokenRootValueForAsset(assetID, asset))
	applyTokenRootLeaf(&buckets, logicalTokenBalanceKey(BalanceKey{AssetID: assetID, OwnerID: ownerID}), tokenRootValueForUint128(Uint128FromUint64(900)))
	applyTokenRootLeaf(&buckets, logicalTokenNonceKey(OwnerNonceKey(ownerID)), tokenRootValueForUint64(7))

	root := tokenRootFromBuckets(&buckets)
	got := hex.EncodeToString(root[:])
	const want = "3ad3d91ea19241c69d6a5ab618798ba3086f20b66b38cc329fd913ce42efd8e9"
	if got != want {
		t.Fatalf("Go token root differs from Rust golden vector: got %s, want %s", got, want)
	}
}

func TestTokenIndexHashRequiresComparableAssetCreationMetadata(t *testing.T) {
	state := NewState()
	assetID := tokenIndexTestBytes32(0x11)
	state.Assets[assetID] = AssetState{
		CreatorOwnerID:       tokenIndexTestBytes32(0x22),
		AssetClass:           AssetClassStandard,
		TokenVersion:         currentStateTokenVersion,
		MintAuthorityOwnerID: tokenIndexTestBytes32(0x33),
		Decimals:             8,
		SupplyMode:           SupplyModeCapped,
		MaxSupply:            Uint128FromUint64(1_000),
		TotalSupply:          Uint128FromUint64(100),
		Name:                 []byte("Token"),
		Symbol:               []byte("TKN"),
		Metadata:             []byte{0xAA},
	}

	if _, ok := state.TokenIndexHash(); ok {
		t.Fatalf("legacy/incomplete asset metadata must not be exposed as a comparable token checkpoint")
	}
	if reason := state.TokenIndexHashUnavailableReason(); reason == "" {
		t.Fatalf("legacy/incomplete asset metadata must report why the token checkpoint is unavailable")
	}

	createdBlockHash := tokenIndexTestBytes32(0x44)
	createdDAA := uint64(123)
	createdAt := uint64(456)
	asset := state.Assets[assetID]
	asset.CreatedBlockHash = &createdBlockHash
	asset.CreatedDAAScore = &createdDAA
	asset.CreatedAt = &createdAt
	state.Assets[assetID] = asset

	if _, ok := state.TokenIndexHash(); !ok {
		t.Fatalf("complete V5 asset metadata should be exposed as a comparable token checkpoint")
	}
	if reason := state.TokenIndexHashUnavailableReason(); reason != "" {
		t.Fatalf("complete V5 asset metadata should not report an unavailable reason: %s", reason)
	}
}

func TestTokenIndexHashRejectsRootOnlyState(t *testing.T) {
	state := NewRootOnlyState(tokenIndexTestBytes32(0x55))
	if _, ok := state.TokenIndexHash(); ok {
		t.Fatalf("root-only state must not be exposed as a comparable token checkpoint")
	}
}

func tokenIndexTestBytes32(value byte) [externalapi.DomainHashSize]byte {
	var out [externalapi.DomainHashSize]byte
	for i := range out {
		out[i] = value
	}
	return out
}
