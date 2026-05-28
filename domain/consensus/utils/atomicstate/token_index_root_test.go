package atomicstate

import (
	"encoding/hex"
	"fmt"
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

func TestTokenIndexHashMatchesRustComplexAuditVector(t *testing.T) {
	assetA := tokenIndexSeqBytes32(0x10)
	assetB := tokenIndexSeqBytes32(0x40)
	ownerA := tokenIndexSeqBytes32(0x70)
	ownerB := tokenIndexSeqBytes32(0x90)
	creatorA := tokenIndexSeqBytes32(0xB0)
	creatorB := tokenIndexSeqBytes32(0xC0)
	authorityA := tokenIndexSeqBytes32(0xD0)
	recipientA := tokenIndexSeqBytes32(0xE0)
	recipientB := tokenIndexSeqBytes32(0xF0)
	createdA := tokenIndexSeqBytes32(0x21)
	createdB := tokenIndexSeqBytes32(0x31)
	vaultTxIDBytes := tokenIndexSeqBytes32(0x55)
	vaultTxID := externalapi.NewDomainTransactionIDFromByteArray(&vaultTxIDBytes)

	createdADAA := uint64(12_345)
	createdATime := uint64(1_779_700_001)
	createdBDAA := uint64(12_678)
	createdBTime := uint64(1_779_700_999)

	state := NewState()
	state.Assets[assetA] = AssetState{
		CreatorOwnerID:       creatorA,
		AssetClass:           AssetClassStandard,
		TokenVersion:         currentStateTokenVersion,
		MintAuthorityOwnerID: authorityA,
		Decimals:             8,
		SupplyMode:           SupplyModeCapped,
		MaxSupply:            Uint128FromUint64(9_000_000),
		TotalSupply:          Uint128FromUint64(1_234_567),
		Name:                 []byte("VectorToken"),
		Symbol:               []byte("VEC"),
		Metadata:             []byte{0x01, 0x02, 0x03, 0x04},
		PlatformTag:          []byte("audit-v1"),
		CreatedBlockHash:     &createdA,
		CreatedDAAScore:      &createdADAA,
		CreatedAt:            &createdATime,
	}
	state.Assets[assetB] = AssetState{
		CreatorOwnerID:       creatorB,
		AssetClass:           AssetClassLiquidity,
		TokenVersion:         currentStateTokenVersion,
		MintAuthorityOwnerID: [externalapi.DomainHashSize]byte{},
		Decimals:             6,
		SupplyMode:           SupplyModeCapped,
		MaxSupply:            Uint128FromUint64(2_000_000),
		TotalSupply:          Uint128FromUint64(777_000),
		Name:                 []byte("LiquidityVector"),
		Symbol:               []byte("LVEC"),
		Metadata:             []byte{0xAA, 0xBB, 0xCC},
		PlatformTag:          []byte("pool-v2"),
		CreatedBlockHash:     &createdB,
		CreatedDAAScore:      &createdBDAA,
		CreatedAt:            &createdBTime,
		Liquidity: &LiquidityPoolState{
			PoolNonce:                           44,
			CurveVersion:                        currentStateLiquidityCurveVersion,
			CurveMode:                           2,
			IndividualVirtualCPayReservesSompi:  12_000,
			IndividualVirtualTokenMultiplierBPS: 150,
			RealCPayReservesSompi:               9_876_543,
			RealTokenReserves:                   Uint128FromUint64(123_456),
			VirtualCPayReserves:                 10_000_000,
			VirtualTokenReserves:                Uint128FromUint64(654_321),
			UnclaimedFeeTotalSompi:              333,
			FeeBPS:                              25,
			FeeRecipients: []LiquidityFeeRecipientState{
				{OwnerID: recipientA, AddressVersion: 0, AddressPayload: []byte{0x10, 0x11}, UnclaimedSompi: 7},
				{OwnerID: recipientB, AddressVersion: 1, AddressPayload: []byte{0x20, 0x21, 0x22}, UnclaimedSompi: 11},
			},
			VaultOutpoint:     externalapi.DomainOutpoint{TransactionID: *vaultTxID, Index: 3},
			VaultValueSompi:   8_888,
			UnlockTargetSompi: 99_999,
			Unlocked:          false,
		},
	}
	state.Balances[BalanceKey{AssetID: assetA, OwnerID: ownerA}] = Uint128FromUint64(555)
	state.Balances[BalanceKey{AssetID: assetA, OwnerID: ownerB}] = Uint128FromUint64(777)
	state.Balances[BalanceKey{AssetID: assetB, OwnerID: ownerA}] = Uint128FromUint64(999)
	state.Balances[BalanceKey{AssetID: assetB, OwnerID: ownerB}] = Uint128{}
	state.NextNonces[OwnerNonceKey(ownerA)] = 4
	state.NextNonces[AssetNonceKey(ownerA, assetA)] = 6
	state.NextNonces[AssetNonceKey(ownerB, assetB)] = 1
	state.AnchorCounts[ownerA] = 3
	state.AnchorCounts[ownerB] = 5

	root, ok := state.TokenIndexHash()
	if !ok {
		t.Fatalf("complex token audit vector root unavailable: %s", state.TokenIndexHashUnavailableReason())
	}
	got := hex.EncodeToString(root[:])
	const want = "47769a46099c386e52f8f0d62a789e1b1b8453b530c6f1385fd92ca53797bd4d"
	if got != want {
		t.Fatalf("Go complex token audit root differs from Rust vector: got %s, want %s", got, want)
	}

	auditRoot, ok := state.P2PTokenAuditHash()
	if !ok {
		t.Fatalf("complex P2P token audit root unavailable: %s", state.P2PTokenAuditHashUnavailableReason())
	}
	gotAudit := hex.EncodeToString(auditRoot[:])
	const wantAudit = "d61e226e9ea824488ff7462e334115a9e5293b4576d58813056dfcc1159f9f92"
	if gotAudit != wantAudit {
		t.Fatalf("Go complex P2P token audit root differs from Rust vector: got %s, want %s", gotAudit, wantAudit)
	}
}

func TestTokenStressInteropVectorMatchesRustHashes(t *testing.T) {
	ownerMain := tokenIndexSeqBytes32(0x11)
	ownerReceiver := tokenIndexSeqBytes32(0x31)
	ownerCreatorB := tokenIndexSeqBytes32(0x51)
	liquidityCreator := tokenIndexSeqBytes32(0x71)
	mintAuthority := tokenIndexSeqBytes32(0x91)
	feePayloadA := tokenIndexRepeatedBytes(0x0A, 32)
	feePayloadB := tokenIndexRepeatedBytes(0x0B, 32)
	feeOwnerA, ok := OwnerIDFromAddressComponents(0, feePayloadA)
	if !ok {
		t.Fatal("valid fee owner A")
	}
	feeOwnerB, ok := OwnerIDFromAddressComponents(0, feePayloadB)
	if !ok {
		t.Fatal("valid fee owner B")
	}

	state := NewState()
	for i := byte(0); i < 20; i++ {
		assetID := tokenIndexSeqBytes32(0x40 + i*2)
		initialSupply := uint64(1_000) + uint64(i)*13
		minted := uint64(0)
		burned := uint64(0)
		transferred := uint64(0)
		if i < 12 {
			minted = 500 + uint64(i)
			burned = 20 + uint64(i)
			transferred = 30 + uint64(i)
		}
		totalSupply := initialSupply + minted - burned
		ownerBalance := totalSupply - transferred
		creator := ownerMain
		if i%3 == 0 {
			creator = ownerCreatorB
		}

		state.Assets[assetID] = AssetState{
			CreatorOwnerID:       creator,
			AssetClass:           AssetClassStandard,
			TokenVersion:         currentStateTokenVersion,
			MintAuthorityOwnerID: mintAuthority,
			Decimals:             i % 9,
			SupplyMode:           SupplyModeCapped,
			MaxSupply:            Uint128FromUint64(1_000_000 + uint64(i)*1_000),
			TotalSupply:          Uint128FromUint64(totalSupply),
			Name:                 []byte(fmt.Sprintf("Stress Token %02d", i)),
			Symbol:               []byte(fmt.Sprintf("ST%02d", i)),
			Metadata:             []byte(fmt.Sprintf("stress-metadata-%02d", i)),
			PlatformTag:          []byte("stress-vector-v1"),
			CreatedBlockHash:     tokenIndexBytes32Ptr(tokenIndexSeqBytes32(0x90 + i)),
			CreatedDAAScore:      tokenIndexUint64Ptr(200_000 + uint64(i)),
			CreatedAt:            tokenIndexUint64Ptr(1_779_900_000_000 + uint64(i)),
		}
		state.Balances[BalanceKey{AssetID: assetID, OwnerID: ownerMain}] = Uint128FromUint64(ownerBalance)
		if transferred > 0 {
			state.Balances[BalanceKey{AssetID: assetID, OwnerID: ownerReceiver}] = Uint128FromUint64(transferred)
		}
		nextNonce := uint64(2)
		if i < 12 {
			nextNonce = 5
		}
		state.NextNonces[AssetNonceKey(ownerMain, assetID)] = nextNonce
	}

	liquidityAssetID := tokenIndexSeqBytes32(0xE0)
	liquidityTotal := uint64(221_320)
	liquidityRemaining := uint64(778_680)
	unclaimedFeeTotal := uint64(12_345_678)
	realCPay := uint64(53_415_169_749_573)
	vaultTxIDBytes := tokenIndexSeqBytes32(0x22)
	vaultTxID := externalapi.NewDomainTransactionIDFromByteArray(&vaultTxIDBytes)
	state.Assets[liquidityAssetID] = AssetState{
		CreatorOwnerID:       liquidityCreator,
		AssetClass:           AssetClassLiquidity,
		TokenVersion:         currentStateTokenVersion,
		MintAuthorityOwnerID: [externalapi.DomainHashSize]byte{},
		Decimals:             0,
		SupplyMode:           SupplyModeCapped,
		MaxSupply:            Uint128FromUint64(liquidityTotal + liquidityRemaining),
		TotalSupply:          Uint128FromUint64(liquidityTotal),
		Name:                 []byte("Stress Liquidity Token"),
		Symbol:               []byte("SLP"),
		Metadata:             []byte("liquidity-stress-vector"),
		PlatformTag:          []byte("stress-vector-v1"),
		CreatedBlockHash:     tokenIndexBytes32Ptr(tokenIndexSeqBytes32(0xA8)),
		CreatedDAAScore:      tokenIndexUint64Ptr(200_777),
		CreatedAt:            tokenIndexUint64Ptr(1_779_900_777_000),
		Liquidity: &LiquidityPoolState{
			PoolNonce:                           187,
			CurveVersion:                        currentStateLiquidityCurveVersion,
			CurveMode:                           1,
			IndividualVirtualCPayReservesSompi:  0,
			IndividualVirtualTokenMultiplierBPS: 0,
			RealCPayReservesSompi:               realCPay,
			RealTokenReserves:                   Uint128FromUint64(liquidityRemaining),
			VirtualCPayReserves:                 253_415_069_749_573,
			VirtualTokenReserves:                Uint128FromUint64(828_680),
			UnclaimedFeeTotalSompi:              unclaimedFeeTotal,
			FeeBPS:                              25,
			FeeRecipients: []LiquidityFeeRecipientState{
				{OwnerID: feeOwnerA, AddressVersion: 0, AddressPayload: feePayloadA, UnclaimedSompi: 5_000_000},
				{OwnerID: feeOwnerB, AddressVersion: 0, AddressPayload: feePayloadB, UnclaimedSompi: 7_345_678},
			},
			VaultOutpoint:     externalapi.DomainOutpoint{TransactionID: *vaultTxID, Index: 7},
			VaultValueSompi:   realCPay + unclaimedFeeTotal,
			UnlockTargetSompi: 900_000_000_000,
			Unlocked:          true,
		},
	}
	state.Balances[BalanceKey{AssetID: liquidityAssetID, OwnerID: ownerMain}] = Uint128FromUint64(liquidityTotal)
	state.NextNonces[OwnerNonceKey(ownerMain)] = 23
	state.NextNonces[AssetNonceKey(ownerMain, liquidityAssetID)] = 6
	state.AnchorCounts[ownerMain] = 97
	state.AnchorCounts[ownerReceiver] = 44
	state.AnchorCounts[ownerCreatorB] = 13
	state.AnchorCounts[liquidityCreator] = 8
	state.AnchorCounts[feeOwnerA] = 5
	state.AnchorCounts[feeOwnerB] = 7
	state.AnchorCounts[tokenIndexSeqBytes32(0xC0)] = 19
	state.AnchorCounts[tokenIndexSeqBytes32(0xD0)] = 23
	state.AnchorCounts[tokenIndexSeqBytes32(0xF0)] = 29
	state.RebuildLiquidityVaultOutpointIndex()

	canonicalHash := state.CanonicalHash()
	gotCanonical := hex.EncodeToString(canonicalHash[:])
	const wantCanonical = "9c4cfb9daca1ec54a69f478e4088223a6132229db4423bc5239e0027c98b9905"
	if gotCanonical != wantCanonical {
		t.Fatalf("Go stress canonical Atomic hash differs from Rust vector: got %s, want %s", gotCanonical, wantCanonical)
	}

	auditRoot, ok := state.P2PTokenAuditHash()
	if !ok {
		t.Fatalf("stress P2P token audit root unavailable: %s", state.P2PTokenAuditHashUnavailableReason())
	}
	gotAudit := hex.EncodeToString(auditRoot[:])
	const wantAudit = "ee4a1f9d29209eead50a53a81a116c59f0f0c178e14d09b3de32fee8524a6332"
	if gotAudit != wantAudit {
		t.Fatalf("Go stress P2P token audit root differs from Rust vector: got %s, want %s", gotAudit, wantAudit)
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
	if _, ok := state.P2PTokenAuditHash(); ok {
		t.Fatalf("root-only state must not be exposed as a P2P token audit checkpoint")
	}
}

func TestTokenIndexHashDetectsPermanentMetadataThatConsensusHashIgnores(t *testing.T) {
	assetID := tokenIndexSeqBytes32(0x10)
	ownerID := tokenIndexSeqBytes32(0x40)
	createdBlock := tokenIndexSeqBytes32(0x70)
	createdDAA := uint64(123)
	createdAt := uint64(456)

	base := NewState()
	base.Assets[assetID] = AssetState{
		CreatorOwnerID:       tokenIndexSeqBytes32(0xA0),
		AssetClass:           AssetClassStandard,
		TokenVersion:         currentStateTokenVersion,
		MintAuthorityOwnerID: tokenIndexSeqBytes32(0xB0),
		Decimals:             2,
		SupplyMode:           SupplyModeCapped,
		MaxSupply:            Uint128FromUint64(1_000_000),
		TotalSupply:          Uint128FromUint64(500),
		Name:                 []byte("Token A"),
		Symbol:               []byte("TKA"),
		Metadata:             []byte("metadata-a"),
		PlatformTag:          []byte("wallet-v1"),
		CreatedBlockHash:     &createdBlock,
		CreatedDAAScore:      &createdDAA,
		CreatedAt:            &createdAt,
	}
	base.Balances[BalanceKey{AssetID: assetID, OwnerID: ownerID}] = Uint128FromUint64(500)
	base.NextNonces[AssetNonceKey(ownerID, assetID)] = 2
	base.AnchorCounts[ownerID] = 1

	changed := base.Clone()
	asset := changed.Assets[assetID]
	changedCreatedBlock := tokenIndexSeqBytes32(0x71)
	changedCreatedDAA := uint64(124)
	changedCreatedAt := uint64(789)
	asset.CreatorOwnerID = tokenIndexSeqBytes32(0xA1)
	asset.Decimals = 8
	asset.Name = []byte("Token B")
	asset.Symbol = []byte("TKB")
	asset.Metadata = []byte("metadata-b")
	asset.CreatedBlockHash = &changedCreatedBlock
	asset.CreatedDAAScore = &changedCreatedDAA
	asset.CreatedAt = &changedCreatedAt
	changed.Assets[assetID] = asset

	if base.CanonicalHash() != changed.CanonicalHash() {
		t.Fatalf("test setup invalid: permanent metadata unexpectedly changed the consensus Atomic hash")
	}
	baseTokenRoot, ok := base.TokenIndexHash()
	if !ok {
		t.Fatalf("base token root unavailable: %s", base.TokenIndexHashUnavailableReason())
	}
	changedTokenRoot, ok := changed.TokenIndexHash()
	if !ok {
		t.Fatalf("changed token root unavailable: %s", changed.TokenIndexHashUnavailableReason())
	}
	if baseTokenRoot == changedTokenRoot {
		t.Fatalf("token audit root must detect permanent metadata differences that the consensus Atomic hash ignores")
	}

	baseAuditRoot, ok := base.P2PTokenAuditHash()
	if !ok {
		t.Fatalf("base P2P token audit root unavailable: %s", base.P2PTokenAuditHashUnavailableReason())
	}
	changedAuditRoot, ok := changed.P2PTokenAuditHash()
	if !ok {
		t.Fatalf("changed P2P token audit root unavailable: %s", changed.P2PTokenAuditHashUnavailableReason())
	}
	if baseAuditRoot != changedAuditRoot {
		t.Fatalf("P2P token audit root must ignore uncommitted permanent metadata")
	}

	anchorChanged := base.Clone()
	anchorChanged.AnchorCounts[ownerID] = 999
	anchorChanged.AnchorCounts[tokenIndexTestBytes32(0x66)] = 123
	anchorTokenRoot, ok := anchorChanged.TokenIndexHash()
	if !ok {
		t.Fatalf("anchor-changed token root unavailable: %s", anchorChanged.TokenIndexHashUnavailableReason())
	}
	if baseTokenRoot == anchorTokenRoot {
		t.Fatalf("full token root must detect anchor-count differences")
	}
	anchorAuditRoot, ok := anchorChanged.P2PTokenAuditHash()
	if !ok {
		t.Fatalf("anchor-changed P2P token audit root unavailable: %s", anchorChanged.P2PTokenAuditHashUnavailableReason())
	}
	if baseAuditRoot != anchorAuditRoot {
		t.Fatalf("P2P token audit root must ignore token-index anchor counts")
	}

	committedChange := base.Clone()
	committedAsset := committedChange.Assets[assetID]
	committedAsset.TotalSupply = Uint128FromUint64(501)
	committedChange.Assets[assetID] = committedAsset
	committedAuditRoot, ok := committedChange.P2PTokenAuditHash()
	if !ok {
		t.Fatalf("committed-change P2P token audit root unavailable: %s", committedChange.P2PTokenAuditHashUnavailableReason())
	}
	if baseAuditRoot == committedAuditRoot {
		t.Fatalf("P2P token audit root must detect committed token state differences")
	}
}

func tokenIndexTestBytes32(value byte) [externalapi.DomainHashSize]byte {
	var out [externalapi.DomainHashSize]byte
	for i := range out {
		out[i] = value
	}
	return out
}

func tokenIndexSeqBytes32(start byte) [externalapi.DomainHashSize]byte {
	var out [externalapi.DomainHashSize]byte
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

func tokenIndexRepeatedBytes(value byte, length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = value
	}
	return out
}

func tokenIndexBytes32Ptr(value [externalapi.DomainHashSize]byte) *[externalapi.DomainHashSize]byte {
	return &value
}

func tokenIndexUint64Ptr(value uint64) *uint64 {
	return &value
}
