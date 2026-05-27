package atomicstate

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"golang.org/x/crypto/blake2b"
)

const (
	atomicTokenRootBuckets         = 4096
	atomicTokenLeafDomain          = "CRYPTIX_ATOMIC_V2_LEAF"
	atomicTokenBucketDomain        = "CRYPTIX_ATOMIC_V2_BUCKETED_ROOT"
	atomicTokenBucketIndexKey      = "CRYPTIX_ATOMIC_V2_BUCKET_INDEX"
	atomicTokenAssetRootV5         = "CAT_ASSET_ROOT_V5"
	atomicTokenP2PAuditAssetRootV1 = "CAT_ASSET_P2P_AUDIT_ROOT_V1"

	atomicTokenLogicalAsset       = byte(0x01)
	atomicTokenLogicalBalance     = byte(0x02)
	atomicTokenLogicalNonce       = byte(0x03)
	atomicTokenLogicalAnchorCount = byte(0x04)
)

type AssetPermanentMetadata struct {
	CreatorOwnerID       [externalapi.DomainHashSize]byte
	AssetClass           AssetClass
	TokenVersion         byte
	MintAuthorityOwnerID [externalapi.DomainHashSize]byte
	Decimals             byte
	SupplyMode           SupplyMode
	MaxSupply            Uint128
	Name                 []byte
	Symbol               []byte
	Metadata             []byte
	PlatformTag          []byte
	CreatedBlockHash     [externalapi.DomainHashSize]byte
	CreatedDAAScore      uint64
	CreatedAt            uint64
	HasLiquidity         bool
	Liquidity            AssetLiquidityPermanentMetadata
}

type AssetLiquidityPermanentMetadata struct {
	CurveVersion                        byte
	CurveMode                           byte
	IndividualVirtualCPayReservesSompi  uint64
	IndividualVirtualTokenMultiplierBPS uint16
	FeeBPS                              uint16
	FeeRecipients                       []LiquidityFeeRecipientPermanentMetadata
	UnlockTargetSompi                   uint64
}

type LiquidityFeeRecipientPermanentMetadata struct {
	OwnerID        [externalapi.DomainHashSize]byte
	AddressVersion byte
	AddressPayload []byte
}

func (s *State) TokenIndexHash() ([externalapi.DomainHashSize]byte, bool) {
	return s.TokenIndexHashWithAssetMetadata(nil)
}

func (s *State) TokenIndexHashWithAssetMetadata(metadata map[[externalapi.DomainHashSize]byte]AssetPermanentMetadata) ([externalapi.DomainHashSize]byte, bool) {
	if s.TokenIndexHashUnavailableReasonWithAssetMetadata(metadata) != "" {
		return [externalapi.DomainHashSize]byte{}, false
	}
	return s.tokenIndexHashWithAssetValue(metadata, tokenRootValueForAsset, true), true
}

func (s *State) P2PTokenAuditHash() ([externalapi.DomainHashSize]byte, bool) {
	if s.P2PTokenAuditHashUnavailableReason() != "" {
		return [externalapi.DomainHashSize]byte{}, false
	}
	return s.tokenIndexHashWithAssetValue(nil, tokenRootValueForP2PAuditAsset, false), true
}

func (s *State) tokenIndexHashWithAssetValue(
	metadata map[[externalapi.DomainHashSize]byte]AssetPermanentMetadata,
	assetValue func([externalapi.DomainHashSize]byte, AssetState) []byte,
	includeAnchorCounts bool) [externalapi.DomainHashSize]byte {

	var buckets [atomicTokenRootBuckets][externalapi.DomainHashSize]byte

	assetIDs := make([][externalapi.DomainHashSize]byte, 0, len(s.Assets))
	for assetID := range s.Assets {
		assetIDs = append(assetIDs, assetID)
	}
	sort.Slice(assetIDs, func(i, j int) bool { return compareBytes32(assetIDs[i], assetIDs[j]) < 0 })
	for _, assetID := range assetIDs {
		asset := assetWithPermanentMetadata(s.Assets[assetID], metadata[assetID])
		applyTokenRootLeaf(&buckets, logicalTokenAssetKey(assetID), assetValue(assetID, asset))
	}

	balanceKeys := make([]BalanceKey, 0, len(s.Balances))
	for key := range s.Balances {
		balanceKeys = append(balanceKeys, key)
	}
	sort.Slice(balanceKeys, func(i, j int) bool {
		if cmp := compareBytes32(balanceKeys[i].AssetID, balanceKeys[j].AssetID); cmp != 0 {
			return cmp < 0
		}
		return compareBytes32(balanceKeys[i].OwnerID, balanceKeys[j].OwnerID) < 0
	})
	for _, key := range balanceKeys {
		amount := s.Balances[key]
		if amount.IsZero() {
			continue
		}
		applyTokenRootLeaf(&buckets, logicalTokenBalanceKey(key), tokenRootValueForUint128(amount))
	}

	nonceKeys := make([]NonceKey, 0, len(s.NextNonces))
	for key := range s.NextNonces {
		nonceKeys = append(nonceKeys, key)
	}
	sort.Slice(nonceKeys, func(i, j int) bool { return compareNonceKeys(nonceKeys[i], nonceKeys[j]) < 0 })
	for _, key := range nonceKeys {
		nonce := s.NextNonces[key]
		if nonce == 1 {
			continue
		}
		applyTokenRootLeaf(&buckets, logicalTokenNonceKey(key), tokenRootValueForUint64(nonce))
	}

	if includeAnchorCounts {
		anchorOwners := make([][externalapi.DomainHashSize]byte, 0, len(s.AnchorCounts))
		for ownerID := range s.AnchorCounts {
			anchorOwners = append(anchorOwners, ownerID)
		}
		sort.Slice(anchorOwners, func(i, j int) bool { return compareBytes32(anchorOwners[i], anchorOwners[j]) < 0 })
		for _, ownerID := range anchorOwners {
			count := s.AnchorCounts[ownerID]
			if count == 0 {
				continue
			}
			applyTokenRootLeaf(&buckets, logicalTokenAnchorCountKey(ownerID), tokenRootValueForUint64(count))
		}
	}

	return tokenRootFromBuckets(&buckets)
}

func (s *State) TokenIndexHashUnavailableReason() string {
	return s.TokenIndexHashUnavailableReasonWithAssetMetadata(nil)
}

func (s *State) P2PTokenAuditHashUnavailableReason() string {
	if s == nil {
		return "state is nil"
	}
	if s.rootHashOverride != nil {
		return "state is root-only"
	}
	return ""
}

func (s *State) TokenIndexHashUnavailableReasonWithAssetMetadata(metadata map[[externalapi.DomainHashSize]byte]AssetPermanentMetadata) string {
	if s == nil {
		return "state is nil"
	}
	if s.rootHashOverride != nil {
		return "state is root-only"
	}
	for assetID, asset := range s.Assets {
		asset = assetWithPermanentMetadata(asset, metadata[assetID])
		missing := make([]string, 0, 3)
		if asset.CreatedBlockHash == nil {
			missing = append(missing, "created_block_hash")
		}
		if asset.CreatedDAAScore == nil {
			missing = append(missing, "created_daa_score")
		}
		if asset.CreatedAt == nil {
			missing = append(missing, "created_at")
		}
		if len(missing) != 0 {
			return fmt.Sprintf("asset %x has legacy/incomplete metadata: missing %s", assetID, strings.Join(missing, ","))
		}
	}
	return ""
}

func AssetsRequiringPermanentMetadata(s *State) [][externalapi.DomainHashSize]byte {
	if s == nil || s.rootHashOverride != nil {
		return nil
	}
	assetIDs := make([][externalapi.DomainHashSize]byte, 0)
	for assetID, asset := range s.Assets {
		if asset.CreatedBlockHash == nil || asset.CreatedDAAScore == nil || asset.CreatedAt == nil {
			assetIDs = append(assetIDs, assetID)
		}
	}
	sort.Slice(assetIDs, func(i, j int) bool { return compareBytes32(assetIDs[i], assetIDs[j]) < 0 })
	return assetIDs
}

func assetWithPermanentMetadata(asset AssetState, metadata AssetPermanentMetadata) AssetState {
	if metadata.CreatedBlockHash == [externalapi.DomainHashSize]byte{} && metadata.CreatedDAAScore == 0 && metadata.CreatedAt == 0 {
		return asset
	}
	out := asset.clone()
	out.CreatorOwnerID = metadata.CreatorOwnerID
	out.AssetClass = metadata.AssetClass
	out.TokenVersion = metadata.TokenVersion
	out.MintAuthorityOwnerID = metadata.MintAuthorityOwnerID
	out.Decimals = metadata.Decimals
	out.SupplyMode = metadata.SupplyMode
	out.MaxSupply = metadata.MaxSupply
	out.Name = append([]byte(nil), metadata.Name...)
	out.Symbol = append([]byte(nil), metadata.Symbol...)
	out.Metadata = append([]byte(nil), metadata.Metadata...)
	out.PlatformTag = append([]byte(nil), metadata.PlatformTag...)
	createdBlockHash := metadata.CreatedBlockHash
	createdDAAScore := metadata.CreatedDAAScore
	createdAt := metadata.CreatedAt
	out.CreatedBlockHash = &createdBlockHash
	out.CreatedDAAScore = &createdDAAScore
	out.CreatedAt = &createdAt
	if metadata.HasLiquidity && out.Liquidity != nil {
		out.Liquidity.CurveVersion = metadata.Liquidity.CurveVersion
		out.Liquidity.CurveMode = metadata.Liquidity.CurveMode
		out.Liquidity.IndividualVirtualCPayReservesSompi = metadata.Liquidity.IndividualVirtualCPayReservesSompi
		out.Liquidity.IndividualVirtualTokenMultiplierBPS = metadata.Liquidity.IndividualVirtualTokenMultiplierBPS
		out.Liquidity.FeeBPS = metadata.Liquidity.FeeBPS
		out.Liquidity.UnlockTargetSompi = metadata.Liquidity.UnlockTargetSompi
		if len(metadata.Liquidity.FeeRecipients) != 0 || len(out.Liquidity.FeeRecipients) != 0 {
			previous := out.Liquidity.FeeRecipients
			out.Liquidity.FeeRecipients = make([]LiquidityFeeRecipientState, len(metadata.Liquidity.FeeRecipients))
			for i, recipient := range metadata.Liquidity.FeeRecipients {
				var unclaimedSompi uint64
				if i < len(previous) {
					unclaimedSompi = previous[i].UnclaimedSompi
				}
				out.Liquidity.FeeRecipients[i] = LiquidityFeeRecipientState{
					OwnerID:        recipient.OwnerID,
					AddressVersion: recipient.AddressVersion,
					AddressPayload: append([]byte(nil), recipient.AddressPayload...),
					UnclaimedSompi: unclaimedSompi,
				}
			}
		}
	}
	return out
}

func AssetWithPermanentMetadata(asset AssetState, metadata AssetPermanentMetadata) AssetState {
	return assetWithPermanentMetadata(asset, metadata)
}

func DebugAssetPermanentMetadata(assetID [externalapi.DomainHashSize]byte, metadata AssetPermanentMetadata) string {
	asset := AssetState{
		CreatorOwnerID:       metadata.CreatorOwnerID,
		AssetClass:           metadata.AssetClass,
		TokenVersion:         metadata.TokenVersion,
		MintAuthorityOwnerID: metadata.MintAuthorityOwnerID,
		Decimals:             metadata.Decimals,
		SupplyMode:           metadata.SupplyMode,
		MaxSupply:            metadata.MaxSupply,
		Name:                 append([]byte(nil), metadata.Name...),
		Symbol:               append([]byte(nil), metadata.Symbol...),
		Metadata:             append([]byte(nil), metadata.Metadata...),
		PlatformTag:          append([]byte(nil), metadata.PlatformTag...),
	}
	createdBlockHash := metadata.CreatedBlockHash
	createdDAAScore := metadata.CreatedDAAScore
	createdAt := metadata.CreatedAt
	asset.CreatedBlockHash = &createdBlockHash
	asset.CreatedDAAScore = &createdDAAScore
	asset.CreatedAt = &createdAt
	if metadata.HasLiquidity {
		recipients := make([]LiquidityFeeRecipientState, len(metadata.Liquidity.FeeRecipients))
		for i, recipient := range metadata.Liquidity.FeeRecipients {
			recipients[i] = LiquidityFeeRecipientState{
				OwnerID:        recipient.OwnerID,
				AddressVersion: recipient.AddressVersion,
				AddressPayload: append([]byte(nil), recipient.AddressPayload...),
			}
		}
		asset.Liquidity = &LiquidityPoolState{
			CurveVersion:                        metadata.Liquidity.CurveVersion,
			CurveMode:                           metadata.Liquidity.CurveMode,
			IndividualVirtualCPayReservesSompi:  metadata.Liquidity.IndividualVirtualCPayReservesSompi,
			IndividualVirtualTokenMultiplierBPS: metadata.Liquidity.IndividualVirtualTokenMultiplierBPS,
			FeeBPS:                              metadata.Liquidity.FeeBPS,
			FeeRecipients:                       recipients,
			UnlockTargetSompi:                   metadata.Liquidity.UnlockTargetSompi,
		}
	}
	return DebugAssetState(assetID, asset)
}

func (s *State) TokenIndexDebugReport(metadata map[[externalapi.DomainHashSize]byte]AssetPermanentMetadata, maxEntries int) string {
	if s == nil {
		return "state=<nil>"
	}
	if maxEntries <= 0 {
		maxEntries = 16
	}
	var builder strings.Builder
	stateHash, ok := s.TokenIndexHashWithAssetMetadata(metadata)
	if ok {
		builder.WriteString(fmt.Sprintf("token_root=%x ", stateHash))
	} else {
		builder.WriteString(fmt.Sprintf("token_root=<unavailable:%s> ", s.TokenIndexHashUnavailableReasonWithAssetMetadata(metadata)))
	}
	builder.WriteString(fmt.Sprintf("assets=%d balances=%d nonces=%d anchor_counts=%d", len(s.Assets), len(s.Balances), len(s.NextNonces), len(s.AnchorCounts)))

	assetIDs := make([][externalapi.DomainHashSize]byte, 0, len(s.Assets))
	for assetID := range s.Assets {
		assetIDs = append(assetIDs, assetID)
	}
	sort.Slice(assetIDs, func(i, j int) bool { return compareBytes32(assetIDs[i], assetIDs[j]) < 0 })
	for i, assetID := range assetIDs {
		if i >= maxEntries {
			builder.WriteString(fmt.Sprintf("\nasset_more=%d", len(assetIDs)-i))
			break
		}
		asset := assetWithPermanentMetadata(s.Assets[assetID], metadata[assetID])
		key := logicalTokenAssetKey(assetID)
		value := tokenRootValueForAsset(assetID, asset)
		leaf := tokenRootLeafHash(key, value)
		builder.WriteString(fmt.Sprintf("\nasset[%d] bucket=%d leaf=%x %s", i, tokenRootBucketIndex(key), leaf, DebugAssetState(assetID, asset)))
	}

	balanceKeys := make([]BalanceKey, 0, len(s.Balances))
	for key, value := range s.Balances {
		if !value.IsZero() {
			balanceKeys = append(balanceKeys, key)
		}
	}
	sort.Slice(balanceKeys, func(i, j int) bool {
		if cmp := compareBytes32(balanceKeys[i].AssetID, balanceKeys[j].AssetID); cmp != 0 {
			return cmp < 0
		}
		return compareBytes32(balanceKeys[i].OwnerID, balanceKeys[j].OwnerID) < 0
	})
	for i, key := range balanceKeys {
		if i >= maxEntries {
			builder.WriteString(fmt.Sprintf("\nbalance_more=%d", len(balanceKeys)-i))
			break
		}
		logicalKey := logicalTokenBalanceKey(key)
		leaf := tokenRootLeafHash(logicalKey, tokenRootValueForUint128(s.Balances[key]))
		builder.WriteString(fmt.Sprintf("\nbalance[%d] bucket=%d leaf=%x asset=%x owner=%x amount=%s",
			i, tokenRootBucketIndex(logicalKey), leaf, key.AssetID, key.OwnerID, s.Balances[key].Big().String()))
	}

	nonceKeys := make([]NonceKey, 0, len(s.NextNonces))
	for key, value := range s.NextNonces {
		if value != 1 {
			nonceKeys = append(nonceKeys, key)
		}
	}
	sort.Slice(nonceKeys, func(i, j int) bool { return compareNonceKeys(nonceKeys[i], nonceKeys[j]) < 0 })
	for i, key := range nonceKeys {
		if i >= maxEntries {
			builder.WriteString(fmt.Sprintf("\nnonce_more=%d", len(nonceKeys)-i))
			break
		}
		logicalKey := logicalTokenNonceKey(key)
		leaf := tokenRootLeafHash(logicalKey, tokenRootValueForUint64(s.NextNonces[key]))
		builder.WriteString(fmt.Sprintf("\nnonce[%d] bucket=%d leaf=%x owner=%x scope=%d scope_id=%x value=%d",
			i, tokenRootBucketIndex(logicalKey), leaf, key.OwnerID, key.ScopeKind, key.ScopeID, s.NextNonces[key]))
	}

	anchorOwners := make([][externalapi.DomainHashSize]byte, 0, len(s.AnchorCounts))
	for ownerID, value := range s.AnchorCounts {
		if value != 0 {
			anchorOwners = append(anchorOwners, ownerID)
		}
	}
	sort.Slice(anchorOwners, func(i, j int) bool { return compareBytes32(anchorOwners[i], anchorOwners[j]) < 0 })
	for i, ownerID := range anchorOwners {
		if i >= maxEntries {
			builder.WriteString(fmt.Sprintf("\nanchor_more=%d", len(anchorOwners)-i))
			break
		}
		logicalKey := logicalTokenAnchorCountKey(ownerID)
		leaf := tokenRootLeafHash(logicalKey, tokenRootValueForUint64(s.AnchorCounts[ownerID]))
		builder.WriteString(fmt.Sprintf("\nanchor[%d] bucket=%d leaf=%x owner=%x count=%d",
			i, tokenRootBucketIndex(logicalKey), leaf, ownerID, s.AnchorCounts[ownerID]))
	}
	return builder.String()
}

func DebugAssetState(assetID [externalapi.DomainHashSize]byte, asset AssetState) string {
	out := fmt.Sprintf(
		"asset=%x class=%d token_version=%d creator=%x mint_authority=%x decimals=%d supply_mode=%d max_supply=%s total_supply=%s name_hex=%s symbol_hex=%s metadata_hex=%s platform_hex=%s created_block=%s created_daa=%s created_at=%s",
		assetID,
		asset.AssetClass,
		asset.TokenVersion,
		asset.CreatorOwnerID,
		asset.MintAuthorityOwnerID,
		asset.Decimals,
		asset.SupplyMode,
		asset.MaxSupply.Big().String(),
		asset.TotalSupply.Big().String(),
		hex.EncodeToString(asset.Name),
		hex.EncodeToString(asset.Symbol),
		hex.EncodeToString(asset.Metadata),
		hex.EncodeToString(asset.PlatformTag),
		debugOptionalHash(asset.CreatedBlockHash),
		debugOptionalUint64(asset.CreatedDAAScore),
		debugOptionalUint64(asset.CreatedAt),
	)
	if asset.Liquidity == nil {
		return out + " liquidity=<none>"
	}
	pool := asset.Liquidity
	out += fmt.Sprintf(
		" liquidity={pool_nonce=%d curve_version=%d curve_mode=%d iv_cpay=%d iv_token_bps=%d real_cpay=%d real_token=%s virtual_cpay=%d virtual_token=%s unclaimed_fee_total=%d fee_bps=%d vault_outpoint=%s vault_value=%d unlock_target=%d unlocked=%t recipients=%d",
		pool.PoolNonce,
		pool.CurveVersion,
		pool.CurveMode,
		pool.IndividualVirtualCPayReservesSompi,
		pool.IndividualVirtualTokenMultiplierBPS,
		pool.RealCPayReservesSompi,
		pool.RealTokenReserves.Big().String(),
		pool.VirtualCPayReserves,
		pool.VirtualTokenReserves.Big().String(),
		pool.UnclaimedFeeTotalSompi,
		pool.FeeBPS,
		pool.VaultOutpoint.String(),
		pool.VaultValueSompi,
		pool.UnlockTargetSompi,
		pool.Unlocked,
		len(pool.FeeRecipients),
	)
	for i, recipient := range pool.FeeRecipients {
		out += fmt.Sprintf(" recipient[%d]={owner=%x version=%d payload_hex=%s unclaimed=%d}",
			i, recipient.OwnerID, recipient.AddressVersion, hex.EncodeToString(recipient.AddressPayload), recipient.UnclaimedSompi)
	}
	return out + "}"
}

func debugOptionalHash(value *[externalapi.DomainHashSize]byte) string {
	if value == nil {
		return "<nil>"
	}
	return hex.EncodeToString(value[:])
}

func debugOptionalUint64(value *uint64) string {
	if value == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%d", *value)
}

func compareBytes32(left, right [externalapi.DomainHashSize]byte) int {
	for i := 0; i < externalapi.DomainHashSize; i++ {
		if left[i] < right[i] {
			return -1
		}
		if left[i] > right[i] {
			return 1
		}
	}
	return 0
}

func logicalTokenAssetKey(assetID [externalapi.DomainHashSize]byte) []byte {
	out := make([]byte, 1+externalapi.DomainHashSize)
	out[0] = atomicTokenLogicalAsset
	copy(out[1:], assetID[:])
	return out
}

func logicalTokenBalanceKey(key BalanceKey) []byte {
	out := make([]byte, 1+externalapi.DomainHashSize*2)
	out[0] = atomicTokenLogicalBalance
	copy(out[1:], key.AssetID[:])
	copy(out[1+externalapi.DomainHashSize:], key.OwnerID[:])
	return out
}

func logicalTokenNonceKey(key NonceKey) []byte {
	out := make([]byte, 1+externalapi.DomainHashSize+1+externalapi.DomainHashSize)
	out[0] = atomicTokenLogicalNonce
	copy(out[1:], key.OwnerID[:])
	out[1+externalapi.DomainHashSize] = byte(key.ScopeKind)
	copy(out[1+externalapi.DomainHashSize+1:], key.ScopeID[:])
	return out
}

func logicalTokenAnchorCountKey(ownerID [externalapi.DomainHashSize]byte) []byte {
	out := make([]byte, 1+externalapi.DomainHashSize)
	out[0] = atomicTokenLogicalAnchorCount
	copy(out[1:], ownerID[:])
	return out
}

func applyTokenRootLeaf(buckets *[atomicTokenRootBuckets][externalapi.DomainHashSize]byte, logicalKey []byte, value []byte) {
	leafHash := tokenRootLeafHash(logicalKey, value)
	bucketIndex := tokenRootBucketIndex(logicalKey)
	xorHash(buckets[bucketIndex][:], leafHash[:])
}

func tokenRootValueForUint64(value uint64) []byte {
	var out [8]byte
	binary.LittleEndian.PutUint64(out[:], value)
	return out[:]
}

func tokenRootValueForUint128(value Uint128) []byte {
	out := value.ToLE()
	return out[:]
}

func tokenRootValueForAsset(assetID [externalapi.DomainHashSize]byte, asset AssetState) []byte {
	out := make([]byte, 0, 256+len(asset.Name)+len(asset.Symbol)+len(asset.Metadata)+len(asset.PlatformTag))
	out = append(out, atomicTokenAssetRootV5...)
	out = append(out, assetID[:]...)
	out = append(out, asset.CreatorOwnerID[:]...)
	out = append(out, byte(asset.AssetClass))
	out = append(out, asset.TokenVersion)
	out = append(out, asset.MintAuthorityOwnerID[:]...)
	out = append(out, asset.Decimals)
	out = append(out, byte(asset.SupplyMode))
	out = append(out, tokenRootValueForUint128(asset.MaxSupply)...)
	out = append(out, tokenRootValueForUint128(asset.TotalSupply)...)
	pushTokenRootBytes(&out, asset.Name)
	pushTokenRootBytes(&out, asset.Symbol)
	pushTokenRootBytes(&out, asset.Metadata)
	pushTokenRootBytes(&out, asset.PlatformTag)
	pushTokenRootOptionalHash(&out, asset.CreatedBlockHash)
	pushTokenRootOptionalUint64(&out, asset.CreatedDAAScore)
	pushTokenRootOptionalUint64(&out, asset.CreatedAt)
	if asset.Liquidity == nil {
		out = append(out, 0)
		return out
	}
	out = append(out, 1)
	pool := asset.Liquidity
	out = append(out, tokenRootValueForUint64(pool.PoolNonce)...)
	out = append(out, pool.CurveVersion)
	out = append(out, pool.CurveMode)
	out = append(out, tokenRootValueForUint64(pool.IndividualVirtualCPayReservesSompi)...)
	out = append(out, tokenRootValueForUint16(pool.IndividualVirtualTokenMultiplierBPS)...)
	out = append(out, tokenRootValueForUint64(pool.RealCPayReservesSompi)...)
	out = append(out, tokenRootValueForUint128(pool.RealTokenReserves)...)
	out = append(out, tokenRootValueForUint64(pool.VirtualCPayReserves)...)
	out = append(out, tokenRootValueForUint128(pool.VirtualTokenReserves)...)
	out = append(out, tokenRootValueForUint64(pool.UnclaimedFeeTotalSompi)...)
	out = append(out, tokenRootValueForUint16(pool.FeeBPS)...)
	out = append(out, tokenRootValueForUint64(uint64(len(pool.FeeRecipients)))...)
	for _, recipient := range pool.FeeRecipients {
		out = append(out, recipient.OwnerID[:]...)
		out = append(out, recipient.AddressVersion)
		pushTokenRootBytes(&out, recipient.AddressPayload)
		out = append(out, tokenRootValueForUint64(recipient.UnclaimedSompi)...)
	}
	out = append(out, pool.VaultOutpoint.TransactionID.ByteSlice()...)
	out = append(out, tokenRootValueForUint32(pool.VaultOutpoint.Index)...)
	out = append(out, tokenRootValueForUint64(pool.VaultValueSompi)...)
	out = append(out, tokenRootValueForUint64(pool.UnlockTargetSompi)...)
	if pool.Unlocked {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	return out
}

func tokenRootValueForP2PAuditAsset(assetID [externalapi.DomainHashSize]byte, asset AssetState) []byte {
	out := make([]byte, 0, 192+len(asset.PlatformTag))
	out = append(out, atomicTokenP2PAuditAssetRootV1...)
	out = append(out, assetID[:]...)
	out = append(out, byte(asset.AssetClass))
	out = append(out, asset.TokenVersion)
	out = append(out, asset.MintAuthorityOwnerID[:]...)
	out = append(out, byte(asset.SupplyMode))
	out = append(out, tokenRootValueForUint128(asset.MaxSupply)...)
	out = append(out, tokenRootValueForUint128(asset.TotalSupply)...)
	pushTokenRootBytes(&out, asset.PlatformTag)
	if asset.Liquidity == nil {
		out = append(out, 0)
		return out
	}
	out = append(out, 1)
	appendTokenRootLiquidity(&out, asset.Liquidity)
	return out
}

func appendTokenRootLiquidity(out *[]byte, pool *LiquidityPoolState) {
	*out = append(*out, tokenRootValueForUint64(pool.PoolNonce)...)
	*out = append(*out, pool.CurveVersion)
	*out = append(*out, pool.CurveMode)
	*out = append(*out, tokenRootValueForUint64(pool.IndividualVirtualCPayReservesSompi)...)
	*out = append(*out, tokenRootValueForUint16(pool.IndividualVirtualTokenMultiplierBPS)...)
	*out = append(*out, tokenRootValueForUint64(pool.RealCPayReservesSompi)...)
	*out = append(*out, tokenRootValueForUint128(pool.RealTokenReserves)...)
	*out = append(*out, tokenRootValueForUint64(pool.VirtualCPayReserves)...)
	*out = append(*out, tokenRootValueForUint128(pool.VirtualTokenReserves)...)
	*out = append(*out, tokenRootValueForUint64(pool.UnclaimedFeeTotalSompi)...)
	*out = append(*out, tokenRootValueForUint16(pool.FeeBPS)...)
	*out = append(*out, tokenRootValueForUint64(uint64(len(pool.FeeRecipients)))...)
	for _, recipient := range pool.FeeRecipients {
		*out = append(*out, recipient.OwnerID[:]...)
		*out = append(*out, recipient.AddressVersion)
		pushTokenRootBytes(out, recipient.AddressPayload)
		*out = append(*out, tokenRootValueForUint64(recipient.UnclaimedSompi)...)
	}
	*out = append(*out, pool.VaultOutpoint.TransactionID.ByteSlice()...)
	*out = append(*out, tokenRootValueForUint32(pool.VaultOutpoint.Index)...)
	*out = append(*out, tokenRootValueForUint64(pool.VaultValueSompi)...)
	*out = append(*out, tokenRootValueForUint64(pool.UnlockTargetSompi)...)
	if pool.Unlocked {
		*out = append(*out, 1)
	} else {
		*out = append(*out, 0)
	}
}

func tokenRootValueForUint16(value uint16) []byte {
	var out [2]byte
	binary.LittleEndian.PutUint16(out[:], value)
	return out[:]
}

func tokenRootValueForUint32(value uint32) []byte {
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], value)
	return out[:]
}

func pushTokenRootBytes(out *[]byte, value []byte) {
	*out = append(*out, tokenRootValueForUint64(uint64(len(value)))...)
	*out = append(*out, value...)
}

func pushTokenRootOptionalHash(out *[]byte, value *[externalapi.DomainHashSize]byte) {
	if value == nil {
		*out = append(*out, 0)
		return
	}
	*out = append(*out, 1)
	*out = append(*out, value[:]...)
}

func pushTokenRootOptionalUint64(out *[]byte, value *uint64) {
	if value == nil {
		*out = append(*out, 0)
		return
	}
	*out = append(*out, 1)
	*out = append(*out, tokenRootValueForUint64(*value)...)
}

func tokenRootLeafHash(logicalKey []byte, value []byte) [externalapi.DomainHashSize]byte {
	hasher, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	_, _ = hasher.Write([]byte(atomicTokenLeafDomain))
	_, _ = hasher.Write(tokenRootValueForUint64(uint64(len(logicalKey))))
	_, _ = hasher.Write(logicalKey)
	_, _ = hasher.Write(tokenRootValueForUint64(uint64(len(value))))
	_, _ = hasher.Write(value)
	return finalizeAtomicHash(hasher)
}

func tokenRootBucketIndex(logicalKey []byte) int {
	hasher, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	_, _ = hasher.Write([]byte(atomicTokenBucketIndexKey))
	_, _ = hasher.Write(logicalKey)
	digest := hasher.Sum(nil)
	return (((int(digest[0])) << 4) | (int(digest[1]) >> 4)) & (atomicTokenRootBuckets - 1)
}

func tokenRootFromBuckets(buckets *[atomicTokenRootBuckets][externalapi.DomainHashSize]byte) [externalapi.DomainHashSize]byte {
	hasher, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	_, _ = hasher.Write([]byte(atomicTokenBucketDomain))
	_, _ = hasher.Write(tokenRootValueForUint64(atomicTokenRootBuckets))
	for i := range buckets {
		_, _ = hasher.Write(buckets[i][:])
	}
	return finalizeAtomicHash(hasher)
}
