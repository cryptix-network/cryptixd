package atomicstate

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"unicode/utf8"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"golang.org/x/crypto/blake2b"
)

var (
	atomicConsensusStateMagic      = []byte("CATCSG02")
	atomicConsensusStateHashDomain = []byte("cryptix-atomic-consensus-state-root-v2")
	atomicStateCommitmentDomain    = []byte("cryptix-utxo-atomic-state-commitment-v1")
)

const (
	currentStateTokenVersion          = byte(1)
	currentStateLiquidityCurveVersion = byte(1)
	maxStateTokenVersion              = byte(99)
	maxStateLiquidityCurveVersion     = byte(99)
	atomicConsensusRootVersion        = byte(2)
	atomicRootNamespaceNonce          = byte('n')
	atomicRootNamespaceAsset          = byte('a')
	atomicRootNamespaceBalance        = byte('b')
	atomicRootNamespaceAnchor         = byte('c')
)

type BalanceKey struct {
	AssetID [externalapi.DomainHashSize]byte
	OwnerID [externalapi.DomainHashSize]byte
}

type NonceScopeKind byte

const (
	NonceScopeOwner NonceScopeKind = iota
	NonceScopeAsset
)

type NonceKey struct {
	OwnerID   [externalapi.DomainHashSize]byte
	ScopeKind NonceScopeKind
	ScopeID   [externalapi.DomainHashSize]byte
}

func OwnerNonceKey(ownerID [externalapi.DomainHashSize]byte) NonceKey {
	return NonceKey{OwnerID: ownerID, ScopeKind: NonceScopeOwner}
}

func AssetNonceKey(ownerID [externalapi.DomainHashSize]byte, assetID [externalapi.DomainHashSize]byte) NonceKey {
	return NonceKey{OwnerID: ownerID, ScopeKind: NonceScopeAsset, ScopeID: assetID}
}

func (key NonceKey) validate() error {
	switch key.ScopeKind {
	case NonceScopeOwner:
		if key.ScopeID == ([externalapi.DomainHashSize]byte{}) {
			return nil
		}
		return fmt.Errorf("owner nonce scope for owner `%x` has non-zero scope id `%x`", key.OwnerID, key.ScopeID)
	case NonceScopeAsset:
		if key.ScopeID != ([externalapi.DomainHashSize]byte{}) {
			return nil
		}
		return fmt.Errorf("asset nonce scope for owner `%x` has zero asset id", key.OwnerID)
	default:
		return fmt.Errorf("atomic nonce for owner `%x` has invalid scope kind `%d`", key.OwnerID, key.ScopeKind)
	}
}

type SupplyMode byte

const (
	SupplyModeUncapped SupplyMode = iota
	SupplyModeCapped
)

type AssetClass byte

const (
	AssetClassStandard AssetClass = iota
	AssetClassLiquidity
)

type LiquidityFeeRecipientState struct {
	OwnerID        [externalapi.DomainHashSize]byte
	AddressVersion byte
	AddressPayload []byte
	UnclaimedSompi uint64
}

type LiquidityPoolState struct {
	PoolNonce                           uint64
	CurveVersion                        byte
	CurveMode                           byte
	IndividualVirtualCPayReservesSompi  uint64
	IndividualVirtualTokenMultiplierBPS uint16
	RealCPayReservesSompi               uint64
	RealTokenReserves                   Uint128
	VirtualCPayReserves                 uint64
	VirtualTokenReserves                Uint128
	UnclaimedFeeTotalSompi              uint64
	FeeBPS                              uint16
	FeeRecipients                       []LiquidityFeeRecipientState
	VaultOutpoint                       externalapi.DomainOutpoint
	VaultValueSompi                     uint64
	UnlockTargetSompi                   uint64
	Unlocked                            bool
}

type AssetState struct {
	AssetClass           AssetClass
	TokenVersion         byte
	MintAuthorityOwnerID [externalapi.DomainHashSize]byte
	SupplyMode           SupplyMode
	MaxSupply            Uint128
	TotalSupply          Uint128
	PlatformTag          []byte
	Liquidity            *LiquidityPoolState
}

type State struct {
	NextNonces              map[NonceKey]uint64
	Assets                  map[[externalapi.DomainHashSize]byte]AssetState
	Balances                map[BalanceKey]Uint128
	AnchorCounts            map[[externalapi.DomainHashSize]byte]uint64
	LiquidityVaultOutpoints map[externalapi.DomainOutpoint][externalapi.DomainHashSize]byte
	rootHashOverride        *[externalapi.DomainHashSize]byte
}

type rootNamespaceAccumulator struct {
	count uint64
	xor   [externalapi.DomainHashSize]byte
}

type rootAccumulator struct {
	version byte
	nonce   rootNamespaceAccumulator
	asset   rootNamespaceAccumulator
	balance rootNamespaceAccumulator
	anchor  rootNamespaceAccumulator
}

func NewState() *State {
	return &State{
		NextNonces:              make(map[NonceKey]uint64),
		Assets:                  make(map[[externalapi.DomainHashSize]byte]AssetState),
		Balances:                make(map[BalanceKey]Uint128),
		AnchorCounts:            make(map[[externalapi.DomainHashSize]byte]uint64),
		LiquidityVaultOutpoints: make(map[externalapi.DomainOutpoint][externalapi.DomainHashSize]byte),
	}
}

func NewRootOnlyState(stateHash [externalapi.DomainHashSize]byte) *State {
	state := NewState()
	state.rootHashOverride = &stateHash
	return state
}

func (s *State) IsRootOnly() bool {
	return s != nil && s.rootHashOverride != nil
}

func (s *State) Clone() *State {
	if s == nil {
		return NewState()
	}
	clone := NewState()
	for key, value := range s.NextNonces {
		clone.NextNonces[key] = value
	}
	for key, value := range s.Assets {
		clone.Assets[key] = value.clone()
	}
	for key, value := range s.Balances {
		clone.Balances[key] = value
	}
	for key, value := range s.AnchorCounts {
		clone.AnchorCounts[key] = value
	}
	for key, value := range s.LiquidityVaultOutpoints {
		clone.LiquidityVaultOutpoints[key] = value
	}
	if s.rootHashOverride != nil {
		rootHash := *s.rootHashOverride
		clone.rootHashOverride = &rootHash
	}
	return clone
}

func (a AssetState) clone() AssetState {
	out := a
	out.PlatformTag = append([]byte(nil), a.PlatformTag...)
	if a.Liquidity != nil {
		pool := *a.Liquidity
		pool.FeeRecipients = make([]LiquidityFeeRecipientState, len(a.Liquidity.FeeRecipients))
		for i, recipient := range a.Liquidity.FeeRecipients {
			pool.FeeRecipients[i] = recipient.clone()
		}
		out.Liquidity = &pool
	}
	return out
}

func (r LiquidityFeeRecipientState) clone() LiquidityFeeRecipientState {
	out := r
	out.AddressPayload = append([]byte(nil), r.AddressPayload...)
	return out
}

func (s *State) RebuildLiquidityVaultOutpointIndex() {
	s.LiquidityVaultOutpoints = make(map[externalapi.DomainOutpoint][externalapi.DomainHashSize]byte)
	for assetID, asset := range s.Assets {
		if asset.AssetClass != AssetClassLiquidity || asset.Liquidity == nil {
			continue
		}
		s.LiquidityVaultOutpoints[asset.Liquidity.VaultOutpoint] = assetID
	}
}

func (s *State) CanonicalBytes() []byte {
	if s.rootHashOverride != nil {
		out := make([]byte, 0, len(atomicConsensusStateMagic)+4+externalapi.DomainHashSize)
		out = append(out, atomicConsensusStateMagic...)
		out = append(out, 'R', 'O', 'O', 'T')
		out = append(out, (*s.rootHashOverride)[:]...)
		return out
	}

	out := make([]byte, 0)
	out = append(out, atomicConsensusStateMagic...)

	nonceKeys := make([]NonceKey, 0, len(s.NextNonces))
	for key := range s.NextNonces {
		nonceKeys = append(nonceKeys, key)
	}
	sort.Slice(nonceKeys, func(i, j int) bool { return compareNonceKeys(nonceKeys[i], nonceKeys[j]) < 0 })
	writeLen(&out, len(nonceKeys))
	for _, key := range nonceKeys {
		out = append(out, key.OwnerID[:]...)
		out = append(out, byte(key.ScopeKind))
		out = append(out, key.ScopeID[:]...)
		writeUint64(&out, s.NextNonces[key])
	}

	assetKeys := make([][externalapi.DomainHashSize]byte, 0, len(s.Assets))
	for assetID := range s.Assets {
		assetKeys = append(assetKeys, assetID)
	}
	sort.Slice(assetKeys, func(i, j int) bool { return bytes.Compare(assetKeys[i][:], assetKeys[j][:]) < 0 })
	writeLen(&out, len(assetKeys))
	for _, assetID := range assetKeys {
		out = append(out, assetID[:]...)
		writeAsset(&out, s.Assets[assetID])
	}

	balanceKeys := make([]BalanceKey, 0, len(s.Balances))
	for key := range s.Balances {
		balanceKeys = append(balanceKeys, key)
	}
	sort.Slice(balanceKeys, func(i, j int) bool {
		if cmp := bytes.Compare(balanceKeys[i].AssetID[:], balanceKeys[j].AssetID[:]); cmp != 0 {
			return cmp < 0
		}
		return bytes.Compare(balanceKeys[i].OwnerID[:], balanceKeys[j].OwnerID[:]) < 0
	})
	writeLen(&out, len(balanceKeys))
	for _, key := range balanceKeys {
		out = append(out, key.AssetID[:]...)
		out = append(out, key.OwnerID[:]...)
		writeUint128(&out, s.Balances[key])
	}

	anchorKeys := make([][externalapi.DomainHashSize]byte, 0, len(s.AnchorCounts))
	for ownerID := range s.AnchorCounts {
		anchorKeys = append(anchorKeys, ownerID)
	}
	sort.Slice(anchorKeys, func(i, j int) bool { return bytes.Compare(anchorKeys[i][:], anchorKeys[j][:]) < 0 })
	writeLen(&out, len(anchorKeys))
	for _, ownerID := range anchorKeys {
		out = append(out, ownerID[:]...)
		writeUint64(&out, s.AnchorCounts[ownerID])
	}

	return out
}

func compareNonceKeys(left, right NonceKey) int {
	if cmp := bytes.Compare(left.OwnerID[:], right.OwnerID[:]); cmp != 0 {
		return cmp
	}
	if left.ScopeKind < right.ScopeKind {
		return -1
	}
	if left.ScopeKind > right.ScopeKind {
		return 1
	}
	return bytes.Compare(left.ScopeID[:], right.ScopeID[:])
}

func rootAccumulatorFromState(state *State) rootAccumulator {
	root := rootAccumulator{version: atomicConsensusRootVersion}
	if state == nil {
		return root
	}
	for key, value := range state.NextNonces {
		root.applyNonce(key, 0, false, value, true)
	}
	for assetID, asset := range state.Assets {
		root.applyAsset(assetID, nil, false, &asset, true)
	}
	for key, value := range state.Balances {
		root.applyBalance(key, Uint128{}, false, value, true)
	}
	for ownerID, value := range state.AnchorCounts {
		root.applyAnchor(ownerID, 0, false, value, true)
	}
	return root
}

func (r *rootAccumulator) applyNonce(key NonceKey, oldValue uint64, oldOK bool, newValue uint64, newOK bool) {
	var oldHash, newHash [externalapi.DomainHashSize]byte
	if oldOK {
		oldHash = hashNonceEntry(key, oldValue)
	}
	if newOK {
		newHash = hashNonceEntry(key, newValue)
	}
	r.applyEntry(atomicRootNamespaceNonce, oldHash, oldOK, newHash, newOK)
}

func (r *rootAccumulator) applyAsset(assetID [externalapi.DomainHashSize]byte, oldValue *AssetState, oldOK bool, newValue *AssetState, newOK bool) {
	var oldHash, newHash [externalapi.DomainHashSize]byte
	if oldOK {
		oldHash = hashAssetEntry(assetID, *oldValue)
	}
	if newOK {
		newHash = hashAssetEntry(assetID, *newValue)
	}
	r.applyEntry(atomicRootNamespaceAsset, oldHash, oldOK, newHash, newOK)
}

func (r *rootAccumulator) applyBalance(key BalanceKey, oldValue Uint128, oldOK bool, newValue Uint128, newOK bool) {
	var oldHash, newHash [externalapi.DomainHashSize]byte
	if oldOK {
		oldHash = hashBalanceEntry(key, oldValue)
	}
	if newOK {
		newHash = hashBalanceEntry(key, newValue)
	}
	r.applyEntry(atomicRootNamespaceBalance, oldHash, oldOK, newHash, newOK)
}

func (r *rootAccumulator) applyAnchor(ownerID [externalapi.DomainHashSize]byte, oldValue uint64, oldOK bool, newValue uint64, newOK bool) {
	var oldHash, newHash [externalapi.DomainHashSize]byte
	if oldOK {
		oldHash = hashAnchorEntry(ownerID, oldValue)
	}
	if newOK {
		newHash = hashAnchorEntry(ownerID, newValue)
	}
	r.applyEntry(atomicRootNamespaceAnchor, oldHash, oldOK, newHash, newOK)
}

func (r *rootAccumulator) applyEntry(namespace byte, oldHash [externalapi.DomainHashSize]byte, oldOK bool, newHash [externalapi.DomainHashSize]byte, newOK bool) {
	if oldOK && newOK && oldHash == newHash {
		return
	}
	acc := r.namespace(namespace)
	if oldOK {
		acc.count--
		xorHash(acc.xor[:], oldHash[:])
	}
	if newOK {
		acc.count++
		xorHash(acc.xor[:], newHash[:])
	}
}

func (r *rootAccumulator) namespace(namespace byte) *rootNamespaceAccumulator {
	switch namespace {
	case atomicRootNamespaceNonce:
		return &r.nonce
	case atomicRootNamespaceAsset:
		return &r.asset
	case atomicRootNamespaceBalance:
		return &r.balance
	case atomicRootNamespaceAnchor:
		return &r.anchor
	default:
		panic("unknown atomic root namespace")
	}
}

func (r rootAccumulator) Hash() [externalapi.DomainHashSize]byte {
	hasher := newAtomicRootHasher()
	hashByte(hasher, r.version)

	hashByte(hasher, atomicRootNamespaceNonce)
	hashUint64ToHasher(hasher, r.nonce.count)
	_, _ = hasher.Write(r.nonce.xor[:])

	hashByte(hasher, atomicRootNamespaceAsset)
	hashUint64ToHasher(hasher, r.asset.count)
	_, _ = hasher.Write(r.asset.xor[:])

	hashByte(hasher, atomicRootNamespaceBalance)
	hashUint64ToHasher(hasher, r.balance.count)
	_, _ = hasher.Write(r.balance.xor[:])

	hashByte(hasher, atomicRootNamespaceAnchor)
	hashUint64ToHasher(hasher, r.anchor.count)
	_, _ = hasher.Write(r.anchor.xor[:])

	var out [externalapi.DomainHashSize]byte
	copy(out[:], hasher.Sum(nil))
	return out
}

func hashNonceEntry(key NonceKey, nonce uint64) [externalapi.DomainHashSize]byte {
	hasher := newAtomicEntryHasher(atomicRootNamespaceNonce)
	_, _ = hasher.Write(key.OwnerID[:])
	hashByte(hasher, byte(key.ScopeKind))
	_, _ = hasher.Write(key.ScopeID[:])
	hashUint64ToHasher(hasher, nonce)
	return finalizeAtomicHash(hasher)
}

func hashAssetEntry(assetID [externalapi.DomainHashSize]byte, asset AssetState) [externalapi.DomainHashSize]byte {
	hasher := newAtomicEntryHasher(atomicRootNamespaceAsset)
	_, _ = hasher.Write(assetID[:])
	hashAssetToHasher(hasher, asset)
	return finalizeAtomicHash(hasher)
}

func hashBalanceEntry(key BalanceKey, amount Uint128) [externalapi.DomainHashSize]byte {
	hasher := newAtomicEntryHasher(atomicRootNamespaceBalance)
	_, _ = hasher.Write(key.AssetID[:])
	_, _ = hasher.Write(key.OwnerID[:])
	hashUint128ToHasher(hasher, amount)
	return finalizeAtomicHash(hasher)
}

func hashAnchorEntry(ownerID [externalapi.DomainHashSize]byte, count uint64) [externalapi.DomainHashSize]byte {
	hasher := newAtomicEntryHasher(atomicRootNamespaceAnchor)
	_, _ = hasher.Write(ownerID[:])
	hashUint64ToHasher(hasher, count)
	return finalizeAtomicHash(hasher)
}

func newAtomicRootHasher() hashWriter {
	hasher, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	_, _ = hasher.Write(atomicConsensusStateHashDomain)
	return hasher
}

func newAtomicEntryHasher(namespace byte) hashWriter {
	hasher := newAtomicRootHasher()
	hashByte(hasher, namespace)
	return hasher
}

type hashWriter interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func finalizeAtomicHash(hasher hashWriter) [externalapi.DomainHashSize]byte {
	var out [externalapi.DomainHashSize]byte
	copy(out[:], hasher.Sum(nil))
	return out
}

func hashAssetToHasher(hasher hashWriter, asset AssetState) {
	hashByte(hasher, byte(asset.AssetClass))
	hashByte(hasher, asset.TokenVersion)
	_, _ = hasher.Write(asset.MintAuthorityOwnerID[:])
	hashByte(hasher, byte(asset.SupplyMode))
	hashUint128ToHasher(hasher, asset.MaxSupply)
	hashUint128ToHasher(hasher, asset.TotalSupply)
	hashLenToHasher(hasher, len(asset.PlatformTag))
	_, _ = hasher.Write(asset.PlatformTag)
	if asset.Liquidity == nil {
		hashByte(hasher, 0)
		return
	}
	hashByte(hasher, 1)
	hashLiquidityPoolToHasher(hasher, *asset.Liquidity)
}

func hashLiquidityPoolToHasher(hasher hashWriter, pool LiquidityPoolState) {
	hashUint64ToHasher(hasher, pool.PoolNonce)
	hashByte(hasher, pool.CurveVersion)
	hashByte(hasher, pool.CurveMode)
	hashUint64ToHasher(hasher, pool.IndividualVirtualCPayReservesSompi)
	hashUint16ToHasher(hasher, pool.IndividualVirtualTokenMultiplierBPS)
	hashUint64ToHasher(hasher, pool.RealCPayReservesSompi)
	hashUint128ToHasher(hasher, pool.RealTokenReserves)
	hashUint64ToHasher(hasher, pool.VirtualCPayReserves)
	hashUint128ToHasher(hasher, pool.VirtualTokenReserves)
	hashUint64ToHasher(hasher, pool.UnclaimedFeeTotalSompi)
	hashUint16ToHasher(hasher, pool.FeeBPS)
	hashLenToHasher(hasher, len(pool.FeeRecipients))
	for _, recipient := range pool.FeeRecipients {
		_, _ = hasher.Write(recipient.OwnerID[:])
		hashByte(hasher, recipient.AddressVersion)
		hashLenToHasher(hasher, len(recipient.AddressPayload))
		_, _ = hasher.Write(recipient.AddressPayload)
		hashUint64ToHasher(hasher, recipient.UnclaimedSompi)
	}
	_, _ = hasher.Write(pool.VaultOutpoint.TransactionID.ByteSlice())
	hashUint32ToHasher(hasher, pool.VaultOutpoint.Index)
	hashUint64ToHasher(hasher, pool.VaultValueSompi)
	hashUint64ToHasher(hasher, pool.UnlockTargetSompi)
	if pool.Unlocked {
		hashByte(hasher, 1)
	} else {
		hashByte(hasher, 0)
	}
}

func hashByte(hasher hashWriter, value byte) {
	_, _ = hasher.Write([]byte{value})
}

func hashLenToHasher(hasher hashWriter, length int) {
	hashUint64ToHasher(hasher, uint64(length))
}

func hashUint16ToHasher(hasher hashWriter, value uint16) {
	var bytes [2]byte
	binary.LittleEndian.PutUint16(bytes[:], value)
	_, _ = hasher.Write(bytes[:])
}

func hashUint32ToHasher(hasher hashWriter, value uint32) {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], value)
	_, _ = hasher.Write(bytes[:])
}

func hashUint64ToHasher(hasher hashWriter, value uint64) {
	var bytes [8]byte
	binary.LittleEndian.PutUint64(bytes[:], value)
	_, _ = hasher.Write(bytes[:])
}

func hashUint128ToHasher(hasher hashWriter, value Uint128) {
	bytes := value.ToLE()
	_, _ = hasher.Write(bytes[:])
}

func xorHash(target []byte, value []byte) {
	for i := range target {
		target[i] ^= value[i]
	}
}

func (s *State) CanonicalHash() [externalapi.DomainHashSize]byte {
	if s != nil && s.rootHashOverride != nil {
		return *s.rootHashOverride
	}
	return rootAccumulatorFromState(s).Hash()
}

func HashCanonicalBytes(stateBytes []byte) [externalapi.DomainHashSize]byte {
	state, err := FromCanonicalBytes(stateBytes)
	if err != nil {
		panic(err)
	}
	return state.CanonicalHash()
}

func HeaderCommitment(utxoCommitment *externalapi.DomainHash, atomicStateHash [externalapi.DomainHashSize]byte, payloadHFActive bool) *externalapi.DomainHash {
	if !payloadHFActive {
		return utxoCommitment
	}
	hasher, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	_, _ = hasher.Write(atomicStateCommitmentDomain)
	_, _ = hasher.Write(utxoCommitment.ByteSlice())
	_, _ = hasher.Write(atomicStateHash[:])
	var out [externalapi.DomainHashSize]byte
	copy(out[:], hasher.Sum(nil))
	return externalapi.NewDomainHashFromByteArray(&out)
}

func (s *State) HeaderCommitment(utxoCommitment *externalapi.DomainHash, payloadHFActive bool) *externalapi.DomainHash {
	return HeaderCommitment(utxoCommitment, s.CanonicalHash(), payloadHFActive)
}

func FromCanonicalBytes(stateBytes []byte) (*State, error) {
	reader := atomicStateReader{bytes: stateBytes}
	magic, err := reader.readBytes(len(atomicConsensusStateMagic))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(magic, atomicConsensusStateMagic) {
		return nil, fmt.Errorf("invalid atomic consensus state magic")
	}
	if len(stateBytes)-reader.cursor == 4+externalapi.DomainHashSize {
		tag, err := reader.readBytes(4)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(tag, []byte{'R', 'O', 'O', 'T'}) {
			rootHash, err := reader.read32()
			if err != nil {
				return nil, err
			}
			if err := reader.finish(); err != nil {
				return nil, err
			}
			return NewRootOnlyState(rootHash), nil
		}
		reader.cursor -= 4
	}
	state := NewState()

	nonceLen, err := reader.readLen()
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < nonceLen; i++ {
		ownerID, err := reader.read32()
		if err != nil {
			return nil, err
		}
		scopeKind, err := reader.readByte()
		if err != nil {
			return nil, err
		}
		scopeID, err := reader.read32()
		if err != nil {
			return nil, err
		}
		nonceKey := NonceKey{OwnerID: ownerID, ScopeKind: NonceScopeKind(scopeKind), ScopeID: scopeID}
		if err := nonceKey.validate(); err != nil {
			return nil, err
		}
		nonce, err := reader.readUint64()
		if err != nil {
			return nil, err
		}
		if _, ok := state.NextNonces[nonceKey]; ok {
			return nil, fmt.Errorf("duplicate atomic nonce key")
		}
		state.NextNonces[nonceKey] = nonce
	}

	assetLen, err := reader.readLen()
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < assetLen; i++ {
		assetID, err := reader.read32()
		if err != nil {
			return nil, err
		}
		asset, err := reader.readAsset()
		if err != nil {
			return nil, err
		}
		if _, ok := state.Assets[assetID]; ok {
			return nil, fmt.Errorf("duplicate atomic asset id")
		}
		state.Assets[assetID] = asset
	}

	balanceLen, err := reader.readLen()
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < balanceLen; i++ {
		assetID, err := reader.read32()
		if err != nil {
			return nil, err
		}
		ownerID, err := reader.read32()
		if err != nil {
			return nil, err
		}
		amount, err := reader.readUint128()
		if err != nil {
			return nil, err
		}
		key := BalanceKey{AssetID: assetID, OwnerID: ownerID}
		if _, ok := state.Balances[key]; ok {
			return nil, fmt.Errorf("duplicate atomic balance key")
		}
		state.Balances[key] = amount
	}

	anchorLen, err := reader.readLen()
	if err != nil {
		return nil, err
	}
	for i := uint64(0); i < anchorLen; i++ {
		ownerID, err := reader.read32()
		if err != nil {
			return nil, err
		}
		count, err := reader.readUint64()
		if err != nil {
			return nil, err
		}
		if _, ok := state.AnchorCounts[ownerID]; ok {
			return nil, fmt.Errorf("duplicate atomic anchor owner id")
		}
		state.AnchorCounts[ownerID] = count
	}

	if err := reader.finish(); err != nil {
		return nil, err
	}
	state.RebuildLiquidityVaultOutpointIndex()
	return state, nil
}

func writeLen(out *[]byte, length int) {
	writeUint64(out, uint64(length))
}

func writeUint16(out *[]byte, value uint16) {
	var bytes [2]byte
	binary.LittleEndian.PutUint16(bytes[:], value)
	*out = append(*out, bytes[:]...)
}

func writeUint32(out *[]byte, value uint32) {
	var bytes [4]byte
	binary.LittleEndian.PutUint32(bytes[:], value)
	*out = append(*out, bytes[:]...)
}

func writeUint64(out *[]byte, value uint64) {
	var bytes [8]byte
	binary.LittleEndian.PutUint64(bytes[:], value)
	*out = append(*out, bytes[:]...)
}

func writeUint128(out *[]byte, value Uint128) {
	bytes := value.ToLE()
	*out = append(*out, bytes[:]...)
}

func writeAsset(out *[]byte, asset AssetState) {
	*out = append(*out, byte(asset.AssetClass))
	*out = append(*out, asset.TokenVersion)
	*out = append(*out, asset.MintAuthorityOwnerID[:]...)
	*out = append(*out, byte(asset.SupplyMode))
	writeUint128(out, asset.MaxSupply)
	writeUint128(out, asset.TotalSupply)
	writeLen(out, len(asset.PlatformTag))
	*out = append(*out, asset.PlatformTag...)
	if asset.Liquidity == nil {
		*out = append(*out, 0)
		return
	}
	*out = append(*out, 1)
	writeLiquidityPool(out, *asset.Liquidity)
}

func writeLiquidityPool(out *[]byte, pool LiquidityPoolState) {
	writeUint64(out, pool.PoolNonce)
	*out = append(*out, pool.CurveVersion)
	*out = append(*out, pool.CurveMode)
	writeUint64(out, pool.IndividualVirtualCPayReservesSompi)
	writeUint16(out, pool.IndividualVirtualTokenMultiplierBPS)
	writeUint64(out, pool.RealCPayReservesSompi)
	writeUint128(out, pool.RealTokenReserves)
	writeUint64(out, pool.VirtualCPayReserves)
	writeUint128(out, pool.VirtualTokenReserves)
	writeUint64(out, pool.UnclaimedFeeTotalSompi)
	writeUint16(out, pool.FeeBPS)
	writeLen(out, len(pool.FeeRecipients))
	for _, recipient := range pool.FeeRecipients {
		*out = append(*out, recipient.OwnerID[:]...)
		*out = append(*out, recipient.AddressVersion)
		writeLen(out, len(recipient.AddressPayload))
		*out = append(*out, recipient.AddressPayload...)
		writeUint64(out, recipient.UnclaimedSompi)
	}
	*out = append(*out, pool.VaultOutpoint.TransactionID.ByteSlice()...)
	writeUint32(out, pool.VaultOutpoint.Index)
	writeUint64(out, pool.VaultValueSompi)
	writeUint64(out, pool.UnlockTargetSompi)
	if pool.Unlocked {
		*out = append(*out, 1)
	} else {
		*out = append(*out, 0)
	}
}

type atomicStateReader struct {
	bytes  []byte
	cursor int
}

func (r *atomicStateReader) readBytes(length int) ([]byte, error) {
	if length < 0 || r.cursor+length > len(r.bytes) {
		return nil, fmt.Errorf("truncated atomic consensus state")
	}
	out := r.bytes[r.cursor : r.cursor+length]
	r.cursor += length
	return out, nil
}

func (r *atomicStateReader) read32() ([externalapi.DomainHashSize]byte, error) {
	bytes, err := r.readBytes(externalapi.DomainHashSize)
	if err != nil {
		return [externalapi.DomainHashSize]byte{}, err
	}
	var out [externalapi.DomainHashSize]byte
	copy(out[:], bytes)
	return out, nil
}

func (r *atomicStateReader) readByte() (byte, error) {
	bytes, err := r.readBytes(1)
	if err != nil {
		return 0, err
	}
	return bytes[0], nil
}

func (r *atomicStateReader) readUint16() (uint16, error) {
	bytes, err := r.readBytes(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(bytes), nil
}

func (r *atomicStateReader) readUint32() (uint32, error) {
	bytes, err := r.readBytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(bytes), nil
}

func (r *atomicStateReader) readUint64() (uint64, error) {
	bytes, err := r.readBytes(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(bytes), nil
}

func (r *atomicStateReader) readUint128() (Uint128, error) {
	bytes, err := r.readBytes(16)
	if err != nil {
		return Uint128{}, err
	}
	value, ok := Uint128FromLE(bytes)
	if !ok {
		return Uint128{}, fmt.Errorf("invalid uint128")
	}
	return value, nil
}

func (r *atomicStateReader) readLen() (uint64, error) {
	return r.readUint64()
}

func validateStateTokenVersion(version byte) error {
	if version >= 1 && version <= maxStateTokenVersion && version == currentStateTokenVersion {
		return nil
	}
	return fmt.Errorf("unsupported atomic token version `%d`", version)
}

func validateStateLiquidityCurveVersion(version byte) error {
	if version >= 1 && version <= maxStateLiquidityCurveVersion && version == currentStateLiquidityCurveVersion {
		return nil
	}
	return fmt.Errorf("unsupported atomic liquidity curve version `%d`", version)
}

func (r *atomicStateReader) readAsset() (AssetState, error) {
	rawClass, err := r.readByte()
	if err != nil {
		return AssetState{}, err
	}
	var class AssetClass
	switch rawClass {
	case 0:
		class = AssetClassStandard
	case 1:
		class = AssetClassLiquidity
	default:
		return AssetState{}, fmt.Errorf("invalid atomic asset class `%d`", rawClass)
	}
	tokenVersion, err := r.readByte()
	if err != nil {
		return AssetState{}, err
	}
	if err := validateStateTokenVersion(tokenVersion); err != nil {
		return AssetState{}, err
	}
	mintAuthorityOwnerID, err := r.read32()
	if err != nil {
		return AssetState{}, err
	}
	rawSupplyMode, err := r.readByte()
	if err != nil {
		return AssetState{}, err
	}
	var supplyMode SupplyMode
	switch rawSupplyMode {
	case 0:
		supplyMode = SupplyModeUncapped
	case 1:
		supplyMode = SupplyModeCapped
	default:
		return AssetState{}, fmt.Errorf("invalid atomic supply mode `%d`", rawSupplyMode)
	}
	maxSupply, err := r.readUint128()
	if err != nil {
		return AssetState{}, err
	}
	totalSupply, err := r.readUint128()
	if err != nil {
		return AssetState{}, err
	}
	platformTagLen, err := r.readLen()
	if err != nil {
		return AssetState{}, err
	}
	if platformTagLen > catMaxPlatformTagLen {
		return AssetState{}, fmt.Errorf("atomic platform tag length `%d` exceeds max", platformTagLen)
	}
	if platformTagLen > uint64(len(r.bytes)-r.cursor) {
		return AssetState{}, fmt.Errorf("truncated atomic consensus state")
	}
	platformTag, err := r.readBytes(int(platformTagLen))
	if err != nil {
		return AssetState{}, err
	}
	if !utf8.Valid(platformTag) {
		return AssetState{}, fmt.Errorf("atomic platform tag must be valid utf-8")
	}
	presence, err := r.readByte()
	if err != nil {
		return AssetState{}, err
	}
	var liquidity *LiquidityPoolState
	switch presence {
	case 0:
	case 1:
		pool, err := r.readLiquidityPool()
		if err != nil {
			return AssetState{}, err
		}
		liquidity = &pool
	default:
		return AssetState{}, fmt.Errorf("invalid atomic liquidity presence flag `%d`", presence)
	}
	return AssetState{
		AssetClass:           class,
		TokenVersion:         tokenVersion,
		MintAuthorityOwnerID: mintAuthorityOwnerID,
		SupplyMode:           supplyMode,
		MaxSupply:            maxSupply,
		TotalSupply:          totalSupply,
		PlatformTag:          append([]byte(nil), platformTag...),
		Liquidity:            liquidity,
	}, nil
}

func (r *atomicStateReader) readLiquidityPool() (LiquidityPoolState, error) {
	poolNonce, err := r.readUint64()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	curveVersion, err := r.readByte()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	if err := validateStateLiquidityCurveVersion(curveVersion); err != nil {
		return LiquidityPoolState{}, err
	}
	curveMode, err := r.readByte()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	if err := validateLiquidityCurveMode(curveMode); err != nil {
		return LiquidityPoolState{}, err
	}
	individualVirtualCPayReservesSompi, err := r.readUint64()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	individualVirtualTokenMultiplierBPS, err := r.readUint16()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	if err := validateLiquidityCurveParameters(curveMode, individualVirtualCPayReservesSompi, individualVirtualTokenMultiplierBPS); err != nil {
		return LiquidityPoolState{}, err
	}
	realCPayReservesSompi, err := r.readUint64()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	realTokenReserves, err := r.readUint128()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	virtualCPayReserves, err := r.readUint64()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	virtualTokenReserves, err := r.readUint128()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	unclaimedFeeTotalSompi, err := r.readUint64()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	feeBPS, err := r.readUint16()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	recipientLen, err := r.readLen()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	if recipientLen > maxLiquidityFeeRecipients {
		return LiquidityPoolState{}, fmt.Errorf("atomic liquidity recipient count `%d` exceeds max", recipientLen)
	}
	feeRecipients := make([]LiquidityFeeRecipientState, 0, recipientLen)
	for i := uint64(0); i < recipientLen; i++ {
		ownerID, err := r.read32()
		if err != nil {
			return LiquidityPoolState{}, err
		}
		addressVersion, err := r.readByte()
		if err != nil {
			return LiquidityPoolState{}, err
		}
		payloadLen, err := r.readLen()
		if err != nil {
			return LiquidityPoolState{}, err
		}
		if payloadLen > uint64(len(r.bytes)-r.cursor) {
			return LiquidityPoolState{}, fmt.Errorf("truncated atomic consensus state")
		}
		addressPayload, err := r.readBytes(int(payloadLen))
		if err != nil {
			return LiquidityPoolState{}, err
		}
		unclaimedSompi, err := r.readUint64()
		if err != nil {
			return LiquidityPoolState{}, err
		}
		feeRecipients = append(feeRecipients, LiquidityFeeRecipientState{
			OwnerID:        ownerID,
			AddressVersion: addressVersion,
			AddressPayload: append([]byte(nil), addressPayload...),
			UnclaimedSompi: unclaimedSompi,
		})
	}
	outpointHash, err := r.read32()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	txID := externalapi.NewDomainTransactionIDFromByteArray(&outpointHash)
	index, err := r.readUint32()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	vaultValueSompi, err := r.readUint64()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	unlockTargetSompi, err := r.readUint64()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	unlockedRaw, err := r.readByte()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	var unlocked bool
	switch unlockedRaw {
	case 0:
		unlocked = false
	case 1:
		unlocked = true
	default:
		return LiquidityPoolState{}, fmt.Errorf("invalid atomic liquidity unlocked flag `%d`", unlockedRaw)
	}
	return LiquidityPoolState{
		PoolNonce:                           poolNonce,
		CurveVersion:                        curveVersion,
		CurveMode:                           curveMode,
		IndividualVirtualCPayReservesSompi:  individualVirtualCPayReservesSompi,
		IndividualVirtualTokenMultiplierBPS: individualVirtualTokenMultiplierBPS,
		RealCPayReservesSompi:               realCPayReservesSompi,
		RealTokenReserves:                   realTokenReserves,
		VirtualCPayReserves:                 virtualCPayReserves,
		VirtualTokenReserves:                virtualTokenReserves,
		UnclaimedFeeTotalSompi:              unclaimedFeeTotalSompi,
		FeeBPS:                              feeBPS,
		FeeRecipients:                       feeRecipients,
		VaultOutpoint: externalapi.DomainOutpoint{
			TransactionID: *txID,
			Index:         index,
		},
		VaultValueSompi:   vaultValueSompi,
		UnlockTargetSompi: unlockTargetSompi,
		Unlocked:          unlocked,
	}, nil
}

func (r *atomicStateReader) finish() error {
	if r.cursor != len(r.bytes) {
		return fmt.Errorf("unexpected trailing bytes in atomic consensus state")
	}
	return nil
}
