package atomicstate

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"golang.org/x/crypto/blake2b"
)

var (
	atomicConsensusStateMagic      = []byte("CATCS001")
	atomicConsensusStateHashDomain = []byte("cryptix-atomic-consensus-state-v1")
	atomicStateCommitmentDomain    = []byte("cryptix-utxo-atomic-state-commitment-v1")
)

type BalanceKey struct {
	AssetID [externalapi.DomainHashSize]byte
	OwnerID [externalapi.DomainHashSize]byte
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
	PoolNonce              uint64
	RemainingPoolSupply    Uint128
	CurveReserveSompi      uint64
	UnclaimedFeeTotalSompi uint64
	FeeBPS                 uint16
	FeeRecipients          []LiquidityFeeRecipientState
	VaultOutpoint          externalapi.DomainOutpoint
	VaultValueSompi        uint64
}

type AssetState struct {
	AssetClass           AssetClass
	MintAuthorityOwnerID [externalapi.DomainHashSize]byte
	SupplyMode           SupplyMode
	MaxSupply            Uint128
	TotalSupply          Uint128
	Liquidity            *LiquidityPoolState
}

type State struct {
	NextNonces              map[[externalapi.DomainHashSize]byte]uint64
	Assets                  map[[externalapi.DomainHashSize]byte]AssetState
	Balances                map[BalanceKey]Uint128
	AnchorCounts            map[[externalapi.DomainHashSize]byte]uint64
	LiquidityVaultOutpoints map[externalapi.DomainOutpoint][externalapi.DomainHashSize]byte
}

func NewState() *State {
	return &State{
		NextNonces:              make(map[[externalapi.DomainHashSize]byte]uint64),
		Assets:                  make(map[[externalapi.DomainHashSize]byte]AssetState),
		Balances:                make(map[BalanceKey]Uint128),
		AnchorCounts:            make(map[[externalapi.DomainHashSize]byte]uint64),
		LiquidityVaultOutpoints: make(map[externalapi.DomainOutpoint][externalapi.DomainHashSize]byte),
	}
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
	return clone
}

func (a AssetState) clone() AssetState {
	out := a
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
	out := make([]byte, 0)
	out = append(out, atomicConsensusStateMagic...)

	nonceKeys := make([][externalapi.DomainHashSize]byte, 0, len(s.NextNonces))
	for ownerID := range s.NextNonces {
		nonceKeys = append(nonceKeys, ownerID)
	}
	sort.Slice(nonceKeys, func(i, j int) bool { return bytes.Compare(nonceKeys[i][:], nonceKeys[j][:]) < 0 })
	writeLen(&out, len(nonceKeys))
	for _, ownerID := range nonceKeys {
		out = append(out, ownerID[:]...)
		writeUint64(&out, s.NextNonces[ownerID])
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

func (s *State) CanonicalHash() [externalapi.DomainHashSize]byte {
	return HashCanonicalBytes(s.CanonicalBytes())
}

func HashCanonicalBytes(stateBytes []byte) [externalapi.DomainHashSize]byte {
	hasher, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	_, _ = hasher.Write(atomicConsensusStateHashDomain)
	var lenBytes [8]byte
	binary.LittleEndian.PutUint64(lenBytes[:], uint64(len(stateBytes)))
	_, _ = hasher.Write(lenBytes[:])
	_, _ = hasher.Write(stateBytes)
	var out [externalapi.DomainHashSize]byte
	copy(out[:], hasher.Sum(nil))
	return out
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
		nonce, err := reader.readUint64()
		if err != nil {
			return nil, err
		}
		if _, ok := state.NextNonces[ownerID]; ok {
			return nil, fmt.Errorf("duplicate atomic nonce owner id")
		}
		state.NextNonces[ownerID] = nonce
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
	*out = append(*out, asset.MintAuthorityOwnerID[:]...)
	*out = append(*out, byte(asset.SupplyMode))
	writeUint128(out, asset.MaxSupply)
	writeUint128(out, asset.TotalSupply)
	if asset.Liquidity == nil {
		*out = append(*out, 0)
		return
	}
	*out = append(*out, 1)
	writeLiquidityPool(out, *asset.Liquidity)
}

func writeLiquidityPool(out *[]byte, pool LiquidityPoolState) {
	writeUint64(out, pool.PoolNonce)
	writeUint128(out, pool.RemainingPoolSupply)
	writeUint64(out, pool.CurveReserveSompi)
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
		MintAuthorityOwnerID: mintAuthorityOwnerID,
		SupplyMode:           supplyMode,
		MaxSupply:            maxSupply,
		TotalSupply:          totalSupply,
		Liquidity:            liquidity,
	}, nil
}

func (r *atomicStateReader) readLiquidityPool() (LiquidityPoolState, error) {
	poolNonce, err := r.readUint64()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	remainingPoolSupply, err := r.readUint128()
	if err != nil {
		return LiquidityPoolState{}, err
	}
	curveReserveSompi, err := r.readUint64()
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
	return LiquidityPoolState{
		PoolNonce:              poolNonce,
		RemainingPoolSupply:    remainingPoolSupply,
		CurveReserveSompi:      curveReserveSompi,
		UnclaimedFeeTotalSompi: unclaimedFeeTotalSompi,
		FeeBPS:                 feeBPS,
		FeeRecipients:          feeRecipients,
		VaultOutpoint: externalapi.DomainOutpoint{
			TransactionID: *txID,
			Index:         index,
		},
		VaultValueSompi: vaultValueSompi,
	}, nil
}

func (r *atomicStateReader) finish() error {
	if r.cursor != len(r.bytes) {
		return fmt.Errorf("unexpected trailing bytes in atomic consensus state")
	}
	return nil
}
