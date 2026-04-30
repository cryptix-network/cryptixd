package atomicstate

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/constants"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/txscript"
	"golang.org/x/crypto/blake2b"
)

var (
	catMagic       = []byte("CAT")
	catOwnerDomain = []byte("CAT_OWNER_V2")
)

const (
	catVersion                 = byte(1)
	ownerAuthSchemePubKey      = byte(0)
	ownerAuthSchemePubKeyECDSA = byte(1)
	ownerAuthSchemeScriptHash  = byte(2)
	catMaxNameLen              = 32
	catMaxSymbolLen            = 10
	catMaxMetadataLen          = 256
	catMaxPlatformTagLen       = 50
	catMaxDecimals             = 18
	maxLiquidityFeeRecipients  = 2
	minLiquidityFeeBPS         = 10
	maxLiquidityFeeBPS         = 1000
	liquidityTokenDecimals     = byte(0)
	minLiquidityTokenSupplyRaw = uint64(100_000)
	liquidityTokenSupplyRaw    = uint64(1_000_000)
	defaultLiquiditySupplyRaw  = liquidityTokenSupplyRaw
	maxLiquidityTokenSupplyRaw = uint64(10_000_000)
	minLiquiditySeedReserve    = constants.SompiPerCryptix
	initialRealCPayReserves    = constants.SompiPerCryptix
	minCPayReserve             = uint64(1)
	minRealTokenReserve        = uint64(1)
	initialVirtualCPayReserves = uint64(250_000_000_000_000)
	initialVirtualTokenReserve = defaultLiquiditySupplyRaw * 6 / 5
)

type PayloadSupplyMode byte

const (
	PayloadSupplyModeUncapped PayloadSupplyMode = iota
	PayloadSupplyModeCapped
)

type PayloadRecipientAddress struct {
	AddressVersion byte
	AddressPayload []byte
}

type PayloadOp interface {
	isPayloadOp()
}

type CreateAssetOp struct {
	Decimals             byte
	SupplyMode           PayloadSupplyMode
	MaxSupply            Uint128
	MintAuthorityOwnerID [externalapi.DomainHashSize]byte
	Name                 []byte
	Symbol               []byte
	Metadata             []byte
	PlatformTag          []byte
}

func (CreateAssetOp) isPayloadOp() {}

type TransferOp struct {
	AssetID   [externalapi.DomainHashSize]byte
	ToOwnerID [externalapi.DomainHashSize]byte
	Amount    Uint128
}

func (TransferOp) isPayloadOp() {}

type MintOp struct {
	AssetID   [externalapi.DomainHashSize]byte
	ToOwnerID [externalapi.DomainHashSize]byte
	Amount    Uint128
}

func (MintOp) isPayloadOp() {}

type BurnOp struct {
	AssetID [externalapi.DomainHashSize]byte
	Amount  Uint128
}

func (BurnOp) isPayloadOp() {}

type CreateAssetWithMintOp struct {
	Decimals             byte
	SupplyMode           PayloadSupplyMode
	MaxSupply            Uint128
	MintAuthorityOwnerID [externalapi.DomainHashSize]byte
	Name                 []byte
	Symbol               []byte
	Metadata             []byte
	InitialMintAmount    Uint128
	InitialMintToOwnerID [externalapi.DomainHashSize]byte
	PlatformTag          []byte
}

func (CreateAssetWithMintOp) isPayloadOp() {}

type CreateLiquidityAssetOp struct {
	Decimals             byte
	MaxSupply            Uint128
	Name                 []byte
	Symbol               []byte
	Metadata             []byte
	SeedReserveSompi     uint64
	FeeBPS               uint16
	Recipients           []PayloadRecipientAddress
	LaunchBuySompi       uint64
	LaunchBuyMinTokenOut Uint128
	PlatformTag          []byte
	UnlockTargetSompi    uint64
}

func (CreateLiquidityAssetOp) isPayloadOp() {}

type BuyLiquidityExactInOp struct {
	AssetID           [externalapi.DomainHashSize]byte
	ExpectedPoolNonce uint64
	CPayInSompi       uint64
	MinTokenOut       Uint128
}

func (BuyLiquidityExactInOp) isPayloadOp() {}

type SellLiquidityExactInOp struct {
	AssetID                [externalapi.DomainHashSize]byte
	ExpectedPoolNonce      uint64
	TokenIn                Uint128
	MinCPayOutSompi        uint64
	CPayReceiveOutputIndex uint16
}

func (SellLiquidityExactInOp) isPayloadOp() {}

type ClaimLiquidityFeesOp struct {
	AssetID                 [externalapi.DomainHashSize]byte
	ExpectedPoolNonce       uint64
	RecipientIndex          byte
	ClaimAmountSompi        uint64
	ClaimReceiveOutputIndex uint16
}

func (ClaimLiquidityFeesOp) isPayloadOp() {}

type ParsedPayload struct {
	AuthInputIndex uint16
	Nonce          uint64
	Op             PayloadOp
}

func ValidatePayloadShape(payload []byte) error {
	_, err := ParsePayload(payload)
	return err
}

func ParsePayload(payload []byte) (*ParsedPayload, error) {
	if len(payload) < len(catMagic) || string(payload[:len(catMagic)]) != string(catMagic) {
		return nil, nil
	}

	cursor := 0
	magic, ok := takeBytes(payload, &cursor, len(catMagic))
	if !ok {
		return nil, fmt.Errorf("truncated CAT magic")
	}
	if string(magic) != string(catMagic) {
		return nil, fmt.Errorf("invalid CAT magic")
	}

	version, ok := takeByte(payload, &cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT version")
	}
	if version != catVersion {
		return nil, fmt.Errorf("unsupported CAT version `%d`", version)
	}

	opcode, ok := takeByte(payload, &cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT op")
	}
	if opcode > 8 {
		return nil, fmt.Errorf("unsupported CAT op `%d`", opcode)
	}

	flags, ok := takeByte(payload, &cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT flags")
	}
	if flags != 0 {
		return nil, fmt.Errorf("invalid CAT flags `%d`", flags)
	}

	authInputIndex, ok := takeUint16LE(payload, &cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT auth_input_index")
	}
	nonce, ok := takeUint64LE(payload, &cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT nonce")
	}
	if nonce == 0 {
		return nil, fmt.Errorf("nonce must be >= 1")
	}

	var op PayloadOp
	var err error
	switch opcode {
	case 0:
		op, err = parseCreateAsset(payload, &cursor)
	case 1:
		op, err = parseTransfer(payload, &cursor)
	case 2:
		op, err = parseMint(payload, &cursor)
	case 3:
		op, err = parseBurn(payload, &cursor)
	case 4:
		op, err = parseCreateAssetWithMint(payload, &cursor)
	case 5:
		op, err = parseCreateLiquidityAsset(payload, &cursor)
	case 6:
		op, err = parseBuyLiquidityExactIn(payload, &cursor)
	case 7:
		op, err = parseSellLiquidityExactIn(payload, &cursor)
	case 8:
		op, err = parseClaimLiquidityFees(payload, &cursor)
	}
	if err != nil {
		return nil, err
	}
	if cursor != len(payload) {
		return nil, fmt.Errorf("unexpected trailing bytes")
	}

	return &ParsedPayload{AuthInputIndex: authInputIndex, Nonce: nonce, Op: op}, nil
}

func parseCreateAsset(payload []byte, cursor *int) (PayloadOp, error) {
	decimals, supplyMode, maxSupply, mintAuthorityOwnerID, name, symbol, metadata, err := parseCreateAssetCommon(payload, cursor)
	if err != nil {
		return nil, err
	}
	platformTag, err := parseOptionalPlatformTagTail(payload, cursor)
	if err != nil {
		return nil, err
	}
	return CreateAssetOp{
		Decimals:             decimals,
		SupplyMode:           supplyMode,
		MaxSupply:            maxSupply,
		MintAuthorityOwnerID: mintAuthorityOwnerID,
		Name:                 name,
		Symbol:               symbol,
		Metadata:             metadata,
		PlatformTag:          platformTag,
	}, nil
}

func parseTransfer(payload []byte, cursor *int) (PayloadOp, error) {
	assetID, ok := take32(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT asset_id")
	}
	toOwnerID, ok := take32(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT to_owner_id")
	}
	amount, ok := takeUint128LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT transfer amount")
	}
	if amount.IsZero() {
		return nil, fmt.Errorf("transfer amount must be non-zero")
	}
	return TransferOp{AssetID: assetID, ToOwnerID: toOwnerID, Amount: amount}, nil
}

func parseMint(payload []byte, cursor *int) (PayloadOp, error) {
	assetID, ok := take32(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT asset_id")
	}
	toOwnerID, ok := take32(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT to_owner_id")
	}
	amount, ok := takeUint128LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT mint amount")
	}
	if amount.IsZero() {
		return nil, fmt.Errorf("mint amount must be non-zero")
	}
	return MintOp{AssetID: assetID, ToOwnerID: toOwnerID, Amount: amount}, nil
}

func parseBurn(payload []byte, cursor *int) (PayloadOp, error) {
	assetID, ok := take32(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT asset_id")
	}
	amount, ok := takeUint128LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT burn amount")
	}
	if amount.IsZero() {
		return nil, fmt.Errorf("burn amount must be non-zero")
	}
	return BurnOp{AssetID: assetID, Amount: amount}, nil
}

func parseCreateAssetWithMint(payload []byte, cursor *int) (PayloadOp, error) {
	decimals, supplyMode, maxSupply, mintAuthorityOwnerID, name, symbol, metadata, err := parseCreateAssetCommon(payload, cursor)
	if err != nil {
		return nil, err
	}
	initialMintAmount, ok := takeUint128LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT initial mint amount")
	}
	initialMintToOwnerID, ok := take32(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT initial mint owner id")
	}
	var zero [externalapi.DomainHashSize]byte
	if initialMintAmount.IsZero() && initialMintToOwnerID != zero {
		return nil, fmt.Errorf("initial_mint_to_owner_id must be zero when initial_mint_amount is zero")
	}
	if !initialMintAmount.IsZero() && initialMintToOwnerID == zero {
		return nil, fmt.Errorf("initial_mint_to_owner_id must be non-zero when initial_mint_amount is non-zero")
	}
	platformTag, err := parseOptionalPlatformTagTail(payload, cursor)
	if err != nil {
		return nil, err
	}
	return CreateAssetWithMintOp{
		Decimals:             decimals,
		SupplyMode:           supplyMode,
		MaxSupply:            maxSupply,
		MintAuthorityOwnerID: mintAuthorityOwnerID,
		Name:                 name,
		Symbol:               symbol,
		Metadata:             metadata,
		InitialMintAmount:    initialMintAmount,
		InitialMintToOwnerID: initialMintToOwnerID,
		PlatformTag:          platformTag,
	}, nil
}

func parseCreateLiquidityAsset(payload []byte, cursor *int) (PayloadOp, error) {
	decimals, ok := takeByte(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT decimals")
	}
	if decimals != liquidityTokenDecimals {
		return nil, fmt.Errorf("liquidity asset decimals must be `%d`", liquidityTokenDecimals)
	}
	maxSupply, ok := takeUint128LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT max_supply")
	}
	if !isLiquidityMaxSupplyAllowed(maxSupply) {
		return nil, fmt.Errorf("liquidity asset max_supply must be in `%d..=%d`", minLiquidityTokenSupplyRaw, maxLiquidityTokenSupplyRaw)
	}
	name, symbol, metadata, err := parseStringFields(payload, cursor)
	if err != nil {
		return nil, err
	}
	seedReserveSompi, ok := takeUint64LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT seed reserve")
	}
	if err := validateLiquidityCreateParams(decimals, maxSupply, seedReserveSompi); err != nil {
		return nil, err
	}
	feeBPS, ok := takeUint16LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT fee bps")
	}
	if !(feeBPS == 0 || (feeBPS >= minLiquidityFeeBPS && feeBPS <= maxLiquidityFeeBPS)) {
		return nil, fmt.Errorf("fee_bps must be 0 or in %d..=%d, got `%d`", minLiquidityFeeBPS, maxLiquidityFeeBPS, feeBPS)
	}
	recipientCount, ok := takeByte(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT recipient count")
	}
	if recipientCount > maxLiquidityFeeRecipients {
		return nil, fmt.Errorf("recipient_count above max `%d`", maxLiquidityFeeRecipients)
	}
	if feeBPS == 0 && recipientCount != 0 {
		return nil, fmt.Errorf("recipient_count must be 0 when fee_bps is 0")
	}
	if feeBPS > 0 && recipientCount == 0 {
		return nil, fmt.Errorf("recipient_count must be 1 or 2 when fee_bps > 0")
	}
	recipients := make([]PayloadRecipientAddress, 0, recipientCount)
	for i := byte(0); i < recipientCount; i++ {
		recipient, err := parseRecipientAddress(payload, cursor)
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, recipient)
	}
	if len(recipients) == 2 {
		if recipients[0].AddressVersion == recipients[1].AddressVersion &&
			string(recipients[0].AddressPayload) == string(recipients[1].AddressPayload) {
			return nil, fmt.Errorf("duplicate liquidity recipients are not allowed")
		}
		if recipientOrderGreater(recipients[0], recipients[1]) {
			return nil, fmt.Errorf("liquidity recipients must be canonically sorted")
		}
	}
	launchBuySompi, ok := takeUint64LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT launch buy sompi")
	}
	launchBuyMinTokenOut, ok := takeUint128LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT launch buy min token out")
	}
	if launchBuySompi == 0 && !launchBuyMinTokenOut.IsZero() {
		return nil, fmt.Errorf("launch_buy_min_token_out must be 0 when launch_buy_sompi is 0")
	}
	if launchBuySompi > 0 && launchBuyMinTokenOut.IsZero() {
		return nil, fmt.Errorf("launch_buy_min_token_out must be >0 when launch_buy_sompi is >0")
	}
	platformTag, unlockTargetSompi, err := parseOptionalLiquidityCreateTail(payload, cursor)
	if err != nil {
		return nil, err
	}
	return CreateLiquidityAssetOp{
		Decimals:             decimals,
		MaxSupply:            maxSupply,
		Name:                 name,
		Symbol:               symbol,
		Metadata:             metadata,
		SeedReserveSompi:     seedReserveSompi,
		FeeBPS:               feeBPS,
		Recipients:           recipients,
		LaunchBuySompi:       launchBuySompi,
		LaunchBuyMinTokenOut: launchBuyMinTokenOut,
		PlatformTag:          platformTag,
		UnlockTargetSompi:    unlockTargetSompi,
	}, nil
}

func parseBuyLiquidityExactIn(payload []byte, cursor *int) (PayloadOp, error) {
	assetID, ok := take32(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT asset_id")
	}
	expectedPoolNonce, ok := takeUint64LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT expected_pool_nonce")
	}
	if expectedPoolNonce == 0 {
		return nil, fmt.Errorf("buy expected_pool_nonce must be >= 1")
	}
	cpayInSompi, ok := takeUint64LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT cpay in")
	}
	minTokenOut, ok := takeUint128LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT min token out")
	}
	if cpayInSompi == 0 {
		return nil, fmt.Errorf("buy cpay_in_sompi must be >0")
	}
	if minTokenOut.IsZero() {
		return nil, fmt.Errorf("buy min_token_out must be >0")
	}
	return BuyLiquidityExactInOp{AssetID: assetID, ExpectedPoolNonce: expectedPoolNonce, CPayInSompi: cpayInSompi, MinTokenOut: minTokenOut}, nil
}

func parseSellLiquidityExactIn(payload []byte, cursor *int) (PayloadOp, error) {
	assetID, ok := take32(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT asset_id")
	}
	expectedPoolNonce, ok := takeUint64LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT expected_pool_nonce")
	}
	if expectedPoolNonce == 0 {
		return nil, fmt.Errorf("sell expected_pool_nonce must be >= 1")
	}
	tokenIn, ok := takeUint128LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT token_in")
	}
	minCPayOutSompi, ok := takeUint64LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT min cpay out")
	}
	cpayReceiveOutputIndex, ok := takeUint16LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT cpay receive output index")
	}
	if tokenIn.IsZero() {
		return nil, fmt.Errorf("sell token_in must be >0")
	}
	if minCPayOutSompi == 0 {
		return nil, fmt.Errorf("sell min_cpay_out_sompi must be >0")
	}
	return SellLiquidityExactInOp{
		AssetID:                assetID,
		ExpectedPoolNonce:      expectedPoolNonce,
		TokenIn:                tokenIn,
		MinCPayOutSompi:        minCPayOutSompi,
		CPayReceiveOutputIndex: cpayReceiveOutputIndex,
	}, nil
}

func parseClaimLiquidityFees(payload []byte, cursor *int) (PayloadOp, error) {
	assetID, ok := take32(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT asset_id")
	}
	expectedPoolNonce, ok := takeUint64LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT expected_pool_nonce")
	}
	if expectedPoolNonce == 0 {
		return nil, fmt.Errorf("claim expected_pool_nonce must be >= 1")
	}
	recipientIndex, ok := takeByte(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT claim recipient index")
	}
	claimAmountSompi, ok := takeUint64LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT claim amount")
	}
	claimReceiveOutputIndex, ok := takeUint16LE(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT claim receive output index")
	}
	if claimAmountSompi == 0 {
		return nil, fmt.Errorf("claim amount must be >0")
	}
	return ClaimLiquidityFeesOp{
		AssetID:                 assetID,
		ExpectedPoolNonce:       expectedPoolNonce,
		RecipientIndex:          recipientIndex,
		ClaimAmountSompi:        claimAmountSompi,
		ClaimReceiveOutputIndex: claimReceiveOutputIndex,
	}, nil
}

func parseCreateAssetCommon(payload []byte, cursor *int) (
	byte, PayloadSupplyMode, Uint128, [externalapi.DomainHashSize]byte, []byte, []byte, []byte, error,
) {
	decimals, ok := takeByte(payload, cursor)
	if !ok {
		return 0, 0, Uint128{}, [externalapi.DomainHashSize]byte{}, nil, nil, nil, fmt.Errorf("truncated CAT decimals")
	}
	if decimals > catMaxDecimals {
		return 0, 0, Uint128{}, [externalapi.DomainHashSize]byte{}, nil, nil, nil,
			fmt.Errorf("decimals `%d` above max `%d`", decimals, catMaxDecimals)
	}
	rawSupplyMode, ok := takeByte(payload, cursor)
	if !ok {
		return 0, 0, Uint128{}, [externalapi.DomainHashSize]byte{}, nil, nil, nil, fmt.Errorf("truncated CAT supply mode")
	}
	var supplyMode PayloadSupplyMode
	switch rawSupplyMode {
	case 0:
		supplyMode = PayloadSupplyModeUncapped
	case 1:
		supplyMode = PayloadSupplyModeCapped
	default:
		return 0, 0, Uint128{}, [externalapi.DomainHashSize]byte{}, nil, nil, nil, fmt.Errorf("invalid supply mode `%d`", rawSupplyMode)
	}
	maxSupply, ok := takeUint128LE(payload, cursor)
	if !ok {
		return 0, 0, Uint128{}, [externalapi.DomainHashSize]byte{}, nil, nil, nil, fmt.Errorf("truncated CAT max_supply")
	}
	mintAuthorityOwnerID, ok := take32(payload, cursor)
	if !ok {
		return 0, 0, Uint128{}, [externalapi.DomainHashSize]byte{}, nil, nil, nil, fmt.Errorf("truncated CAT mint authority")
	}
	name, symbol, metadata, err := parseStringFields(payload, cursor)
	if err != nil {
		return 0, 0, Uint128{}, [externalapi.DomainHashSize]byte{}, nil, nil, nil, err
	}
	switch {
	case supplyMode == PayloadSupplyModeCapped && maxSupply.IsZero():
		return 0, 0, Uint128{}, [externalapi.DomainHashSize]byte{}, nil, nil, nil, fmt.Errorf("capped assets require non-zero max_supply")
	case supplyMode == PayloadSupplyModeUncapped && !maxSupply.IsZero():
		return 0, 0, Uint128{}, [externalapi.DomainHashSize]byte{}, nil, nil, nil, fmt.Errorf("uncapped assets must encode max_supply=0")
	}
	return decimals, supplyMode, maxSupply, mintAuthorityOwnerID, name, symbol, metadata, nil
}

func parseOptionalPlatformTagTail(payload []byte, cursor *int) ([]byte, error) {
	if *cursor == len(payload) {
		return nil, nil
	}
	return parsePlatformTag(payload, cursor)
}

func parseOptionalLiquidityCreateTail(payload []byte, cursor *int) ([]byte, uint64, error) {
	if *cursor == len(payload) {
		return nil, 0, nil
	}
	platformTag, err := parsePlatformTag(payload, cursor)
	if err != nil {
		return nil, 0, err
	}
	unlockTargetSompi, ok := takeUint64LE(payload, cursor)
	if !ok {
		return nil, 0, fmt.Errorf("truncated CAT liquidity unlock target")
	}
	if err := validateLiquidityUnlockTarget(unlockTargetSompi); err != nil {
		return nil, 0, err
	}
	return platformTag, unlockTargetSompi, nil
}

func parsePlatformTag(payload []byte, cursor *int) ([]byte, error) {
	platformTagLen, ok := takeByte(payload, cursor)
	if !ok {
		return nil, fmt.Errorf("truncated CAT platform tag length")
	}
	if int(platformTagLen) > catMaxPlatformTagLen {
		return nil, fmt.Errorf("platform tag length exceeds max `%d`", catMaxPlatformTagLen)
	}
	platformTag, ok := takeVec(payload, cursor, int(platformTagLen))
	if !ok {
		return nil, fmt.Errorf("truncated CAT platform tag")
	}
	if !utf8.Valid(platformTag) {
		return nil, fmt.Errorf("platform tag must be valid utf-8")
	}
	return platformTag, nil
}

func validateLiquidityUnlockTarget(unlockTargetSompi uint64) error {
	if unlockTargetSompi > constants.MaxSompi {
		return fmt.Errorf("liquidity unlock target `%d` exceeds MaxSompi `%d`", unlockTargetSompi, constants.MaxSompi)
	}
	return nil
}

func parseStringFields(payload []byte, cursor *int) ([]byte, []byte, []byte, error) {
	nameLen, ok := takeByte(payload, cursor)
	if !ok {
		return nil, nil, nil, fmt.Errorf("truncated CAT name length")
	}
	symbolLen, ok := takeByte(payload, cursor)
	if !ok {
		return nil, nil, nil, fmt.Errorf("truncated CAT symbol length")
	}
	metadataLen, ok := takeUint16LE(payload, cursor)
	if !ok {
		return nil, nil, nil, fmt.Errorf("truncated CAT metadata length")
	}
	if int(nameLen) > catMaxNameLen || int(symbolLen) > catMaxSymbolLen || int(metadataLen) > catMaxMetadataLen {
		return nil, nil, nil, fmt.Errorf("string field exceeds allowed length")
	}
	name, ok := takeVec(payload, cursor, int(nameLen))
	if !ok {
		return nil, nil, nil, fmt.Errorf("truncated CAT name")
	}
	symbol, ok := takeVec(payload, cursor, int(symbolLen))
	if !ok {
		return nil, nil, nil, fmt.Errorf("truncated CAT symbol")
	}
	metadata, ok := takeVec(payload, cursor, int(metadataLen))
	if !ok {
		return nil, nil, nil, fmt.Errorf("truncated CAT metadata")
	}
	if !utf8.Valid(name) || !utf8.Valid(symbol) {
		return nil, nil, nil, fmt.Errorf("name/symbol must be valid utf-8")
	}
	return name, symbol, metadata, nil
}

func parseRecipientAddress(payload []byte, cursor *int) (PayloadRecipientAddress, error) {
	addressVersion, ok := takeByte(payload, cursor)
	if !ok {
		return PayloadRecipientAddress{}, fmt.Errorf("truncated CAT recipient address version")
	}
	var expectedLen int
	switch addressVersion {
	case 0:
		expectedLen = 32
	case 1:
		expectedLen = 33
	case 8:
		expectedLen = 32
	default:
		return PayloadRecipientAddress{}, fmt.Errorf("unsupported recipient address_version `%d`", addressVersion)
	}
	addressPayload, ok := takeVec(payload, cursor, expectedLen)
	if !ok {
		return PayloadRecipientAddress{}, fmt.Errorf("truncated CAT recipient address payload")
	}
	return PayloadRecipientAddress{AddressVersion: addressVersion, AddressPayload: addressPayload}, nil
}

func recipientOrderGreater(left, right PayloadRecipientAddress) bool {
	if left.AddressVersion != right.AddressVersion {
		return left.AddressVersion > right.AddressVersion
	}
	return string(left.AddressPayload) > string(right.AddressPayload)
}

func OwnerIDFromScript(scriptPublicKey *externalapi.ScriptPublicKey) ([externalapi.DomainHashSize]byte, bool) {
	authScheme, canonicalBytes, ok := canonicalOwnerIdentity(scriptPublicKey)
	if !ok {
		return [externalapi.DomainHashSize]byte{}, false
	}
	return ownerID(authScheme, canonicalBytes)
}

func OwnerIDFromAddressComponents(addressVersion byte, addressPayload []byte) ([externalapi.DomainHashSize]byte, bool) {
	var authScheme byte
	switch {
	case addressVersion == 0 && len(addressPayload) == 32:
		authScheme = ownerAuthSchemePubKey
	case addressVersion == 1 && len(addressPayload) == 33:
		authScheme = ownerAuthSchemePubKeyECDSA
	case addressVersion == 8 && len(addressPayload) == 32:
		authScheme = ownerAuthSchemeScriptHash
	default:
		return [externalapi.DomainHashSize]byte{}, false
	}
	return ownerID(authScheme, addressPayload)
}

func ownerID(authScheme byte, canonicalBytes []byte) ([externalapi.DomainHashSize]byte, bool) {
	if len(canonicalBytes) > 0xffff {
		return [externalapi.DomainHashSize]byte{}, false
	}
	hasher, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	_, _ = hasher.Write(catOwnerDomain)
	_, _ = hasher.Write([]byte{authScheme})
	var lenBytes [2]byte
	binary.LittleEndian.PutUint16(lenBytes[:], uint16(len(canonicalBytes)))
	_, _ = hasher.Write(lenBytes[:])
	_, _ = hasher.Write(canonicalBytes)
	var out [externalapi.DomainHashSize]byte
	copy(out[:], hasher.Sum(nil))
	return out, true
}

func canonicalOwnerIdentity(scriptPublicKey *externalapi.ScriptPublicKey) (byte, []byte, bool) {
	if scriptPublicKey == nil || scriptPublicKey.Version != constants.MaxScriptPublicKeyVersion {
		return 0, nil, false
	}
	script := scriptPublicKey.Script
	switch {
	case isPayToPubKey(script):
		return ownerAuthSchemePubKey, script[1:33], true
	case isPayToPubKeyECDSA(script):
		return ownerAuthSchemePubKeyECDSA, script[1:34], true
	case isPayToScriptHash(script):
		return ownerAuthSchemeScriptHash, script[2:34], true
	default:
		return 0, nil, false
	}
}

func scriptClass(scriptPublicKey *externalapi.ScriptPublicKey) txscript.ScriptClass {
	if scriptPublicKey == nil || scriptPublicKey.Version != constants.MaxScriptPublicKeyVersion {
		return txscript.NonStandardTy
	}
	if isLiquidityVault(scriptPublicKey.Script) {
		return txscript.ScriptClass(4)
	}
	return txscript.GetScriptClass(scriptPublicKey.Script)
}

func isPayToPubKey(script []byte) bool {
	return len(script) == 34 && script[0] == txscript.OpData32 && script[33] == txscript.OpCheckSig
}

func isPayToPubKeyECDSA(script []byte) bool {
	return len(script) == 35 && script[0] == txscript.OpData33 && script[34] == txscript.OpCheckSigECDSA
}

func isPayToScriptHash(script []byte) bool {
	return len(script) == 35 && script[0] == txscript.OpBlake2b && script[1] == txscript.OpData32 && script[34] == txscript.OpEqual
}

func isLiquidityVault(script []byte) bool {
	return len(script) == 7 &&
		script[0] == txscript.OpData4 &&
		script[1] == 'C' &&
		script[2] == 'L' &&
		script[3] == 'V' &&
		script[4] == '1' &&
		script[5] == txscript.OpDrop &&
		script[6] == txscript.OpTrue
}

func takeBytes(payload []byte, cursor *int, length int) ([]byte, bool) {
	if length < 0 || *cursor+length > len(payload) {
		return nil, false
	}
	out := payload[*cursor : *cursor+length]
	*cursor += length
	return out, true
}

func takeByte(payload []byte, cursor *int) (byte, bool) {
	bytes, ok := takeBytes(payload, cursor, 1)
	if !ok {
		return 0, false
	}
	return bytes[0], true
}

func takeUint16LE(payload []byte, cursor *int) (uint16, bool) {
	bytes, ok := takeBytes(payload, cursor, 2)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint16(bytes), true
}

func takeUint64LE(payload []byte, cursor *int) (uint64, bool) {
	bytes, ok := takeBytes(payload, cursor, 8)
	if !ok {
		return 0, false
	}
	return binary.LittleEndian.Uint64(bytes), true
}

func takeUint128LE(payload []byte, cursor *int) (Uint128, bool) {
	bytes, ok := takeBytes(payload, cursor, 16)
	if !ok {
		return Uint128{}, false
	}
	return Uint128FromLE(bytes)
}

func take32(payload []byte, cursor *int) ([externalapi.DomainHashSize]byte, bool) {
	bytes, ok := takeBytes(payload, cursor, externalapi.DomainHashSize)
	if !ok {
		return [externalapi.DomainHashSize]byte{}, false
	}
	var out [externalapi.DomainHashSize]byte
	copy(out[:], bytes)
	return out, true
}

func takeVec(payload []byte, cursor *int, length int) ([]byte, bool) {
	bytes, ok := takeBytes(payload, cursor, length)
	if !ok {
		return nil, false
	}
	return append([]byte(nil), bytes...), true
}
