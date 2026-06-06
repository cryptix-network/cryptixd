package consensusstatemanager_test

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus"
	"github.com/cryptix-network/cryptixd/domain/consensus/model"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/testapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/constants"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/txscript"
	"github.com/cryptix-network/cryptixd/domain/dagconfig"
)

const (
	atomicStressDefaultRounds      = 45
	atomicStressWalletCount        = 8
	atomicStressCoinbaseBlocks     = 80
	atomicStressOwnerFanoutInputs  = 30
	atomicStressFanoutOutputs      = 10
	atomicStressWalletFundingUTXOs = 14
	atomicStressTxFee              = 1_000
	atomicStressBaseInitialSupply  = 1_000_000
	atomicStressBaseMaxSupply      = 100_000_000
	atomicStressLiquidityMaxSupply = 1_000_000
	atomicStressExpectedStateHash  = "158620cc4029cf8b001a2410266a62142749bf2bbec6a13f5778d1500ec2a1f8"
	atomicStressExpectedTokenHash  = "2e21f9ec6ab0556bde6c541dccf34a85bb2d7e79bdee88ae48c8446cdd341ff3"
)

func TestAtomicDeterministicStressCrossCheckStateHash(t *testing.T) {
	consensusConfig := atomicStressConsensusConfig()
	tc, teardown, err := consensus.NewFactory().NewTestConsensus(consensusConfig, "TestAtomicDeterministicStressCrossCheckStateHash")
	if err != nil {
		t.Fatalf("NewTestConsensus: %+v", err)
	}
	defer teardown(false)

	owner := newAtomicStressActor(t, "owner")
	receiver := newAtomicStressActor(t, "receiver")
	wallets := make([]*atomicStressActor, atomicStressWalletCount)
	for i := range wallets {
		wallets[i] = newAtomicStressActor(t, fmt.Sprintf("wallet-%02d", i))
	}

	miner := newAtomicStressMiner(tc, owner)
	counters := atomicStressCounters{}
	var firstCoinbaseTxID *externalapi.DomainTransactionID

	for i := 0; i < atomicStressCoinbaseBlocks; i++ {
		block, _ := miner.mine(t, fmt.Sprintf("coinbase funding %d", i), nil)
		if i == 0 {
			firstCoinbaseTxID = consensushashing.TransactionID(block.Transactions[0])
			values := make([]uint64, 0, len(block.Transactions[0].Outputs))
			for _, output := range block.Transactions[0].Outputs {
				values = append(values, output.Value)
			}
			t.Logf("go first coinbase details: outputs=%d values=%v payload=%x",
				len(block.Transactions[0].Outputs),
				values,
				block.Transactions[0].Payload,
			)
		}
		recordCoinbaseOutputs(t, block, owner)
		counters.minedStressBlocks++
	}

	splitTxs, splitAssignments := buildOwnerFanoutTransactions(t, owner)
	miner.mine(t, "owner fanout", splitTxs)
	recordAssignments(t, splitTxs, splitAssignments)
	counters.native += len(splitTxs)
	counters.maxBlockTemplateTxs = maxInt(counters.maxBlockTemplateTxs, len(splitTxs)+1)
	counters.minedStressBlocks++

	fundingTxs, fundingAssignments := buildWalletFundingTransactions(t, owner, wallets)
	miner.mine(t, "wallet funding", fundingTxs)
	recordAssignments(t, fundingTxs, fundingAssignments)
	counters.native += len(fundingTxs)
	counters.maxBlockTemplateTxs = maxInt(counters.maxBlockTemplateTxs, len(fundingTxs)+1)
	counters.minedStressBlocks++

	setupTxs := make([]*externalapi.DomainTransaction, 0, 2)
	setupAssignments := make([][]*atomicStressActor, 0, 2)
	createdAssets := make([]atomicStressAssetExpectation, 0)

	basePayload := catCreateAssetWithMintPayload(
		owner.nextOwnerNonce,
		0,
		1,
		atomicStressBaseMaxSupply,
		owner.ownerID,
		owner.ownerID,
		atomicStressBaseInitialSupply,
		"Stress Base",
		"GSTB",
		[]byte("go deterministic base asset"),
	)
	owner.nextOwnerNonce++
	baseTx, baseOwners := buildSingleInputPayloadTx(t, owner, basePayload, nil, atomicStressTxFee)
	baseAssetID := *consensushashing.TransactionID(baseTx).ByteArray()
	owner.expectedBaseBalance = atomicStressBaseInitialSupply
	setupTxs = append(setupTxs, baseTx)
	setupAssignments = append(setupAssignments, baseOwners)

	liquidityPayload := catCreateLiquidityPayload(
		owner.nextOwnerNonce,
		atomicStressLiquidityMaxSupply,
		owner.recipientPayload,
		"Stress Liquidity",
		"GSLQ",
		[]byte("go deterministic liquidity asset"),
	)
	owner.nextOwnerNonce++
	liquidityTx, liquidityOwners := buildCreateLiquidityTransaction(t, owner, liquidityPayload)
	liquidityAssetID := *consensushashing.TransactionID(liquidityTx).ByteArray()
	setupTxs = append(setupTxs, liquidityTx)
	setupAssignments = append(setupAssignments, liquidityOwners)
	t.Logf("go deterministic atomic stress ids: owner_id=%x first_coinbase_tx=%s base_asset_id=%x liquidity_asset_id=%x",
		owner.ownerID,
		firstCoinbaseTxID,
		baseAssetID,
		liquidityAssetID,
	)

	miner.mine(t, "base and liquidity setup", setupTxs)
	recordAssignments(t, setupTxs, setupAssignments)
	logAtomicStressCheckpoint(t, tc, "after_setup")
	counters.tokenCreates++
	counters.maxBlockTemplateTxs = maxInt(counters.maxBlockTemplateTxs, len(setupTxs)+1)
	counters.minedStressBlocks++

	baseAssetNonce := uint64(1)
	liquidityAssetNonce := uint64(1)
	rounds := atomicStressRoundsFromEnv(t)

	for round := 0; round < rounds; round++ {
		phaseTxs := make([]*externalapi.DomainTransaction, 0, 80)
		phaseAssignments := make([][]*atomicStressActor, 0, 80)

		for i := 0; i < 4; i++ {
			tx, owners := buildNativeTransferTx(t, owner, owner, 40_000+uint64(round*37+i*11), atomicStressTxFee)
			phaseTxs = append(phaseTxs, tx)
			phaseAssignments = append(phaseAssignments, owners)
			counters.native++
		}
		for i := 0; i < 4; i++ {
			payload := messengerPayload(round, i, owner.ownerID[:], 96+(round+i)%64)
			tx, owners := buildSingleInputPayloadTx(t, owner, payload, nil, atomicStressTxFee)
			phaseTxs = append(phaseTxs, tx)
			phaseAssignments = append(phaseAssignments, owners)
			counters.messenger++
		}
		for i := 0; i < 2; i++ {
			payload := rawStressPayload(round, i, 160+(round+i)%96)
			tx, owners := buildSingleInputPayloadTx(t, owner, payload, nil, atomicStressTxFee)
			phaseTxs = append(phaseTxs, tx)
			phaseAssignments = append(phaseAssignments, owners)
			counters.rawPayloads++
		}

		for i, wallet := range wallets {
			to := wallets[(i+round+1)%len(wallets)]
			tx, owners := buildNativeTransferTx(t, wallet, to, 9_000+uint64(round*17+i*13), atomicStressTxFee)
			phaseTxs = append(phaseTxs, tx)
			phaseAssignments = append(phaseAssignments, owners)
			counters.native++
			counters.walletNative++

			payload := messengerPayload(round, i+10, wallet.ownerID[:], 72+(round+i)%48)
			tx, owners = buildSingleInputPayloadTx(t, wallet, payload, nil, atomicStressTxFee)
			phaseTxs = append(phaseTxs, tx)
			phaseAssignments = append(phaseAssignments, owners)
			counters.messenger++
			counters.walletMessenger++

			payload = rawStressPayload(round, i+20, 96+(round+i)%80)
			tx, owners = buildSingleInputPayloadTx(t, wallet, payload, nil, atomicStressTxFee)
			phaseTxs = append(phaseTxs, tx)
			phaseAssignments = append(phaseAssignments, owners)
			counters.rawPayloads++
			counters.walletRawPayloads++
		}

		for i := 0; i < 6; i++ {
			amount := uint64(10 + round%7 + i)
			maxSupply := 10_000 + amount + uint64(round*20+i)
			payload := catCreateAssetWithMintPayload(
				owner.nextOwnerNonce,
				byte((round+i)%4),
				1,
				maxSupply,
				owner.ownerID,
				owner.ownerID,
				amount,
				fmt.Sprintf("Owner Stress %02d %02d", round, i),
				fmt.Sprintf("O%02d%02d", round%100, i),
				[]byte("owner stress asset"),
			)
			owner.nextOwnerNonce++
			tx, owners := buildSingleInputPayloadTx(t, owner, payload, nil, atomicStressTxFee)
			assetID := *consensushashing.TransactionID(tx).ByteArray()
			createdAssets = append(createdAssets, atomicStressAssetExpectation{
				assetID:              assetID,
				creatorOwnerID:       owner.ownerID,
				mintAuthorityOwnerID: owner.ownerID,
				initialOwnerID:       owner.ownerID,
				initialAmount:        amount,
			})
			phaseTxs = append(phaseTxs, tx)
			phaseAssignments = append(phaseAssignments, owners)
			counters.tokenCreates++
		}

		for i := 0; i < 4; i++ {
			wallet := wallets[(round+i)%len(wallets)]
			amount := uint64(5 + round%5 + i)
			maxSupply := 5_000 + amount + uint64(round*10+i)
			payload := catCreateAssetWithMintPayload(
				wallet.nextOwnerNonce,
				byte((round+i)%3),
				1,
				maxSupply,
				wallet.ownerID,
				wallet.ownerID,
				amount,
				fmt.Sprintf("Wallet Stress %02d %02d", round, i),
				fmt.Sprintf("W%02d%02d", round%100, i),
				[]byte("wallet stress asset"),
			)
			wallet.nextOwnerNonce++
			tx, owners := buildSingleInputPayloadTx(t, wallet, payload, nil, atomicStressTxFee)
			assetID := *consensushashing.TransactionID(tx).ByteArray()
			createdAssets = append(createdAssets, atomicStressAssetExpectation{
				assetID:              assetID,
				creatorOwnerID:       wallet.ownerID,
				mintAuthorityOwnerID: wallet.ownerID,
				initialOwnerID:       wallet.ownerID,
				initialAmount:        amount,
			})
			phaseTxs = append(phaseTxs, tx)
			phaseAssignments = append(phaseAssignments, owners)
			counters.tokenCreates++
			counters.walletTokenCreates++
		}

		for i := 0; i < 4; i++ {
			mintAmount := uint64(70 + round%19 + i*3)
			payload := catMintPayload(baseAssetID, baseAssetNonce, owner.ownerID, mintAmount)
			baseAssetNonce++
			tx, owners := buildSingleInputPayloadTx(t, owner, payload, nil, atomicStressTxFee)
			phaseTxs = append(phaseTxs, tx)
			phaseAssignments = append(phaseAssignments, owners)
			owner.expectedBaseBalance += mintAmount
			counters.baseOps++

			recipient := wallets[(round+i)%len(wallets)]
			transferAmount := uint64(11 + (round+i)%9)
			payload = catTransferPayload(baseAssetID, baseAssetNonce, recipient.ownerID, transferAmount)
			baseAssetNonce++
			tx, owners = buildSingleInputPayloadTx(t, owner, payload, nil, atomicStressTxFee)
			phaseTxs = append(phaseTxs, tx)
			phaseAssignments = append(phaseAssignments, owners)
			owner.expectedBaseBalance -= transferAmount
			recipient.expectedBaseBalance += transferAmount
			counters.baseOps++

			burnAmount := uint64(3 + (round+i)%5)
			payload = catBurnPayload(baseAssetID, baseAssetNonce, burnAmount)
			baseAssetNonce++
			tx, owners = buildSingleInputPayloadTx(t, owner, payload, nil, atomicStressTxFee)
			phaseTxs = append(phaseTxs, tx)
			phaseAssignments = append(phaseAssignments, owners)
			owner.expectedBaseBalance -= burnAmount
			counters.baseOps++
		}

		sortStressTransactionsWithAssignments(phaseTxs, phaseAssignments)
		miner.mine(t, fmt.Sprintf("round %d mixed stress", round), phaseTxs)
		recordAssignments(t, phaseTxs, phaseAssignments)
		counters.maxBlockTemplateTxs = maxInt(counters.maxBlockTemplateTxs, len(phaseTxs)+1)
		counters.minedStressBlocks++
		if round == 0 {
			logAtomicStressCheckpoint(t, tc, "after_round_0_mixed")
		}

		state := virtualAtomicState(t, tc)
		buyTx, buyOwners := buildLiquidityBuyTransaction(t, owner, state, liquidityAssetID, liquidityAssetNonce, 1+uint64(round%4))
		if round == 0 {
			logStressTransaction(t, "go round0 buy", buyTx)
		}
		liquidityAssetNonce++
		miner.mine(t, fmt.Sprintf("round %d liquidity buy", round), []*externalapi.DomainTransaction{buyTx})
		recordAssignments(t, []*externalapi.DomainTransaction{buyTx}, [][]*atomicStressActor{buyOwners})
		counters.buys++
		counters.maxBlockTemplateTxs = maxInt(counters.maxBlockTemplateTxs, 2)
		counters.minedStressBlocks++
		if round == 0 {
			logAtomicStressCheckpoint(t, tc, "after_round_0_buy")
			logLiquidityState(t, tc, "after_round_0_buy", liquidityAssetID, owner.ownerID)
		}

		state = virtualAtomicState(t, tc)
		if liquidityTokenBalance(state, liquidityAssetID, owner.ownerID) > 0 {
			tokenIn := uint64(1 + round%2)
			if balance := liquidityTokenBalance(state, liquidityAssetID, owner.ownerID); tokenIn > balance {
				tokenIn = balance
			}
			sellTx, sellOwners := buildLiquiditySellTransaction(t, owner, state, liquidityAssetID, liquidityAssetNonce, tokenIn)
			liquidityAssetNonce++
			miner.mine(t, fmt.Sprintf("round %d liquidity sell", round), []*externalapi.DomainTransaction{sellTx})
			recordAssignments(t, []*externalapi.DomainTransaction{sellTx}, [][]*atomicStressActor{sellOwners})
			counters.sells++
			counters.maxBlockTemplateTxs = maxInt(counters.maxBlockTemplateTxs, 2)
			counters.minedStressBlocks++
			if round == 0 {
				logAtomicStressCheckpoint(t, tc, "after_round_0_sell")
			}
		}

		if round%3 == 2 {
			state = virtualAtomicState(t, tc)
			claimTx, claimOwners, ok := buildLiquidityClaimTransaction(t, owner, state, liquidityAssetID, liquidityAssetNonce)
			if ok {
				liquidityAssetNonce++
				miner.mine(t, fmt.Sprintf("round %d liquidity fee claim", round), []*externalapi.DomainTransaction{claimTx})
				recordAssignments(t, []*externalapi.DomainTransaction{claimTx}, [][]*atomicStressActor{claimOwners})
				counters.claims++
				counters.maxBlockTemplateTxs = maxInt(counters.maxBlockTemplateTxs, 2)
				counters.minedStressBlocks++
			}
		}
		if round < 3 {
			logAtomicStressCheckpoint(t, tc, fmt.Sprintf("after_round_%d", round))
		}
	}

	miner.mine(t, "final atomic state checkpoint", nil)
	counters.minedStressBlocks++

	finalState := virtualAtomicState(t, tc)
	assertAtomicStressFinalState(t, tc, finalState, owner, receiver, wallets, baseAssetID, liquidityAssetID, createdAssets, baseAssetNonce, liquidityAssetNonce, counters, rounds)
	finalHash := finalState.CanonicalHash()
	selectedParent, err := tc.GetVirtualSelectedParent()
	if err != nil {
		t.Fatalf("GetVirtualSelectedParent for summary: %+v", err)
	}
	tokenAuditHash, tokenAuditOK, err := tc.GetAtomicTokenStateHash(selectedParent)
	if err != nil {
		t.Fatalf("GetAtomicTokenStateHash for summary: %+v", err)
	}
	if !tokenAuditOK {
		t.Fatalf("final Atomic token audit hash unavailable")
	}
	t.Logf("go deterministic atomic stress summary: rounds=%d wallets=%d active_wallets=%d native=%d wallet_native=%d messenger=%d wallet_messenger=%d raw_payloads=%d wallet_raw_payloads=%d token_creates=%d wallet_token_creates=%d base_ops=%d buys=%d sells=%d claims=%d max_block_template_txs=%d mined_stress_blocks=%d state_hash=%x",
		rounds,
		len(wallets),
		activeStressWalletCount(wallets),
		counters.native,
		counters.walletNative,
		counters.messenger,
		counters.walletMessenger,
		counters.rawPayloads,
		counters.walletRawPayloads,
		counters.tokenCreates,
		counters.walletTokenCreates,
		counters.baseOps,
		counters.buys,
		counters.sells,
		counters.claims,
		counters.maxBlockTemplateTxs,
		counters.minedStressBlocks,
		finalHash,
	)
	t.Logf("go deterministic atomic stress token_audit_hash=%x", tokenAuditHash)
}

type atomicStressCounters struct {
	native              int
	walletNative        int
	messenger           int
	walletMessenger     int
	rawPayloads         int
	walletRawPayloads   int
	tokenCreates        int
	walletTokenCreates  int
	baseOps             int
	buys                int
	sells               int
	claims              int
	maxBlockTemplateTxs int
	minedStressBlocks   int
}

type atomicStressActor struct {
	label               string
	redeemScript        []byte
	scriptPublicKey     *externalapi.ScriptPublicKey
	ownerID             [externalapi.DomainHashSize]byte
	recipientPayload    []byte
	utxos               []atomicStressUTXO
	nextOwnerNonce      uint64
	expectedBaseBalance uint64
}

type atomicStressUTXO struct {
	outpoint        externalapi.DomainOutpoint
	amount          uint64
	scriptPublicKey *externalapi.ScriptPublicKey
	redeemScript    []byte
}

type atomicStressPayment struct {
	actor  *atomicStressActor
	amount uint64
}

type atomicStressAssetExpectation struct {
	assetID              [externalapi.DomainHashSize]byte
	creatorOwnerID       [externalapi.DomainHashSize]byte
	mintAuthorityOwnerID [externalapi.DomainHashSize]byte
	initialOwnerID       [externalapi.DomainHashSize]byte
	initialAmount        uint64
}

type atomicStressMiner struct {
	tc        testapi.TestConsensus
	coinbase  *externalapi.DomainCoinbaseData
	nextTime  int64
	nextNonce uint64
}

func atomicStressConsensusConfig() *consensus.Config {
	params := dagconfig.SimnetParams
	params.SkipProofOfWork = true
	params.BlockCoinbaseMaturity = 0
	params.K = 0
	params.MergeSetSizeLimit = 1
	params.MaxBlockParents = 4
	params.FinalityDuration = 2 * params.TargetTimePerBlock
	params.PruningProofM = 1
	params.PayloadHfActivationDAAScore = 0
	return &consensus.Config{
		Params:                          params,
		EnableSanityCheckPruningUTXOSet: true,
	}
}

func atomicStressRoundsFromEnv(t *testing.T) int {
	t.Helper()
	raw := strings.TrimSpace(os.Getenv("CRYPTIX_GO_STRESS_ROUNDS"))
	if raw == "" {
		return atomicStressDefaultRounds
	}
	rounds, err := strconv.Atoi(raw)
	if err != nil || rounds <= 0 {
		t.Fatalf("CRYPTIX_GO_STRESS_ROUNDS must be a positive integer, got %q", raw)
	}
	return rounds
}

func expectedAtomicStressHash(envKey string, defaultHash string, rounds int) string {
	if expected := strings.TrimSpace(os.Getenv(envKey)); expected != "" {
		return expected
	}
	if rounds == atomicStressDefaultRounds {
		return defaultHash
	}
	return ""
}

func newAtomicStressActor(t *testing.T, label string) *atomicStressActor {
	t.Helper()
	redeemScript, err := txscript.NewScriptBuilder().
		AddData([]byte("go-atomic-stress:" + label)).
		AddOp(txscript.OpDrop).
		AddOp(txscript.OpTrue).
		Script()
	if err != nil {
		t.Fatalf("build redeem script %s: %+v", label, err)
	}
	script, err := txscript.PayToScriptHashScript(redeemScript)
	if err != nil {
		t.Fatalf("PayToScriptHashScript %s: %+v", label, err)
	}
	scriptPublicKey := &externalapi.ScriptPublicKey{Script: script, Version: constants.MaxScriptPublicKeyVersion}
	ownerID, ok := atomicstate.OwnerIDFromScript(scriptPublicKey)
	if !ok {
		t.Fatalf("OwnerIDFromScript failed for %s", label)
	}
	return &atomicStressActor{
		label:            label,
		redeemScript:     redeemScript,
		scriptPublicKey:  scriptPublicKey,
		ownerID:          ownerID,
		recipientPayload: append([]byte(nil), script[2:34]...),
		nextOwnerNonce:   1,
	}
}

func newAtomicStressMiner(tc testapi.TestConsensus, coinbaseActor *atomicStressActor) *atomicStressMiner {
	return &atomicStressMiner{
		tc: tc,
		coinbase: &externalapi.DomainCoinbaseData{
			ScriptPublicKey: coinbaseActor.scriptPublicKey,
			ExtraData:       []byte("go-atomic-stress"),
		},
		nextTime:  tc.DAGParams().GenesisBlock.Header.TimeInMilliseconds() + 1_000,
		nextNonce: 1,
	}
}

func (miner *atomicStressMiner) mine(t *testing.T, label string, transactions []*externalapi.DomainTransaction) (*externalapi.DomainBlock, *externalapi.DomainHash) {
	t.Helper()
	template, err := miner.tc.BuildBlockTemplate(miner.coinbase, transactions)
	if err != nil {
		logStressInvalidCandidates(t, transactions, err)
		t.Fatalf("%s BuildBlockTemplate: %+v", label, err)
	}
	block := cloneStressBlockWithoutUTXOEntries(template.Block)
	header := block.Header.ToMutable()
	header.SetTimeInMilliseconds(miner.nextTime)
	header.SetNonce(miner.nextNonce)
	block.Header = header.ToImmutable()
	miner.nextTime += 1_000
	miner.nextNonce++

	if err := miner.tc.ValidateAndInsertBlock(block, true); err != nil {
		t.Fatalf("%s ValidateAndInsertBlock txs=%d: %+v", label, len(transactions), err)
	}
	blockHash := consensushashing.BlockHash(block)
	valid, reason, err := miner.tc.IsStoredBlockUTXOCommitmentValid(blockHash)
	if err != nil {
		t.Fatalf("%s IsStoredBlockUTXOCommitmentValid: %+v", label, err)
	}
	if !valid {
		t.Fatalf("%s stored UTXO/Atomic commitment is invalid: %s", label, reason)
	}
	if _, ok, err := miner.tc.GetAtomicTokenStateHash(blockHash); err != nil {
		t.Fatalf("%s GetAtomicTokenStateHash: %+v", label, err)
	} else if !ok {
		t.Fatalf("%s block has no Atomic token state hash", label)
	}
	return block, blockHash
}

func sortStressTransactionsWithAssignments(transactions []*externalapi.DomainTransaction, assignments [][]*atomicStressActor) {
	bundles := make([]atomicStressTransactionBundle, len(transactions))
	for i := range transactions {
		bundles[i] = atomicStressTransactionBundle{transaction: transactions[i], assignments: assignments[i]}
	}
	sort.SliceStable(bundles, func(i, j int) bool {
		return subnetworks.Less(bundles[i].transaction.SubnetworkID, bundles[j].transaction.SubnetworkID)
	})
	for i, bundle := range bundles {
		transactions[i] = bundle.transaction
		assignments[i] = bundle.assignments
	}
}

type atomicStressTransactionBundle struct {
	transaction *externalapi.DomainTransaction
	assignments []*atomicStressActor
}

func logStressInvalidCandidates(t *testing.T, transactions []*externalapi.DomainTransaction, err error) {
	t.Helper()
	errText := err.Error()
	for i, tx := range transactions {
		txID := consensushashing.TransactionID(tx)
		if !strings.Contains(errText, txID.String()) {
			continue
		}
		inputs := make([]string, 0, len(tx.Inputs))
		for _, input := range tx.Inputs {
			inputs = append(inputs, input.PreviousOutpoint.String())
		}
		t.Logf("invalid stress candidate index=%d tx=%s subnetwork=%s payload=%s inputs=%s outputs=%d",
			i, txID, tx.SubnetworkID, describeStressPayload(tx.Payload), strings.Join(inputs, ","), len(tx.Outputs))
	}
}

func describeStressPayload(payload []byte) string {
	if len(payload) == 0 {
		return "native"
	}
	if parsed, err := atomicstate.ParsePayload(payload); err == nil && parsed != nil {
		return fmt.Sprintf("CAT nonce=%d op=%T", parsed.Nonce, parsed.Op)
	}
	prefix := payload
	if len(prefix) > 24 {
		prefix = prefix[:24]
	}
	return hex.EncodeToString(prefix)
}

func cloneStressBlockWithoutUTXOEntries(block *externalapi.DomainBlock) *externalapi.DomainBlock {
	clone := block.Clone()
	for _, tx := range clone.Transactions {
		for _, input := range tx.Inputs {
			input.UTXOEntry = nil
		}
	}
	return clone
}

func buildOwnerFanoutTransactions(t *testing.T, owner *atomicStressActor) ([]*externalapi.DomainTransaction, [][]*atomicStressActor) {
	t.Helper()
	txs := make([]*externalapi.DomainTransaction, 0, atomicStressOwnerFanoutInputs)
	assignments := make([][]*atomicStressActor, 0, atomicStressOwnerFanoutInputs)
	for i := 0; i < atomicStressOwnerFanoutInputs; i++ {
		tx, owners := buildFanoutTx(t, owner, owner, atomicStressFanoutOutputs, atomicStressTxFee)
		txs = append(txs, tx)
		assignments = append(assignments, owners)
	}
	return txs, assignments
}

func buildWalletFundingTransactions(t *testing.T, owner *atomicStressActor, wallets []*atomicStressActor) ([]*externalapi.DomainTransaction, [][]*atomicStressActor) {
	t.Helper()
	txs := make([]*externalapi.DomainTransaction, 0, len(wallets))
	assignments := make([][]*atomicStressActor, 0, len(wallets))
	for _, wallet := range wallets {
		payments := make([]atomicStressPayment, 0, atomicStressWalletFundingUTXOs)
		for i := 0; i < atomicStressWalletFundingUTXOs; i++ {
			payments = append(payments, atomicStressPayment{actor: wallet, amount: 35_000_000 + uint64(i)*10_000})
		}
		tx, owners := buildSingleInputTxWithPayments(t, owner, subnetworks.SubnetworkIDNative, nil, payments, atomicStressTxFee)
		txs = append(txs, tx)
		assignments = append(assignments, owners)
	}
	return txs, assignments
}

func buildFanoutTx(t *testing.T, from *atomicStressActor, to *atomicStressActor, outputs int, fee uint64) (*externalapi.DomainTransaction, []*atomicStressActor) {
	t.Helper()
	utxo := from.popUTXO(t, fee+uint64(outputs))
	spendable := utxo.amount - fee
	value := spendable / uint64(outputs)
	if value == 0 {
		t.Fatalf("fanout value for %s is zero from utxo amount %d", from.label, utxo.amount)
	}
	remainder := spendable % uint64(outputs)
	txOutputs := make([]*externalapi.DomainTransactionOutput, 0, outputs)
	owners := make([]*atomicStressActor, 0, outputs)
	for i := 0; i < outputs; i++ {
		amount := value
		if i == outputs-1 {
			amount += remainder
		}
		txOutputs = append(txOutputs, atomicStressOutput(to, amount))
		owners = append(owners, to)
	}
	return atomicStressTransaction([]atomicStressUTXO{utxo}, txOutputs, subnetworks.SubnetworkIDNative, nil), owners
}

func buildNativeTransferTx(
	t *testing.T,
	from *atomicStressActor,
	to *atomicStressActor,
	amount uint64,
	fee uint64,
) (*externalapi.DomainTransaction, []*atomicStressActor) {
	t.Helper()
	return buildSingleInputTxWithPayments(t, from, subnetworks.SubnetworkIDNative, nil, []atomicStressPayment{{actor: to, amount: amount}}, fee)
}

func buildSingleInputPayloadTx(
	t *testing.T,
	from *atomicStressActor,
	payload []byte,
	payments []atomicStressPayment,
	fee uint64,
) (*externalapi.DomainTransaction, []*atomicStressActor) {
	t.Helper()
	return buildSingleInputTxWithPayments(t, from, subnetworks.SubnetworkIDPayload, payload, payments, fee)
}

func buildSingleInputTxWithPayments(
	t *testing.T,
	from *atomicStressActor,
	subnetworkID externalapi.DomainSubnetworkID,
	payload []byte,
	payments []atomicStressPayment,
	fee uint64,
) (*externalapi.DomainTransaction, []*atomicStressActor) {
	t.Helper()
	totalPayment := uint64(0)
	for _, payment := range payments {
		totalPayment = checkedAddTest(t, totalPayment, payment.amount)
	}
	utxo := from.popUTXO(t, checkedAddTest(t, totalPayment, fee+1))
	change := utxo.amount - totalPayment - fee
	if change == 0 {
		t.Fatalf("%s single-input tx would produce zero anchor change", from.label)
	}
	txOutputs := make([]*externalapi.DomainTransactionOutput, 0, len(payments)+1)
	owners := make([]*atomicStressActor, 0, len(payments)+1)
	for _, payment := range payments {
		txOutputs = append(txOutputs, atomicStressOutput(payment.actor, payment.amount))
		owners = append(owners, payment.actor)
	}
	txOutputs = append(txOutputs, atomicStressOutput(from, change))
	owners = append(owners, from)
	return atomicStressTransaction([]atomicStressUTXO{utxo}, txOutputs, subnetworkID, payload), owners
}

func buildCreateLiquidityTransaction(t *testing.T, owner *atomicStressActor, payload []byte) (*externalapi.DomainTransaction, []*atomicStressActor) {
	t.Helper()
	seedReserve := uint64(constants.SompiPerCryptix)
	utxo := owner.popUTXO(t, seedReserve+atomicStressTxFee+1)
	change := utxo.amount - seedReserve - atomicStressTxFee
	if change == 0 {
		t.Fatalf("create-liquidity owner change is zero")
	}
	txOutputs := []*externalapi.DomainTransactionOutput{
		atomicStressOutput(owner, change),
		atomicStressVaultOutput(seedReserve),
	}
	return atomicStressTransaction([]atomicStressUTXO{utxo}, txOutputs, subnetworks.SubnetworkIDPayload, payload), []*atomicStressActor{owner, nil}
}

func buildLiquidityBuyTransaction(
	t *testing.T,
	owner *atomicStressActor,
	state *atomicstate.State,
	assetID [externalapi.DomainHashSize]byte,
	assetNonce uint64,
	targetTokenOut uint64,
) (*externalapi.DomainTransaction, []*atomicStressActor) {
	t.Helper()
	asset, pool := liquidityAssetAndPool(t, state, assetID)
	spendable, ok := pool.RealTokenReserves.Sub(atomicstate.Uint128FromUint64(1))
	if !ok || spendable.IsZero() {
		t.Fatalf("liquidity pool has no spendable real token reserves")
	}
	if targetTokenOut > spendable.Lo {
		targetTokenOut = spendable.Lo
	}
	cpayIn, err := minGrossInputForTokenOutStress(pool.RealTokenReserves, pool.VirtualCPayReserves, pool.VirtualTokenReserves, atomicstate.Uint128FromUint64(targetTokenOut), pool.FeeBPS)
	if err != nil {
		t.Fatalf("minGrossInputForTokenOutStress: %+v", err)
	}
	utxo := owner.popUTXO(t, cpayIn+atomicStressTxFee+1)
	change := utxo.amount - cpayIn - atomicStressTxFee
	vaultUTXO := atomicStressVaultUTXO(*pool)
	payload := catBuyLiquidityPayload(assetID, assetNonce, pool.PoolNonce, cpayIn, targetTokenOut)
	txOutputs := []*externalapi.DomainTransactionOutput{
		atomicStressOutput(owner, change),
		atomicStressVaultOutput(pool.VaultValueSompi + cpayIn),
	}
	_ = asset
	return atomicStressTransaction([]atomicStressUTXO{utxo, vaultUTXO}, txOutputs, subnetworks.SubnetworkIDPayload, payload), []*atomicStressActor{owner, nil}
}

func buildLiquiditySellTransaction(
	t *testing.T,
	owner *atomicStressActor,
	state *atomicstate.State,
	assetID [externalapi.DomainHashSize]byte,
	assetNonce uint64,
	tokenIn uint64,
) (*externalapi.DomainTransaction, []*atomicStressActor) {
	t.Helper()
	_, pool := liquidityAssetAndPool(t, state, assetID)
	tokenIn128 := atomicstate.Uint128FromUint64(tokenIn)
	grossOut, _, _, _, err := cpmmSellStress(pool.RealCPayReservesSompi, pool.VirtualCPayReserves, pool.VirtualTokenReserves, tokenIn128)
	if err != nil {
		t.Fatalf("cpmmSellStress: %+v", err)
	}
	fee, err := calculateTradeFeeStress(grossOut, pool.FeeBPS)
	if err != nil {
		t.Fatalf("sell fee: %+v", err)
	}
	cpayOut := grossOut - fee
	if cpayOut == 0 {
		t.Fatalf("sell cpayOut is zero")
	}
	utxo := owner.popUTXO(t, atomicStressTxFee+1)
	change := utxo.amount - atomicStressTxFee
	vaultUTXO := atomicStressVaultUTXO(*pool)
	if pool.VaultValueSompi <= cpayOut {
		t.Fatalf("sell would drain vault: vault=%d cpayOut=%d", pool.VaultValueSompi, cpayOut)
	}
	payload := catSellLiquidityPayload(assetID, assetNonce, pool.PoolNonce, tokenIn, cpayOut, 0)
	txOutputs := []*externalapi.DomainTransactionOutput{
		atomicStressOutput(owner, cpayOut),
		atomicStressVaultOutput(pool.VaultValueSompi - cpayOut),
		atomicStressOutput(owner, change),
	}
	return atomicStressTransaction([]atomicStressUTXO{utxo, vaultUTXO}, txOutputs, subnetworks.SubnetworkIDPayload, payload), []*atomicStressActor{owner, nil, owner}
}

func buildLiquidityClaimTransaction(
	t *testing.T,
	owner *atomicStressActor,
	state *atomicstate.State,
	assetID [externalapi.DomainHashSize]byte,
	assetNonce uint64,
) (*externalapi.DomainTransaction, []*atomicStressActor, bool) {
	t.Helper()
	_, pool := liquidityAssetAndPool(t, state, assetID)
	if len(pool.FeeRecipients) == 0 || pool.FeeRecipients[0].OwnerID != owner.ownerID {
		t.Fatalf("liquidity fee recipient is not the stress owner")
	}
	unclaimed := pool.FeeRecipients[0].UnclaimedSompi
	if unclaimed == 0 {
		return nil, nil, false
	}
	claimAmount := minUint64(unclaimed, 250_000)
	utxo := owner.popUTXO(t, atomicStressTxFee+1)
	change := utxo.amount - atomicStressTxFee
	vaultUTXO := atomicStressVaultUTXO(*pool)
	if pool.VaultValueSompi <= claimAmount {
		t.Fatalf("claim would drain vault: vault=%d claim=%d", pool.VaultValueSompi, claimAmount)
	}
	payload := catClaimLiquidityPayload(assetID, assetNonce, pool.PoolNonce, 0, claimAmount, 0)
	txOutputs := []*externalapi.DomainTransactionOutput{
		atomicStressOutput(owner, claimAmount),
		atomicStressVaultOutput(pool.VaultValueSompi - claimAmount),
		atomicStressOutput(owner, change),
	}
	return atomicStressTransaction([]atomicStressUTXO{utxo, vaultUTXO}, txOutputs, subnetworks.SubnetworkIDPayload, payload), []*atomicStressActor{owner, nil, owner}, true
}

func atomicStressTransaction(
	utxos []atomicStressUTXO,
	outputs []*externalapi.DomainTransactionOutput,
	subnetworkID externalapi.DomainSubnetworkID,
	payload []byte,
) *externalapi.DomainTransaction {
	inputs := make([]*externalapi.DomainTransactionInput, 0, len(utxos))
	for _, utxo := range utxos {
		inputs = append(inputs, atomicStressInput(utxo))
	}
	return &externalapi.DomainTransaction{
		Version:      constants.MaxTransactionVersion,
		Inputs:       inputs,
		Outputs:      outputs,
		SubnetworkID: subnetworkID,
		Gas:          0,
		Payload:      append([]byte(nil), payload...),
	}
}

func atomicStressInput(utxo atomicStressUTXO) *externalapi.DomainTransactionInput {
	signatureScript := []byte{}
	if len(utxo.redeemScript) > 0 {
		var err error
		signatureScript, err = txscript.PayToScriptHashSignatureScript(utxo.redeemScript, nil)
		if err != nil {
			panic(err)
		}
	}
	return &externalapi.DomainTransactionInput{
		PreviousOutpoint: utxo.outpoint,
		SignatureScript:  signatureScript,
		Sequence:         constants.MaxTxInSequenceNum,
		SigOpCount:       0,
	}
}

func atomicStressOutput(actor *atomicStressActor, amount uint64) *externalapi.DomainTransactionOutput {
	if amount == 0 {
		panic("zero-value stress output")
	}
	return &externalapi.DomainTransactionOutput{Value: amount, ScriptPublicKey: actor.scriptPublicKey}
}

func atomicStressVaultOutput(amount uint64) *externalapi.DomainTransactionOutput {
	if amount == 0 {
		panic("zero-value liquidity vault output")
	}
	return &externalapi.DomainTransactionOutput{
		Value: amount,
		ScriptPublicKey: &externalapi.ScriptPublicKey{
			Script:  []byte{txscript.OpData4, 'C', 'L', 'V', '1', txscript.OpDrop, txscript.OpTrue},
			Version: constants.MaxScriptPublicKeyVersion,
		},
	}
}

func atomicStressVaultUTXO(pool atomicstate.LiquidityPoolState) atomicStressUTXO {
	return atomicStressUTXO{
		outpoint:        pool.VaultOutpoint,
		amount:          pool.VaultValueSompi,
		scriptPublicKey: atomicStressVaultOutput(pool.VaultValueSompi).ScriptPublicKey,
	}
}

func (actor *atomicStressActor) popUTXO(t *testing.T, minAmount uint64) atomicStressUTXO {
	t.Helper()
	for i, utxo := range actor.utxos {
		if utxo.amount >= minAmount {
			actor.utxos = append(actor.utxos[:i], actor.utxos[i+1:]...)
			return utxo
		}
	}
	total := uint64(0)
	for _, utxo := range actor.utxos {
		total += utxo.amount
	}
	t.Fatalf("%s has no UTXO >= %d; count=%d total=%d", actor.label, minAmount, len(actor.utxos), total)
	return atomicStressUTXO{}
}

func (actor *atomicStressActor) addUTXO(utxo atomicStressUTXO) {
	if utxo.amount == 0 {
		return
	}
	actor.utxos = append(actor.utxos, utxo)
}

func recordCoinbaseOutputs(t *testing.T, block *externalapi.DomainBlock, actor *atomicStressActor) {
	t.Helper()
	if len(block.Transactions) == 0 {
		t.Fatalf("block has no coinbase transaction")
	}
	recordTransactionOutputs(block.Transactions[0], []*atomicStressActor{actor})
}

func recordAssignments(t *testing.T, txs []*externalapi.DomainTransaction, assignments [][]*atomicStressActor) {
	t.Helper()
	if len(txs) != len(assignments) {
		t.Fatalf("assignment mismatch: txs=%d assignments=%d", len(txs), len(assignments))
	}
	for i, tx := range txs {
		recordTransactionOutputs(tx, assignments[i])
	}
}

func recordTransactionOutputs(tx *externalapi.DomainTransaction, owners []*atomicStressActor) {
	txID := *consensushashing.TransactionID(tx)
	for index, owner := range owners {
		if owner == nil || index >= len(tx.Outputs) {
			continue
		}
		output := tx.Outputs[index]
		owner.addUTXO(atomicStressUTXO{
			outpoint: externalapi.DomainOutpoint{
				TransactionID: txID,
				Index:         uint32(index),
			},
			amount:          output.Value,
			scriptPublicKey: output.ScriptPublicKey,
			redeemScript:    owner.redeemScript,
		})
	}
}

func virtualAtomicState(t *testing.T, tc testapi.TestConsensus) *atomicstate.State {
	t.Helper()
	_, _, _, state, err := tc.ConsensusStateManager().CalculatePastUTXOAndAcceptanceDataAndAtomicState(model.NewStagingArea(), model.VirtualBlockHash)
	if err != nil {
		t.Fatalf("CalculatePastUTXOAndAcceptanceDataAndAtomicState(virtual): %+v", err)
	}
	if state == nil || state.IsRootOnly() {
		t.Fatalf("virtual Atomic state is missing or root-only")
	}
	return state
}

func logAtomicStressCheckpoint(t *testing.T, tc testapi.TestConsensus, label string) {
	t.Helper()
	state := virtualAtomicState(t, tc)
	selectedParent, err := tc.GetVirtualSelectedParent()
	if err != nil {
		t.Fatalf("%s GetVirtualSelectedParent: %+v", label, err)
	}
	tokenAuditHash, ok, err := tc.GetAtomicTokenStateHash(selectedParent)
	if err != nil {
		t.Fatalf("%s GetAtomicTokenStateHash: %+v", label, err)
	}
	if !ok {
		t.Fatalf("%s Atomic token audit hash unavailable", label)
	}
	virtualTokenAuditHash, virtualAuditOK := state.P2PTokenAuditHash()
	if !virtualAuditOK {
		t.Fatalf("%s virtual Atomic token audit hash unavailable: %s", label, state.P2PTokenAuditHashUnavailableReason())
	}
	t.Logf("go deterministic atomic stress checkpoint %s: state_hash=%x stored_token_audit_hash=%x virtual_token_audit_hash=%x sink=%s",
		label,
		state.CanonicalHash(),
		tokenAuditHash,
		virtualTokenAuditHash,
		selectedParent,
	)
}

func logStressTransaction(t *testing.T, label string, tx *externalapi.DomainTransaction) {
	t.Helper()
	inputs := make([]string, 0, len(tx.Inputs))
	for _, input := range tx.Inputs {
		inputs = append(inputs, input.PreviousOutpoint.String())
	}
	outputs := make([]uint64, 0, len(tx.Outputs))
	for _, output := range tx.Outputs {
		outputs = append(outputs, output.Value)
	}
	t.Logf("%s: txid=%s inputs=%v outputs=%v payload=%x",
		label,
		consensushashing.TransactionID(tx),
		inputs,
		outputs,
		tx.Payload,
	)
}

func logLiquidityState(
	t *testing.T,
	tc testapi.TestConsensus,
	label string,
	assetID [externalapi.DomainHashSize]byte,
	ownerID [externalapi.DomainHashSize]byte,
) {
	t.Helper()
	state := virtualAtomicState(t, tc)
	asset, pool := liquidityAssetAndPool(t, state, assetID)
	t.Logf("go liquidity %s: total_supply=%s owner_balance=%d pool_nonce=%d curve_version=%d curve_mode=%d individual_cpay=%d individual_token_bps=%d real_cpay=%d real_token=%s virtual_cpay=%d virtual_token=%s unclaimed_total=%d fee_bps=%d fee0_version=%d fee0_payload=%x fee0_unclaimed=%d vault_value=%d vault_outpoint=%s unlock_target=%d unlocked=%t",
		label,
		asset.TotalSupply.Big(),
		liquidityTokenBalance(state, assetID, ownerID),
		pool.PoolNonce,
		pool.CurveVersion,
		pool.CurveMode,
		pool.IndividualVirtualCPayReservesSompi,
		pool.IndividualVirtualTokenMultiplierBPS,
		pool.RealCPayReservesSompi,
		pool.RealTokenReserves.Big(),
		pool.VirtualCPayReserves,
		pool.VirtualTokenReserves.Big(),
		pool.UnclaimedFeeTotalSompi,
		pool.FeeBPS,
		pool.FeeRecipients[0].AddressVersion,
		pool.FeeRecipients[0].AddressPayload,
		pool.FeeRecipients[0].UnclaimedSompi,
		pool.VaultValueSompi,
		pool.VaultOutpoint.String(),
		pool.UnlockTargetSompi,
		pool.Unlocked,
	)
}

func assertAtomicStressFinalState(
	t *testing.T,
	tc testapi.TestConsensus,
	state *atomicstate.State,
	owner *atomicStressActor,
	receiver *atomicStressActor,
	wallets []*atomicStressActor,
	baseAssetID [externalapi.DomainHashSize]byte,
	liquidityAssetID [externalapi.DomainHashSize]byte,
	createdAssets []atomicStressAssetExpectation,
	baseAssetNonce uint64,
	liquidityAssetNonce uint64,
	counters atomicStressCounters,
	rounds int,
) {
	t.Helper()
	selectedParent, err := tc.GetVirtualSelectedParent()
	if err != nil {
		t.Fatalf("GetVirtualSelectedParent: %+v", err)
	}
	storedHash, ok, err := tc.GetAtomicStateHash(selectedParent)
	if err != nil {
		t.Fatalf("GetAtomicStateHash(selected parent): %+v", err)
	}
	if !ok {
		t.Fatalf("selected parent must have a stored Atomic consensus state hash")
	}
	calculatedHash := state.CanonicalHash()
	if storedHash != calculatedHash {
		t.Fatalf("stored Atomic state hash mismatch: stored=%x calculated=%x", storedHash, calculatedHash)
	}
	tokenAuditHash, ok, err := tc.GetAtomicTokenStateHash(selectedParent)
	if err != nil {
		t.Fatalf("GetAtomicTokenStateHash(selected parent): %+v", err)
	}
	if !ok {
		t.Fatalf("selected parent must have an Atomic token audit hash")
	}
	valid, reason, err := tc.IsStoredBlockUTXOCommitmentValid(selectedParent)
	if err != nil {
		t.Fatalf("IsStoredBlockUTXOCommitmentValid(final): %+v", err)
	}
	if !valid {
		t.Fatalf("final selected parent stored UTXO/Atomic commitment is invalid: %s", reason)
	}
	if expected := expectedAtomicStressHash("CRYPTIX_GO_STRESS_EXPECTED_HASH", atomicStressExpectedStateHash, rounds); expected != "" {
		if !strings.EqualFold(expected, hex.EncodeToString(calculatedHash[:])) {
			t.Fatalf("final Atomic hash mismatch against CRYPTIX_GO_STRESS_EXPECTED_HASH: got=%x want=%s", calculatedHash, expected)
		}
	}
	if expected := expectedAtomicStressHash("CRYPTIX_GO_STRESS_EXPECTED_TOKEN_HASH", atomicStressExpectedTokenHash, rounds); expected != "" {
		if !strings.EqualFold(expected, hex.EncodeToString(tokenAuditHash[:])) {
			t.Fatalf("final Atomic token audit hash mismatch against CRYPTIX_GO_STRESS_EXPECTED_TOKEN_HASH: got=%x want=%s", tokenAuditHash, expected)
		}
	}

	if counters.maxBlockTemplateTxs < 50 {
		t.Fatalf("stress never built a large mixed block: max template txs=%d", counters.maxBlockTemplateTxs)
	}
	if counters.buys == 0 || counters.sells == 0 || counters.claims == 0 {
		t.Fatalf("liquidity stress did not exercise buy/sell/claim: buys=%d sells=%d claims=%d", counters.buys, counters.sells, counters.claims)
	}
	if counters.walletNative == 0 || counters.walletMessenger == 0 || counters.walletRawPayloads == 0 || counters.walletTokenCreates == 0 {
		t.Fatalf("wallet diversity missing: walletNative=%d walletMessenger=%d walletRaw=%d walletCreates=%d",
			counters.walletNative, counters.walletMessenger, counters.walletRawPayloads, counters.walletTokenCreates)
	}

	baseAsset, ok := state.Assets[baseAssetID]
	if !ok {
		t.Fatalf("base asset %x missing from Atomic state", baseAssetID)
	}
	expectedBaseSupply := owner.expectedBaseBalance + receiver.expectedBaseBalance
	for _, wallet := range wallets {
		expectedBaseSupply += wallet.expectedBaseBalance
	}
	if got := baseAsset.TotalSupply; got.Compare(atomicstate.Uint128FromUint64(expectedBaseSupply)) != 0 {
		t.Fatalf("base asset total supply mismatch: got=%s want=%d", got.Big(), expectedBaseSupply)
	}
	assertAtomicBalance(t, state, baseAssetID, owner.ownerID, owner.expectedBaseBalance, "owner base")
	assertAtomicBalance(t, state, baseAssetID, receiver.ownerID, receiver.expectedBaseBalance, "receiver base")
	for _, wallet := range wallets {
		assertAtomicBalance(t, state, baseAssetID, wallet.ownerID, wallet.expectedBaseBalance, wallet.label+" base")
	}

	if got := state.NextNonces[atomicstate.OwnerNonceKey(owner.ownerID)]; got != owner.nextOwnerNonce {
		t.Fatalf("owner nonce mismatch: got=%d want=%d", got, owner.nextOwnerNonce)
	}
	if got := state.NextNonces[atomicstate.AssetNonceKey(owner.ownerID, baseAssetID)]; got != baseAssetNonce {
		t.Fatalf("base asset nonce mismatch: got=%d want=%d", got, baseAssetNonce)
	}
	if got := state.NextNonces[atomicstate.AssetNonceKey(owner.ownerID, liquidityAssetID)]; got != liquidityAssetNonce {
		t.Fatalf("liquidity asset nonce mismatch: got=%d want=%d", got, liquidityAssetNonce)
	}
	for _, wallet := range wallets {
		if got := state.NextNonces[atomicstate.OwnerNonceKey(wallet.ownerID)]; got != wallet.nextOwnerNonce {
			t.Fatalf("%s owner nonce mismatch: got=%d want=%d", wallet.label, got, wallet.nextOwnerNonce)
		}
		if state.AnchorCounts[wallet.ownerID] == 0 {
			t.Fatalf("%s lost all Atomic owner anchors", wallet.label)
		}
	}
	if state.AnchorCounts[owner.ownerID] == 0 {
		t.Fatalf("owner lost all Atomic owner anchors")
	}

	for _, expected := range createdAssets {
		asset, ok := state.Assets[expected.assetID]
		if !ok {
			t.Fatalf("created asset %x missing", expected.assetID)
		}
		if asset.AssetClass != atomicstate.AssetClassStandard {
			t.Fatalf("created asset %x has class %d", expected.assetID, asset.AssetClass)
		}
		if asset.CreatorOwnerID != expected.creatorOwnerID {
			t.Fatalf("created asset %x creator mismatch", expected.assetID)
		}
		if asset.MintAuthorityOwnerID != expected.mintAuthorityOwnerID {
			t.Fatalf("created asset %x mint authority mismatch", expected.assetID)
		}
		if asset.TotalSupply.Compare(atomicstate.Uint128FromUint64(expected.initialAmount)) != 0 {
			t.Fatalf("created asset %x total supply mismatch: got=%s want=%d", expected.assetID, asset.TotalSupply.Big(), expected.initialAmount)
		}
		assertAtomicBalance(t, state, expected.assetID, expected.initialOwnerID, expected.initialAmount, "created asset initial balance")
	}

	liquidityAsset, pool := liquidityAssetAndPool(t, state, liquidityAssetID)
	if liquidityAsset.AssetClass != atomicstate.AssetClassLiquidity {
		t.Fatalf("liquidity asset has class %d", liquidityAsset.AssetClass)
	}
	if liquidityAsset.CreatorOwnerID != owner.ownerID {
		t.Fatalf("liquidity asset creator mismatch")
	}
	if len(pool.FeeRecipients) != 1 || pool.FeeRecipients[0].OwnerID != owner.ownerID {
		t.Fatalf("liquidity fee recipient mismatch")
	}
	if pool.PoolNonce <= 1 {
		t.Fatalf("liquidity pool nonce did not advance: %d", pool.PoolNonce)
	}
	expectedVaultValue := pool.RealCPayReservesSompi + pool.UnclaimedFeeTotalSompi
	if pool.VaultValueSompi != expectedVaultValue {
		t.Fatalf("liquidity vault value mismatch: got=%d want real+fees=%d", pool.VaultValueSompi, expectedVaultValue)
	}
	sum, ok := liquidityAsset.TotalSupply.Add(pool.RealTokenReserves)
	if !ok || sum.Compare(liquidityAsset.MaxSupply) != 0 {
		t.Fatalf("liquidity supply invariant mismatch: total=%s real=%s max=%s",
			liquidityAsset.TotalSupply.Big(), pool.RealTokenReserves.Big(), liquidityAsset.MaxSupply.Big())
	}
	if _, ok := state.LiquidityVaultOutpoints[pool.VaultOutpoint]; !ok {
		t.Fatalf("liquidity vault outpoint index missing for %s", pool.VaultOutpoint)
	}
}

func assertAtomicBalance(
	t *testing.T,
	state *atomicstate.State,
	assetID [externalapi.DomainHashSize]byte,
	ownerID [externalapi.DomainHashSize]byte,
	expected uint64,
	label string,
) {
	t.Helper()
	got := state.Balances[atomicstate.BalanceKey{AssetID: assetID, OwnerID: ownerID}]
	if got.Compare(atomicstate.Uint128FromUint64(expected)) != 0 {
		t.Fatalf("%s balance mismatch: got=%s want=%d", label, got.Big(), expected)
	}
}

func liquidityAssetAndPool(
	t *testing.T,
	state *atomicstate.State,
	assetID [externalapi.DomainHashSize]byte,
) (atomicstate.AssetState, *atomicstate.LiquidityPoolState) {
	t.Helper()
	asset, ok := state.Assets[assetID]
	if !ok {
		t.Fatalf("liquidity asset %x missing", assetID)
	}
	if asset.Liquidity == nil {
		t.Fatalf("liquidity asset %x has no pool", assetID)
	}
	return asset, asset.Liquidity
}

func liquidityTokenBalance(state *atomicstate.State, assetID [externalapi.DomainHashSize]byte, ownerID [externalapi.DomainHashSize]byte) uint64 {
	value := state.Balances[atomicstate.BalanceKey{AssetID: assetID, OwnerID: ownerID}]
	out, ok := value.Uint64()
	if !ok {
		return math.MaxUint64
	}
	return out
}

func activeStressWalletCount(wallets []*atomicStressActor) int {
	active := 0
	for _, wallet := range wallets {
		if len(wallet.utxos) > 0 {
			active++
		}
	}
	return active
}

func catPayloadHeader(opcode byte, authInputIndex uint16, nonce uint64) []byte {
	payload := make([]byte, 16)
	copy(payload, []byte("CAT"))
	payload[3] = 1
	payload[4] = opcode
	binary.LittleEndian.PutUint16(payload[6:8], authInputIndex)
	binary.LittleEndian.PutUint64(payload[8:16], nonce)
	return payload
}

func catCreateAssetWithMintPayload(
	nonce uint64,
	decimals byte,
	supplyMode byte,
	maxSupply uint64,
	mintAuthorityOwnerID [externalapi.DomainHashSize]byte,
	initialOwnerID [externalapi.DomainHashSize]byte,
	initialAmount uint64,
	name string,
	symbol string,
	metadata []byte,
) []byte {
	payload := catPayloadHeader(4, 0, nonce)
	payload = append(payload, 1, decimals, supplyMode)
	payload = appendUint128LE(payload, maxSupply)
	payload = append(payload, mintAuthorityOwnerID[:]...)
	payload = appendStringFields(payload, []byte(name), []byte(symbol), metadata)
	payload = appendUint128LE(payload, initialAmount)
	return append(payload, initialOwnerID[:]...)
}

func catCreateLiquidityPayload(
	nonce uint64,
	maxSupply uint64,
	recipientPayload []byte,
	name string,
	symbol string,
	metadata []byte,
) []byte {
	payload := catPayloadHeader(5, 0, nonce)
	payload = append(payload, 1, 1, 0)
	payload = appendUint128LE(payload, maxSupply)
	payload = appendStringFields(payload, []byte(name), []byte(symbol), metadata)
	payload = appendUint64LE(payload, constants.SompiPerCryptix)
	payload = appendUint16LE(payload, 100)
	payload = append(payload, 1, 8)
	payload = append(payload, recipientPayload...)
	payload = appendUint64LE(payload, 0)
	return appendUint128LE(payload, 0)
}

func catTransferPayload(assetID [externalapi.DomainHashSize]byte, nonce uint64, toOwnerID [externalapi.DomainHashSize]byte, amount uint64) []byte {
	payload := catPayloadHeader(1, 0, nonce)
	payload = append(payload, assetID[:]...)
	payload = append(payload, toOwnerID[:]...)
	return appendUint128LE(payload, amount)
}

func catMintPayload(assetID [externalapi.DomainHashSize]byte, nonce uint64, toOwnerID [externalapi.DomainHashSize]byte, amount uint64) []byte {
	payload := catPayloadHeader(2, 0, nonce)
	payload = append(payload, assetID[:]...)
	payload = append(payload, toOwnerID[:]...)
	return appendUint128LE(payload, amount)
}

func catBurnPayload(assetID [externalapi.DomainHashSize]byte, nonce uint64, amount uint64) []byte {
	payload := catPayloadHeader(3, 0, nonce)
	payload = append(payload, assetID[:]...)
	return appendUint128LE(payload, amount)
}

func catBuyLiquidityPayload(assetID [externalapi.DomainHashSize]byte, nonce uint64, expectedPoolNonce uint64, cpayIn uint64, minTokenOut uint64) []byte {
	payload := catPayloadHeader(6, 0, nonce)
	payload = append(payload, assetID[:]...)
	payload = appendUint64LE(payload, expectedPoolNonce)
	payload = appendUint64LE(payload, cpayIn)
	return appendUint128LE(payload, minTokenOut)
}

func catSellLiquidityPayload(
	assetID [externalapi.DomainHashSize]byte,
	nonce uint64,
	expectedPoolNonce uint64,
	tokenIn uint64,
	minCPayOut uint64,
	receiveOutputIndex uint16,
) []byte {
	payload := catPayloadHeader(7, 0, nonce)
	payload = append(payload, assetID[:]...)
	payload = appendUint64LE(payload, expectedPoolNonce)
	payload = appendUint128LE(payload, tokenIn)
	payload = appendUint64LE(payload, minCPayOut)
	return appendUint16LE(payload, receiveOutputIndex)
}

func catClaimLiquidityPayload(
	assetID [externalapi.DomainHashSize]byte,
	nonce uint64,
	expectedPoolNonce uint64,
	recipientIndex byte,
	claimAmount uint64,
	receiveOutputIndex uint16,
) []byte {
	payload := catPayloadHeader(8, 0, nonce)
	payload = append(payload, assetID[:]...)
	payload = appendUint64LE(payload, expectedPoolNonce)
	payload = append(payload, recipientIndex)
	payload = appendUint64LE(payload, claimAmount)
	return appendUint16LE(payload, receiveOutputIndex)
}

func appendStringFields(payload []byte, name []byte, symbol []byte, metadata []byte) []byte {
	if len(name) > 32 || len(symbol) > 10 || len(metadata) > 256 {
		panic("CAT string field too long")
	}
	payload = append(payload, byte(len(name)), byte(len(symbol)))
	payload = appendUint16LE(payload, uint16(len(metadata)))
	payload = append(payload, name...)
	payload = append(payload, symbol...)
	return append(payload, metadata...)
}

func appendUint16LE(payload []byte, value uint16) []byte {
	var encoded [2]byte
	binary.LittleEndian.PutUint16(encoded[:], value)
	return append(payload, encoded[:]...)
}

func appendUint64LE(payload []byte, value uint64) []byte {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	return append(payload, encoded[:]...)
}

func appendUint128LE(payload []byte, value uint64) []byte {
	var encoded [16]byte
	binary.LittleEndian.PutUint64(encoded[:8], value)
	return append(payload, encoded[:]...)
}

func messengerPayload(round int, slot int, ownerID []byte, length int) []byte {
	payload := []byte(fmt.Sprintf("CXM:go-stress:%04d:%02d:", round, slot))
	payload = append(payload, ownerID[:minInt(len(ownerID), 8)]...)
	for len(payload) < length {
		payload = append(payload, byte('a'+(round+slot+len(payload))%26))
	}
	return payload
}

func rawStressPayload(round int, slot int, length int) []byte {
	payload := []byte(fmt.Sprintf("RAW:go-stress:%04d:%02d:", round, slot))
	for len(payload) < length {
		payload = append(payload, byte((round*31+slot*17+len(payload))&0xff))
	}
	return payload
}

func minGrossInputForTokenOutStress(
	realTokenReserves atomicstate.Uint128,
	virtualCPayReserves uint64,
	virtualTokenReserves atomicstate.Uint128,
	tokenOut atomicstate.Uint128,
	feeBPS uint16,
) (uint64, error) {
	if tokenOut.IsZero() || virtualCPayReserves == 0 || virtualTokenReserves.IsZero() {
		return 0, fmt.Errorf("canonical buy target token_out is invalid")
	}
	spendableTokens, ok := realTokenReserves.Sub(atomicstate.Uint128FromUint64(1))
	if !ok || tokenOut.Compare(spendableTokens) > 0 {
		return 0, fmt.Errorf("canonical buy token_out drains final token")
	}
	yAfter, ok := virtualTokenReserves.Sub(tokenOut)
	if !ok || yAfter.IsZero() {
		return 0, fmt.Errorf("canonical buy y_after is invalid")
	}
	xBefore := new(big.Int).SetUint64(virtualCPayReserves)
	k := new(big.Int).Mul(xBefore, virtualTokenReserves.Big())
	xAfter := ceilDivBigStress(k, yAfter.Big())
	if xAfter.Cmp(xBefore) <= 0 {
		return 0, fmt.Errorf("canonical buy produced zero net input")
	}
	netInBig := new(big.Int).Sub(xAfter, xBefore)
	if !netInBig.IsUint64() {
		return 0, fmt.Errorf("canonical buy net input does not fit u64")
	}
	grossIn, err := minGrossInputForNetInputStress(netInBig.Uint64(), feeBPS)
	if err != nil {
		return 0, err
	}
	fee, err := calculateTradeFeeStress(grossIn, feeBPS)
	if err != nil {
		return 0, err
	}
	actualTokenOut, _, _, _, err := cpmmBuyStress(realTokenReserves, virtualCPayReserves, virtualTokenReserves, grossIn-fee)
	if err != nil {
		return 0, err
	}
	if actualTokenOut.Compare(tokenOut) < 0 {
		return 0, fmt.Errorf("canonical buy verification failed")
	}
	return grossIn, nil
}

func minGrossInputForNetInputStress(netIn uint64, feeBPS uint16) (uint64, error) {
	if netIn == 0 || feeBPS >= 10_000 {
		return 0, fmt.Errorf("canonical buy net input or fee_bps is invalid")
	}
	if feeBPS == 0 {
		return netIn, nil
	}
	feeDenominator := 10_000 - uint64(feeBPS)
	gross := new(big.Int).SetUint64(netIn - 1)
	gross.Mul(gross, big.NewInt(10_000))
	gross.Div(gross, new(big.Int).SetUint64(feeDenominator))
	gross.Add(gross, big.NewInt(1))
	if !gross.IsUint64() {
		return 0, fmt.Errorf("canonical buy gross input does not fit u64")
	}
	grossIn := gross.Uint64()
	for grossIn > 1 {
		previous := grossIn - 1
		previousFee, err := calculateTradeFeeStress(previous, feeBPS)
		if err != nil {
			return 0, err
		}
		if previous-previousFee < netIn {
			break
		}
		grossIn = previous
	}
	for {
		fee, err := calculateTradeFeeStress(grossIn, feeBPS)
		if err != nil {
			return 0, err
		}
		if grossIn-fee >= netIn {
			break
		}
		if grossIn == math.MaxUint64 {
			return 0, fmt.Errorf("canonical buy gross input overflow")
		}
		grossIn++
	}
	return grossIn, nil
}

func cpmmBuyStress(
	realTokenReserves atomicstate.Uint128,
	virtualCPayReserves uint64,
	virtualTokenReserves atomicstate.Uint128,
	cpayNetIn uint64,
) (atomicstate.Uint128, atomicstate.Uint128, uint64, atomicstate.Uint128, error) {
	if cpayNetIn == 0 {
		return atomicstate.Uint128{}, atomicstate.Uint128{}, 0, atomicstate.Uint128{}, fmt.Errorf("CPMM buy net input cannot be zero")
	}
	spendableTokens, ok := realTokenReserves.Sub(atomicstate.Uint128FromUint64(1))
	if !ok || spendableTokens.IsZero() {
		return atomicstate.Uint128{}, atomicstate.Uint128{}, 0, atomicstate.Uint128{}, fmt.Errorf("CPMM buy real token reserve floor reached")
	}
	xAfter, ok := checkedAddUint64Stress(virtualCPayReserves, cpayNetIn)
	if !ok {
		return atomicstate.Uint128{}, atomicstate.Uint128{}, 0, atomicstate.Uint128{}, fmt.Errorf("CPMM x_after overflow")
	}
	k := new(big.Int).Mul(new(big.Int).SetUint64(virtualCPayReserves), virtualTokenReserves.Big())
	yAfterBig := ceilDivBigStress(k, new(big.Int).SetUint64(xAfter))
	yAfter, ok := uint128FromBigStress(yAfterBig)
	if !ok || yAfter.IsZero() {
		return atomicstate.Uint128{}, atomicstate.Uint128{}, 0, atomicstate.Uint128{}, fmt.Errorf("CPMM buy y_after conversion failed")
	}
	tokenOut, ok := virtualTokenReserves.Sub(yAfter)
	if !ok || tokenOut.IsZero() || tokenOut.Compare(spendableTokens) > 0 {
		return atomicstate.Uint128{}, atomicstate.Uint128{}, 0, atomicstate.Uint128{}, fmt.Errorf("CPMM buy token_out invalid")
	}
	newRealTokenReserves, ok := realTokenReserves.Sub(tokenOut)
	if !ok {
		return atomicstate.Uint128{}, atomicstate.Uint128{}, 0, atomicstate.Uint128{}, fmt.Errorf("CPMM buy real token reserve underflow")
	}
	return tokenOut, newRealTokenReserves, xAfter, yAfter, nil
}

func cpmmSellStress(
	realCPayReservesSompi uint64,
	virtualCPayReserves uint64,
	virtualTokenReserves atomicstate.Uint128,
	tokenIn atomicstate.Uint128,
) (uint64, uint64, uint64, atomicstate.Uint128, error) {
	if tokenIn.IsZero() {
		return 0, 0, 0, atomicstate.Uint128{}, fmt.Errorf("CPMM sell token input cannot be zero")
	}
	yAfter, ok := virtualTokenReserves.Add(tokenIn)
	if !ok || yAfter.IsZero() {
		return 0, 0, 0, atomicstate.Uint128{}, fmt.Errorf("CPMM y_after overflow")
	}
	k := new(big.Int).Mul(new(big.Int).SetUint64(virtualCPayReserves), virtualTokenReserves.Big())
	xAfterBig := ceilDivBigStress(k, yAfter.Big())
	if !xAfterBig.IsUint64() {
		return 0, 0, 0, atomicstate.Uint128{}, fmt.Errorf("CPMM sell x_after does not fit u64")
	}
	xAfter := xAfterBig.Uint64()
	if xAfter > virtualCPayReserves {
		return 0, 0, 0, atomicstate.Uint128{}, fmt.Errorf("CPMM sell x_after exceeds x_before")
	}
	grossOut, ok := checkedSubUint64Stress(virtualCPayReserves, xAfter)
	if !ok || grossOut == 0 {
		return 0, 0, 0, atomicstate.Uint128{}, fmt.Errorf("CPMM sell produced zero gross_out")
	}
	spendableCPay, ok := checkedSubUint64Stress(realCPayReservesSompi, 1)
	if !ok || grossOut > spendableCPay {
		return 0, 0, 0, atomicstate.Uint128{}, fmt.Errorf("CPMM sell would drain final real sompi")
	}
	newRealCPayReserves, ok := checkedSubUint64Stress(realCPayReservesSompi, grossOut)
	if !ok {
		return 0, 0, 0, atomicstate.Uint128{}, fmt.Errorf("CPMM sell real CPAY reserve underflow")
	}
	return grossOut, newRealCPayReserves, xAfter, yAfter, nil
}

func calculateTradeFeeStress(amount uint64, feeBPS uint16) (uint64, error) {
	fee := new(big.Int).Mul(new(big.Int).SetUint64(amount), new(big.Int).SetUint64(uint64(feeBPS)))
	fee.Div(fee, big.NewInt(10_000))
	if !fee.IsUint64() {
		return 0, fmt.Errorf("fee does not fit into u64")
	}
	return fee.Uint64(), nil
}

func ceilDivBigStress(numerator *big.Int, denominator *big.Int) *big.Int {
	if denominator.Sign() == 0 {
		panic("division by zero")
	}
	quotient, remainder := new(big.Int).QuoRem(numerator, denominator, new(big.Int))
	if remainder.Sign() != 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	return quotient
}

func uint128FromBigStress(value *big.Int) (atomicstate.Uint128, bool) {
	if value.Sign() < 0 || value.BitLen() > 128 {
		return atomicstate.Uint128{}, false
	}
	bytes := value.FillBytes(make([]byte, 16))
	for i := 0; i < 8; i++ {
		bytes[i], bytes[15-i] = bytes[15-i], bytes[i]
	}
	return atomicstate.Uint128FromLE(bytes)
}

func checkedAddUint64Stress(left uint64, right uint64) (uint64, bool) {
	value := left + right
	return value, value >= left
}

func checkedSubUint64Stress(left uint64, right uint64) (uint64, bool) {
	if left < right {
		return 0, false
	}
	return left - right, true
}

func checkedAddTest(t *testing.T, left uint64, right uint64) uint64 {
	t.Helper()
	value, ok := checkedAddUint64Stress(left, right)
	if !ok {
		t.Fatalf("uint64 overflow: %d + %d", left, right)
	}
	return value
}

func maxInt(left int, right int) int {
	if left > right {
		return left
	}
	return right
}

func minInt(left int, right int) int {
	if left < right {
		return left
	}
	return right
}

func minUint64(left uint64, right uint64) uint64 {
	if left < right {
		return left
	}
	return right
}
