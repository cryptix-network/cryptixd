package miningmanager_test

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"

	"github.com/cryptix-network/cryptixd/cmd/cryptixwallet/libcryptixwallet"
	"github.com/cryptix-network/cryptixd/domain/consensusreference"
	"github.com/cryptix-network/cryptixd/domain/miningmanager/model"
	"github.com/cryptix-network/cryptixd/util"
	"github.com/cryptix-network/cryptixd/version"

	"github.com/cryptix-network/cryptixd/domain/miningmanager/mempool"

	"github.com/cryptix-network/cryptixd/domain/consensus"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/testapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/constants"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/testutils"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/transactionhelper"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/txscript"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/utxo"
	"github.com/cryptix-network/cryptixd/domain/miningmanager"
	"github.com/pkg/errors"
)

// TestValidateAndInsertTransaction verifies that valid transactions were successfully inserted into the mempool.
func TestValidateAndInsertTransaction(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestValidateAndInsertTransaction")
		if err != nil {
			t.Fatalf("Error setting up TestConsensus: %+v", err)
		}
		defer teardown(false)

		miningFactory := miningmanager.NewFactory()
		tcAsConsensus := tc.(externalapi.Consensus)
		tcAsConsensusPointer := &tcAsConsensus
		consensusReference := consensusreference.NewConsensusReference(&tcAsConsensusPointer)
		miningManager := miningFactory.NewMiningManager(consensusReference, &consensusConfig.Params, mempool.DefaultConfig(&consensusConfig.Params))
		transactionsToInsert := make([]*externalapi.DomainTransaction, 10)
		for i := range transactionsToInsert {
			transactionsToInsert[i] = createTransactionWithUTXOEntry(t, i, 0)
			_, err = miningManager.ValidateAndInsertTransaction(transactionsToInsert[i], false, true)
			if err != nil {
				t.Fatalf("ValidateAndInsertTransaction: %v", err)
			}
		}
		// The UTXOEntry was filled manually for those transactions, so the transactions won't be considered orphans.
		// Therefore, all the transactions expected to be contained in the mempool.
		transactionsFromMempool, _ := miningManager.AllTransactions(true, false)
		if len(transactionsToInsert) != len(transactionsFromMempool) {
			t.Fatalf("Wrong number of transactions in mempool: expected: %d, got: %d", len(transactionsToInsert), len(transactionsFromMempool))
		}
		for _, transactionToInsert := range transactionsToInsert {
			if !contains(transactionToInsert, transactionsFromMempool) {
				t.Fatalf("Missing transaction %s in the mempool", consensushashing.TransactionID(transactionToInsert))
			}
		}

		// The parent's transaction was inserted by consensus(AddBlock), and we want to verify that
		// the transaction is not considered an orphan and inserted into the mempool.
		transactionNotAnOrphan, err := createChildAndParentTxsAndAddParentToConsensus(tc)
		if err != nil {
			t.Fatalf("Error in createParentAndChildrenTransaction: %v", err)
		}
		_, err = miningManager.ValidateAndInsertTransaction(transactionNotAnOrphan, false, true)
		if err != nil {
			t.Fatalf("ValidateAndInsertTransaction: %v", err)
		}
		transactionsFromMempool, _ = miningManager.AllTransactions(true, false)
		if !contains(transactionNotAnOrphan, transactionsFromMempool) {
			t.Fatalf("Missing transaction %s in the mempool", consensushashing.TransactionID(transactionNotAnOrphan))
		}
	})
}

func TestPayloadTransactionTemplateBuild(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestPayloadTransactionTemplateBuild")
		if err != nil {
			t.Fatalf("Error setting up TestConsensus: %+v", err)
		}
		defer teardown(false)

		miningFactory := miningmanager.NewFactory()
		tcAsConsensus := tc.(externalapi.Consensus)
		tcAsConsensusPointer := &tcAsConsensus
		consensusReference := consensusreference.NewConsensusReference(&tcAsConsensusPointer)
		miningManager := miningFactory.NewMiningManager(consensusReference, &consensusConfig.Params, mempool.DefaultConfig(&consensusConfig.Params))

		payloadTx, err := createChildAndParentTxsAndAddParentToConsensus(tc)
		if err != nil {
			t.Fatalf("Error creating payload transaction parent: %v", err)
		}
		payloadTx.SubnetworkID = subnetworks.SubnetworkIDPayload
		payloadTx.Payload = []byte("payload-hf")

		_, err = miningManager.ValidateAndInsertTransaction(payloadTx, false, true)
		if err != nil {
			t.Fatalf("ValidateAndInsertTransaction: %v", err)
		}

		blockTemplate, err := miningManager.GetBlockTemplateBuilder().BuildBlockTemplate(&externalapi.DomainCoinbaseData{
			ScriptPublicKey: &externalapi.ScriptPublicKey{Script: nil, Version: 0},
			ExtraData:       nil,
		})
		if err != nil {
			t.Fatalf("BuildBlockTemplate: %v", err)
		}

		payloadTxID := consensushashing.TransactionID(payloadTx)
		foundPayloadTx := false
		for _, tx := range blockTemplate.Block.Transactions[1:] {
			if *consensushashing.TransactionID(tx) == *payloadTxID {
				foundPayloadTx = true
				break
			}
		}
		if !foundPayloadTx {
			t.Fatalf("expected payload transaction %s in block template", payloadTxID)
		}
	})
}

func TestGetBlockTemplateMixedReadyMempoolBuildsFreshCommitment(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		miningManager, tc := newTestMiningManagerWithConfig(
			t,
			consensusConfig,
			"TestGetBlockTemplateMixedReadyMempoolBuildsFreshCommitment",
			nil,
		)

		readyTxs := make([]*externalapi.DomainTransaction, 0, 7)
		for i := 0; i < 4; i++ {
			tx, err := createReadyTransactionFromConsensusFunding(tc)
			if err != nil {
				t.Fatalf("create native transaction parent: %v", err)
			}
			readyTxs = append(readyTxs, tx)
		}
		for i := 0; i < 2; i++ {
			tx, err := createReadyTransactionFromConsensusFunding(tc)
			if err != nil {
				t.Fatalf("create messenger transaction parent: %v", err)
			}
			tx.SubnetworkID = subnetworks.SubnetworkIDPayload
			tx.Payload = []byte("MSG:cross-parity")
			readyTxs = append(readyTxs, tx)
		}
		tokenCreateTx, err := createReadyTransactionFromConsensusFundingWithFee(tc, 10_000)
		if err != nil {
			t.Fatalf("create token transaction parent: %v", err)
		}
		tokenCreateTx.SubnetworkID = subnetworks.SubnetworkIDPayload
		tokenCreateTx.Payload = createCATCreateAssetWithMintPayload(1)
		readyTxs = append(readyTxs, tokenCreateTx)

		for _, tx := range readyTxs {
			if _, err := miningManager.ValidateAndInsertTransaction(tx, false, true); err != nil {
				t.Fatalf("ValidateAndInsertTransaction %s: %v", consensushashing.TransactionID(tx), err)
			}
		}

		coinbase1, err := generateNewCoinbase(consensusConfig.Params.Prefix, opTrue)
		if err != nil {
			t.Fatalf("Generate coinbase1: %v", err)
		}
		coinbase2, err := generateNewCoinbase(consensusConfig.Params.Prefix, opUsual)
		if err != nil {
			t.Fatalf("Generate coinbase2: %v", err)
		}

		block1, _, err := miningManager.GetBlockTemplate(coinbase1)
		if err != nil {
			t.Fatalf("GetBlockTemplate coinbase1: %v", err)
		}
		block2, _, err := miningManager.GetBlockTemplate(coinbase2)
		if err != nil {
			t.Fatalf("GetBlockTemplate coinbase2: %v", err)
		}
		if *consensushashing.TransactionID(block1.Transactions[0]) == *consensushashing.TransactionID(block2.Transactions[0]) {
			t.Fatalf("coinbase transaction id did not change after miner data changed")
		}
		assertMixedTemplateShape(t, block2.Transactions, 4, 3)

		expectedTemplate, err := tc.BuildBlockTemplate(coinbase2, block2.Transactions[1:])
		if err != nil {
			t.Fatalf("BuildBlockTemplate fresh reference: %v", err)
		}
		if !block2.Header.UTXOCommitment().Equal(expectedTemplate.Block.Header.UTXOCommitment()) {
			t.Fatalf("GetBlockTemplate returned stale UTXO/Atomic commitment: got %s want %s",
				block2.Header.UTXOCommitment(), expectedTemplate.Block.Header.UTXOCommitment())
		}

		submittedBlock := cloneBlockWithoutUTXOEntries(block2)
		if err := tc.ValidateAndInsertBlock(submittedBlock, true); err != nil {
			t.Fatalf("GetBlockTemplate returned a consensus-invalid mixed block: %v", err)
		}
	})
}

func TestGetBlockTemplateMixedMempoolOverParallelTipsIsConsensusValid(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		miningManager, tc := newTestMiningManagerWithConfig(
			t,
			consensusConfig,
			"TestGetBlockTemplateMixedMempoolOverParallelTipsIsConsensusValid",
			nil,
		)

		readyTxs := make([]*externalapi.DomainTransaction, 0, 5)
		for i := 0; i < 2; i++ {
			tx, err := createReadyTransactionFromConsensusFunding(tc)
			if err != nil {
				t.Fatalf("create native transaction parent: %v", err)
			}
			readyTxs = append(readyTxs, tx)
		}
		messengerTx, err := createReadyTransactionFromConsensusFunding(tc)
		if err != nil {
			t.Fatalf("create messenger transaction parent: %v", err)
		}
		messengerTx.SubnetworkID = subnetworks.SubnetworkIDPayload
		messengerTx.Payload = []byte("MSG:parallel-template")
		readyTxs = append(readyTxs, messengerTx)

		tokenCreateTx, err := createReadyTransactionFromConsensusFundingWithFee(tc, 10_000)
		if err != nil {
			t.Fatalf("create token transaction parent: %v", err)
		}
		tokenCreateTx.SubnetworkID = subnetworks.SubnetworkIDPayload
		tokenCreateTx.Payload = createCATCreateAssetWithMintPayload(1)
		readyTxs = append(readyTxs, tokenCreateTx)

		for _, tx := range readyTxs {
			if _, err := miningManager.ValidateAndInsertTransaction(tx, false, true); err != nil {
				t.Fatalf("ValidateAndInsertTransaction %s: %v", consensushashing.TransactionID(tx), err)
			}
		}

		tips, err := tc.Tips()
		if err != nil {
			t.Fatalf("Tips before fork: %v", err)
		}
		if len(tips) != 1 {
			t.Fatalf("expected one tip before fork, got %d", len(tips))
		}
		if _, _, err := tc.AddBlock(tips, nil, nil); err != nil {
			t.Fatalf("AddBlock fork A: %v", err)
		}
		if _, _, err := tc.AddBlock(tips, nil, nil); err != nil {
			t.Fatalf("AddBlock fork B: %v", err)
		}

		blockTemplate, err := miningManager.GetBlockTemplateBuilder().BuildBlockTemplate(&externalapi.DomainCoinbaseData{
			ScriptPublicKey: &externalapi.ScriptPublicKey{Script: nil, Version: 0},
			ExtraData:       nil,
		})
		if err != nil {
			t.Fatalf("BuildBlockTemplate: %v", err)
		}
		if len(blockTemplate.Block.Header.DirectParents()) < 2 {
			t.Fatalf("expected a template over parallel tips, got parents=%v", blockTemplate.Block.Header.DirectParents())
		}
		assertMixedTemplateShape(t, blockTemplate.Block.Transactions, 2, 2)

		submittedBlock := cloneBlockWithoutUTXOEntries(blockTemplate.Block)
		if err := tc.ValidateAndInsertBlock(submittedBlock, true); err != nil {
			t.Fatalf("parallel-tip mixed mempool template was consensus-invalid: %v", err)
		}
	})
}

func cloneBlockWithoutUTXOEntries(block *externalapi.DomainBlock) *externalapi.DomainBlock {
	clone := block.Clone()
	for _, tx := range clone.Transactions {
		for _, input := range tx.Inputs {
			input.UTXOEntry = nil
		}
	}
	return clone
}

func newTestMiningManager(t *testing.T, consensusConfig *consensus.Config, name string) miningmanager.MiningManager {
	t.Helper()
	miningManager, _ := newTestMiningManagerWithConfig(t, consensusConfig, name, nil)
	return miningManager
}

func newTestMiningManagerWithConfig(
	t *testing.T,
	consensusConfig *consensus.Config,
	name string,
	configureMempool func(*mempool.Config),
) (miningmanager.MiningManager, testapi.TestConsensus) {
	t.Helper()

	factory := consensus.NewFactory()
	tc, teardown, err := factory.NewTestConsensus(consensusConfig, name)
	if err != nil {
		t.Fatalf("Error setting up TestConsensus: %+v", err)
	}
	t.Cleanup(func() {
		teardown(false)
	})

	miningFactory := miningmanager.NewFactory()
	tcAsConsensus := tc.(externalapi.Consensus)
	tcAsConsensusPointer := &tcAsConsensus
	consensusReference := consensusreference.NewConsensusReference(&tcAsConsensusPointer)
	mempoolConfig := mempool.DefaultConfig(&consensusConfig.Params)
	if configureMempool != nil {
		configureMempool(mempoolConfig)
	}
	return miningFactory.NewMiningManager(consensusReference, &consensusConfig.Params, mempoolConfig), tc
}

func TestAtomicMempoolRejectsDuplicateAssetNonceSlot(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		miningManager := newTestMiningManager(t, consensusConfig, "TestAtomicMempoolRejectsDuplicateAssetNonceSlot")

		var assetID [externalapi.DomainHashSize]byte
		assetID[0] = 0x11
		payload := createCATTransferPayload(assetID, 1)
		firstTx := createCATTransactionWithUTXOEntry(t, 1, payload)
		secondTx := createCATTransactionWithUTXOEntry(t, 2, payload)

		_, err := miningManager.ValidateAndInsertTransaction(firstTx, false, true)
		if err != nil {
			t.Fatalf("ValidateAndInsertTransaction firstTx: %v", err)
		}

		_, err = miningManager.ValidateAndInsertTransaction(secondTx, false, true)
		if err == nil {
			t.Fatalf("expected duplicate CAT nonce slot rejection")
		}
		if !strings.Contains(err.Error(), "atomic slot nonce:asset") {
			t.Fatalf("expected duplicate CAT asset nonce slot error, got: %v", err)
		}
	})
}

func TestAtomicDuplicateNonceDoesNotEvictPendingFutureNonceWhenFull(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		miningManager, _ := newTestMiningManagerWithConfig(
			t,
			consensusConfig,
			"TestAtomicDuplicateNonceDoesNotEvictPendingFutureNonceWhenFull",
			func(config *mempool.Config) {
				config.MaximumTransactionCount = 2
				config.MinimumRelayTransactionFee = 0
			},
		)

		var assetID [externalapi.DomainHashSize]byte
		assetID[0] = 0x12
		firstTx := createCATTransactionWithUTXOEntry(t, 1, createCATTransferPayload(assetID, 1))
		futureTx := createCATTransactionWithUTXOEntry(t, 2, createCATTransferPayload(assetID, 2))
		duplicateFirstTx := createCATTransactionWithUTXOEntry(t, 3, createCATTransferPayload(assetID, 1))
		duplicateFirstTx.Fee = 500_000

		if _, err := miningManager.ValidateAndInsertTransaction(firstTx, false, true); err != nil {
			t.Fatalf("ValidateAndInsertTransaction firstTx: %v", err)
		}
		if _, err := miningManager.ValidateAndInsertTransaction(futureTx, false, true); err != nil {
			t.Fatalf("ValidateAndInsertTransaction futureTx: %v", err)
		}

		_, err := miningManager.ValidateAndInsertTransaction(duplicateFirstTx, false, true)
		if err == nil {
			t.Fatalf("expected duplicate CAT nonce slot rejection")
		}
		if !strings.Contains(err.Error(), "atomic slot nonce:asset") {
			t.Fatalf("expected duplicate CAT asset nonce slot error, got: %v", err)
		}

		transactionsFromMempool, _ := miningManager.AllTransactions(true, false)
		if len(transactionsFromMempool) != 2 {
			t.Fatalf("expected duplicate rejection to keep two pending txs, got %s", consensushashing.TransactionIDs(transactionsFromMempool))
		}
		if !contains(futureTx, transactionsFromMempool) {
			t.Fatalf("duplicate same-nonce CAT must not evict pending future nonce, got %s", consensushashing.TransactionIDs(transactionsFromMempool))
		}
	})
}

func TestAtomicMempoolRejectsDuplicateOwnerNonceSlot(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		miningManager := newTestMiningManager(t, consensusConfig, "TestAtomicMempoolRejectsDuplicateOwnerNonceSlot")

		payload := createCATCreateAssetPayload(1)
		firstTx := createCATTransactionWithUTXOEntry(t, 1, payload)
		secondTx := createCATTransactionWithUTXOEntry(t, 2, payload)

		_, err := miningManager.ValidateAndInsertTransaction(firstTx, false, true)
		if err != nil {
			t.Fatalf("ValidateAndInsertTransaction firstTx: %v", err)
		}

		_, err = miningManager.ValidateAndInsertTransaction(secondTx, false, true)
		if err == nil {
			t.Fatalf("expected duplicate CAT owner nonce slot rejection")
		}
		if !strings.Contains(err.Error(), "atomic slot nonce:owner") {
			t.Fatalf("expected duplicate CAT owner nonce slot error, got: %v", err)
		}
	})
}

func TestAtomicMempoolRejectsDuplicateLiquidityPoolSlot(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		miningManager := newTestMiningManager(t, consensusConfig, "TestAtomicMempoolRejectsDuplicateLiquidityPoolSlot")

		var assetID [externalapi.DomainHashSize]byte
		assetID[0] = 0x22
		firstTx := createCATTransactionWithUTXOEntry(t, 1, createCATBuyPayload(assetID, 1, 9))
		secondTx := createCATTransactionWithUTXOEntry(t, 2, createCATBuyPayload(assetID, 2, 9))

		_, err := miningManager.ValidateAndInsertTransaction(firstTx, false, true)
		if err != nil {
			t.Fatalf("ValidateAndInsertTransaction firstTx: %v", err)
		}

		_, err = miningManager.ValidateAndInsertTransaction(secondTx, false, true)
		if err == nil {
			t.Fatalf("expected duplicate CAT liquidity pool slot rejection")
		}
		if !strings.Contains(err.Error(), "atomic slot liquidity-pool") {
			t.Fatalf("expected duplicate CAT liquidity pool slot error, got: %v", err)
		}
	})
}

func TestAtomicMempoolRemovesAcceptedLiquidityPoolConflict(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		miningManager := newTestMiningManager(t, consensusConfig, "TestAtomicMempoolRemovesAcceptedLiquidityPoolConflict")

		var assetID [externalapi.DomainHashSize]byte
		assetID[0] = 0x33
		localTx := createCATTransactionWithUTXOEntry(t, 1, createCATBuyPayload(assetID, 1, 9))
		acceptedTxFromAnotherNode := createCATTransactionWithUTXOEntry(t, 2, createCATBuyPayload(assetID, 2, 9))

		_, err := miningManager.ValidateAndInsertTransaction(localTx, false, true)
		if err != nil {
			t.Fatalf("ValidateAndInsertTransaction localTx: %v", err)
		}

		_, err = miningManager.HandleNewBlockTransactions([]*externalapi.DomainTransaction{
			{},
			acceptedTxFromAnotherNode,
		})
		if err != nil {
			t.Fatalf("HandleNewBlockTransactions: %v", err)
		}

		transactionsFromMempool, _ := miningManager.AllTransactions(true, false)
		if len(transactionsFromMempool) != 0 {
			t.Fatalf("expected accepted liquidity pool conflict to evict local tx, got %d transactions", len(transactionsFromMempool))
		}
	})
}

func TestAtomicMempoolCountLimitPreservesPendingNonceChain(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		miningManager, _ := newTestMiningManagerWithConfig(
			t,
			consensusConfig,
			"TestAtomicMempoolCountLimitPreservesPendingNonceChain",
			func(config *mempool.Config) {
				config.MaximumTransactionCount = 1
				config.MinimumRelayTransactionFee = 0
			},
		)

		var assetID [externalapi.DomainHashSize]byte
		assetID[0] = 0x34
		firstTx := createCATTransactionWithUTXOEntry(t, 1, createCATTransferPayload(assetID, 1))
		firstTx.Fee = 10
		highFeeSameAsset := createCATTransactionWithUTXOEntry(t, 2, createCATTransferPayload(assetID, 2))
		highFeeSameAsset.Fee = 500_000

		_, err := miningManager.ValidateAndInsertTransaction(firstTx, false, true)
		if err != nil {
			t.Fatalf("ValidateAndInsertTransaction firstTx: %v", err)
		}
		_, err = miningManager.ValidateAndInsertTransaction(highFeeSameAsset, false, true)
		if err == nil {
			t.Fatalf("expected future CAT nonce to be rejected when only its pending predecessor could be evicted")
		}

		transactionsFromMempool, _ := miningManager.AllTransactions(true, false)
		if len(transactionsFromMempool) != 1 || *consensushashing.TransactionID(transactionsFromMempool[0]) != *consensushashing.TransactionID(firstTx) {
			t.Fatalf("expected pending predecessor CAT to remain in mempool, got %s", consensushashing.TransactionIDs(transactionsFromMempool))
		}
	})
}

func TestAtomicMempoolCountLimitCanEvictDifferentAssetCAT(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		miningManager, _ := newTestMiningManagerWithConfig(
			t,
			consensusConfig,
			"TestAtomicMempoolCountLimitCanEvictDifferentAssetCAT",
			func(config *mempool.Config) {
				config.MaximumTransactionCount = 1
				config.MinimumRelayTransactionFee = 0
			},
		)

		var firstAssetID [externalapi.DomainHashSize]byte
		firstAssetID[0] = 0x35
		var secondAssetID [externalapi.DomainHashSize]byte
		secondAssetID[0] = 0x36
		firstTx := createCATTransactionWithUTXOEntry(t, 1, createCATTransferPayload(firstAssetID, 1))
		firstTx.Fee = 10
		highFeeOtherAsset := createCATTransactionWithUTXOEntry(t, 2, createCATTransferPayload(secondAssetID, 1))
		highFeeOtherAsset.Fee = 500_000

		_, err := miningManager.ValidateAndInsertTransaction(firstTx, false, true)
		if err != nil {
			t.Fatalf("ValidateAndInsertTransaction firstTx: %v", err)
		}
		_, err = miningManager.ValidateAndInsertTransaction(highFeeOtherAsset, false, true)
		if err != nil {
			t.Fatalf("expected different-asset CAT to enter by evicting lower-fee CAT from another asset: %v", err)
		}

		transactionsFromMempool, _ := miningManager.AllTransactions(true, false)
		if len(transactionsFromMempool) != 1 || *consensushashing.TransactionID(transactionsFromMempool[0]) != *consensushashing.TransactionID(highFeeOtherAsset) {
			t.Fatalf("expected high-fee different-asset CAT to remain in mempool, got %s", consensushashing.TransactionIDs(transactionsFromMempool))
		}
	})
}

func TestAtomicMempoolKeepsFutureSameAssetNonceAfterAcceptedPredecessor(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		miningManager := newTestMiningManager(t, consensusConfig, "TestAtomicMempoolKeepsFutureSameAssetNonceAfterAcceptedPredecessor")

		var assetID [externalapi.DomainHashSize]byte
		assetID[0] = 0x37
		var otherAssetID [externalapi.DomainHashSize]byte
		otherAssetID[0] = 0x38
		localFutureSameAsset := createCATTransactionWithUTXOEntry(t, 1, createCATTransferPayload(assetID, 2))
		localOtherAsset := createCATTransactionWithUTXOEntry(t, 2, createCATTransferPayload(otherAssetID, 1))
		acceptedFromAnotherNode := createCATTransactionWithUTXOEntry(t, 3, createCATTransferPayload(assetID, 1))

		if _, err := miningManager.ValidateAndInsertTransaction(localFutureSameAsset, false, true); err != nil {
			t.Fatalf("ValidateAndInsertTransaction localFutureSameAsset: %v", err)
		}
		if _, err := miningManager.ValidateAndInsertTransaction(localOtherAsset, false, true); err != nil {
			t.Fatalf("ValidateAndInsertTransaction localOtherAsset: %v", err)
		}

		_, err := miningManager.HandleNewBlockTransactions([]*externalapi.DomainTransaction{
			{},
			acceptedFromAnotherNode,
		})
		if err != nil {
			t.Fatalf("HandleNewBlockTransactions: %v", err)
		}

		transactionsFromMempool, _ := miningManager.AllTransactions(true, false)
		if !contains(localFutureSameAsset, transactionsFromMempool) {
			t.Fatalf("expected future same-asset CAT nonce to remain in mempool, got %s", consensushashing.TransactionIDs(transactionsFromMempool))
		}
		if !contains(localOtherAsset, transactionsFromMempool) {
			t.Fatalf("expected other-asset CAT to remain in mempool, got %s", consensushashing.TransactionIDs(transactionsFromMempool))
		}
	})
}

func TestAtomicLowPriorityExpiryRemovesRedeemerChain(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		miningManager, tc := newTestMiningManagerWithConfig(
			t,
			consensusConfig,
			"TestAtomicLowPriorityExpiryRemovesRedeemerChain",
			func(config *mempool.Config) {
				config.AtomicTransactionExpireIntervalDAAScore = 5
				config.TransactionExpireScanIntervalDAAScore = 0
				config.MinimumRelayTransactionFee = 0
			},
		)

		var assetID [externalapi.DomainHashSize]byte
		assetID[0] = 0x39
		parentTx := createCATTransactionWithUTXOEntry(t, 1, createCATTransferPayload(assetID, 1))
		childTx, err := testutils.CreateTransaction(parentTx, 1000)
		if err != nil {
			t.Fatalf("CreateTransaction childTx: %v", err)
		}
		childTx.SubnetworkID = subnetworks.SubnetworkIDPayload
		childTx.Payload = createCATTransferPayload(assetID, 2)

		if _, err := miningManager.ValidateAndInsertTransaction(parentTx, false, true); err != nil {
			t.Fatalf("ValidateAndInsertTransaction parentTx: %v", err)
		}
		if _, err := miningManager.ValidateAndInsertTransaction(childTx, false, true); err != nil {
			t.Fatalf("ValidateAndInsertTransaction childTx: %v", err)
		}
		transactionsFromMempool, _ := miningManager.AllTransactions(true, false)
		if len(transactionsFromMempool) != 2 {
			t.Fatalf("expected parent and child before expiry, got %s", consensushashing.TransactionIDs(transactionsFromMempool))
		}

		tips, err := tc.Tips()
		if err != nil {
			t.Fatalf("Tips: %v", err)
		}
		for i := 0; i < 6; i++ {
			tip, _, err := tc.AddBlock(tips, nil, nil)
			if err != nil {
				t.Fatalf("AddBlock %d: %v", i, err)
			}
			tips = []*externalapi.DomainHash{tip}
		}

		expiredTransactions, _, err := miningManager.ExpireLowPriorityTransactions()
		if err != nil {
			t.Fatalf("ExpireLowPriorityTransactions: %v", err)
		}
		if expiredTransactions != 2 {
			t.Fatalf("expected expired parent to remove its child redeemer as well, got %d expired transactions", expiredTransactions)
		}
		transactionsFromMempool, _ = miningManager.AllTransactions(true, false)
		if len(transactionsFromMempool) != 0 {
			t.Fatalf("expected Atomic expiry to remove the full redeemer chain, got %s", consensushashing.TransactionIDs(transactionsFromMempool))
		}
	})
}

func TestAtomicLowPriorityExpiryTimerStartsWhenRedeemerBecomesReady(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		miningManager, tc := newTestMiningManagerWithConfig(
			t,
			consensusConfig,
			"TestAtomicLowPriorityExpiryTimerStartsWhenRedeemerBecomesReady",
			func(config *mempool.Config) {
				config.AtomicTransactionExpireIntervalDAAScore = 5
				config.TransactionExpireScanIntervalDAAScore = 0
				config.MinimumRelayTransactionFee = 0
			},
		)

		var assetID [externalapi.DomainHashSize]byte
		assetID[0] = 0x3a
		parentTx := createCATTransactionWithUTXOEntry(t, 1, createCATTransferPayload(assetID, 1))
		childTx, err := testutils.CreateTransaction(parentTx, 1000)
		if err != nil {
			t.Fatalf("CreateTransaction childTx: %v", err)
		}
		childTx.SubnetworkID = subnetworks.SubnetworkIDPayload
		childTx.Payload = createCATTransferPayload(assetID, 2)

		if _, err := miningManager.ValidateAndInsertTransaction(parentTx, false, true); err != nil {
			t.Fatalf("ValidateAndInsertTransaction parentTx: %v", err)
		}
		if _, err := miningManager.ValidateAndInsertTransaction(childTx, false, true); err != nil {
			t.Fatalf("ValidateAndInsertTransaction childTx: %v", err)
		}

		tips, err := tc.Tips()
		if err != nil {
			t.Fatalf("Tips: %v", err)
		}
		for i := 0; i < 6; i++ {
			tip, _, err := tc.AddBlock(tips, nil, nil)
			if err != nil {
				t.Fatalf("AddBlock %d: %v", i, err)
			}
			tips = []*externalapi.DomainHash{tip}
		}

		if _, err := miningManager.HandleNewBlockTransactions([]*externalapi.DomainTransaction{{}, parentTx}); err != nil {
			t.Fatalf("HandleNewBlockTransactions: %v", err)
		}
		transactionsFromMempool, _ := miningManager.AllTransactions(true, false)
		if len(transactionsFromMempool) != 1 || !contains(childTx, transactionsFromMempool) {
			t.Fatalf("expected child to remain when it just became ready, got %s", consensushashing.TransactionIDs(transactionsFromMempool))
		}

		for i := 0; i < 6; i++ {
			tip, _, err := tc.AddBlock(tips, nil, nil)
			if err != nil {
				t.Fatalf("AddBlock second window %d: %v", i, err)
			}
			tips = []*externalapi.DomainHash{tip}
		}
		expiredTransactions, _, err := miningManager.ExpireLowPriorityTransactions()
		if err != nil {
			t.Fatalf("ExpireLowPriorityTransactions: %v", err)
		}
		if expiredTransactions != 1 {
			t.Fatalf("expected child to expire after its own ready window elapsed, got %d expired transactions", expiredTransactions)
		}
		transactionsFromMempool, _ = miningManager.AllTransactions(true, false)
		if len(transactionsFromMempool) != 0 {
			t.Fatalf("expected child to be expired, got %s", consensushashing.TransactionIDs(transactionsFromMempool))
		}
	})
}

func TestAtomicTotalExpiryRemovesNonReadyChainAfterLongCap(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		miningManager, tc := newTestMiningManagerWithConfig(
			t,
			consensusConfig,
			"TestAtomicTotalExpiryRemovesNonReadyChainAfterLongCap",
			func(config *mempool.Config) {
				config.TransactionExpireIntervalDAAScore = 1000
				config.AtomicTransactionExpireIntervalDAAScore = 5
				config.AtomicTransactionTotalExpireIntervalDAAScore = 8
				config.TransactionExpireScanIntervalDAAScore = 0
				config.MinimumRelayTransactionFee = 0
			},
		)

		var assetID [externalapi.DomainHashSize]byte
		assetID[0] = 0x3c
		parentTx := createTransactionWithUTXOEntry(t, 1, 0)
		childTx, err := testutils.CreateTransaction(parentTx, 1000)
		if err != nil {
			t.Fatalf("CreateTransaction childTx: %v", err)
		}
		childTx.SubnetworkID = subnetworks.SubnetworkIDPayload
		childTx.Payload = createCATTransferPayload(assetID, 2)

		if _, err := miningManager.ValidateAndInsertTransaction(parentTx, false, true); err != nil {
			t.Fatalf("ValidateAndInsertTransaction parentTx: %v", err)
		}
		if _, err := miningManager.ValidateAndInsertTransaction(childTx, false, true); err != nil {
			t.Fatalf("ValidateAndInsertTransaction childTx: %v", err)
		}

		tips, err := tc.Tips()
		if err != nil {
			t.Fatalf("Tips: %v", err)
		}
		for i := 0; i < 9; i++ {
			tip, _, err := tc.AddBlock(tips, nil, nil)
			if err != nil {
				t.Fatalf("AddBlock %d: %v", i, err)
			}
			tips = []*externalapi.DomainHash{tip}
		}

		expiredTransactions, _, err := miningManager.ExpireLowPriorityTransactions()
		if err != nil {
			t.Fatalf("ExpireLowPriorityTransactions: %v", err)
		}
		if expiredTransactions != 1 {
			t.Fatalf("expected non-ready CAT child to expire at total lifetime cap, got %d expired transactions", expiredTransactions)
		}
		transactionsFromMempool, _ := miningManager.AllTransactions(true, false)
		if !contains(parentTx, transactionsFromMempool) {
			t.Fatalf("expected non-CAT parent to keep the normal expiry window, got %s", consensushashing.TransactionIDs(transactionsFromMempool))
		}
		if contains(childTx, transactionsFromMempool) {
			t.Fatalf("expected non-ready CAT child to expire at total lifetime cap, got %s", consensushashing.TransactionIDs(transactionsFromMempool))
		}
	})
}

func TestAtomicHighPriorityFrontierTransactionExpires(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		miningManager, tc := newTestMiningManagerWithConfig(
			t,
			consensusConfig,
			"TestAtomicHighPriorityFrontierTransactionExpires",
			func(config *mempool.Config) {
				config.AtomicTransactionExpireIntervalDAAScore = 5
				config.TransactionExpireScanIntervalDAAScore = 0
				config.MinimumRelayTransactionFee = 0
			},
		)

		var assetID [externalapi.DomainHashSize]byte
		assetID[0] = 0x3b
		atomicTx := createCATTransactionWithUTXOEntry(t, 1, createCATTransferPayload(assetID, 1))
		if _, err := miningManager.ValidateAndInsertTransaction(atomicTx, true, false); err != nil {
			t.Fatalf("ValidateAndInsertTransaction atomicTx: %v", err)
		}

		tips, err := tc.Tips()
		if err != nil {
			t.Fatalf("Tips: %v", err)
		}
		for i := 0; i < 6; i++ {
			tip, _, err := tc.AddBlock(tips, nil, nil)
			if err != nil {
				t.Fatalf("AddBlock %d: %v", i, err)
			}
			tips = []*externalapi.DomainHash{tip}
		}

		expiredTransactions, _, err := miningManager.ExpireLowPriorityTransactions()
		if err != nil {
			t.Fatalf("ExpireLowPriorityTransactions: %v", err)
		}
		if expiredTransactions != 1 {
			t.Fatalf("expected high-priority frontier CAT to expire, got %d expired transactions", expiredTransactions)
		}
		transactionsFromMempool, _ := miningManager.AllTransactions(true, false)
		if len(transactionsFromMempool) != 0 {
			t.Fatalf("expected high-priority frontier CAT to be expired, got %s", consensushashing.TransactionIDs(transactionsFromMempool))
		}
	})
}

func TestImmatureSpend(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestValidateAndInsertTransaction")
		if err != nil {
			t.Fatalf("Error setting up TestConsensus: %+v", err)
		}
		defer teardown(false)

		miningFactory := miningmanager.NewFactory()
		tcAsConsensus := tc.(externalapi.Consensus)
		tcAsConsensusPointer := &tcAsConsensus
		consensusReference := consensusreference.NewConsensusReference(&tcAsConsensusPointer)
		miningManager := miningFactory.NewMiningManager(consensusReference, &consensusConfig.Params, mempool.DefaultConfig(&consensusConfig.Params))
		tx := createTransactionWithUTXOEntry(t, 0, consensusConfig.GenesisBlock.Header.DAAScore())
		_, err = miningManager.ValidateAndInsertTransaction(tx, false, false)
		txRuleError := &mempool.TxRuleError{}
		if !errors.As(err, txRuleError) || txRuleError.RejectCode != mempool.RejectImmatureSpend {
			t.Fatalf("Unexpected error %+v", err)
		}
		transactionsFromMempool, _ := miningManager.AllTransactions(true, false)
		if contains(tx, transactionsFromMempool) {
			t.Fatalf("Mempool contains a transaction with immature coinbase")
		}
	})
}

// TestInsertDoubleTransactionsToMempool verifies that an attempt to insert a transaction
// more than once into the mempool will result in raising an appropriate error.
func TestInsertDoubleTransactionsToMempool(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestInsertDoubleTransactionsToMempool")
		if err != nil {
			t.Fatalf("Error setting up TestConsensus: %+v", err)
		}
		defer teardown(false)

		miningFactory := miningmanager.NewFactory()
		tcAsConsensus := tc.(externalapi.Consensus)
		tcAsConsensusPointer := &tcAsConsensus
		consensusReference := consensusreference.NewConsensusReference(&tcAsConsensusPointer)
		miningManager := miningFactory.NewMiningManager(consensusReference, &consensusConfig.Params, mempool.DefaultConfig(&consensusConfig.Params))
		transaction := createTransactionWithUTXOEntry(t, 0, 0)
		_, err = miningManager.ValidateAndInsertTransaction(transaction, false, true)
		if err != nil {
			t.Fatalf("ValidateAndInsertTransaction: %v", err)
		}
		_, err = miningManager.ValidateAndInsertTransaction(transaction, false, true)
		if err == nil || !strings.Contains(err.Error(), "is already in the mempool") {
			t.Fatalf("ValidateAndInsertTransaction: %v", err)
		}
	})
}

// TestDoubleSpendInMempool verifies that an attempt to insert a transaction double-spending
// another transaction already in  the mempool will result in raising an appropriate error.
func TestDoubleSpendInMempool(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestDoubleSpendInMempool")
		if err != nil {
			t.Fatalf("Error setting up TestConsensus: %+v", err)
		}
		defer teardown(false)

		miningFactory := miningmanager.NewFactory()
		tcAsConsensus := tc.(externalapi.Consensus)
		tcAsConsensusPointer := &tcAsConsensus
		consensusReference := consensusreference.NewConsensusReference(&tcAsConsensusPointer)
		miningManager := miningFactory.NewMiningManager(consensusReference, &consensusConfig.Params, mempool.DefaultConfig(&consensusConfig.Params))
		transaction, err := createChildAndParentTxsAndAddParentToConsensus(tc)
		if err != nil {
			t.Fatalf("Error creating transaction: %+v", err)
		}
		_, err = miningManager.ValidateAndInsertTransaction(transaction, false, true)
		if err != nil {
			t.Fatalf("ValidateAndInsertTransaction: %v", err)
		}

		doubleSpendingTransaction := transaction.Clone()
		doubleSpendingTransaction.ID = nil
		doubleSpendingTransaction.Outputs[0].Value-- // do some minor change so that txID is different

		_, err = miningManager.ValidateAndInsertTransaction(doubleSpendingTransaction, false, true)
		if err == nil || !strings.Contains(err.Error(), "already spent by transaction") {
			t.Fatalf("ValidateAndInsertTransaction: %v", err)
		}
	})
}

// TestHandleNewBlockTransactions verifies that all the transactions in the block were successfully removed from the mempool.
func TestHandleNewBlockTransactions(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestHandleNewBlockTransactions")
		if err != nil {
			t.Fatalf("Error setting up TestConsensus: %+v", err)
		}
		defer teardown(false)

		miningFactory := miningmanager.NewFactory()
		tcAsConsensus := tc.(externalapi.Consensus)
		tcAsConsensusPointer := &tcAsConsensus
		consensusReference := consensusreference.NewConsensusReference(&tcAsConsensusPointer)
		miningManager := miningFactory.NewMiningManager(consensusReference, &consensusConfig.Params, mempool.DefaultConfig(&consensusConfig.Params))
		transactionsToInsert := make([]*externalapi.DomainTransaction, 10)
		for i := range transactionsToInsert {
			transaction := createTransactionWithUTXOEntry(t, i, 0)
			transactionsToInsert[i] = transaction
			_, err = miningManager.ValidateAndInsertTransaction(transaction, false, true)
			if err != nil {
				t.Fatalf("ValidateAndInsertTransaction: %v", err)
			}
		}

		const partialLength = 3
		blockWithFirstPartOfTheTransactions := append([]*externalapi.DomainTransaction{nil}, transactionsToInsert[0:partialLength]...)
		blockWithRestOfTheTransactions := append([]*externalapi.DomainTransaction{nil}, transactionsToInsert[partialLength:]...)
		_, err = miningManager.HandleNewBlockTransactions(blockWithFirstPartOfTheTransactions)
		if err != nil {
			t.Fatalf("HandleNewBlockTransactions: %v", err)
		}
		mempoolTransactions, _ := miningManager.AllTransactions(true, false)
		for _, removedTransaction := range blockWithFirstPartOfTheTransactions {
			if contains(removedTransaction, mempoolTransactions) {
				t.Fatalf("This transaction shouldnt be in mempool: %s", consensushashing.TransactionID(removedTransaction))
			}
		}

		// There are no chained/double-spends transactions, and hence it is expected that all the other
		// transactions, will still be included in the mempool.
		mempoolTransactions, _ = miningManager.AllTransactions(true, false)
		for _, transaction := range blockWithRestOfTheTransactions[transactionhelper.CoinbaseTransactionIndex+1:] {
			if !contains(transaction, mempoolTransactions) {
				t.Fatalf("This transaction %s should be in mempool.", consensushashing.TransactionID(transaction))
			}
		}
		// Handle all the other transactions.
		_, err = miningManager.HandleNewBlockTransactions(blockWithRestOfTheTransactions)
		if err != nil {
			t.Fatalf("HandleNewBlockTransactions: %v", err)
		}
		mempoolTransactions, _ = miningManager.AllTransactions(true, false)
		if len(mempoolTransactions) != 0 {
			blockIDs := domainBlocksToBlockIds(mempoolTransactions)
			t.Fatalf("The mempool contains unexpected transactions: %s", blockIDs)
		}
	})
}

func domainBlocksToBlockIds(blocks []*externalapi.DomainTransaction) []*externalapi.DomainTransactionID {
	blockIDs := make([]*externalapi.DomainTransactionID, len(blocks))
	for i := range blockIDs {
		blockIDs[i] = consensushashing.TransactionID(blocks[i])
	}
	return blockIDs
}

// TestDoubleSpendWithBlock verifies that any transactions which are now double spends as a result of the block's new transactions
// will be removed from the mempool.
func TestDoubleSpendWithBlock(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestDoubleSpendWithBlock")
		if err != nil {
			t.Fatalf("Failed setting up TestConsensus: %+v", err)
		}
		defer teardown(false)

		miningFactory := miningmanager.NewFactory()
		tcAsConsensus := tc.(externalapi.Consensus)
		tcAsConsensusPointer := &tcAsConsensus
		consensusReference := consensusreference.NewConsensusReference(&tcAsConsensusPointer)
		miningManager := miningFactory.NewMiningManager(consensusReference, &consensusConfig.Params, mempool.DefaultConfig(&consensusConfig.Params))
		transactionInTheMempool := createTransactionWithUTXOEntry(t, 0, 0)
		_, err = miningManager.ValidateAndInsertTransaction(transactionInTheMempool, false, true)
		if err != nil {
			t.Fatalf("ValidateAndInsertTransaction: %v", err)
		}
		doubleSpendTransactionInTheBlock := createTransactionWithUTXOEntry(t, 0, 0)
		doubleSpendTransactionInTheBlock.Inputs[0].PreviousOutpoint = transactionInTheMempool.Inputs[0].PreviousOutpoint
		blockTransactions := []*externalapi.DomainTransaction{nil, doubleSpendTransactionInTheBlock}
		_, err = miningManager.HandleNewBlockTransactions(blockTransactions)
		if err != nil {
			t.Fatalf("HandleNewBlockTransactions: %v", err)
		}
		mempoolTransactions, _ := miningManager.AllTransactions(true, false)
		if contains(transactionInTheMempool, mempoolTransactions) {
			t.Fatalf("The transaction %s, shouldn't be in the mempool, since at least one "+
				"output was already spent.", consensushashing.TransactionID(transactionInTheMempool))
		}
	})
}

// TestOrphanTransactions verifies that a transaction could be a part of a new block template, only if it's not an orphan.
func TestOrphanTransactions(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestOrphanTransactions")
		if err != nil {
			t.Fatalf("Error setting up TestConsensus: %+v", err)
		}
		defer teardown(false)

		miningFactory := miningmanager.NewFactory()
		tcAsConsensus := tc.(externalapi.Consensus)
		tcAsConsensusPointer := &tcAsConsensus
		consensusReference := consensusreference.NewConsensusReference(&tcAsConsensusPointer)
		miningManager := miningFactory.NewMiningManager(consensusReference, &consensusConfig.Params, mempool.DefaultConfig(&consensusConfig.Params))
		// Before each parent transaction, We will add two blocks by consensus in order to fund the parent transactions.
		parentTransactions, childTransactions, err := createArraysOfParentAndChildrenTransactions(tc)
		if err != nil {
			t.Fatalf("Error in createArraysOfParentAndChildrenTransactions: %v", err)
		}
		for _, orphanTransaction := range childTransactions {
			_, err = miningManager.ValidateAndInsertTransaction(orphanTransaction, false, true)
			if err != nil {
				t.Fatalf("ValidateAndInsertTransaction: %v", err)
			}
		}
		transactionsMempool, _ := miningManager.AllTransactions(true, false)
		for _, transaction := range transactionsMempool {
			if contains(transaction, childTransactions) {
				t.Fatalf("Error: an orphan transaction is exist in the mempool")
			}
		}

		block, _, err := miningManager.GetBlockTemplate(&externalapi.DomainCoinbaseData{
			ScriptPublicKey: &externalapi.ScriptPublicKey{Script: nil, Version: 0},
			ExtraData:       nil})
		if err != nil {
			t.Fatalf("Failed get a block template: %v", err)
		}
		for _, transactionFromBlock := range block.Transactions[1:] {
			for _, orphanTransaction := range childTransactions {
				if consensushashing.TransactionID(transactionFromBlock) == consensushashing.TransactionID(orphanTransaction) {
					t.Fatalf("Tranasaction with unknown parents is exist in a block that was built from GetTemplate option.")
				}
			}
		}
		tips, err := tc.Tips()
		if err != nil {
			t.Fatalf("Tips: %v.", err)
		}
		blockParentsTransactionsHash, _, err := tc.AddBlock(tips, nil, parentTransactions)
		if err != nil {
			t.Fatalf("AddBlock: %v", err)
		}

		_, _, err = tc.AddBlock([]*externalapi.DomainHash{blockParentsTransactionsHash}, nil, nil)
		if err != nil {
			t.Fatalf("AddBlock: %v", err)
		}

		blockParentsTransactions, _, err := tc.GetBlock(blockParentsTransactionsHash)
		if err != nil {
			t.Fatalf("GetBlock: %v", err)
		}
		_, err = miningManager.HandleNewBlockTransactions(blockParentsTransactions.Transactions)
		if err != nil {
			t.Fatalf("HandleNewBlockTransactions: %+v", err)
		}
		transactionsMempool, _ = miningManager.AllTransactions(true, false)
		if len(transactionsMempool) != len(childTransactions) {
			t.Fatalf("Expected %d transactions in the mempool but got %d", len(childTransactions), len(transactionsMempool))
		}

		for _, transaction := range transactionsMempool {
			if !contains(transaction, childTransactions) {
				t.Fatalf("Error: the transaction %s, should be in the mempool since its not "+
					"oprhan anymore.", consensushashing.TransactionID(transaction))
			}
		}
		block, _, err = miningManager.GetBlockTemplate(&externalapi.DomainCoinbaseData{
			ScriptPublicKey: &externalapi.ScriptPublicKey{Script: nil, Version: 0},
			ExtraData:       nil})
		if err != nil {
			t.Fatalf("GetBlockTemplate: %v", err)
		}
		for _, transactionFromBlock := range block.Transactions[1:] {
			isContained := false
			for _, childTransaction := range childTransactions {
				if *consensushashing.TransactionID(transactionFromBlock) == *consensushashing.TransactionID(childTransaction) {
					isContained = true
					break
				}
			}
			if !isContained {
				t.Fatalf("Error: Unknown Transaction %s in a block.", consensushashing.TransactionID(transactionFromBlock))
			}
		}
	})
}

func TestRevalidateOrphanTransactionsAfterConsensusUTXOUpdate(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0

		miningManager, tc := newTestMiningManagerWithConfig(
			t,
			consensusConfig,
			"TestRevalidateOrphanTransactionsAfterConsensusUTXOUpdate",
			nil,
		)

		parentTransaction, childTransaction, err := createParentAndChildrenTransactions(tc)
		if err != nil {
			t.Fatalf("createParentAndChildrenTransactions: %v", err)
		}
		for _, input := range childTransaction.Inputs {
			input.UTXOEntry = nil
		}

		accepted, err := miningManager.ValidateAndInsertTransaction(childTransaction, false, true)
		if err != nil {
			t.Fatalf("ValidateAndInsertTransaction child orphan: %v", err)
		}
		if len(accepted) != 0 {
			t.Fatalf("expected child to be stored as orphan, accepted %d transaction(s)", len(accepted))
		}
		if count := miningManager.TransactionCount(false, true); count != 1 {
			t.Fatalf("expected one orphan transaction, got %d", count)
		}

		tips, err := tc.Tips()
		if err != nil {
			t.Fatalf("Tips: %v", err)
		}
		_, _, err = tc.AddBlock(tips, nil, []*externalapi.DomainTransaction{parentTransaction})
		if err != nil {
			t.Fatalf("AddBlock parent transaction: %v", err)
		}

		accepted, err = miningManager.RevalidateOrphanTransactions()
		if err != nil {
			t.Fatalf("RevalidateOrphanTransactions: %v", err)
		}
		if len(accepted) != 1 || !contains(childTransaction, accepted) {
			t.Fatalf("expected child to be accepted after UTXO revalidation, got %s",
				consensushashing.TransactionIDs(accepted))
		}
		if count := miningManager.TransactionCount(false, true); count != 0 {
			t.Fatalf("expected orphan pool to be empty, got %d", count)
		}

		transactionsMempool, _ := miningManager.AllTransactions(true, false)
		if !contains(childTransaction, transactionsMempool) {
			t.Fatalf("expected child transaction in mempool after orphan revalidation")
		}
	})
}

func TestHighPriorityTransactions(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestDoubleSpendWithBlock")
		if err != nil {
			t.Fatalf("Failed setting up TestConsensus: %+v", err)
		}
		defer teardown(false)

		miningFactory := miningmanager.NewFactory()
		mempoolConfig := mempool.DefaultConfig(&consensusConfig.Params)
		mempoolConfig.MaximumTransactionCount = 1
		mempoolConfig.MaximumOrphanTransactionCount = 1
		tcAsConsensus := tc.(externalapi.Consensus)
		tcAsConsensusPointer := &tcAsConsensus
		consensusReference := consensusreference.NewConsensusReference(&tcAsConsensusPointer)
		miningManager := miningFactory.NewMiningManager(consensusReference, &consensusConfig.Params, mempoolConfig)

		// Create 3 pairs of transaction parent-and-child pairs: 1 low priority and 2 high priority
		lowPriorityParentTransaction, lowPriorityChildTransaction, err := createParentAndChildrenTransactions(tc)
		if err != nil {
			t.Fatalf("error creating low-priority transaction pair: %+v", err)
		}
		firstHighPriorityParentTransaction, firstHighPriorityChildTransaction, err := createParentAndChildrenTransactions(tc)
		if err != nil {
			t.Fatalf("error creating first high-priority transaction pair: %+v", err)
		}
		secondHighPriorityParentTransaction, secondHighPriorityChildTransaction, err := createParentAndChildrenTransactions(tc)
		if err != nil {
			t.Fatalf("error creating second high-priority transaction pair: %+v", err)
		}

		// Submit all the children, make sure the 2 highPriority ones remain in the orphan pool
		_, err = miningManager.ValidateAndInsertTransaction(lowPriorityChildTransaction, false, true)
		if err != nil {
			t.Fatalf("error submitting low-priority transaction: %+v", err)
		}
		_, err = miningManager.ValidateAndInsertTransaction(firstHighPriorityChildTransaction, true, true)
		if err != nil {
			t.Fatalf("error submitting first high-priority transaction: %+v", err)
		}
		_, err = miningManager.ValidateAndInsertTransaction(secondHighPriorityChildTransaction, true, true)
		if err != nil {
			t.Fatalf("error submitting second high-priority transaction: %+v", err)
		}
		// There's no API to check what stayed in the orphan pool, but we'll find it out when we begin to unorphan

		// Submit all the parents.
		// Low priority transaction will only accept the parent, since the child was evicted from orphanPool
		lowPriorityAcceptedTransactions, err :=
			miningManager.ValidateAndInsertTransaction(lowPriorityParentTransaction, false, true)
		if err != nil {
			t.Fatalf("error submitting low-priority transaction: %+v", err)
		}
		expectedLowPriorityAcceptedTransactions := []*externalapi.DomainTransaction{lowPriorityParentTransaction}
		if !reflect.DeepEqual(lowPriorityAcceptedTransactions, expectedLowPriorityAcceptedTransactions) {
			t.Errorf("Expected only lowPriorityParent (%v) to be in lowPriorityAcceptedTransactions, but got %v",
				consensushashing.TransactionIDs(expectedLowPriorityAcceptedTransactions),
				consensushashing.TransactionIDs(lowPriorityAcceptedTransactions))
		}

		// Both high priority transactions should accept parent and child

		// Insert firstHighPriorityParentTransaction
		firstHighPriorityAcceptedTransactions, err :=
			miningManager.ValidateAndInsertTransaction(firstHighPriorityParentTransaction, true, true)
		if err != nil {
			t.Fatalf("error submitting first high-priority transaction: %+v", err)
		}
		expectedFirstHighPriorityAcceptedTransactions :=
			[]*externalapi.DomainTransaction{firstHighPriorityParentTransaction, firstHighPriorityChildTransaction}
		if !reflect.DeepEqual(firstHighPriorityAcceptedTransactions, expectedFirstHighPriorityAcceptedTransactions) {
			t.Errorf(
				"Expected both firstHighPriority transaction (%v) to be in firstHighPriorityAcceptedTransactions, but got %v",
				consensushashing.TransactionIDs(firstHighPriorityAcceptedTransactions),
				consensushashing.TransactionIDs(expectedFirstHighPriorityAcceptedTransactions))
		}
		// Insert secondHighPriorityParentTransaction
		secondHighPriorityAcceptedTransactions, err :=
			miningManager.ValidateAndInsertTransaction(secondHighPriorityParentTransaction, true, true)
		if err != nil {
			t.Fatalf("error submitting second high-priority transaction: %+v", err)
		}
		expectedSecondHighPriorityAcceptedTransactions :=
			[]*externalapi.DomainTransaction{secondHighPriorityParentTransaction, secondHighPriorityChildTransaction}
		if !reflect.DeepEqual(secondHighPriorityAcceptedTransactions, expectedSecondHighPriorityAcceptedTransactions) {
			t.Errorf(
				"Expected both secondHighPriority transaction (%v) to be in secondHighPriorityAcceptedTransactions, but got %v",
				consensushashing.TransactionIDs(secondHighPriorityAcceptedTransactions),
				consensushashing.TransactionIDs(expectedSecondHighPriorityAcceptedTransactions))
		}
	})
}

func TestRevalidateHighPriorityTransactions(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestRevalidateHighPriorityTransactions")
		if err != nil {
			t.Fatalf("Failed setting up TestConsensus: %+v", err)
		}
		defer teardown(false)

		miningFactory := miningmanager.NewFactory()
		mempoolConfig := mempool.DefaultConfig(&consensusConfig.Params)
		tcAsConsensus := tc.(externalapi.Consensus)
		tcAsConsensusPointer := &tcAsConsensus
		consensusReference := consensusreference.NewConsensusReference(&tcAsConsensusPointer)
		miningManager := miningFactory.NewMiningManager(consensusReference, &consensusConfig.Params, mempoolConfig)

		// Create two valid transactions that double-spend each other (childTransaction1, childTransaction2)
		parentTransaction, childTransaction1, err := createParentAndChildrenTransactions(tc)
		if err != nil {
			t.Fatalf("Error creating parentTransaction and childTransaction1: %+v", err)
		}
		tips, err := tc.Tips()
		if err != nil {
			t.Fatalf("Error getting tips: %+v", err)
		}

		fundingBlock, _, err := tc.AddBlock(tips, nil, []*externalapi.DomainTransaction{parentTransaction})
		if err != nil {
			t.Fatalf("Error getting function block: %+v", err)
		}

		childTransaction2 := childTransaction1.Clone()
		childTransaction2.Outputs[0].Value-- // decrement value to change id

		// Mine 1 block with confirming childTransaction1 and 2 blocks confirming childTransaction2, so that
		// childTransaction2 is accepted
		tip1, _, err := tc.AddBlock([]*externalapi.DomainHash{fundingBlock}, nil,
			[]*externalapi.DomainTransaction{childTransaction1})
		if err != nil {
			t.Fatalf("Error adding tip1: %+v", err)
		}
		tip2, _, err := tc.AddBlock([]*externalapi.DomainHash{fundingBlock}, nil,
			[]*externalapi.DomainTransaction{childTransaction2})
		if err != nil {
			t.Fatalf("Error adding tip2: %+v", err)
		}
		_, _, err = tc.AddBlock([]*externalapi.DomainHash{tip2}, nil, nil)
		if err != nil {
			t.Fatalf("Error mining on top of tip2: %+v", err)
		}

		// Add to mempool transaction that spends childTransaction2 (as high priority)
		spendingTransaction, err := testutils.CreateTransaction(childTransaction2, 1000)
		if err != nil {
			t.Fatalf("Error creating spendingTransaction: %+v", err)
		}
		_, err = miningManager.ValidateAndInsertTransaction(spendingTransaction, true, false)
		if err != nil {
			t.Fatalf("Error inserting spendingTransaction: %+v", err)
		}

		// Revalidate, to make sure spendingTransaction is still valid
		validTransactions, err := miningManager.RevalidateHighPriorityTransactions()
		if err != nil {
			t.Fatalf("Error from first RevalidateHighPriorityTransactions: %+v", err)
		}
		if len(validTransactions) != 1 || !validTransactions[0].Equal(spendingTransaction) {
			t.Fatalf("Expected to have spendingTransaction as only validTransaction returned from "+
				"RevalidateHighPriorityTransactions, but got %v instead", validTransactions)
		}

		// Mine 2 more blocks on top of tip1, to re-org out childTransaction1, thus making spendingTransaction invalid
		for i := 0; i < 2; i++ {
			tip1, _, err = tc.AddBlock([]*externalapi.DomainHash{tip1}, nil, nil)
			if err != nil {
				t.Fatalf("Error mining on top of tip1: %+v", err)
			}
		}

		// Make sure spendingTransaction is still in mempool
		mempoolTransactions, _ := miningManager.AllTransactions(true, false)
		if len(mempoolTransactions) != 1 || !mempoolTransactions[0].Equal(spendingTransaction) {
			t.Fatalf("Expected to have spendingTransaction as only validTransaction returned from "+
				"RevalidateHighPriorityTransactions, but got %v instead", validTransactions)
		}

		// Revalidate again, this time validTransactions should be empty
		validTransactions, err = miningManager.RevalidateHighPriorityTransactions()
		if err != nil {
			t.Fatalf("Error from first RevalidateHighPriorityTransactions: %+v", err)
		}
		if len(validTransactions) != 0 {
			t.Fatalf("Expected to have empty validTransactions, but got %v instead", validTransactions)
		}
		// And also AllTransactions should be empty as well
		mempoolTransactions, _ = miningManager.AllTransactions(true, false)
		if len(mempoolTransactions) != 0 {
			t.Fatalf("Expected to have empty allTransactions, but got %v instead", mempoolTransactions)
		}
	})
}

func TestRevalidateHighPriorityTransactionsWithChain(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestRevalidateHighPriorityTransactions")
		if err != nil {
			t.Fatalf("Failed setting up TestConsensus: %+v", err)
		}
		defer teardown(false)

		miningFactory := miningmanager.NewFactory()
		mempoolConfig := mempool.DefaultConfig(&consensusConfig.Params)
		tcAsConsensus := tc.(externalapi.Consensus)
		tcAsConsensusPointer := &tcAsConsensus
		consensusReference := consensusreference.NewConsensusReference(&tcAsConsensusPointer)
		miningManager := miningFactory.NewMiningManager(consensusReference, &consensusConfig.Params, mempoolConfig)

		const chainSize = 10
		chain, err := createTxChain(tc, chainSize)
		if err != nil {
			t.Fatal(err)
		}

		_, err = miningManager.ValidateAndInsertTransaction(chain[0], true, false)
		if err != nil {
			t.Fatal(err)
		}

		blockHash, _, err := tc.AddBlockOnTips(nil, []*externalapi.DomainTransaction{chain[0].Clone()})
		if err != nil {
			t.Fatal(err)
		}

		block, _, err := tc.GetBlock(blockHash)
		if err != nil {
			t.Fatal(err)
		}

		_, err = miningManager.HandleNewBlockTransactions(block.Transactions)
		if err != nil {
			t.Fatal(err)
		}

		for _, transaction := range chain[1:] {
			_, err = miningManager.ValidateAndInsertTransaction(transaction, true, false)
			if err != nil {
				t.Fatal(err)
			}
		}

		_, _, err = tc.AddBlockOnTips(nil, []*externalapi.DomainTransaction{chain[1].Clone()})
		if err != nil {
			t.Fatal(err)
		}

		revalidated, err := miningManager.RevalidateHighPriorityTransactions()
		if err != nil {
			t.Fatal(err)
		}

		if len(revalidated) != chainSize-2 {
			t.Fatalf("expected %d transactions to revalidate but instead only %d revalidated", chainSize-2, len(revalidated))
		}
	})
}

// TestModifyBlockTemplate verifies that modifying a block template changes coinbase data correctly.
func TestModifyBlockTemplate(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		factory := consensus.NewFactory()
		tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestModifyBlockTemplate")
		if err != nil {
			t.Fatalf("Error setting up TestConsensus: %+v", err)
		}
		defer teardown(false)

		miningFactory := miningmanager.NewFactory()
		tcAsConsensus := tc.(externalapi.Consensus)
		tcAsConsensusPointer := &tcAsConsensus
		consensusReference := consensusreference.NewConsensusReference(&tcAsConsensusPointer)
		miningManager := miningFactory.NewMiningManager(consensusReference, &consensusConfig.Params, mempool.DefaultConfig(&consensusConfig.Params))

		// Create some complex transactions. Logic taken from TestOrphanTransactions

		// Before each parent transaction, We will add two blocks by consensus in order to fund the parent transactions.
		parentTransactions, childTransactions, err := createArraysOfParentAndChildrenTransactions(tc)
		if err != nil {
			t.Fatalf("Error in createArraysOfParentAndChildrenTransactions: %v", err)
		}
		for _, orphanTransaction := range childTransactions {
			_, err = miningManager.ValidateAndInsertTransaction(orphanTransaction, false, true)
			if err != nil {
				t.Fatalf("ValidateAndInsertTransaction: %v", err)
			}
		}
		transactionsMempool, _ := miningManager.AllTransactions(true, false)
		for _, transaction := range transactionsMempool {
			if contains(transaction, childTransactions) {
				t.Fatalf("Error: an orphan transaction is exist in the mempool")
			}
		}

		emptyCoinbaseData := &externalapi.DomainCoinbaseData{
			ScriptPublicKey: &externalapi.ScriptPublicKey{Script: nil, Version: 0},
			ExtraData:       nil}
		block, _, err := miningManager.GetBlockTemplate(emptyCoinbaseData)
		if err != nil {
			t.Fatalf("Failed get a block template: %v", err)
		}

		for _, transactionFromBlock := range block.Transactions[1:] {
			for _, orphanTransaction := range childTransactions {
				if consensushashing.TransactionID(transactionFromBlock) == consensushashing.TransactionID(orphanTransaction) {
					t.Fatalf("Tranasaction with unknown parents is exist in a block that was built from GetTemplate option.")
				}
			}
		}

		// Run the purpose of this test, compare modified block templates
		sweepCompareModifiedTemplateToBuilt(t, consensusConfig, miningManager.GetBlockTemplateBuilder())

		// Create some more complex blocks and transactions. Logic taken from TestOrphanTransactions
		tips, err := tc.Tips()
		if err != nil {
			t.Fatalf("Tips: %v.", err)
		}
		blockParentsTransactionsHash, _, err := tc.AddBlock(tips, nil, parentTransactions)
		if err != nil {
			t.Fatalf("AddBlock: %v", err)
		}

		_, _, err = tc.AddBlock([]*externalapi.DomainHash{blockParentsTransactionsHash}, nil, nil)
		if err != nil {
			t.Fatalf("AddBlock: %v", err)
		}

		blockParentsTransactions, _, err := tc.GetBlock(blockParentsTransactionsHash)
		if err != nil {
			t.Fatalf("GetBlock: %v", err)
		}
		_, err = miningManager.HandleNewBlockTransactions(blockParentsTransactions.Transactions)
		if err != nil {
			t.Fatalf("HandleNewBlockTransactions: %+v", err)
		}
		transactionsMempool, _ = miningManager.AllTransactions(true, false)
		if len(transactionsMempool) != len(childTransactions) {
			t.Fatalf("Expected %d transactions in the mempool but got %d", len(childTransactions), len(transactionsMempool))
		}

		for _, transaction := range transactionsMempool {
			if !contains(transaction, childTransactions) {
				t.Fatalf("Error: the transaction %s, should be in the mempool since its not "+
					"oprhan anymore.", consensushashing.TransactionID(transaction))
			}
		}
		block, _, err = miningManager.GetBlockTemplate(emptyCoinbaseData)
		if err != nil {
			t.Fatalf("GetBlockTemplate: %v", err)
		}

		for _, transactionFromBlock := range block.Transactions[1:] {
			isContained := false
			for _, childTransaction := range childTransactions {
				if *consensushashing.TransactionID(transactionFromBlock) == *consensushashing.TransactionID(childTransaction) {
					isContained = true
					break
				}
			}
			if !isContained {
				t.Fatalf("Error: Unknown Transaction %s in a block.", consensushashing.TransactionID(transactionFromBlock))
			}
		}

		// Run the purpose of this test, compare modified block templates
		sweepCompareModifiedTemplateToBuilt(t, consensusConfig, miningManager.GetBlockTemplateBuilder())

		// Create a real coinbase to use
		coinbaseUsual, err := generateNewCoinbase(consensusConfig.Prefix, opUsual)
		if err != nil {
			t.Fatalf("Generate coinbase: %v.", err)
		}
		var emptyTransactions []*externalapi.DomainTransaction

		// Create interesting DAG structures and rerun the template comparisons
		tips, err = tc.Tips()
		if err != nil {
			t.Fatalf("Tips: %v.", err)
		}
		// Create a fork
		_, _, err = tc.AddBlock(tips[:1], coinbaseUsual, emptyTransactions)
		if err != nil {
			t.Fatalf("AddBlock: %v", err)
		}
		chainTip, _, err := tc.AddBlock(tips[:1], coinbaseUsual, emptyTransactions)
		if err != nil {
			t.Fatalf("AddBlock: %v", err)
		}

		sweepCompareModifiedTemplateToBuilt(t, consensusConfig, miningManager.GetBlockTemplateBuilder())

		// Create some blue blocks
		for i := externalapi.KType(0); i < consensusConfig.K-2; i++ {
			chainTip, _, err = tc.AddBlock([]*externalapi.DomainHash{chainTip}, coinbaseUsual, emptyTransactions)
			if err != nil {
				t.Fatalf("AddBlock: %v", err)
			}
		}

		sweepCompareModifiedTemplateToBuilt(t, consensusConfig, miningManager.GetBlockTemplateBuilder())

		// Mine more such that we have a merged red
		for i := externalapi.KType(0); i < consensusConfig.K; i++ {
			chainTip, _, err = tc.AddBlock([]*externalapi.DomainHash{chainTip}, coinbaseUsual, emptyTransactions)
			if err != nil {
				t.Fatalf("AddBlock: %v", err)
			}
		}
		blockTemplate, err := miningManager.GetBlockTemplateBuilder().BuildBlockTemplate(emptyCoinbaseData)
		if err != nil {
			t.Fatalf("BuildBlockTemplate: %v", err)
		}
		if !blockTemplate.CoinbaseHasRedReward {
			t.Fatalf("Expected block template to have red reward")
		}

		sweepCompareModifiedTemplateToBuilt(t, consensusConfig, miningManager.GetBlockTemplateBuilder())
	})
}

func sweepCompareModifiedTemplateToBuilt(
	t *testing.T, consensusConfig *consensus.Config, builder model.BlockTemplateBuilder) {
	for i := 0; i < 4; i++ {
		// Run a few times to get more randomness
		compareModifiedTemplateToBuilt(t, consensusConfig, builder, opUsual, opUsual)
		compareModifiedTemplateToBuilt(t, consensusConfig, builder, opECDSA, opECDSA)
	}
	compareModifiedTemplateToBuilt(t, consensusConfig, builder, opTrue, opUsual)
	compareModifiedTemplateToBuilt(t, consensusConfig, builder, opUsual, opTrue)
	compareModifiedTemplateToBuilt(t, consensusConfig, builder, opECDSA, opUsual)
	compareModifiedTemplateToBuilt(t, consensusConfig, builder, opUsual, opECDSA)
	compareModifiedTemplateToBuilt(t, consensusConfig, builder, opEmpty, opUsual)
	compareModifiedTemplateToBuilt(t, consensusConfig, builder, opUsual, opEmpty)
}

type opType uint8

const (
	opUsual opType = iota
	opECDSA
	opTrue
	opEmpty
)

func compareModifiedTemplateToBuilt(
	t *testing.T, consensusConfig *consensus.Config, builder model.BlockTemplateBuilder,
	firstCoinbaseOp, secondCoinbaseOp opType) {
	coinbase1, err := generateNewCoinbase(consensusConfig.Params.Prefix, firstCoinbaseOp)
	if err != nil {
		t.Fatalf("Failed to generate new coinbase: %v", err)
	}
	coinbase2, err := generateNewCoinbase(consensusConfig.Params.Prefix, secondCoinbaseOp)
	if err != nil {
		t.Fatalf("Failed to generate new coinbase: %v", err)
	}

	// Build a fresh template for coinbase2 as a reference
	expectedTemplate, err := builder.BuildBlockTemplate(coinbase2)
	if err != nil {
		t.Fatalf("Failed to build block template: %v", err)
	}
	// Modify to coinbase1
	modifiedTemplate, err := builder.ModifyBlockTemplate(coinbase1, expectedTemplate.Clone())
	if err != nil {
		t.Fatalf("Failed to modify block template: %v", err)
	}
	// And modify back to coinbase2
	modifiedTemplate, err = builder.ModifyBlockTemplate(coinbase2, modifiedTemplate.Clone())
	if err != nil {
		t.Fatalf("Failed to modify block template: %v", err)
	}

	// Make sure timestamps are equal before comparing the hash
	mutableHeader := modifiedTemplate.Block.Header.ToMutable()
	mutableHeader.SetTimeInMilliseconds(expectedTemplate.Block.Header.TimeInMilliseconds())
	modifiedTemplate.Block.Header = mutableHeader.ToImmutable()

	// Assert hashes are equal
	expectedTemplateHash := consensushashing.BlockHash(expectedTemplate.Block)
	modifiedTemplateHash := consensushashing.BlockHash(modifiedTemplate.Block)
	if !expectedTemplateHash.Equal(modifiedTemplateHash) {
		t.Fatalf("Expected block hashes %s, %s to be equal", expectedTemplateHash, modifiedTemplateHash)
	}
}

func generateNewCoinbase(addressPrefix util.Bech32Prefix, op opType) (*externalapi.DomainCoinbaseData, error) {
	if op == opTrue {
		scriptPublicKey, _ := testutils.OpTrueScript()
		return &externalapi.DomainCoinbaseData{
			ScriptPublicKey: scriptPublicKey, ExtraData: []byte(version.Version()),
		}, nil
	}
	if op == opEmpty {
		return &externalapi.DomainCoinbaseData{
			ScriptPublicKey: &externalapi.ScriptPublicKey{Script: nil, Version: 0},
			ExtraData:       nil,
		}, nil
	}
	_, publicKey, err := libcryptixwallet.CreateKeyPair(op == opECDSA)
	if err != nil {
		return nil, err
	}
	var address string
	if op == opECDSA {
		addressPublicKeyECDSA, err := util.NewAddressPublicKeyECDSA(publicKey, addressPrefix)
		if err != nil {
			return nil, err
		}
		address = addressPublicKeyECDSA.EncodeAddress()
	} else {
		addressPublicKey, err := util.NewAddressPublicKey(publicKey, addressPrefix)
		if err != nil {
			return nil, err
		}
		address = addressPublicKey.EncodeAddress()
	}
	payAddress, err := util.DecodeAddress(address, addressPrefix)
	if err != nil {
		return nil, err
	}
	scriptPublicKey, err := txscript.PayToAddrScript(payAddress)
	if err != nil {
		return nil, err
	}
	return &externalapi.DomainCoinbaseData{
		ScriptPublicKey: scriptPublicKey, ExtraData: []byte(version.Version()),
	}, nil
}

func assertMixedTemplateShape(
	t *testing.T,
	transactions []*externalapi.DomainTransaction,
	expectedNativeNonCoinbase int,
	expectedPayload int,
) {
	t.Helper()
	if len(transactions) != 1+expectedNativeNonCoinbase+expectedPayload {
		t.Fatalf("mixed template transaction count: expected %d, got %d",
			1+expectedNativeNonCoinbase+expectedPayload, len(transactions))
	}
	if len(transactions[0].Inputs) != 0 {
		t.Fatalf("first template transaction must be coinbase")
	}

	nativeCount := 0
	payloadCount := 0
	seenPayload := false
	for _, tx := range transactions[1:] {
		switch tx.SubnetworkID {
		case subnetworks.SubnetworkIDPayload:
			seenPayload = true
			payloadCount++
		case subnetworks.SubnetworkIDNative:
			if seenPayload {
				t.Fatalf("native transaction appeared after payload/CAT transaction")
			}
			nativeCount++
		default:
			t.Fatalf("unexpected subnetwork %s in mixed template", tx.SubnetworkID)
		}
	}
	if nativeCount != expectedNativeNonCoinbase || payloadCount != expectedPayload {
		t.Fatalf("mixed template shape: native=%d payload=%d, expected native=%d payload=%d",
			nativeCount, payloadCount, expectedNativeNonCoinbase, expectedPayload)
	}
}

func createTransactionWithUTXOEntry(t *testing.T, i int, daaScore uint64) *externalapi.DomainTransaction {
	prevOutTxID := externalapi.DomainTransactionID{}
	prevOutPoint := externalapi.DomainOutpoint{TransactionID: prevOutTxID, Index: uint32(i)}
	scriptPublicKey, redeemScript := testutils.OpTrueScript()
	signatureScript, err := txscript.PayToScriptHashSignatureScript(redeemScript, nil)
	if err != nil {
		t.Fatalf("PayToScriptHashSignatureScript: %v", err)
	}
	txInput := externalapi.DomainTransactionInput{
		PreviousOutpoint: prevOutPoint,
		SignatureScript:  signatureScript,
		Sequence:         constants.MaxTxInSequenceNum,
		UTXOEntry: utxo.NewUTXOEntry(
			100000000, // 1 CPAY
			scriptPublicKey,
			true,
			daaScore),
	}
	txOut := externalapi.DomainTransactionOutput{
		Value:           10000,
		ScriptPublicKey: scriptPublicKey,
	}
	tx := externalapi.DomainTransaction{
		Version:      constants.MaxTransactionVersion,
		Inputs:       []*externalapi.DomainTransactionInput{&txInput},
		Outputs:      []*externalapi.DomainTransactionOutput{&txOut},
		SubnetworkID: subnetworks.SubnetworkIDNative,
		Gas:          0,
		Fee:          289,
		Mass:         1,
		LockTime:     0}

	return &tx
}

func createCATTransactionWithUTXOEntry(t *testing.T, i int, payload []byte) *externalapi.DomainTransaction {
	tx := createTransactionWithUTXOEntry(t, i, 0)
	tx.SubnetworkID = subnetworks.SubnetworkIDPayload
	tx.Payload = append([]byte(nil), payload...)
	return tx
}

func createCATTransferPayload(assetID [externalapi.DomainHashSize]byte, nonce uint64) []byte {
	payload := createCATPayloadHeader(1, nonce)
	payload = append(payload, assetID[:]...)
	var toOwnerID [externalapi.DomainHashSize]byte
	toOwnerID[0] = 0x77
	payload = append(payload, toOwnerID[:]...)
	return appendCATUint128(payload, 1)
}

func createCATCreateAssetPayload(nonce uint64) []byte {
	payload := createCATPayloadHeader(0, nonce)
	payload = append(payload, 1, 0, 0)
	payload = appendCATUint128(payload, 0)
	var mintAuthorityOwnerID [externalapi.DomainHashSize]byte
	mintAuthorityOwnerID[0] = 0x55
	payload = append(payload, mintAuthorityOwnerID[:]...)
	payload = append(payload, 1, 1)
	payload = appendUint16LE(payload, 0)
	payload = append(payload, 'A', 'A')
	return payload
}

func createCATCreateAssetWithMintPayload(nonce uint64) []byte {
	payload := createCATPayloadHeader(4, nonce)
	payload = append(payload, 1, 0, 1)
	payload = appendCATUint128(payload, 10_000)
	var mintAuthorityOwnerID [externalapi.DomainHashSize]byte
	mintAuthorityOwnerID[0] = 0x55
	payload = append(payload, mintAuthorityOwnerID[:]...)
	payload = append(payload, 1, 1)
	payload = appendUint16LE(payload, 0)
	payload = append(payload, 'M', 'M')
	payload = appendCATUint128(payload, 1)
	var initialMintToOwnerID [externalapi.DomainHashSize]byte
	initialMintToOwnerID[0] = 0x66
	payload = append(payload, initialMintToOwnerID[:]...)
	return payload
}

func createCATBuyPayload(assetID [externalapi.DomainHashSize]byte, nonce uint64, expectedPoolNonce uint64) []byte {
	payload := createCATPayloadHeader(6, nonce)
	payload = append(payload, assetID[:]...)
	payload = appendUint64LE(payload, expectedPoolNonce)
	payload = appendUint64LE(payload, 1)
	return appendCATUint128(payload, 1)
}

func createCATPayloadHeader(opcode byte, nonce uint64) []byte {
	payload := make([]byte, 16)
	copy(payload, []byte("CAT"))
	payload[3] = 1
	payload[4] = opcode
	binary.LittleEndian.PutUint16(payload[6:8], 0)
	binary.LittleEndian.PutUint64(payload[8:16], nonce)
	return payload
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

func appendCATUint128(payload []byte, value uint64) []byte {
	var encoded [16]byte
	binary.LittleEndian.PutUint64(encoded[:8], value)
	return append(payload, encoded[:]...)
}

func createArraysOfParentAndChildrenTransactions(tc testapi.TestConsensus) ([]*externalapi.DomainTransaction,
	[]*externalapi.DomainTransaction, error) {

	const numOfTransactions = 5
	transactions := make([]*externalapi.DomainTransaction, numOfTransactions)
	parentTransactions := make([]*externalapi.DomainTransaction, len(transactions))
	var err error
	for i := range transactions {
		parentTransactions[i], transactions[i], err = createParentAndChildrenTransactions(tc)
		if err != nil {
			return nil, nil, err
		}
	}
	return parentTransactions, transactions, nil
}

func createParentAndChildrenTransactions(tc testapi.TestConsensus) (txParent *externalapi.DomainTransaction,
	txChild *externalapi.DomainTransaction, err error) {

	chain, err := createTxChain(tc, 2)
	if err != nil {
		return nil, nil, err
	}

	return chain[0], chain[1], nil
}

func createReadyTransactionFromConsensusFunding(tc testapi.TestConsensus) (*externalapi.DomainTransaction, error) {
	return createReadyTransactionFromConsensusFundingWithFee(tc, 1000)
}

func createReadyTransactionFromConsensusFundingWithFee(tc testapi.TestConsensus, fee uint64) (*externalapi.DomainTransaction, error) {
	tips, err := tc.Tips()
	if err != nil {
		return nil, err
	}

	_, _, err = tc.AddBlock(tips, nil, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "AddBlock: %v", err)
	}

	tips, err = tc.Tips()
	if err != nil {
		return nil, err
	}

	fundingBlockHash, _, err := tc.AddBlock(tips, nil, nil)
	if err != nil {
		return nil, errors.Wrap(err, "AddBlock: ")
	}
	fundingBlock, _, err := tc.GetBlock(fundingBlockHash)
	if err != nil {
		return nil, errors.Wrap(err, "GetBlock: ")
	}
	fundingTransaction := fundingBlock.Transactions[transactionhelper.CoinbaseTransactionIndex]
	return testutils.CreateTransaction(fundingTransaction, fee)
}

func createTxChain(tc testapi.TestConsensus, numTxs int) ([]*externalapi.DomainTransaction, error) {
	// We will add two blocks by consensus before the parent transactions, in order to fund the parent transactions.
	tips, err := tc.Tips()
	if err != nil {
		return nil, err
	}

	_, _, err = tc.AddBlock(tips, nil, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "AddBlock: %v", err)
	}

	tips, err = tc.Tips()
	if err != nil {
		return nil, err
	}

	fundingBlockHashForParent, _, err := tc.AddBlock(tips, nil, nil)
	if err != nil {
		return nil, errors.Wrap(err, "AddBlock: ")
	}
	fundingBlockForParent, _, err := tc.GetBlock(fundingBlockHashForParent)
	if err != nil {
		return nil, errors.Wrap(err, "GetBlock: ")
	}
	fundingTransactionForParent := fundingBlockForParent.Transactions[transactionhelper.CoinbaseTransactionIndex]

	transactions := make([]*externalapi.DomainTransaction, numTxs)
	transactions[0], err = testutils.CreateTransaction(fundingTransactionForParent, 1000)
	if err != nil {
		return nil, err
	}

	txParent := transactions[0]
	for i := 1; i < numTxs; i++ {
		transactions[i], err = testutils.CreateTransaction(txParent, 1000)
		if err != nil {
			return nil, err
		}

		txParent = transactions[i]
	}

	return transactions, nil
}

func createChildAndParentTxsAndAddParentToConsensus(tc testapi.TestConsensus) (*externalapi.DomainTransaction, error) {
	firstBlockHash, _, err := tc.AddBlock([]*externalapi.DomainHash{tc.DAGParams().GenesisHash}, nil, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "AddBlock: %v", err)
	}
	ParentBlockHash, _, err := tc.AddBlock([]*externalapi.DomainHash{firstBlockHash}, nil, nil)
	if err != nil {
		return nil, errors.Wrap(err, "AddBlock: ")
	}
	ParentBlock, _, err := tc.GetBlock(ParentBlockHash)
	if err != nil {
		return nil, errors.Wrap(err, "GetBlock: ")
	}
	parentTransaction := ParentBlock.Transactions[transactionhelper.CoinbaseTransactionIndex]
	txChild, err := testutils.CreateTransaction(parentTransaction, 1000)
	if err != nil {
		return nil, err
	}
	return txChild, nil
}

func contains(transaction *externalapi.DomainTransaction, transactions []*externalapi.DomainTransaction) bool {
	for _, candidateTransaction := range transactions {
		if candidateTransaction.Equal(transaction) {
			return true
		}
	}
	return false
}
