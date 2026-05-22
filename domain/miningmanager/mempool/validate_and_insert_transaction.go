package mempool

import (
	"fmt"
	"strings"

	"github.com/cryptix-network/cryptixd/infrastructure/logger"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
)

func (mp *mempool) validateAndInsertTransaction(transaction *externalapi.DomainTransaction, isHighPriority bool,
	allowOrphan bool) (acceptedTransactions []*externalapi.DomainTransaction, err error) {

	onEnd := logger.LogAndMeasureExecutionTime(log,
		fmt.Sprintf("validateAndInsertTransaction %s", consensushashing.TransactionID(transaction)))
	defer onEnd()

	// Populate mass in the beginning, it will be used in multiple places throughout the validation and insertion.
	mp.consensusReference.Consensus().PopulateMass(transaction)

	err = mp.validateTransactionPreUTXOEntry(transaction)
	if err != nil {
		return nil, err
	}

	parentsInPool, missingOutpoints, err := mp.fillInputsAndGetMissingParents(transaction)
	if err != nil {
		return nil, err
	}

	if len(missingOutpoints) > 0 {
		if isCATTransaction(transaction) {
			log.Infof("CAT transaction deferred by mempool as orphan: tx=%s %s missing_outpoints=%d first_missing=%s allow_orphan=%t tx_pool=%d orphan_pool=%d",
				consensushashing.TransactionID(transaction),
				atomicMempoolDebugSummary(transaction),
				len(missingOutpoints),
				summarizeMissingOutpoints(missingOutpoints, 3),
				allowOrphan,
				mp.transactionsPool.transactionCount(),
				mp.orphansPool.orphanTransactionCount(),
			)
		}
		if !allowOrphan {
			if isCATTransaction(transaction) {
				log.Warnf("Rejecting CAT transaction as disallowed orphan: tx=%s %s inputs=%d missing_outpoints=%d first_missing=%s",
					consensushashing.TransactionID(transaction),
					atomicMempoolDebugSummary(transaction),
					len(transaction.Inputs),
					len(missingOutpoints),
					summarizeMissingOutpoints(missingOutpoints, 8),
				)
			}
			str := fmt.Sprintf("Transaction %s is an orphan, where allowOrphan = false",
				consensushashing.TransactionID(transaction))
			return nil, transactionRuleError(RejectBadOrphan, str)
		}

		err := mp.orphansPool.maybeAddOrphan(transaction, isHighPriority)
		if err != nil {
			return nil, err
		}
		if isCATTransaction(transaction) {
			log.Infof("CAT transaction stored in orphan pool: tx=%s orphan_pool=%d",
				consensushashing.TransactionID(transaction),
				mp.orphansPool.orphanTransactionCount(),
			)
		}
		return nil, nil
	}

	err = mp.validateTransactionInContext(transaction)
	if err != nil {
		return nil, err
	}

	mempoolTransaction, err := mp.transactionsPool.addTransaction(transaction, parentsInPool, isHighPriority)
	if err != nil {
		return nil, err
	}

	err = mp.transactionsPool.limitTransactionCount(mempoolTransaction)
	if err != nil {
		removeErr := mp.removeTransaction(mempoolTransaction.TransactionID(), true)
		if removeErr != nil {
			log.Warnf("Failed to remove rejected transaction %s after mempool limit failure: %s",
				mempoolTransaction.TransactionID(), removeErr)
		}
		return nil, err
	}

	acceptedOrphans, err := mp.orphansPool.processOrphansAfterAcceptedTransaction(mempoolTransaction.Transaction())
	if err != nil {
		return nil, err
	}

	acceptedTransactions = append([]*externalapi.DomainTransaction{transaction.Clone()}, acceptedOrphans...) //these pointer leave the mempool, hence we clone.

	return acceptedTransactions, nil
}

func summarizeMissingOutpoints(outpoints []*externalapi.DomainOutpoint, limit int) string {
	if len(outpoints) == 0 {
		return "[]"
	}
	if limit <= 0 || limit > len(outpoints) {
		limit = len(outpoints)
	}
	parts := make([]string, 0, limit+1)
	for _, outpoint := range outpoints[:limit] {
		parts = append(parts, outpoint.String())
	}
	if len(outpoints) > limit {
		parts = append(parts, fmt.Sprintf("...+%d", len(outpoints)-limit))
	}
	return "[" + strings.Join(parts, ",") + "]"
}
