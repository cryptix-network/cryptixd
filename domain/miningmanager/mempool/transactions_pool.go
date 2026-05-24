package mempool

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/miningmanager/mempool/model"
)

type transactionsPool struct {
	mempool                       *mempool
	allTransactions               model.IDToTransactionMap
	highPriorityTransactions      model.IDToTransactionMap
	chainedTransactionsByParentID model.IDToTransactionsSliceMap
	transactionsOrderedByFeeRate  model.TransactionsOrderedByFeeRate
	atomicSlotOwners              map[atomicMempoolSlot]externalapi.DomainTransactionID
	atomicSlotsByTransactionID    map[externalapi.DomainTransactionID][]atomicMempoolSlot
	lastExpireScanDAAScore        uint64
}

func newTransactionsPool(mp *mempool) *transactionsPool {
	return &transactionsPool{
		mempool:                       mp,
		allTransactions:               model.IDToTransactionMap{},
		highPriorityTransactions:      model.IDToTransactionMap{},
		chainedTransactionsByParentID: model.IDToTransactionsSliceMap{},
		transactionsOrderedByFeeRate:  model.TransactionsOrderedByFeeRate{},
		atomicSlotOwners:              map[atomicMempoolSlot]externalapi.DomainTransactionID{},
		atomicSlotsByTransactionID:    map[externalapi.DomainTransactionID][]atomicMempoolSlot{},
		lastExpireScanDAAScore:        0,
	}
}

func (tp *transactionsPool) addTransaction(transaction *externalapi.DomainTransaction,
	parentTransactionsInPool model.IDToTransactionMap, isHighPriority bool) (*model.MempoolTransaction, error) {

	virtualDAAScore, err := tp.mempool.consensusReference.Consensus().GetVirtualDAAScore()
	if err != nil {
		return nil, err
	}

	mempoolTransaction := model.NewMempoolTransaction(
		transaction, parentTransactionsInPool, isHighPriority, virtualDAAScore)

	err = tp.addMempoolTransaction(mempoolTransaction)
	if err != nil {
		return nil, err
	}

	return mempoolTransaction, nil
}

func (tp *transactionsPool) addMempoolTransaction(transaction *model.MempoolTransaction) error {
	atomicSlots, err := atomicMempoolSlots(transaction.Transaction())
	if err != nil {
		return err
	}
	for _, slot := range atomicSlots {
		if existingTransactionID, ok := tp.atomicSlotOwners[slot]; ok {
			return transactionRuleError(RejectDuplicate, fmt.Sprintf(
				"transaction %s conflicts with pending CAT transaction %s on atomic slot %s",
				transaction.TransactionID(), existingTransactionID, slot))
		}
	}

	tp.allTransactions[*transaction.TransactionID()] = transaction

	for _, parentTransactionInPool := range transaction.ParentTransactionsInPool() {
		parentTransactionID := *parentTransactionInPool.TransactionID()
		if tp.chainedTransactionsByParentID[parentTransactionID] == nil {
			tp.chainedTransactionsByParentID[parentTransactionID] = []*model.MempoolTransaction{}
		}
		tp.chainedTransactionsByParentID[parentTransactionID] =
			append(tp.chainedTransactionsByParentID[parentTransactionID], transaction)
	}

	tp.mempool.mempoolUTXOSet.addTransaction(transaction)

	transactionID := *transaction.TransactionID()
	if len(atomicSlots) > 0 {
		tp.atomicSlotsByTransactionID[transactionID] = atomicSlots
		for _, slot := range atomicSlots {
			tp.atomicSlotOwners[slot] = transactionID
		}
	}

	err = tp.transactionsOrderedByFeeRate.Push(transaction)
	if err != nil {
		return err
	}

	if transaction.IsHighPriority() {
		tp.highPriorityTransactions[*transaction.TransactionID()] = transaction
	}

	return nil
}

func (tp *transactionsPool) removeTransaction(transaction *model.MempoolTransaction) error {
	transactionID := *transaction.TransactionID()
	delete(tp.allTransactions, transactionID)
	tp.removeAtomicSlots(transactionID)

	err := tp.transactionsOrderedByFeeRate.Remove(transaction)
	if err != nil {
		if errors.Is(err, model.ErrTransactionNotFound) {
			log.Errorf("Transaction %s not found in tp.transactionsOrderedByFeeRate. This should never happen but sometime does",
				transaction.TransactionID())
		} else {
			return err
		}
	}

	delete(tp.highPriorityTransactions, transactionID)

	delete(tp.chainedTransactionsByParentID, transactionID)

	return nil
}

func (tp *transactionsPool) removeAtomicSlots(transactionID externalapi.DomainTransactionID) {
	slots, ok := tp.atomicSlotsByTransactionID[transactionID]
	if !ok {
		return
	}

	for _, slot := range slots {
		if ownerTransactionID, ok := tp.atomicSlotOwners[slot]; ok && ownerTransactionID == transactionID {
			delete(tp.atomicSlotOwners, slot)
		}
	}
	delete(tp.atomicSlotsByTransactionID, transactionID)
}

func (tp *transactionsPool) expireOldTransactions() error {
	virtualDAAScore, err := tp.mempool.consensusReference.Consensus().GetVirtualDAAScore()
	if err != nil {
		return err
	}

	if virtualDAAScore-tp.lastExpireScanDAAScore < tp.mempool.config.TransactionExpireScanIntervalDAAScore {
		return nil
	}

	for _, mempoolTransaction := range tp.allTransactions {
		isCAT := isCATTransaction(mempoolTransaction.Transaction())

		// Never expire high priority transactions, except CAT transactions. CAT slots can block
		// token/pool progress, so their ready-frontier lifetime is bounded even for local RPC submits.
		if mempoolTransaction.IsHighPriority() && !isCAT {
			continue
		}

		expireInterval := tp.mempool.config.TransactionExpireIntervalDAAScore
		if isCAT {
			hasMempoolParents := len(mempoolTransaction.ParentTransactionsInPool()) > 0
			totalExpired := virtualDAAScore > mempoolTransaction.AddedAtDAAScore()+tp.mempool.config.AtomicTransactionTotalExpireIntervalDAAScore
			frontierExpired := !hasMempoolParents &&
				virtualDAAScore > mempoolTransaction.ReadyAtDAAScore()+tp.mempool.config.AtomicTransactionExpireIntervalDAAScore
			if !totalExpired && !frontierExpired {
				continue
			}
			if frontierExpired {
				expireInterval = tp.mempool.config.AtomicTransactionExpireIntervalDAAScore
			} else {
				expireInterval = tp.mempool.config.AtomicTransactionTotalExpireIntervalDAAScore
			}
		} else if mempoolTransaction.IsHighPriority() ||
			virtualDAAScore <= mempoolTransaction.AddedAtDAAScore()+expireInterval {
			continue
		}

		daaScoreSinceAdded := virtualDAAScore - mempoolTransaction.AddedAtDAAScore()
		log.Debugf("Removing transaction %s, because it expired. DAAScore moved by %d, expire interval: %d",
			mempoolTransaction.TransactionID(), daaScoreSinceAdded, expireInterval)
		err = tp.mempool.removeTransaction(mempoolTransaction.TransactionID(), true)
		if err != nil {
			return err
		}
	}

	tp.lastExpireScanDAAScore = virtualDAAScore
	return nil
}

func (tp *transactionsPool) allReadyTransactions() []*externalapi.DomainTransaction {
	result := []*externalapi.DomainTransaction{}

	for _, mempoolTransaction := range tp.allTransactions {
		if len(mempoolTransaction.ParentTransactionsInPool()) == 0 {
			result = append(result, mempoolTransaction.Transaction().Clone()) //this pointer leaves the mempool, and gets its utxo set to nil, hence we clone.
		}
	}

	return result
}

func (tp *transactionsPool) getParentTransactionsInPool(
	transaction *externalapi.DomainTransaction) model.IDToTransactionMap {

	parentsTransactionsInPool := model.IDToTransactionMap{}

	for _, input := range transaction.Inputs {
		if transaction, ok := tp.allTransactions[input.PreviousOutpoint.TransactionID]; ok {
			parentsTransactionsInPool[*transaction.TransactionID()] = transaction
		}
	}

	return parentsTransactionsInPool
}

func (tp *transactionsPool) getRedeemers(transaction *model.MempoolTransaction) []*model.MempoolTransaction {
	stack := []*model.MempoolTransaction{transaction}
	redeemers := []*model.MempoolTransaction{}
	for len(stack) > 0 {
		var current *model.MempoolTransaction
		last := len(stack) - 1
		current, stack = stack[last], stack[:last]

		for _, redeemerTransaction := range tp.chainedTransactionsByParentID[*current.TransactionID()] {
			stack = append(stack, redeemerTransaction)
			redeemers = append(redeemers, redeemerTransaction)
		}
	}
	return redeemers
}

func (tp *transactionsPool) limitTransactionCount(admittedTransaction *model.MempoolTransaction) error {
	currentIndex := 0
	blockedByPolicy := false
	var admittedSlots []atomicMempoolSlot
	var admittedTransactionID *externalapi.DomainTransactionID
	if admittedTransaction != nil {
		admittedTransactionID = admittedTransaction.TransactionID()
		var err error
		admittedSlots, err = atomicMempoolSlots(admittedTransaction.Transaction())
		if err != nil {
			return err
		}
	}

	for uint64(len(tp.allTransactions)) > tp.mempool.config.MaximumTransactionCount {
		var transactionToRemove *model.MempoolTransaction
		for {
			if currentIndex >= len(tp.allTransactions) {
				if !blockedByPolicy {
					log.Warnf(
						"Number of high-priority transactions in mempool (%d) is higher than maximum allowed (%d)",
						len(tp.allTransactions), tp.mempool.config.MaximumTransactionCount)
					return nil
				}
				return transactionRuleError(RejectInsufficientFee, fmt.Sprintf(
					"mempool is full and no removable low-priority transaction is available"))
			}
			transactionToRemove = tp.transactionsOrderedByFeeRate.GetByIndex(currentIndex)
			if admittedTransactionID != nil && transactionToRemove.TransactionID().Equal(admittedTransactionID) {
				if admittedTransaction.IsHighPriority() {
					currentIndex++
					continue
				}
				blockedByPolicy = true
				return transactionRuleError(RejectInsufficientFee, fmt.Sprintf(
					"transaction %s rejected: mempool is full and it would be the eviction candidate",
					admittedTransactionID))
			}
			canRemove := !transactionToRemove.IsHighPriority()
			if canRemove && len(admittedSlots) > 0 {
				transactionSlots, err := atomicMempoolSlots(transactionToRemove.Transaction())
				if err != nil {
					return err
				}
				if atomicSlotsBlockCapacityEviction(admittedSlots, transactionSlots) {
					blockedByPolicy = true
					canRemove = false
				}
			}
			if canRemove {
				break
			}
			currentIndex++
		}

		log.Debugf("Removing transaction %s, because mempoolTransaction count (%d) exceeded the limit (%d)",
			transactionToRemove.TransactionID(), len(tp.allTransactions), tp.mempool.config.MaximumTransactionCount)
		err := tp.mempool.removeTransaction(transactionToRemove.TransactionID(), true)
		if err != nil {
			return err
		}
		if currentIndex >= len(tp.allTransactions) {
			break
		}
	}
	return nil
}

func atomicSlotsBlockCapacityEviction(incoming []atomicMempoolSlot, existing []atomicMempoolSlot) bool {
	for _, incomingSlot := range incoming {
		for _, existingSlot := range existing {
			if atomicSlotBlocksCapacityEviction(incomingSlot, existingSlot) {
				return true
			}
		}
	}
	return false
}

func atomicSlotBlocksCapacityEviction(incoming atomicMempoolSlot, existing atomicMempoolSlot) bool {
	if incoming.kind != existing.kind {
		return false
	}

	switch incoming.kind {
	case atomicMempoolSlotKindNonce:
		return incoming.nonceKey == existing.nonceKey && existing.nonce <= incoming.nonce
	case atomicMempoolSlotKindLiquidityPool:
		return incoming.assetID == existing.assetID && existing.poolNonce <= incoming.poolNonce
	default:
		return false
	}
}

func (tp *transactionsPool) getTransaction(transactionID *externalapi.DomainTransactionID, clone bool) (*externalapi.DomainTransaction, bool) {
	if mempoolTransaction, ok := tp.allTransactions[*transactionID]; ok {
		if clone {
			return mempoolTransaction.Transaction().Clone(), true //this pointer leaves the mempool, hence we clone.
		}
		return mempoolTransaction.Transaction(), true
	}
	return nil, false
}

func (tp *transactionsPool) getTransactionsByAddresses() (
	sending model.ScriptPublicKeyStringToDomainTransaction,
	receiving model.ScriptPublicKeyStringToDomainTransaction,
	err error) {
	sending = make(model.ScriptPublicKeyStringToDomainTransaction, tp.transactionCount())
	receiving = make(model.ScriptPublicKeyStringToDomainTransaction, tp.transactionCount())
	var transaction *externalapi.DomainTransaction
	for _, mempoolTransaction := range tp.allTransactions {
		transaction = mempoolTransaction.Transaction().Clone() //this pointer leaves the mempool, hence we clone.
		for _, input := range transaction.Inputs {
			if input.UTXOEntry == nil {
				return nil, nil, errors.Errorf("Mempool transaction %s is missing an UTXOEntry. This should be fixed, and not happen", consensushashing.TransactionID(transaction).String())
			}
			sending[input.UTXOEntry.ScriptPublicKey().String()] = transaction
		}
		for _, output := range transaction.Outputs {
			receiving[output.ScriptPublicKey.String()] = transaction
		}
	}
	return sending, receiving, nil
}

func (tp *transactionsPool) getAllTransactions() []*externalapi.DomainTransaction {
	allTransactions := make([]*externalapi.DomainTransaction, len(tp.allTransactions))
	i := 0
	for _, mempoolTransaction := range tp.allTransactions {
		allTransactions[i] = mempoolTransaction.Transaction().Clone() //this pointer leaves the mempool, hence we clone.
		i++
	}
	return allTransactions
}

func (tp *transactionsPool) transactionCount() int {
	return len(tp.allTransactions)
}
