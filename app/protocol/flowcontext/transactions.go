package flowcontext

import (
	"fmt"
	"time"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
)

// TransactionIDPropagationInterval is the interval between transaction IDs propagations
const TransactionIDPropagationInterval = 500 * time.Millisecond
const maxTransactionRelayAncestors = 64

// AddTransaction adds transaction to the mempool and propagates it.
func (f *FlowContext) AddTransaction(tx *externalapi.DomainTransaction, allowOrphan bool) error {
	acceptedTransactions, err := f.Domain().MiningManager().ValidateAndInsertTransaction(tx, true, allowOrphan)
	if err != nil {
		return err
	}

	if len(acceptedTransactions) > 0 {
		if catSummary, isCAT := describeCATTransaction(tx); isCAT {
			log.Infof("Accepted local CAT transaction into mempool: tx=%s %s accepted_total=%d",
				consensushashing.TransactionID(tx), catSummary, len(acceptedTransactions))
		}
		f.OnTransactionAddedToMempool()
	}

	acceptedTransactionIDs := consensushashing.TransactionIDs(acceptedTransactions)
	return f.EnqueueTransactionIDsForPropagation(acceptedTransactionIDs)
}

func (f *FlowContext) shouldRebroadcastTransactions() bool {
	const rebroadcastInterval = 30 * time.Second
	return time.Since(f.lastRebroadcastTime) > rebroadcastInterval
}

// SharedRequestedTransactions returns a *transactionrelay.SharedRequestedTransactions for sharing
// data about requested transactions between different peers.
func (f *FlowContext) SharedRequestedTransactions() *SharedRequestedTransactions {
	return f.sharedRequestedTransactions
}

// OnTransactionAddedToMempool notifies the handler function that a transaction
// has been added to the mempool
func (f *FlowContext) OnTransactionAddedToMempool() {
	f.Domain().MiningManager().ClearBlockTemplate()
	log.Infof("Mempool changed: cleared cached block template (tx_pool=%d orphan_pool=%d)",
		f.Domain().MiningManager().TransactionCount(true, false),
		f.Domain().MiningManager().TransactionCount(false, true))
	if f.onTransactionAddedToMempoolHandler != nil {
		f.onTransactionAddedToMempoolHandler()
	}
}

func (f *FlowContext) RevalidateMempoolOrphans(reason string) error {
	acceptedTransactions, err := f.Domain().MiningManager().RevalidateOrphanTransactions()
	if err != nil {
		return err
	}
	if len(acceptedTransactions) == 0 {
		return nil
	}

	log.Infof("Mempool orphan revalidation accepted transactions after %s: accepted=%d tx_pool=%d orphan_pool=%d",
		reason,
		len(acceptedTransactions),
		f.Domain().MiningManager().TransactionCount(true, false),
		f.Domain().MiningManager().TransactionCount(false, true))
	f.OnTransactionAddedToMempool()

	if f.IsIBDRunning() {
		return nil
	}
	return f.EnqueueTransactionIDsForPropagation(consensushashing.TransactionIDs(acceptedTransactions))
}

func (f *FlowContext) RunMempoolMaintenance(reason string) error {
	expiredTransactions, expiredOrphans, err := f.Domain().MiningManager().ExpireLowPriorityTransactions()
	if err != nil {
		return err
	}
	if expiredTransactions == 0 && expiredOrphans == 0 {
		return nil
	}

	log.Infof("Mempool maintenance after %s expired low-priority entries: tx_pool_removed=%d orphan_pool_removed=%d tx_pool=%d orphan_pool=%d",
		reason,
		expiredTransactions,
		expiredOrphans,
		f.Domain().MiningManager().TransactionCount(true, false),
		f.Domain().MiningManager().TransactionCount(false, true))
	f.OnTransactionAddedToMempool()
	return nil
}

// EnqueueTransactionIDsForPropagation add the given transactions IDs to a set of IDs to
// propagate. The IDs will be broadcast to all peers within a single transaction Inv message.
// The broadcast itself may happen only during a subsequent call to this method
func (f *FlowContext) EnqueueTransactionIDsForPropagation(transactionIDs []*externalapi.DomainTransactionID) error {
	f.transactionIDPropagationLock.Lock()
	defer f.transactionIDPropagationLock.Unlock()

	transactionIDs = f.expandTransactionIDsWithMempoolParents(transactionIDs)
	f.transactionIDsToPropagate = append(f.transactionIDsToPropagate, transactionIDs...)

	return f.maybePropagateTransactions()
}

func (f *FlowContext) expandTransactionIDsWithMempoolParents(
	transactionIDs []*externalapi.DomainTransactionID) []*externalapi.DomainTransactionID {

	expanded := expandTransactionIDsWithMempoolParents(transactionIDs,
		func(transactionID *externalapi.DomainTransactionID) (*externalapi.DomainTransaction, bool) {
			transaction, _, found := f.Domain().MiningManager().GetTransaction(transactionID, true, false)
			return transaction, found
		})
	if addedAncestors := len(expanded) - len(transactionIDs); addedAncestors > 0 {
		log.Debugf("Transaction propagation added %d mempool ancestor transaction IDs before child announcements", addedAncestors)
	}
	return expanded
}

func expandTransactionIDsWithMempoolParents(
	transactionIDs []*externalapi.DomainTransactionID,
	lookup func(*externalapi.DomainTransactionID) (*externalapi.DomainTransaction, bool)) []*externalapi.DomainTransactionID {

	if len(transactionIDs) == 0 {
		return transactionIDs
	}

	expanded := make([]*externalapi.DomainTransactionID, 0, len(transactionIDs))
	seen := make(map[externalapi.DomainTransactionID]struct{}, len(transactionIDs))
	visiting := make(map[externalapi.DomainTransactionID]struct{}, len(transactionIDs))
	ancestorWalks := 0

	var visit func(*externalapi.DomainTransactionID)
	visit = func(transactionID *externalapi.DomainTransactionID) {
		if transactionID == nil {
			return
		}
		key := *transactionID
		if _, ok := seen[key]; ok {
			return
		}
		if _, ok := visiting[key]; ok {
			return
		}

		visiting[key] = struct{}{}
		if transaction, found := lookup(transactionID); found && ancestorWalks < maxTransactionRelayAncestors {
			for _, input := range transaction.Inputs {
				parentID := input.PreviousOutpoint.TransactionID
				if _, ok := seen[parentID]; ok {
					continue
				}
				if _, found := lookup(&parentID); !found {
					continue
				}
				ancestorWalks++
				if ancestorWalks > maxTransactionRelayAncestors {
					break
				}
				visit(&parentID)
			}
		}
		delete(visiting, key)

		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		transactionIDCopy := key
		expanded = append(expanded, &transactionIDCopy)
	}

	for _, transactionID := range transactionIDs {
		visit(transactionID)
	}

	return expanded
}

func (f *FlowContext) maybePropagateTransactions() error {
	if time.Since(f.lastTransactionIDPropagationTime) < TransactionIDPropagationInterval &&
		len(f.transactionIDsToPropagate) < appmessage.MaxInvPerTxInvMsg {
		return nil
	}

	for len(f.transactionIDsToPropagate) > 0 {
		transactionIDsToBroadcast := f.transactionIDsToPropagate
		if len(transactionIDsToBroadcast) > appmessage.MaxInvPerTxInvMsg {
			transactionIDsToBroadcast = f.transactionIDsToPropagate[:appmessage.MaxInvPerTxInvMsg]
		}
		log.Debugf("Transaction propagation: broadcasting %d transactions", len(transactionIDsToBroadcast))

		inv := appmessage.NewMsgInvTransaction(transactionIDsToBroadcast)
		err := f.Broadcast(inv)
		if err != nil {
			return err
		}

		f.transactionIDsToPropagate = f.transactionIDsToPropagate[len(transactionIDsToBroadcast):]
	}

	f.lastTransactionIDPropagationTime = time.Now()

	return nil
}

func describeCATTransaction(tx *externalapi.DomainTransaction) (string, bool) {
	if !subnetworks.IsPayload(tx.SubnetworkID) || len(tx.Payload) == 0 {
		return "", false
	}

	parsedPayload, err := atomicstate.ParsePayload(tx.Payload)
	if err != nil {
		return fmt.Sprintf("cat=parse_error:%s payload_bytes=%d", err, len(tx.Payload)), true
	}
	if parsedPayload == nil {
		return "", false
	}

	return fmt.Sprintf("op=%T nonce=%d payload_bytes=%d", parsedPayload.Op, parsedPayload.Nonce, len(tx.Payload)), true
}
