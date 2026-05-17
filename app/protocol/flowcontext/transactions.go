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

// EnqueueTransactionIDsForPropagation add the given transactions IDs to a set of IDs to
// propagate. The IDs will be broadcast to all peers within a single transaction Inv message.
// The broadcast itself may happen only during a subsequent call to this method
func (f *FlowContext) EnqueueTransactionIDsForPropagation(transactionIDs []*externalapi.DomainTransactionID) error {
	f.transactionIDPropagationLock.Lock()
	defer f.transactionIDPropagationLock.Unlock()

	f.transactionIDsToPropagate = append(f.transactionIDsToPropagate, transactionIDs...)

	return f.maybePropagateTransactions()
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
