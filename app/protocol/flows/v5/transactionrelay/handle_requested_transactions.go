package transactionrelay

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
)

type handleRequestedTransactionsFlow struct {
	TransactionsRelayContext
	incomingRoute, outgoingRoute *router.Route
}

// HandleRequestedTransactions listens to appmessage.MsgRequestTransactions messages, responding with the requested
// transactions if those are in the mempool.
// Missing transactions would be ignored
func HandleRequestedTransactions(context TransactionsRelayContext, incomingRoute *router.Route, outgoingRoute *router.Route) error {
	flow := &handleRequestedTransactionsFlow{
		TransactionsRelayContext: context,
		incomingRoute:            incomingRoute,
		outgoingRoute:            outgoingRoute,
	}
	return flow.start()
}

func (flow *handleRequestedTransactionsFlow) start() error {
	for {
		msgRequestTransactions, err := flow.readRequestTransactions()
		if err != nil {
			return err
		}

		for _, transactionID := range msgRequestTransactions.IDs {
			tx, _, ok := flow.Domain().MiningManager().GetTransaction(transactionID, true, false)

			if !ok {
				log.Debugf("Requested transaction not found in mempool: tx=%s", transactionID)
				msgTransactionNotFound := appmessage.NewMsgTransactionNotFound(transactionID)
				err := flow.outgoingRoute.Enqueue(msgTransactionNotFound)
				if err != nil {
					return err
				}
				continue
			}
			if catSummary, isCAT := describeCATTransaction(tx); isCAT {
				log.Infof("Serving requested CAT transaction from mempool: tx=%s %s",
					transactionID, catSummary)
			}
			err := flow.outgoingRoute.Enqueue(appmessage.DomainTransactionToMsgTx(tx))
			if err != nil {
				return err
			}
		}
	}
}

func (flow *handleRequestedTransactionsFlow) readRequestTransactions() (*appmessage.MsgRequestTransactions, error) {
	msg, err := flow.incomingRoute.Dequeue()
	if err != nil {
		return nil, err
	}

	return msg.(*appmessage.MsgRequestTransactions), nil
}
