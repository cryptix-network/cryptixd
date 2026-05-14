package rpchandlers

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/app/rpc/rpccontext"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
)

// HandleSubmitTransactionReplacement rejects transaction replacement requests. The Go node does not implement RBF,
// and CAT payloads must never be replaceable by fee.
func HandleSubmitTransactionReplacement(_ *rpccontext.Context, _ *router.Router, request appmessage.Message) (appmessage.Message, error) {
	submitTransactionReplacementRequest := request.(*appmessage.SubmitTransactionReplacementRequestMessage)

	domainTransaction, err := appmessage.RPCTransactionToDomainTransaction(submitTransactionReplacementRequest.Transaction)
	if err != nil {
		response := &appmessage.SubmitTransactionReplacementResponseMessage{}
		response.Error = appmessage.RPCErrorf("Could not parse transaction: %s", err)
		return response, nil
	}

	transactionID := consensushashing.TransactionID(domainTransaction)
	response := appmessage.NewSubmitTransactionReplacementResponseMessage(transactionID.String())

	if subnetworks.IsPayload(domainTransaction.SubnetworkID) {
		parsedPayload, err := atomicstate.ParsePayload(domainTransaction.Payload)
		if err != nil {
			response.Error = appmessage.RPCErrorf("Rejected transaction replacement %s: invalid CAT payload: %s",
				transactionID, err)
			return response, nil
		}
		if parsedPayload != nil {
			response.Error = appmessage.RPCErrorf("Rejected transaction replacement %s: CAT payload transactions do not support replacement",
				transactionID)
			return response, nil
		}
	}

	response.Error = appmessage.RPCErrorf("Rejected transaction replacement %s: transaction replacement is not supported by this node",
		transactionID)
	return response, nil
}
