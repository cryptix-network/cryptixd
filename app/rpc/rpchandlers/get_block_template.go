package rpchandlers

import (
	"sync"
	"time"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/app/rpc/rpccontext"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/transactionhelper"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/txscript"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
	"github.com/cryptix-network/cryptixd/util"
	"github.com/cryptix-network/cryptixd/version"
)

const getBlockTemplateUnsyncedLogInterval = time.Minute

var (
	getBlockTemplateUnsyncedLogLock sync.Mutex
	getBlockTemplateUnsyncedLastLog time.Time
)

func shouldLogGetBlockTemplateUnsynced() bool {
	now := time.Now()
	getBlockTemplateUnsyncedLogLock.Lock()
	defer getBlockTemplateUnsyncedLogLock.Unlock()

	if getBlockTemplateUnsyncedLastLog.IsZero() || now.Sub(getBlockTemplateUnsyncedLastLog) >= getBlockTemplateUnsyncedLogInterval {
		getBlockTemplateUnsyncedLastLog = now
		return true
	}
	return false
}

// HandleGetBlockTemplate handles the respectively named RPC command
func HandleGetBlockTemplate(context *rpccontext.Context, _ *router.Router, request appmessage.Message) (appmessage.Message, error) {
	getBlockTemplateRequest := request.(*appmessage.GetBlockTemplateRequestMessage)

	payAddress, err := util.DecodeAddress(getBlockTemplateRequest.PayAddress, context.Config.ActiveNetParams.Prefix)
	if err != nil {
		errorMessage := &appmessage.GetBlockTemplateResponseMessage{}
		errorMessage.Error = appmessage.RPCErrorf("Could not decode address: %s", err)
		return errorMessage, nil
	}

	scriptPublicKey, err := txscript.PayToAddrScript(payAddress)
	if err != nil {
		return nil, err
	}

	coinbaseData := &externalapi.DomainCoinbaseData{ScriptPublicKey: scriptPublicKey, ExtraData: []byte(version.Version() + "/" + getBlockTemplateRequest.ExtraData)}

	virtualDAAScore, err := context.Domain.Consensus().GetVirtualDAAScore()
	if err != nil {
		return nil, err
	}
	isSynced := false
	if context.ProtocolManager.Context().HasPeers() {
		isSynced, err = context.ProtocolManager.Context().IsNearlySynced()
		if err != nil {
			return nil, err
		}
	}
	if virtualDAAScore >= context.Config.NetParams().PayloadHfActivationDAAScore && !isSynced {
		if shouldLogGetBlockTemplateUnsynced() {
			log.Warnf("Rejecting getBlockTemplate while node is not nearly synced after payload HF: virtualDAAScore=%d activationDAA=%d allowSubmitBlockWhenNotSynced=%t; mining from a partial Atomic/UTXO view can create blocks with invalid state commitments (warning throttled to once per 60s)",
				virtualDAAScore, context.Config.NetParams().PayloadHfActivationDAAScore, context.Config.AllowSubmitBlockWhenNotSynced)
		}
		errorMessage := &appmessage.GetBlockTemplateResponseMessage{}
		errorMessage.Error = appmessage.RPCErrorf("mining template unavailable: node is not nearly synced after payload hardfork; wait for sync/Atomic catch-up before mining")
		return errorMessage, nil
	}

	templateBlock, isNearlySynced, err := context.Domain.MiningManager().GetBlockTemplate(coinbaseData)
	if err != nil {
		return nil, err
	}

	if uint64(len(templateBlock.Transactions[transactionhelper.CoinbaseTransactionIndex].Payload)) > context.Config.NetParams().MaxCoinbasePayloadLength {
		errorMessage := &appmessage.GetBlockTemplateResponseMessage{}
		errorMessage.Error = appmessage.RPCErrorf("Coinbase payload is above max length (%d). Try to shorten the extra data.", context.Config.NetParams().MaxCoinbasePayloadLength)
		return errorMessage, nil
	}

	rpcBlock := appmessage.DomainBlockToRPCBlock(templateBlock)

	return appmessage.NewGetBlockTemplateResponseMessage(rpcBlock, context.ProtocolManager.Context().HasPeers() && isNearlySynced), nil
}
