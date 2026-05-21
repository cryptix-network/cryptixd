package flowcontext

import (
	"time"

	peerpkg "github.com/cryptix-network/cryptixd/app/protocol/peer"
	"github.com/cryptix-network/cryptixd/app/protocol/protocolerrors"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/ruleerrors"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/transactionhelper"
	"github.com/pkg/errors"

	"github.com/cryptix-network/cryptixd/app/appmessage"
)

// OnNewBlock updates the mempool after a new block arrival, and
// relays newly unorphaned transactions and possibly rebroadcast
// manually added transactions when not in IBD.
func (f *FlowContext) OnNewBlock(block *externalapi.DomainBlock) error {

	hash := consensushashing.BlockHash(block)
	log.Tracef("OnNewBlock start for block %s", hash)
	defer log.Tracef("OnNewBlock end for block %s", hash)

	if err := f.refreshStrongNodeClaimsWindow(); err != nil {
		log.Warnf("OnNewBlock: failed refreshing strong-node claim window: %s", err)
	}

	unorphanedBlocks, err := f.UnorphanBlocks(block)
	if err != nil {
		return err
	}

	log.Debugf("OnNewBlock: block %s unorphaned %d blocks", hash, len(unorphanedBlocks))

	newBlocks := []*externalapi.DomainBlock{block}
	newBlocks = append(newBlocks, unorphanedBlocks...)

	allAcceptedTransactions, err := f.processMempoolVirtualAcceptance()
	if err != nil {
		return err
	}

	return f.broadcastTransactionsAfterBlockAdded(newBlocks, allAcceptedTransactions)
}

func (f *FlowContext) processMempoolVirtualAcceptance() ([]*externalapi.DomainTransaction, error) {
	f.mempoolVirtualSinkMutex.Lock()
	defer f.mempoolVirtualSinkMutex.Unlock()

	sink, err := f.Domain().Consensus().GetVirtualSelectedParent()
	if err != nil {
		return nil, err
	}
	if f.mempoolVirtualSink == nil {
		f.mempoolVirtualSink = sink
		return nil, nil
	}
	previousSink := f.mempoolVirtualSink
	if previousSink.Equal(sink) {
		return nil, nil
	}

	chainPath, err := f.Domain().Consensus().GetVirtualSelectedParentChainFromBlock(previousSink)
	if err != nil {
		log.Warnf("Skipping mempool virtual acceptance update: failed reading virtual chain path from %s to %s: %s",
			previousSink, sink, err)
		return nil, nil
	}
	if len(chainPath.Added) == 0 {
		f.mempoolVirtualSink = sink
		return nil, nil
	}

	blocksAcceptanceData, err := f.Domain().Consensus().GetBlocksAcceptanceData(chainPath.Added)
	if err != nil {
		log.Warnf("Skipping mempool virtual acceptance update: failed reading acceptance data for %d selected-chain block(s): %s",
			len(chainPath.Added), err)
		return nil, nil
	}

	allAcceptedTransactions := make([]*externalapi.DomainTransaction, 0)
	acceptedNonCoinbase := 0
	for _, acceptanceData := range blocksAcceptanceData {
		acceptedTransactions := make([]*externalapi.DomainTransaction, 0)
		for _, blockAcceptanceData := range acceptanceData {
			if blockAcceptanceData == nil {
				continue
			}
			for _, transactionAcceptanceData := range blockAcceptanceData.TransactionAcceptanceData {
				if transactionAcceptanceData == nil || !transactionAcceptanceData.IsAccepted || transactionAcceptanceData.Transaction == nil {
					continue
				}
				if transactionhelper.IsCoinBase(transactionAcceptanceData.Transaction) {
					continue
				}
				acceptedTransactions = append(acceptedTransactions, transactionAcceptanceData.Transaction)
			}
		}

		if len(acceptedTransactions) == 0 {
			continue
		}
		acceptedNonCoinbase += len(acceptedTransactions)
		acceptedOrphans, err := f.Domain().MiningManager().HandleAcceptedTransactions(acceptedTransactions)
		if err != nil {
			return nil, err
		}
		allAcceptedTransactions = append(allAcceptedTransactions, acceptedOrphans...)
	}

	log.Debugf("Mempool virtual acceptance update: previous_sink=%s sink=%s selected_added=%d accepted_non_coinbase_txs=%d promoted_orphans=%d",
		previousSink, sink, len(chainPath.Added), acceptedNonCoinbase, len(allAcceptedTransactions))
	f.mempoolVirtualSink = sink
	return allAcceptedTransactions, nil
}

// OnNewBlockTemplate calls the handler function whenever a new block template is available for miners.
func (f *FlowContext) OnNewBlockTemplate() error {
	// Clear current template cache. Note we call this even if the handler is nil, in order to keep the
	// state consistent without dependency on external event registration
	f.Domain().MiningManager().ClearBlockTemplate()
	if f.onNewBlockTemplateHandler != nil {
		return f.onNewBlockTemplateHandler()
	}

	return nil
}

// OnPruningPointUTXOSetOverride calls the handler function whenever the UTXO set
// resets due to pruning point change via IBD.
func (f *FlowContext) OnPruningPointUTXOSetOverride() error {
	if f.onPruningPointUTXOSetOverrideHandler != nil {
		return f.onPruningPointUTXOSetOverrideHandler()
	}
	return nil
}

func (f *FlowContext) broadcastTransactionsAfterBlockAdded(
	addedBlocks []*externalapi.DomainBlock, transactionsAcceptedToMempool []*externalapi.DomainTransaction) error {

	// Don't relay transactions when in IBD.
	if f.IsIBDRunning() {
		return nil
	}

	var txIDsToRebroadcast []*externalapi.DomainTransactionID
	if f.shouldRebroadcastTransactions() {
		txsToRebroadcast, err := f.Domain().MiningManager().RevalidateHighPriorityTransactions()
		if err != nil {
			return err
		}
		txIDsToRebroadcast = consensushashing.TransactionIDs(txsToRebroadcast)
		f.lastRebroadcastTime = time.Now()
	}

	txIDsToBroadcast := make([]*externalapi.DomainTransactionID, len(transactionsAcceptedToMempool)+len(txIDsToRebroadcast))
	for i, tx := range transactionsAcceptedToMempool {
		txIDsToBroadcast[i] = consensushashing.TransactionID(tx)
	}
	offset := len(transactionsAcceptedToMempool)
	for i, txID := range txIDsToRebroadcast {
		txIDsToBroadcast[offset+i] = txID
	}
	return f.EnqueueTransactionIDsForPropagation(txIDsToBroadcast)
}

// SharedRequestedBlocks returns a *blockrelay.SharedRequestedBlocks for sharing
// data about requested blocks between different peers.
func (f *FlowContext) SharedRequestedBlocks() *SharedRequestedBlocks {
	return f.sharedRequestedBlocks
}

// AddBlock adds the given block to the DAG and propagates it.
func (f *FlowContext) AddBlock(block *externalapi.DomainBlock) error {
	if len(block.Transactions) == 0 {
		return protocolerrors.Errorf(false, "cannot add header only block")
	}

	blockHash := consensushashing.BlockHash(block)
	err := f.Domain().Consensus().ValidateAndInsertBlock(block, true)
	if err != nil {
		if errors.As(err, &ruleerrors.RuleError{}) {
			log.Warnf("Validation failed for block %s: %s", blockHash, err)
		}
		return err
	}

	blockInfo, err := f.Domain().Consensus().GetBlockInfo(blockHash)
	if err != nil {
		return err
	}
	if blockInfo.BlockStatus == externalapi.StatusDisqualifiedFromChain || blockInfo.BlockStatus == externalapi.StatusInvalid {
		f.Domain().MiningManager().ClearBlockTemplate()
		log.Warnf("Rejecting locally submitted block after consensus insertion because it is not UTXO-valid: block=%s status=%s; not broadcasting and not treating it as accepted",
			blockHash, blockInfo.BlockStatus)
		return protocolerrors.Errorf(false, "submitted block %s is not UTXO-valid after insertion: status=%s", blockHash, blockInfo.BlockStatus)
	}

	err = f.OnNewBlockTemplate()
	if err != nil {
		return err
	}
	err = f.OnNewBlock(block)
	if err != nil {
		return err
	}
	f.BroadcastLocalBlockProducerClaim(blockHash)
	return f.Broadcast(appmessage.NewMsgInvBlock(blockHash))
}

// IsIBDRunning returns true if IBD is currently marked as running
func (f *FlowContext) IsIBDRunning() bool {
	f.ibdPeerMutex.RLock()
	defer f.ibdPeerMutex.RUnlock()

	return f.ibdPeer != nil
}

// TrySetIBDRunning attempts to set `isInIBD`. Returns false
// if it is already set
func (f *FlowContext) TrySetIBDRunning(ibdPeer *peerpkg.Peer) bool {
	f.ibdPeerMutex.Lock()
	defer f.ibdPeerMutex.Unlock()

	if f.ibdPeer != nil {
		return false
	}
	f.ibdPeer = ibdPeer
	log.Infof("IBD started with peer %s", ibdPeer)

	return true
}

// UnsetIBDRunning unsets isInIBD
func (f *FlowContext) UnsetIBDRunning() {
	f.ibdPeerMutex.Lock()
	defer f.ibdPeerMutex.Unlock()

	if f.ibdPeer == nil {
		panic("attempted to unset isInIBD when it was not set to begin with")
	}

	f.ibdPeer = nil
}

// IBDPeer returns the current IBD peer or null if the node is not
// in IBD
func (f *FlowContext) IBDPeer() *peerpkg.Peer {
	f.ibdPeerMutex.RLock()
	defer f.ibdPeerMutex.RUnlock()

	return f.ibdPeer
}
