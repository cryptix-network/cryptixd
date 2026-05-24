package blockrelay

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/app/protocol/peer"
	"github.com/cryptix-network/cryptixd/app/protocol/protocolerrors"
	"github.com/cryptix-network/cryptixd/domain"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
)

// HandleIBDBlockLocatorContext is the interface for the context needed for the HandleIBDBlockLocator flow.
type HandleIBDBlockLocatorContext interface {
	Domain() domain.Domain
}

// HandleIBDBlockLocator listens to appmessage.MsgIBDBlockLocator messages and sends
// the highest known block that's in the selected parent chain of `targetHash` to the
// requesting peer.
func HandleIBDBlockLocator(context HandleIBDBlockLocatorContext, incomingRoute *router.Route,
	outgoingRoute *router.Route, peer *peer.Peer) error {

	for {
		message, err := incomingRoute.Dequeue()
		if err != nil {
			return err
		}
		ibdBlockLocatorMessage := message.(*appmessage.MsgIBDBlockLocator)

		targetHash := ibdBlockLocatorMessage.TargetHash
		log.Debugf("Received IBDBlockLocator from %s with targetHash %s", peer, targetHash)

		blockInfo, err := context.Domain().Consensus().GetBlockInfo(targetHash)
		if err != nil {
			return err
		}
		if !blockInfo.HasHeader() {
			return protocolerrors.Errorf(true, "received IBDBlockLocator "+
				"with an unknown targetHash %s", targetHash)
		}
		unsafe, reason, err := isUnsafeIBDBlock(context.Domain().Consensus(), targetHash, blockInfo)
		if err != nil {
			return err
		}
		if unsafe {
			return protocolerrors.Errorf(true, "received IBDBlockLocator with unsafe targetHash %s: %s",
				targetHash, reason)
		}

		foundHighestHashInTheSelectedParentChainOfTargetHash := false
		for _, blockLocatorHash := range ibdBlockLocatorMessage.BlockLocatorHashes {
			blockInfo, err := context.Domain().Consensus().GetBlockInfo(blockLocatorHash)
			if err != nil {
				return err
			}

			// The IBD block locator is checking only existing blocks with bodies.
			if !blockInfo.HasBody() {
				continue
			}
			unsafe, _, err := isUnsafeIBDBlock(context.Domain().Consensus(), blockLocatorHash, blockInfo)
			if err != nil {
				return err
			}
			if unsafe {
				continue
			}

			isBlockLocatorHashInSelectedParentChainOfHighHash, err :=
				context.Domain().Consensus().IsInSelectedParentChainOf(blockLocatorHash, targetHash)
			if err != nil {
				return err
			}
			if !isBlockLocatorHashInSelectedParentChainOfHighHash {
				continue
			}

			foundHighestHashInTheSelectedParentChainOfTargetHash = true
			log.Debugf("Found a known hash %s amongst peer %s's "+
				"blockLocator that's in the selected parent chain of targetHash %s", blockLocatorHash, peer, targetHash)

			ibdBlockLocatorHighestHashMessage := appmessage.NewMsgIBDBlockLocatorHighestHash(blockLocatorHash)
			err = outgoingRoute.Enqueue(ibdBlockLocatorHighestHashMessage)
			if err != nil {
				return err
			}
			break
		}

		if !foundHighestHashInTheSelectedParentChainOfTargetHash {
			log.Warnf("no hash was found in the blockLocator "+
				"that was in the selected parent chain of targetHash %s", targetHash)

			ibdBlockLocatorHighestHashNotFoundMessage := appmessage.NewMsgIBDBlockLocatorHighestHashNotFound()
			err = outgoingRoute.Enqueue(ibdBlockLocatorHighestHashNotFoundMessage)
			if err != nil {
				return err
			}
		}
	}
}

func isUnsafeIBDStatus(status externalapi.BlockStatus) bool {
	return status == externalapi.StatusInvalid || status == externalapi.StatusDisqualifiedFromChain
}

func isUnsafeIBDBlock(consensus externalapi.Consensus, blockHash *externalapi.DomainHash, blockInfo *externalapi.BlockInfo) (bool, string, error) {
	if blockInfo == nil {
		var err error
		blockInfo, err = consensus.GetBlockInfo(blockHash)
		if err != nil {
			return false, "", err
		}
	}
	if !blockInfo.Exists {
		return true, "missing block info", nil
	}
	if isUnsafeIBDStatus(blockInfo.BlockStatus) {
		return true, "status=" + blockInfo.BlockStatus.String(), nil
	}
	if blockInfo.BlockStatus != externalapi.StatusUTXOValid {
		return false, "", nil
	}

	ok, reason, err := consensus.IsStoredBlockUTXOCommitmentValid(blockHash)
	if err != nil {
		return false, "", err
	}
	if !ok {
		return true, reason, nil
	}
	return false, "", nil
}

func isSafeIBDSourceBlock(consensus externalapi.Consensus, blockHash *externalapi.DomainHash, blockInfo *externalapi.BlockInfo) (bool, string, error) {
	if blockInfo == nil {
		var err error
		blockInfo, err = consensus.GetBlockInfo(blockHash)
		if err != nil {
			return false, "", err
		}
	}
	if !blockInfo.Exists {
		return false, "missing block info", nil
	}
	if blockInfo.BlockStatus != externalapi.StatusUTXOValid {
		return false, "status=" + blockInfo.BlockStatus.String() + " is not UTXOValid", nil
	}

	ok, reason, err := consensus.IsStoredBlockUTXOCommitmentValid(blockHash)
	if err != nil {
		return false, "", err
	}
	if !ok {
		return false, reason, nil
	}
	return true, "", nil
}
