package blockrelay

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/app/protocol/protocolerrors"
	"github.com/cryptix-network/cryptixd/domain"
	"github.com/cryptix-network/cryptixd/domain/consensus/model"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
	"github.com/pkg/errors"
)

// RequestIBDChainBlockLocatorContext is the interface for the context needed for the HandleRequestBlockLocator flow.
type RequestIBDChainBlockLocatorContext interface {
	Domain() domain.Domain
}

type handleRequestIBDChainBlockLocatorFlow struct {
	RequestIBDChainBlockLocatorContext
	incomingRoute, outgoingRoute *router.Route
}

// HandleRequestIBDChainBlockLocator handles getBlockLocator messages
func HandleRequestIBDChainBlockLocator(context RequestIBDChainBlockLocatorContext, incomingRoute *router.Route,
	outgoingRoute *router.Route) error {

	flow := &handleRequestIBDChainBlockLocatorFlow{
		RequestIBDChainBlockLocatorContext: context,
		incomingRoute:                      incomingRoute,
		outgoingRoute:                      outgoingRoute,
	}
	return flow.start()
}

func (flow *handleRequestIBDChainBlockLocatorFlow) start() error {
	for {
		highHash, lowHash, responseID, err := flow.receiveRequestIBDChainBlockLocator()
		if err != nil {
			return err
		}
		log.Debugf("Received getIBDChainBlockLocator with highHash: %s, lowHash: %s", highHash, lowHash)

		var locator externalapi.BlockLocator
		if highHash == nil || lowHash == nil {
			locator, err = flow.createFullSafeIBDChainBlockLocator()
		} else {
			if flow.isUnsafeLocatorBound(highHash) || flow.isUnsafeLocatorBound(lowHash) {
				// The peer is zooming into a range which this node can no longer serve safely.
				// An empty locator makes the syncee restart negotiation and request the full
				// safe locator again, where we will advertise the last commitment-safe chain tip.
				locator, err = externalapi.BlockLocator{}, nil
			} else {
				locator, err = flow.Domain().Consensus().CreateHeadersSelectedChainBlockLocator(lowHash, highHash)
				if errors.Is(model.ErrBlockNotInSelectedParentChain, err) {
					// The chain has been modified, signal it by sending an empty locator
					locator, err = externalapi.BlockLocator{}, nil
				}
			}
		}

		if err != nil {
			log.Debugf("Received error from CreateHeadersSelectedChainBlockLocator: %s", err)
			return protocolerrors.Errorf(true, "couldn't build a block "+
				"locator between %s and %s", lowHash, highHash)
		}

		err = flow.sendIBDChainBlockLocator(locator, responseID)
		if err != nil {
			return err
		}
	}
}

func (flow *handleRequestIBDChainBlockLocatorFlow) createFullSafeIBDChainBlockLocator() (externalapi.BlockLocator, error) {
	pruningPoint, err := flow.Domain().Consensus().PruningPoint()
	if err != nil {
		return nil, err
	}

	virtualSelectedParent, err := flow.Domain().Consensus().GetVirtualSelectedParent()
	if err != nil {
		return nil, err
	}

	safeTip, walkedBack, err := flow.highestSafeSelectedChainBlock(virtualSelectedParent, pruningPoint)
	if err != nil {
		return nil, err
	}
	if walkedBack > 0 {
		log.Warnf("IBD chain locator recovered to last safe selected-chain block %s after walking back %d block(s) from virtual selected parent %s",
			safeTip, walkedBack, virtualSelectedParent)
	}

	// For IBD we must advertise the chain that is UTXO/Atomic-valid locally. The headers
	// selected tip can temporarily or historically point through a disqualified branch.
	return flow.Domain().Consensus().CreateHeadersSelectedChainBlockLocator(pruningPoint, safeTip)
}

func (flow *handleRequestIBDChainBlockLocatorFlow) highestSafeSelectedChainBlock(
	startHash *externalapi.DomainHash, floorHash *externalapi.DomainHash) (*externalapi.DomainHash, int, error) {
	current := startHash
	walkedBack := 0
	for {
		blockInfo, err := flow.Domain().Consensus().GetBlockInfo(current)
		if err != nil {
			return nil, 0, err
		}
		safe, reason, err := isSafeIBDSourceBlock(flow.Domain().Consensus(), current, blockInfo)
		if err != nil {
			return nil, 0, err
		}
		if safe {
			return current, walkedBack, nil
		}

		log.Warnf("IBD chain locator skipping non-source-safe selected-chain block %s: %s", current, reason)
		if current.Equal(floorHash) {
			return nil, walkedBack, protocolerrors.Errorf(false, "IBD safe locator reached pruning point %s but it is not source-safe: %s",
				current, reason)
		}
		if blockInfo.SelectedParent == nil || blockInfo.SelectedParent.Equal(current) {
			return nil, walkedBack, protocolerrors.Errorf(false, "IBD safe locator cannot walk back from non-source-safe block %s: selected parent unavailable",
				current)
		}
		current = blockInfo.SelectedParent
		walkedBack++
	}
}

func (flow *handleRequestIBDChainBlockLocatorFlow) isUnsafeLocatorBound(hash *externalapi.DomainHash) bool {
	blockInfo, err := flow.Domain().Consensus().GetBlockInfo(hash)
	if err != nil {
		log.Warnf("IBD chain locator failed to inspect bound %s: %s", hash, err)
		return true
	}
	safe, reason, err := isSafeIBDSourceBlock(flow.Domain().Consensus(), hash, blockInfo)
	if err != nil {
		log.Warnf("IBD chain locator failed to validate bound %s: %s", hash, err)
		return true
	}
	if !safe {
		log.Warnf("IBD chain locator refusing non-source-safe zoom bound %s: %s", hash, reason)
		return true
	}
	return false
}

func (flow *handleRequestIBDChainBlockLocatorFlow) receiveRequestIBDChainBlockLocator() (
	highHash, lowHash *externalapi.DomainHash, responseID uint32, err error) {

	message, err := flow.incomingRoute.Dequeue()
	if err != nil {
		return nil, nil, 0, err
	}
	msgGetBlockLocator := message.(*appmessage.MsgRequestIBDChainBlockLocator)

	return msgGetBlockLocator.HighHash, msgGetBlockLocator.LowHash, msgGetBlockLocator.RequestID(), nil
}

func (flow *handleRequestIBDChainBlockLocatorFlow) sendIBDChainBlockLocator(locator externalapi.BlockLocator, responseID uint32) error {
	msgIBDChainBlockLocator := appmessage.NewMsgIBDChainBlockLocator(locator)
	msgIBDChainBlockLocator.SetResponseID(responseID)
	err := flow.outgoingRoute.Enqueue(msgIBDChainBlockLocator)
	if err != nil {
		return err
	}
	return nil
}
