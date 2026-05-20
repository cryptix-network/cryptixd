package blockrelay

import (
	"time"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/app/protocol/protocolerrors"
	"github.com/cryptix-network/cryptixd/domain"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
)

const atomicStateHashResponseWait = 10 * time.Second
const atomicStateHashResponsePoll = 250 * time.Millisecond

type AtomicStateHashRequestsContext interface {
	Domain() domain.Domain
	IsIBDRunning() bool
}

type handleAtomicStateHashRequestsFlow struct {
	AtomicStateHashRequestsContext
	incomingRoute, outgoingRoute *router.Route
}

func HandleAtomicStateHashRequests(context AtomicStateHashRequestsContext, incomingRoute *router.Route,
	outgoingRoute *router.Route) error {

	flow := &handleAtomicStateHashRequestsFlow{
		AtomicStateHashRequestsContext: context,
		incomingRoute:                  incomingRoute,
		outgoingRoute:                  outgoingRoute,
	}
	return flow.start()
}

func (flow *handleAtomicStateHashRequestsFlow) start() error {
	for {
		message, err := flow.incomingRoute.Dequeue()
		if err != nil {
			return err
		}

		switch message := message.(type) {
		case *appmessage.MsgRequestConsensusAtomicStateHash:
			if err := flow.handleConsensusAtomicStateHashRequest(message); err != nil {
				return err
			}
		case *appmessage.MsgRequestAtomicTokenStateHash:
			if err := flow.handleAtomicTokenStateHashRequest(message); err != nil {
				return err
			}
		default:
			return protocolerrors.Errorf(true, "unexpected Atomic state hash request message: %s", message.Command())
		}
	}
}

func (flow *handleAtomicStateHashRequestsFlow) handleConsensusAtomicStateHashRequest(
	request *appmessage.MsgRequestConsensusAtomicStateHash) error {

	if request.RequestID() == 0 {
		return protocolerrors.Errorf(true, "RequestConsensusAtomicStateHash missing non-zero request id")
	}

	stateHash, hasState, err := flow.atomicStateHashForPeer(request.BlockHash, request.AnchorDAAScore)
	if err != nil {
		return protocolerrors.Wrap(true, err, "Failed querying consensus Atomic state hash")
	}

	response := appmessage.NewMsgConsensusAtomicStateHash(request.BlockHash, stateHash[:], hasState, request.AnchorDAAScore)
	response.SetResponseID(request.RequestID())
	return flow.outgoingRoute.Enqueue(response)
}

func (flow *handleAtomicStateHashRequestsFlow) handleAtomicTokenStateHashRequest(
	request *appmessage.MsgRequestAtomicTokenStateHash) error {

	if request.RequestID() == 0 {
		return protocolerrors.Errorf(true, "RequestAtomicTokenStateHash missing non-zero request id")
	}

	stateHash, hasState, err := flow.atomicTokenStateHashForPeer(request.BlockHash, request.AnchorDAAScore)
	if err != nil {
		return protocolerrors.Wrap(true, err, "Failed querying Atomic token state hash")
	}

	response := appmessage.NewMsgAtomicTokenStateHash(request.BlockHash, stateHash[:], hasState, request.AnchorDAAScore)
	response.SetResponseID(request.RequestID())
	return flow.outgoingRoute.Enqueue(response)
}

func (flow *handleAtomicStateHashRequestsFlow) atomicStateHashForPeer(
	blockHash *externalapi.DomainHash, anchorDAAScore uint64) ([externalapi.DomainHashSize]byte, bool, error) {

	if !flow.waitForAnchor(blockHash, anchorDAAScore) {
		return [externalapi.DomainHashSize]byte{}, false, nil
	}
	return flow.Domain().Consensus().GetAtomicStateHash(blockHash)
}

func (flow *handleAtomicStateHashRequestsFlow) atomicTokenStateHashForPeer(
	blockHash *externalapi.DomainHash, anchorDAAScore uint64) ([externalapi.DomainHashSize]byte, bool, error) {

	if !flow.waitForAnchor(blockHash, anchorDAAScore) {
		return [externalapi.DomainHashSize]byte{}, false, nil
	}
	return flow.Domain().Consensus().GetAtomicTokenStateHash(blockHash)
}

func (flow *handleAtomicStateHashRequestsFlow) waitForAnchor(blockHash *externalapi.DomainHash, anchorDAAScore uint64) bool {
	deadline := time.Now().Add(atomicStateHashResponseWait)
	for {
		if !flow.IsIBDRunning() {
			header, err := flow.Domain().Consensus().GetBlockHeader(blockHash)
			if err == nil && header.DAAScore() == anchorDAAScore {
				return true
			}
		}

		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(atomicStateHashResponsePoll)
	}
}
