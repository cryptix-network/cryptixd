package ready

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/app/protocol/common"
	"sync/atomic"

	peerpkg "github.com/cryptix-network/cryptixd/app/protocol/peer"
	"github.com/cryptix-network/cryptixd/app/protocol/protocolerrors"
	routerpkg "github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
	"github.com/pkg/errors"
)

// HandleReady notify the other peer that peer is ready for messages, and wait for the other peer
// to send a ready message before start running the flows.
func HandleReady(incomingRoute *routerpkg.Route, outgoingRoute *routerpkg.Route,
	peer *peerpkg.Peer,
	outgoingReady *appmessage.MsgReady,
) (*appmessage.MsgReady, error) {

	log.Debugf("Sending ready message to %s", peer)

	isStopping := uint32(0)
	if outgoingReady == nil {
		outgoingReady = appmessage.NewMsgReady()
	}
	err := outgoingRoute.Enqueue(outgoingReady)
	if err != nil {
		return nil, handleError(err, "HandleReady", &isStopping)
	}

	message, err := incomingRoute.DequeueWithTimeout(common.DefaultTimeout)
	if err != nil {
		return nil, handleError(err, "HandleReady", &isStopping)
	}
	incomingReady, ok := message.(*appmessage.MsgReady)
	if !ok {
		return nil, protocolerrors.New(true, "a ready message must be received in ready flow")
	}

	log.Debugf("Got ready message from %s", peer)

	return incomingReady, nil
}

// Ready is different from other flows, since in it should forward router.ErrRouteClosed to errChan
// Therefore we implement a separate handleError for 'ready'
func handleError(err error, flowName string, isStopping *uint32) error {
	if errors.Is(err, routerpkg.ErrRouteClosed) {
		if atomic.AddUint32(isStopping, 1) == 1 {
			return err
		}
		return nil
	}

	if protocolErr := (protocolerrors.ProtocolError{}); errors.As(err, &protocolErr) {
		log.Errorf("Ready protocol error from %s: %s", flowName, err)
		if atomic.AddUint32(isStopping, 1) == 1 {
			return err
		}
		return nil
	}
	panic(err)
}
