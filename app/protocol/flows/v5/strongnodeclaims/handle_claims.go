package strongnodeclaims

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	peerpkg "github.com/cryptix-network/cryptixd/app/protocol/peer"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
)

// HandleBlockProducerClaimsContext is the context required for block producer claim handling.
type HandleBlockProducerClaimsContext interface {
	HandleBlockProducerClaim(peer *peerpkg.Peer, message *appmessage.MsgBlockProducerClaimV1) error
}

type handleBlockProducerClaimsFlow struct {
	HandleBlockProducerClaimsContext
	incomingRoute *router.Route
	peer          *peerpkg.Peer
}

// HandleBlockProducerClaims handles claimant gossip messages.
func HandleBlockProducerClaims(
	context HandleBlockProducerClaimsContext,
	incomingRoute *router.Route,
	peer *peerpkg.Peer,
) error {
	flow := &handleBlockProducerClaimsFlow{
		HandleBlockProducerClaimsContext: context,
		incomingRoute:                    incomingRoute,
		peer:                             peer,
	}
	return flow.start()
}

func (flow *handleBlockProducerClaimsFlow) start() error {
	for {
		message, err := flow.incomingRoute.Dequeue()
		if err != nil {
			return err
		}

		claim := message.(*appmessage.MsgBlockProducerClaimV1)
		if err := flow.HandleBlockProducerClaim(flow.peer, claim); err != nil {
			return err
		}
	}
}
