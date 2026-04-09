package strongnodes

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	peerpkg "github.com/cryptix-network/cryptixd/app/protocol/peer"
	"github.com/cryptix-network/cryptixd/infrastructure/network/connmanager"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
)

// HandleStrongNodeAnnouncementsContext is the interface for the context needed
// for handling strong-node announcements.
type HandleStrongNodeAnnouncementsContext interface {
	ConnectionManager() *connmanager.ConnectionManager
}

type handleStrongNodeAnnouncementsFlow struct {
	HandleStrongNodeAnnouncementsContext
	incomingRoute *router.Route
	peer          *peerpkg.Peer
}

// HandleStrongNodeAnnouncements handles all strong-node announcement messages.
func HandleStrongNodeAnnouncements(
	context HandleStrongNodeAnnouncementsContext,
	incomingRoute *router.Route,
	peer *peerpkg.Peer,
) error {
	flow := &handleStrongNodeAnnouncementsFlow{
		HandleStrongNodeAnnouncementsContext: context,
		incomingRoute:                        incomingRoute,
		peer:                                 peer,
	}
	return flow.start()
}

func (flow *handleStrongNodeAnnouncementsFlow) start() error {
	for {
		message, err := flow.incomingRoute.Dequeue()
		if err != nil {
			return err
		}

		announcement := message.(*appmessage.MsgStrongNodeAnnouncement)
		netConnection := flow.peer.Connection()

		strongNodeID := flow.ConnectionManager().ApplyStrongNodeAnnouncement(netConnection, announcement)
		if strongNodeID == "" {
			continue
		}

		if flow.ConnectionManager().IsStrongNodeIDBanned(strongNodeID) {
			log.Infof("Disconnecting %s due to external antifraud strong-node ID ban %s", netConnection, strongNodeID)
			netConnection.Disconnect()
			return nil
		}
	}
}
