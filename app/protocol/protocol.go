package protocol

import (
	"github.com/cryptix-network/cryptixd/app/protocol/common"
	"github.com/cryptix-network/cryptixd/app/protocol/flows/ready"
	"github.com/cryptix-network/cryptixd/app/protocol/flows/v5"
	"sync"
	"sync/atomic"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/app/protocol/flows/handshake"
	peerpkg "github.com/cryptix-network/cryptixd/app/protocol/peer"
	"github.com/cryptix-network/cryptixd/app/protocol/protocolerrors"
	"github.com/cryptix-network/cryptixd/infrastructure/network/addressmanager"
	"github.com/cryptix-network/cryptixd/infrastructure/network/connmanager"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter"
	routerpkg "github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
	"github.com/pkg/errors"
)

func (m *Manager) routerInitializer(router *routerpkg.Router, netConnection *netadapter.NetConnection) {
	// isStopping flag is raised the moment that the connection associated with this router is disconnected
	// errChan is used by the flow goroutines to return to runFlows when an error occurs.
	// They are both initialized here and passed to register flows.
	isStopping := uint32(0)
	errChan := make(chan error, 1)

	receiveVersionRoute, sendVersionRoute, receiveReadyRoute := registerHandshakeRoutes(router)

	// After flows were registered - spawn a new thread that will wait for connection to finish initializing
	// and start receiving messages
	spawn("routerInitializer-runFlows", func() {
		m.routersWaitGroup.Add(1)
		defer m.routersWaitGroup.Done()

		if atomic.LoadUint32(&m.isClosed) == 1 {
			panic(errors.Errorf("tried to initialize router when the protocol manager is closed"))
		}

		isBanned, err := m.context.ConnectionManager().IsBanned(netConnection)
		if err != nil && !errors.Is(err, addressmanager.ErrAddressNotFound) {
			panic(err)
		}
		if isBanned {
			log.Infof("Peer %s is banned. Disconnecting...", netConnection)
			netConnection.Disconnect()
			return
		}

		netConnection.SetOnInvalidMessageHandler(func(err error) {
			if atomic.AddUint32(&isStopping, 1) == 1 {
				errChan <- protocolerrors.Wrap(true, err, "received bad message")
			}
		})

		peer, err := handshake.HandleHandshake(m.context, netConnection, receiveVersionRoute,
			sendVersionRoute, router.OutgoingRoute())

		if err != nil {
			// non-blocking read from channel
			select {
			case innerError := <-errChan:
				if errors.Is(err, routerpkg.ErrRouteClosed) {
					m.handleError(innerError, netConnection, router.OutgoingRoute())
				} else {
					log.Errorf("Peer %s sent invalid message: %s", netConnection, innerError)
					m.handleError(err, netConnection, router.OutgoingRoute())
				}
			default:
				m.handleError(err, netConnection, router.OutgoingRoute())
			}
			return
		}
		defer m.context.RemoveFromPeers(peer)

		if unifiedNodeID := peer.UnifiedNodeID(); unifiedNodeID != nil && m.context.ConnectionManager().IsUnifiedNodeIDBanned(*unifiedNodeID) {
			log.Infof("Peer %s is externally banned by unified node ID. Disconnecting...", netConnection)
			netConnection.Disconnect()
			return
		}

		var flows []*common.Flow
		log.Infof("Registering p2p flows for peer %s for protocol version %d", peer, peer.ProtocolVersion())
		enforceAntiFraud := false
		virtualDAAScore, err := m.context.Domain().Consensus().GetVirtualDAAScore()
		if err != nil {
			log.Warnf("Failed reading virtual DAA score for anti-fraud mode check: %s", err)
		} else if virtualDAAScore >= m.context.Config().NetParams().PayloadHfActivationDAAScore {
			enforceAntiFraud = true
		}
		antiFraudMode := connmanager.AntiFraudModeFull
		if enforceAntiFraud {
			antiFraudMode = m.context.ConnectionManager().AntiFraudModeForPeerHashes(peer.AntiFraudHashes())
			peer.SetAntiFraudRestricted(antiFraudMode == connmanager.AntiFraudModeRestricted)
		}
		switch peer.ProtocolVersion() {
		case 5, 6, 7:
			// Protocol versions 6/7 keep using the v5 flow set in this node implementation.
			if enforceAntiFraud && antiFraudMode == connmanager.AntiFraudModeRestricted {
				log.Infof("Peer %s has no valid anti-fraud hash overlap and will run in RESTRICTED_AF mode", peer)
				flows = v5.RegisterRestricted(m, router, errChan, &isStopping)
			} else {
				flows = v5.Register(m, router, errChan, &isStopping)
			}
		default:
			panic(errors.Errorf("no way to handle protocol version %d", peer.ProtocolVersion()))
		}

		outgoingReady := appmessage.NewMsgReady()
		peerUnifiedNodeID := peer.UnifiedNodeID()
		if peerUnifiedNodeID != nil {
			localNonce, hasLocalNonce := netConnection.LocalNodeChallengeNonce()
			remoteNonce, hasRemoteNonce := netConnection.RemoteNodeChallengeNonce()
			if enforceAntiFraud && (!hasLocalNonce || !hasRemoteNonce) {
				m.handleError(protocolerrors.New(false, "missing ready handshake challenge nonce"), netConnection, router.OutgoingRoute())
				return
			}
			if hasLocalNonce && hasRemoteNonce {
				readySignature, signErr := m.context.NetAdapter().SignUnifiedNodeAuthProof(
					m.context.Config().ActiveNetParams.Name,
					*peerUnifiedNodeID,
					localNonce,
					remoteNonce,
				)
				if signErr != nil {
					m.handleError(protocolerrors.Wrap(false, signErr, "failed signing ready auth proof"), netConnection, router.OutgoingRoute())
					return
				}
				outgoingReady.NodeAuthSignature = append(outgoingReady.NodeAuthSignature[:0], readySignature[:]...)
			}
		}

		incomingReady, err := ready.HandleReady(receiveReadyRoute, router.OutgoingRoute(), peer, outgoingReady)
		if err != nil {
			m.handleError(err, netConnection, router.OutgoingRoute())
			return
		}
		if peerUnifiedNodeID != nil {
			if len(incomingReady.NodeAuthSignature) == 0 {
				if enforceAntiFraud {
					m.handleError(protocolerrors.New(false, "missing ready auth signature after hardfork"), netConnection, router.OutgoingRoute())
					return
				}
			} else {
				if len(incomingReady.NodeAuthSignature) != 64 {
					m.handleError(protocolerrors.New(true, "ready auth signature must be exactly 64 bytes"), netConnection, router.OutgoingRoute())
					return
				}
				peerPubKeyXOnly, hasPeerPubKey := netConnection.UnifiedNodePubKeyXOnly()
				remoteNonce, hasRemoteNonce := netConnection.RemoteNodeChallengeNonce()
				localNonce, hasLocalNonce := netConnection.LocalNodeChallengeNonce()
				if !hasPeerPubKey || !hasRemoteNonce || !hasLocalNonce {
					if enforceAntiFraud {
						m.handleError(protocolerrors.New(false, "missing ready auth context"), netConnection, router.OutgoingRoute())
						return
					}
				} else {
					var signature [64]byte
					copy(signature[:], incomingReady.NodeAuthSignature)
					if !m.context.NetAdapter().VerifyUnifiedNodeAuthProof(
						m.context.Config().ActiveNetParams.Name,
						peerPubKeyXOnly,
						*peerUnifiedNodeID,
						m.context.NetAdapter().UnifiedNodeID(),
						remoteNonce,
						localNonce,
						signature,
					) {
						m.handleError(protocolerrors.New(true, "ready auth signature verification failed"), netConnection, router.OutgoingRoute())
						return
					}
				}
			}
		}

		removeHandshakeRoutes(router)

		flowsWaitGroup := &sync.WaitGroup{}
		err = m.runFlows(flows, peer, errChan, flowsWaitGroup)
		if err != nil {
			m.handleError(err, netConnection, router.OutgoingRoute())
			// We call `flowsWaitGroup.Wait()` in two places instead of deferring, because
			// we already defer `m.routersWaitGroup.Done()`, so we try to avoid error prone
			// and confusing use of multiple dependent defers.
			flowsWaitGroup.Wait()
			return
		}
		flowsWaitGroup.Wait()
	})
}

func (m *Manager) handleError(err error, netConnection *netadapter.NetConnection, outgoingRoute *routerpkg.Route) {
	if protocolErr := (protocolerrors.ProtocolError{}); errors.As(err, &protocolErr) {
		if m.context.Config().EnableBanning && protocolErr.ShouldBan {
			log.Warnf("Banning %s (reason: %s)", netConnection, protocolErr.Cause)

			var err error
			if unifiedNodeID, hasUnifiedNodeID := netConnection.UnifiedNodeID(); hasUnifiedNodeID {
				err = m.context.ConnectionManager().BanByUnifiedNodeID(unifiedNodeID)
			} else {
				err = m.context.ConnectionManager().Ban(netConnection)
			}
			if err != nil && !errors.Is(err, connmanager.ErrCannotBanPermanent) {
				panic(err)
			}

			err = outgoingRoute.Enqueue(appmessage.NewMsgReject(protocolErr.Error()))
			if err != nil && !errors.Is(err, routerpkg.ErrRouteClosed) {
				panic(err)
			}
		}
		log.Infof("Disconnecting from %s (reason: %s)", netConnection, protocolErr.Cause)
		netConnection.Disconnect()
		return
	}
	if errors.Is(err, routerpkg.ErrTimeout) {
		log.Warnf("Got timeout from %s. Disconnecting...", netConnection)
		netConnection.Disconnect()
		return
	}
	if errors.Is(err, routerpkg.ErrRouteClosed) {
		return
	}
	panic(err)
}

// RegisterFlow registers a flow to the given router.
func (m *Manager) RegisterFlow(name string, router *routerpkg.Router, messageTypes []appmessage.MessageCommand, isStopping *uint32,
	errChan chan error, initializeFunc common.FlowInitializeFunc) *common.Flow {

	route, err := router.AddIncomingRoute(name, messageTypes)
	if err != nil {
		panic(err)
	}

	return m.registerFlowForRoute(route, name, isStopping, errChan, initializeFunc)
}

// RegisterFlowWithCapacity registers a flow to the given router with a custom capacity.
func (m *Manager) RegisterFlowWithCapacity(name string, capacity int, router *routerpkg.Router,
	messageTypes []appmessage.MessageCommand, isStopping *uint32,
	errChan chan error, initializeFunc common.FlowInitializeFunc) *common.Flow {

	route, err := router.AddIncomingRouteWithCapacity(name, capacity, messageTypes)
	if err != nil {
		panic(err)
	}

	return m.registerFlowForRoute(route, name, isStopping, errChan, initializeFunc)
}

func (m *Manager) registerFlowForRoute(route *routerpkg.Route, name string, isStopping *uint32,
	errChan chan error, initializeFunc common.FlowInitializeFunc) *common.Flow {

	return &common.Flow{
		Name: name,
		ExecuteFunc: func(peer *peerpkg.Peer) {
			err := initializeFunc(route, peer)
			if err != nil {
				m.context.HandleError(err, name, isStopping, errChan)
				return
			}
		},
	}
}

// RegisterOneTimeFlow registers a one-time flow (that exits once some operations are done) to the given router.
func (m *Manager) RegisterOneTimeFlow(name string, router *routerpkg.Router, messageTypes []appmessage.MessageCommand,
	isStopping *uint32, stopChan chan error, initializeFunc common.FlowInitializeFunc) *common.Flow {

	route, err := router.AddIncomingRoute(name, messageTypes)
	if err != nil {
		panic(err)
	}

	return &common.Flow{
		Name: name,
		ExecuteFunc: func(peer *peerpkg.Peer) {
			defer func() {
				err := router.RemoveRoute(messageTypes)
				if err != nil {
					panic(err)
				}
			}()

			err := initializeFunc(route, peer)
			if err != nil {
				m.context.HandleError(err, name, isStopping, stopChan)
				return
			}
		},
	}
}

func registerHandshakeRoutes(router *routerpkg.Router) (
	receiveVersionRoute, sendVersionRoute, receiveReadyRoute *routerpkg.Route) {
	receiveVersionRoute, err := router.AddIncomingRoute("recieveVersion - incoming", []appmessage.MessageCommand{appmessage.CmdVersion})
	if err != nil {
		panic(err)
	}

	sendVersionRoute, err = router.AddIncomingRoute("sendVersion - incoming", []appmessage.MessageCommand{appmessage.CmdVerAck})
	if err != nil {
		panic(err)
	}

	receiveReadyRoute, err = router.AddIncomingRoute("recieveReady - incoming", []appmessage.MessageCommand{appmessage.CmdReady})
	if err != nil {
		panic(err)
	}

	return receiveVersionRoute, sendVersionRoute, receiveReadyRoute
}

func removeHandshakeRoutes(router *routerpkg.Router) {
	err := router.RemoveRoute([]appmessage.MessageCommand{appmessage.CmdVersion, appmessage.CmdVerAck, appmessage.CmdReady})
	if err != nil {
		panic(err)
	}
}
