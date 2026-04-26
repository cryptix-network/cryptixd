package protocol

import (
	"crypto/subtle"
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

const (
	quantumHandshakeStateUnknown  = uint32(0)
	quantumHandshakeStateLegacy   = uint32(1)
	quantumHandshakeStateEnforced = uint32(2)
)

var quantumHandshakeModeState uint32 = quantumHandshakeStateUnknown
var quantumHandshakeStartupLogged uint32

func logQuantumHandshakeModeTransition(enforceQuantumHandshake bool) {
	nextState := quantumHandshakeStateLegacy
	if enforceQuantumHandshake {
		nextState = quantumHandshakeStateEnforced
	}
	previousState := atomic.SwapUint32(&quantumHandshakeModeState, nextState)
	if previousState == nextState {
		return
	}

	if nextState == quantumHandshakeStateEnforced {
		log.Infof("Hardfork reached: switching to quantum-safe handshake (ML-KEM-1024 enforced)")
		return
	}

	if previousState == quantumHandshakeStateEnforced {
		log.Warnf("Quantum-safe handshake enforcement disabled; returning to legacy-compatible handshake mode")
	} else {
		log.Infof("Handshake mode initialized: legacy-compatible (quantum-safe ML-KEM-1024 is not enforced)")
	}
}

func logQuantumHandshakeStartupOnce(enforceQuantumHandshake bool) {
	if !atomic.CompareAndSwapUint32(&quantumHandshakeStartupLogged, 0, 1) {
		return
	}
	if enforceQuantumHandshake {
		log.Infof("Peer handshake started: running in quantum-safe mode (ML-KEM-1024 enforced)")
	} else {
		log.Infof("Peer handshake started: running in legacy-compatible mode")
	}
}

func peerSupportsQuantumHandshakeFallback(peer *peerpkg.Peer) bool {
	return peer.Services()&appmessage.SFNodeQuantumHandshakeFallback != 0
}

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
		enforceHardforkCore := false
		antiFraudRuntimeEnabled := m.context.ConnectionManager().IsAntiFraudRuntimeEnabled()
		virtualDAAScore, err := m.context.Domain().Consensus().GetVirtualDAAScore()
		if err != nil {
			log.Warnf("Failed reading virtual DAA score for hardfork mode check: %s", err)
		} else if virtualDAAScore >= m.context.Config().NetParams().PayloadHfActivationDAAScore {
			enforceHardforkCore = true
		}
		enforceAntiFraud := enforceHardforkCore && antiFraudRuntimeEnabled
		peerSupportsQuantumFallback := peerSupportsQuantumHandshakeFallback(peer)
		requireQuantumReady := enforceHardforkCore && !peerSupportsQuantumFallback
		logQuantumHandshakeModeTransition(enforceHardforkCore)
		logQuantumHandshakeStartupOnce(enforceHardforkCore)
		if enforceHardforkCore {
			log.Debugf("Starting handshake with peer %s in quantum-safe mode (ML-KEM-1024 enforced)", peer)
		} else {
			log.Debugf("Starting handshake with peer %s in legacy-compatible mode", peer)
		}
		if enforceHardforkCore && !requireQuantumReady {
			log.Debugf("Peer %s supports post-HF quantum-safe handshake fallback negotiation", peer)
		}
		antiFraudMode := connmanager.AntiFraudModeFull
		if enforceAntiFraud {
			antiFraudMode = m.context.ConnectionManager().AntiFraudModeForPeerHashes(peer.AntiFraudHashes())
			peer.SetAntiFraudRestricted(antiFraudMode == connmanager.AntiFraudModeRestricted)
		}
		switch peer.ProtocolVersion() {
		case 5, 6, 7, 8, 9:
			// Protocol versions 5/6/7/8/9 currently use the v5 flow set in this node implementation.
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
		var localNonce uint64
		var remoteNonce uint64
		var hasLocalNonce bool
		var hasRemoteNonce bool
		if peerUnifiedNodeID != nil {
			localNonce, hasLocalNonce = netConnection.LocalNodeChallengeNonce()
			remoteNonce, hasRemoteNonce = netConnection.RemoteNodeChallengeNonce()
			if enforceHardforkCore && (!hasLocalNonce || !hasRemoteNonce) {
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

				peerQuantumPubKey, hasPeerQuantumPubKey := netConnection.RemotePQMLKEM1024PublicKey()
				if hasPeerQuantumPubKey {
					pqCiphertext, pqSharedSecret, pqErr := m.context.NetAdapter().EncapsulateQuantumHandshake(peerQuantumPubKey)
					if pqErr != nil {
						if requireQuantumReady {
							m.handleError(protocolerrors.Wrap(false, pqErr, "failed encapsulating ML-KEM-1024 ready payload"), netConnection, router.OutgoingRoute())
							return
						}
						log.Warnf(
							"Peer %s PQ fallback: failed encapsulating ML-KEM-1024 ready payload (%s); continuing with classical ready-auth only",
							peer,
							pqErr,
						)
					} else {
						pqProof, pqProofErr := m.context.NetAdapter().ComputeQuantumHandshakeProof(
							m.context.Config().ActiveNetParams.Name,
							m.context.NetAdapter().UnifiedNodeID(),
							*peerUnifiedNodeID,
							localNonce,
							remoteNonce,
							pqSharedSecret,
						)
						if pqProofErr != nil {
							if requireQuantumReady {
								m.handleError(protocolerrors.Wrap(false, pqProofErr, "failed computing quantum-safe handshake proof"), netConnection, router.OutgoingRoute())
								return
							}
							log.Warnf(
								"Peer %s PQ fallback: failed computing quantum-safe handshake proof (%s); continuing with classical ready-auth only",
								peer,
								pqProofErr,
							)
						} else {
							outgoingReady.PQMLKEM1024Ciphertext = append(outgoingReady.PQMLKEM1024Ciphertext[:0], pqCiphertext...)
							outgoingReady.PQHandshakeProof = append(outgoingReady.PQHandshakeProof[:0], pqProof[:]...)
						}
					}
				} else if requireQuantumReady {
					m.handleError(protocolerrors.New(false, "missing peer ML-KEM-1024 public key for hardfork handshake"), netConnection, router.OutgoingRoute())
					return
				} else if enforceHardforkCore {
					log.Warnf(
						"Peer %s PQ fallback: peer omitted ML-KEM-1024 public key after hardfork; continuing with classical ready-auth only",
						peer,
					)
				}
			}
		}

		incomingReady, err := ready.HandleReady(receiveReadyRoute, router.OutgoingRoute(), peer, outgoingReady)
		if err != nil {
			m.handleError(err, netConnection, router.OutgoingRoute())
			return
		}
		if peerUnifiedNodeID != nil {
			if len(incomingReady.NodeAuthSignature) == 0 {
				if enforceHardforkCore {
					m.handleError(protocolerrors.New(false, "missing ready auth signature after hardfork"), netConnection, router.OutgoingRoute())
					return
				}
			} else {
				if len(incomingReady.NodeAuthSignature) != 64 {
					m.handleError(protocolerrors.New(true, "ready auth signature must be exactly 64 bytes"), netConnection, router.OutgoingRoute())
					return
				}
				peerPubKeyXOnly, hasPeerPubKey := netConnection.UnifiedNodePubKeyXOnly()
				if !hasPeerPubKey || !hasRemoteNonce || !hasLocalNonce {
					if enforceHardforkCore {
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

			peerHasQuantumReadyPayload := len(incomingReady.PQMLKEM1024Ciphertext) > 0 || len(incomingReady.PQHandshakeProof) > 0
			if !peerHasQuantumReadyPayload {
				if requireQuantumReady {
					m.handleError(protocolerrors.New(false, "missing quantum-safe ready payload after hardfork"), netConnection, router.OutgoingRoute())
					return
				}
				if enforceHardforkCore {
					log.Warnf(
						"Peer %s PQ fallback: peer omitted quantum-safe ready payload after hardfork; accepting classical ready-auth only",
						peer,
					)
				}
			} else {
				if len(incomingReady.PQMLKEM1024Ciphertext) != netadapter.QuantumHandshakeMLKEM1024CiphertextSize {
					if requireQuantumReady {
						m.handleError(protocolerrors.New(true, "ML-KEM-1024 ready ciphertext has invalid length"), netConnection, router.OutgoingRoute())
						return
					}
					log.Warnf(
						"Peer %s PQ fallback: invalid ML-KEM-1024 ready ciphertext length (%d); accepting classical ready-auth only",
						peer,
						len(incomingReady.PQMLKEM1024Ciphertext),
					)
				}
				if len(incomingReady.PQMLKEM1024Ciphertext) == netadapter.QuantumHandshakeMLKEM1024CiphertextSize &&
					len(incomingReady.PQHandshakeProof) != netadapter.QuantumHandshakeProofSize {
					if requireQuantumReady {
						m.handleError(protocolerrors.New(true, "quantum-safe handshake proof has invalid length"), netConnection, router.OutgoingRoute())
						return
					}
					log.Warnf(
						"Peer %s PQ fallback: invalid quantum-safe handshake proof length (%d); accepting classical ready-auth only",
						peer,
						len(incomingReady.PQHandshakeProof),
					)
				}
				if len(incomingReady.PQMLKEM1024Ciphertext) == netadapter.QuantumHandshakeMLKEM1024CiphertextSize &&
					len(incomingReady.PQHandshakeProof) == netadapter.QuantumHandshakeProofSize {
					if !hasLocalNonce || !hasRemoteNonce {
						if requireQuantumReady {
							m.handleError(protocolerrors.New(false, "missing quantum-safe handshake nonce context"), netConnection, router.OutgoingRoute())
							return
						}
						log.Warnf(
							"Peer %s PQ fallback: missing local nonce context for quantum-safe verification; accepting classical ready-auth only",
							peer,
						)
					} else {
						localQuantumPrivateKey, hasLocalQuantumPrivateKey := netConnection.LocalPQMLKEM1024PrivateKey()
						if !hasLocalQuantumPrivateKey {
							if requireQuantumReady {
								m.handleError(protocolerrors.New(false, "missing local ML-KEM-1024 private key for handshake verification"), netConnection, router.OutgoingRoute())
								return
							}
							log.Warnf(
								"Peer %s PQ fallback: missing local ML-KEM-1024 private key; accepting classical ready-auth only",
								peer,
							)
						} else {
							peerSharedSecret, decapErr := m.context.NetAdapter().DecapsulateQuantumHandshake(
								localQuantumPrivateKey,
								incomingReady.PQMLKEM1024Ciphertext,
							)
							if decapErr != nil {
								if requireQuantumReady {
									m.handleError(protocolerrors.Wrap(true, decapErr, "failed decapsulating peer ML-KEM-1024 ready payload"), netConnection, router.OutgoingRoute())
									return
								}
								log.Warnf(
									"Peer %s PQ fallback: failed decapsulating peer ML-KEM-1024 ready payload (%s); accepting classical ready-auth only",
									peer,
									decapErr,
								)
							} else {
								expectedProof, proofErr := m.context.NetAdapter().ComputeQuantumHandshakeProof(
									m.context.Config().ActiveNetParams.Name,
									*peerUnifiedNodeID,
									m.context.NetAdapter().UnifiedNodeID(),
									remoteNonce,
									localNonce,
									peerSharedSecret,
								)
								if proofErr != nil {
									if requireQuantumReady {
										m.handleError(protocolerrors.Wrap(false, proofErr, "failed computing expected quantum-safe handshake proof"), netConnection, router.OutgoingRoute())
										return
									}
									log.Warnf(
										"Peer %s PQ fallback: failed computing expected quantum-safe handshake proof (%s); accepting classical ready-auth only",
										peer,
										proofErr,
									)
								} else if subtle.ConstantTimeCompare(expectedProof[:], incomingReady.PQHandshakeProof) != 1 {
									if requireQuantumReady {
										m.handleError(protocolerrors.New(true, "quantum-safe handshake proof verification failed"), netConnection, router.OutgoingRoute())
										return
									}
									log.Warnf(
										"Peer %s PQ fallback: quantum-safe handshake proof verification failed; accepting classical ready-auth only",
										peer,
									)
								}
							}
						}
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
