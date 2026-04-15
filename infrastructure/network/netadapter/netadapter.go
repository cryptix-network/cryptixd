package netadapter

import (
	"sync"
	"sync/atomic"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/infrastructure/config"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/id"
	routerpkg "github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/server"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/server/grpcserver"
	"github.com/pkg/errors"
)

// RouterInitializer is a function that initializes a new
// router to be used with a new connection
type RouterInitializer func(*routerpkg.Router, *NetConnection)

// NetAdapter is an abstraction layer over networking.
// This type expects a RouteInitializer function. This
// function weaves together the various "routes" (messages
// and message handlers) without exposing anything related
// to networking internals.
type NetAdapter struct {
	cfg                  *config.Config
	id                   *id.ID
	unifiedNodeIdentity  *UnifiedNodeIdentity
	p2pServer            server.P2PServer
	p2pRouterInitializer RouterInitializer
	rpcServer            server.Server
	rpcRouterInitializer RouterInitializer
	stop                 uint32

	p2pConnections     map[*NetConnection]struct{}
	p2pConnectionsLock sync.RWMutex
}

// NewNetAdapter creates and starts a new NetAdapter on the
// given listeningPort
func NewNetAdapter(cfg *config.Config) (*NetAdapter, error) {
	netAdapterID, err := id.GenerateID()
	if err != nil {
		return nil, err
	}
	unifiedNodeIdentity, err := loadOrCreateUnifiedNodeIdentity(cfg.AppDir, cfg.ActiveNetParams.Name)
	if err != nil {
		return nil, errors.Wrap(err, "failed loading persistent unified node identity")
	}
	p2pServer, err := grpcserver.NewP2PServer(cfg.Listeners)
	if err != nil {
		return nil, err
	}
	rpcServer, err := grpcserver.NewRPCServer(cfg.RPCListeners, cfg.RPCMaxClients)
	if err != nil {
		return nil, err
	}
	adapter := NetAdapter{
		cfg:                 cfg,
		id:                  netAdapterID,
		unifiedNodeIdentity: unifiedNodeIdentity,
		p2pServer:           p2pServer,
		rpcServer:           rpcServer,

		p2pConnections: make(map[*NetConnection]struct{}),
	}

	adapter.p2pServer.SetOnConnectedHandler(adapter.onP2PConnectedHandler)
	adapter.rpcServer.SetOnConnectedHandler(adapter.onRPCConnectedHandler)

	return &adapter, nil
}

// Start begins the operation of the NetAdapter
func (na *NetAdapter) Start() error {
	if na.p2pRouterInitializer == nil {
		return errors.New("p2pRouterInitializer was not set")
	}
	if na.rpcRouterInitializer == nil {
		return errors.New("rpcRouterInitializer was not set")
	}

	err := na.p2pServer.Start()
	if err != nil {
		return err
	}
	err = na.rpcServer.Start()
	if err != nil {
		return err
	}

	return nil
}

// Stop safely closes the NetAdapter
func (na *NetAdapter) Stop() error {
	if atomic.AddUint32(&na.stop, 1) != 1 {
		return errors.New("net adapter stopped more than once")
	}
	err := na.p2pServer.Stop()
	if err != nil {
		return err
	}
	return na.rpcServer.Stop()
}

// P2PConnect tells the NetAdapter's underlying p2p server to initiate a connection
// to the given address
func (na *NetAdapter) P2PConnect(address string) error {
	_, err := na.p2pServer.Connect(address)
	return err
}

// P2PConnections returns a list of p2p connections currently connected and active
func (na *NetAdapter) P2PConnections() []*NetConnection {
	na.p2pConnectionsLock.RLock()
	defer na.p2pConnectionsLock.RUnlock()

	netConnections := make([]*NetConnection, 0, len(na.p2pConnections))

	for netConnection := range na.p2pConnections {
		netConnections = append(netConnections, netConnection)
	}

	return netConnections
}

// P2PConnectionCount returns the count of the connected p2p connections
func (na *NetAdapter) P2PConnectionCount() int {
	na.p2pConnectionsLock.RLock()
	defer na.p2pConnectionsLock.RUnlock()

	return len(na.p2pConnections)
}

func (na *NetAdapter) onP2PConnectedHandler(connection server.Connection) error {
	netConnection := newNetConnection(connection, na.p2pRouterInitializer, "on P2P connected")

	na.p2pConnectionsLock.Lock()
	defer na.p2pConnectionsLock.Unlock()

	netConnection.setOnDisconnectedHandler(func() {
		na.p2pConnectionsLock.Lock()
		defer na.p2pConnectionsLock.Unlock()

		delete(na.p2pConnections, netConnection)
	})

	na.p2pConnections[netConnection] = struct{}{}

	netConnection.start()

	return nil
}

func (na *NetAdapter) onRPCConnectedHandler(connection server.Connection) error {
	netConnection := newNetConnection(connection, na.rpcRouterInitializer, "on RPC connected")
	netConnection.setOnDisconnectedHandler(func() {})
	netConnection.start()

	return nil
}

// SetP2PRouterInitializer sets the p2pRouterInitializer function
// for the net adapter
func (na *NetAdapter) SetP2PRouterInitializer(routerInitializer RouterInitializer) {
	na.p2pRouterInitializer = routerInitializer
}

// SetRPCRouterInitializer sets the rpcRouterInitializer function
// for the net adapter
func (na *NetAdapter) SetRPCRouterInitializer(routerInitializer RouterInitializer) {
	na.rpcRouterInitializer = routerInitializer
}

// ID returns this netAdapter's ID in the network
func (na *NetAdapter) ID() *id.ID {
	return na.id
}

// UnifiedNodePubKeyXOnly returns the local unified node identity x-only pubkey.
func (na *NetAdapter) UnifiedNodePubKeyXOnly() [32]byte {
	if na.unifiedNodeIdentity == nil {
		return [32]byte{}
	}
	return na.unifiedNodeIdentity.PubKeyXOnly
}

// UnifiedNodePowNonce returns the local unified node identity PoW nonce.
func (na *NetAdapter) UnifiedNodePowNonce() uint64 {
	if na.unifiedNodeIdentity == nil {
		return 0
	}
	return na.unifiedNodeIdentity.PowNonce
}

// UnifiedNodeID returns the local unified node ID (blake3 over x-only pubkey).
func (na *NetAdapter) UnifiedNodeID() [32]byte {
	if na.unifiedNodeIdentity == nil {
		return [32]byte{}
	}
	return na.unifiedNodeIdentity.NodeID
}

// SignUnifiedNodeAuthProof signs a per-connection proof-of-possession for unified node identity.
func (na *NetAdapter) SignUnifiedNodeAuthProof(
	networkName string,
	verifierNodeID [32]byte,
	signerChallengeNonce uint64,
	verifierChallengeNonce uint64,
) ([64]byte, error) {
	if na.unifiedNodeIdentity == nil {
		return [64]byte{}, errors.New("unified node identity is not initialized")
	}
	networkCode, err := networkCodeFromName(networkName)
	if err != nil {
		return [64]byte{}, err
	}
	return signUnifiedNodeAuthProof(na.unifiedNodeIdentity, networkCode, verifierNodeID, signerChallengeNonce, verifierChallengeNonce)
}

// VerifyUnifiedNodeAuthProof verifies a peer proof-of-possession signature for unified node identity.
func (na *NetAdapter) VerifyUnifiedNodeAuthProof(
	networkName string,
	signerPubKeyXOnly [32]byte,
	signerNodeID [32]byte,
	verifierNodeID [32]byte,
	signerChallengeNonce uint64,
	verifierChallengeNonce uint64,
	signature [64]byte,
) bool {
	networkCode, err := networkCodeFromName(networkName)
	if err != nil {
		return false
	}
	return verifyUnifiedNodeAuthProof(
		networkCode,
		signerPubKeyXOnly,
		signerNodeID,
		verifierNodeID,
		signerChallengeNonce,
		verifierChallengeNonce,
		signature,
	)
}

// P2PBroadcast sends the given `message` to every peer corresponding
// to each NetConnection in the given netConnections
func (na *NetAdapter) P2PBroadcast(netConnections []*NetConnection, message appmessage.Message) error {
	na.p2pConnectionsLock.RLock()
	defer na.p2pConnectionsLock.RUnlock()

	for _, netConnection := range netConnections {
		err := netConnection.router.OutgoingRoute().Enqueue(message)
		if err != nil {
			if errors.Is(err, routerpkg.ErrRouteClosed) {
				log.Debugf("Cannot enqueue message to %s: router is closed", netConnection)
				continue
			}
			return err
		}
	}
	return nil
}
