package netadapter

import (
	"fmt"
	"github.com/cryptix-network/cryptixd/app/appmessage"
	routerpkg "github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
	"github.com/pkg/errors"
	"sync"
	"sync/atomic"

	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/id"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/server"
)

// NetConnection is a wrapper to a server connection for use by services external to NetAdapter
type NetConnection struct {
	connection                    server.Connection
	id                            *id.ID
	unifiedNodeID                 [32]byte
	hasUnifiedNodeID              bool
	unifiedNodePubKeyXOnly        [32]byte
	hasUnifiedNodePubKeyXOnly     bool
	localNodeChallengeNonce       uint64
	hasLocalNodeChallengeNonce    bool
	remoteNodeChallengeNonce      uint64
	hasRemoteNodeChallengeNonce   bool
	localPQMLKEM1024PrivateKey    []byte
	hasLocalPQMLKEM1024PrivateKey bool
	remotePQMLKEM1024PublicKey    []byte
	hasRemotePQMLKEM1024PublicKey bool
	metadataLock                  sync.RWMutex
	router                        *routerpkg.Router
	onDisconnectedHandler         server.OnDisconnectedHandler
	isRouterClosed                uint32
}

func newNetConnection(connection server.Connection, routerInitializer RouterInitializer, name string) *NetConnection {
	router := routerpkg.NewRouter(name)

	netConnection := &NetConnection{
		connection: connection,
		router:     router,
	}

	netConnection.connection.SetOnDisconnectedHandler(func() {
		log.Infof("Disconnected from %s", netConnection)
		// If the disconnection came because of a network error and not because of the application layer, we
		// need to close the router as well.
		if atomic.AddUint32(&netConnection.isRouterClosed, 1) == 1 {
			netConnection.router.Close()
		}
		netConnection.onDisconnectedHandler()
	})

	routerInitializer(router, netConnection)

	return netConnection
}

func (c *NetConnection) start() {
	if c.onDisconnectedHandler == nil {
		panic(errors.New("onDisconnectedHandler is nil"))
	}

	c.connection.Start(c.router)
}

func (c *NetConnection) String() string {
	return fmt.Sprintf("<%s: %s>", c.id, c.connection)
}

// ID returns the ID associated with this connection
func (c *NetConnection) ID() *id.ID {
	return c.id
}

// SetID sets the ID associated with this connection
func (c *NetConnection) SetID(peerID *id.ID) {
	c.id = peerID
}

// UnifiedNodeID returns the unified node ID associated with this connection.
func (c *NetConnection) UnifiedNodeID() ([32]byte, bool) {
	c.metadataLock.RLock()
	defer c.metadataLock.RUnlock()
	return c.unifiedNodeID, c.hasUnifiedNodeID
}

// SetUnifiedNodeID sets the unified node ID associated with this connection.
func (c *NetConnection) SetUnifiedNodeID(nodeID [32]byte) {
	c.metadataLock.Lock()
	defer c.metadataLock.Unlock()
	c.unifiedNodeID = nodeID
	c.hasUnifiedNodeID = true
}

// UnifiedNodePubKeyXOnly returns the unified node x-only pubkey associated with this connection.
func (c *NetConnection) UnifiedNodePubKeyXOnly() ([32]byte, bool) {
	c.metadataLock.RLock()
	defer c.metadataLock.RUnlock()
	return c.unifiedNodePubKeyXOnly, c.hasUnifiedNodePubKeyXOnly
}

// SetUnifiedNodePubKeyXOnly sets the unified node x-only pubkey associated with this connection.
func (c *NetConnection) SetUnifiedNodePubKeyXOnly(pubKey [32]byte) {
	c.metadataLock.Lock()
	defer c.metadataLock.Unlock()
	c.unifiedNodePubKeyXOnly = pubKey
	c.hasUnifiedNodePubKeyXOnly = true
}

// LocalNodeChallengeNonce returns the locally advertised handshake challenge nonce for this connection.
func (c *NetConnection) LocalNodeChallengeNonce() (uint64, bool) {
	c.metadataLock.RLock()
	defer c.metadataLock.RUnlock()
	return c.localNodeChallengeNonce, c.hasLocalNodeChallengeNonce
}

// SetLocalNodeChallengeNonce stores the locally advertised handshake challenge nonce for this connection.
func (c *NetConnection) SetLocalNodeChallengeNonce(nonce uint64) {
	c.metadataLock.Lock()
	defer c.metadataLock.Unlock()
	c.localNodeChallengeNonce = nonce
	c.hasLocalNodeChallengeNonce = true
}

// RemoteNodeChallengeNonce returns the peer-advertised handshake challenge nonce for this connection.
func (c *NetConnection) RemoteNodeChallengeNonce() (uint64, bool) {
	c.metadataLock.RLock()
	defer c.metadataLock.RUnlock()
	return c.remoteNodeChallengeNonce, c.hasRemoteNodeChallengeNonce
}

// SetRemoteNodeChallengeNonce stores the peer-advertised handshake challenge nonce for this connection.
func (c *NetConnection) SetRemoteNodeChallengeNonce(nonce uint64) {
	c.metadataLock.Lock()
	defer c.metadataLock.Unlock()
	c.remoteNodeChallengeNonce = nonce
	c.hasRemoteNodeChallengeNonce = true
}

// LocalPQMLKEM1024PrivateKey returns the local per-connection ML-KEM-1024 private key.
func (c *NetConnection) LocalPQMLKEM1024PrivateKey() ([]byte, bool) {
	c.metadataLock.RLock()
	defer c.metadataLock.RUnlock()
	if !c.hasLocalPQMLKEM1024PrivateKey {
		return nil, false
	}
	return append([]byte(nil), c.localPQMLKEM1024PrivateKey...), true
}

// SetLocalPQMLKEM1024PrivateKey stores the local per-connection ML-KEM-1024 private key.
func (c *NetConnection) SetLocalPQMLKEM1024PrivateKey(privateKey []byte) {
	c.metadataLock.Lock()
	defer c.metadataLock.Unlock()
	c.localPQMLKEM1024PrivateKey = append(c.localPQMLKEM1024PrivateKey[:0], privateKey...)
	c.hasLocalPQMLKEM1024PrivateKey = true
}

// RemotePQMLKEM1024PublicKey returns the peer ML-KEM-1024 public key from handshake.
func (c *NetConnection) RemotePQMLKEM1024PublicKey() ([]byte, bool) {
	c.metadataLock.RLock()
	defer c.metadataLock.RUnlock()
	if !c.hasRemotePQMLKEM1024PublicKey {
		return nil, false
	}
	return append([]byte(nil), c.remotePQMLKEM1024PublicKey...), true
}

// SetRemotePQMLKEM1024PublicKey stores the peer ML-KEM-1024 public key from handshake.
func (c *NetConnection) SetRemotePQMLKEM1024PublicKey(publicKey []byte) {
	c.metadataLock.Lock()
	defer c.metadataLock.Unlock()
	c.remotePQMLKEM1024PublicKey = append(c.remotePQMLKEM1024PublicKey[:0], publicKey...)
	c.hasRemotePQMLKEM1024PublicKey = true
}

// Address returns the address associated with this connection
func (c *NetConnection) Address() string {
	return c.connection.Address().String()
}

// IsOutbound returns whether the connection is outbound
func (c *NetConnection) IsOutbound() bool {
	return c.connection.IsOutbound()
}

// NetAddress returns the NetAddress associated with this connection
func (c *NetConnection) NetAddress() *appmessage.NetAddress {
	return appmessage.NewNetAddress(c.connection.Address())
}

func (c *NetConnection) setOnDisconnectedHandler(onDisconnectedHandler server.OnDisconnectedHandler) {
	c.onDisconnectedHandler = onDisconnectedHandler
}

// Disconnect disconnects the given connection
func (c *NetConnection) Disconnect() {
	if atomic.AddUint32(&c.isRouterClosed, 1) == 1 {
		c.router.Close()
	}
}

// SetOnInvalidMessageHandler sets the invalid message handler for this connection
func (c *NetConnection) SetOnInvalidMessageHandler(onInvalidMessageHandler server.OnInvalidMessageHandler) {
	c.connection.SetOnInvalidMessageHandler(onInvalidMessageHandler)
}
