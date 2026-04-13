package handshake

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/app/protocol/common"
	peerpkg "github.com/cryptix-network/cryptixd/app/protocol/peer"
	"github.com/cryptix-network/cryptixd/app/protocol/protocolerrors"
	"github.com/cryptix-network/cryptixd/infrastructure/logger"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
	"github.com/pkg/errors"
)

var (
	// allowSelfConnections is only used to allow the tests to bypass the self
	// connection detecting and disconnect logic since they intentionally
	// do so for testing purposes.
	allowSelfConnections bool
)

type receiveVersionFlow struct {
	HandleHandshakeContext
	incomingRoute, outgoingRoute *router.Route
	peer                         *peerpkg.Peer
}

// ReceiveVersion waits for the peer to send a version message, sends a
// verack in response, and updates its info accordingly.
func ReceiveVersion(context HandleHandshakeContext, incomingRoute *router.Route, outgoingRoute *router.Route,
	peer *peerpkg.Peer) (*appmessage.NetAddress, error) {

	flow := &receiveVersionFlow{
		HandleHandshakeContext: context,
		incomingRoute:          incomingRoute,
		outgoingRoute:          outgoingRoute,
		peer:                   peer,
	}

	return flow.start()
}

func (flow *receiveVersionFlow) start() (*appmessage.NetAddress, error) {
	onEnd := logger.LogAndMeasureExecutionTime(log, "receiveVersionFlow.start")
	defer onEnd()

	log.Debugf("Starting receiveVersionFlow with %s", flow.peer.Address())

	message, err := flow.incomingRoute.DequeueWithTimeout(common.DefaultTimeout)
	if err != nil {
		return nil, err
	}

	log.Debugf("Got version message")

	msgVersion, ok := message.(*appmessage.MsgVersion)
	if !ok {
		return nil, protocolerrors.New(true, "a version message must precede all others")
	}

	if !allowSelfConnections && flow.NetAdapter().ID().IsEqual(msgVersion.ID) {
		return nil, protocolerrors.New(false, "connected to self")
	}

	// Disconnect and ban peers from a different network.
	if !isCompatiblePeerNetwork(flow.Config().ActiveNetParams.Name, msgVersion.Network) {
		return nil, protocolerrors.Errorf(true, "wrong network")
	}

	minAcceptableProtocolVersion, err := minAcceptableProtocolVersionFor(flow.HandleHandshakeContext)
	if err != nil {
		return nil, err
	}

	// Notify and disconnect clients that have a protocol version that is
	// too old.
	//
	// NOTE: If minAcceptableProtocolVersion is raised to be higher than
	// appmessage.RejectVersion, this should send a reject packet before
	// disconnecting.
	if msgVersion.ProtocolVersion < minAcceptableProtocolVersion {
		return nil, protocolerrors.Errorf(false, "protocol version must be %d or greater",
			minAcceptableProtocolVersion)
	}
	hardforkActive := minAcceptableProtocolVersion >= hardforkProtocolVersion
	if hardforkActive && !msgVersion.HasService(appmessage.SFNodeStrongNodeClaims) {
		return nil, protocolerrors.New(false, "peer missing mandatory strong-node-claims service bit after hardfork")
	}
	peerUnifiedNodeID, peerUnifiedNodePubKeyXOnly, err := validatePeerUnifiedNodeIdentity(flow.Config().ActiveNetParams.Name, msgVersion, hardforkActive)
	if err != nil {
		return nil, protocolerrors.Wrapf(false, err, "invalid unified node identity")
	}
	peerQuantumHandshakePubKey, err := validatePeerQuantumHandshakePubKey(msgVersion, hardforkActive)
	if err != nil {
		return nil, protocolerrors.Wrapf(false, err, "invalid quantum-safe handshake key")
	}

	// Disconnect from partial nodes in networks that don't allow them
	if !flow.Config().ActiveNetParams.EnableNonNativeSubnetworks && msgVersion.SubnetworkID != nil {
		return nil, protocolerrors.New(true, "partial nodes are not allowed")
	}

	// Disconnect if:
	// - we are a full node and the outbound connection we've initiated is a partial node
	// - the remote node is partial and our subnetwork doesn't match their subnetwork
	localSubnetworkID := flow.Config().SubnetworkID
	isLocalNodeFull := localSubnetworkID == nil
	isRemoteNodeFull := msgVersion.SubnetworkID == nil
	isOutbound := flow.peer.Connection().IsOutbound()
	if (isLocalNodeFull && !isRemoteNodeFull && isOutbound) ||
		(!isLocalNodeFull && !isRemoteNodeFull && !msgVersion.SubnetworkID.Equal(localSubnetworkID)) {

		return nil, protocolerrors.New(false, "incompatible subnetworks")
	}

	if flow.Config().ProtocolVersion > maxAcceptableProtocolVersion() {
		return nil, errors.Errorf("%d is a non existing protocol version", flow.Config().ProtocolVersion)
	}
	if flow.Config().ProtocolVersion < minAcceptableProtocolVersion {
		return nil, errors.Errorf("configured protocol version %d is obsolete (minimum required: %d)",
			flow.Config().ProtocolVersion, minAcceptableProtocolVersion)
	}

	maxProtocolVersion := flow.Config().ProtocolVersion
	flow.peer.UpdateFieldsFromMsgVersion(msgVersion, maxProtocolVersion)
	err = flow.outgoingRoute.Enqueue(appmessage.NewMsgVerAck())
	if err != nil {
		return nil, err
	}

	flow.peer.Connection().SetID(msgVersion.ID)
	if peerUnifiedNodeID != nil {
		flow.peer.Connection().SetUnifiedNodeID(*peerUnifiedNodeID)
	}
	if peerUnifiedNodePubKeyXOnly != nil {
		flow.peer.Connection().SetUnifiedNodePubKeyXOnly(*peerUnifiedNodePubKeyXOnly)
	}
	if msgVersion.NodeChallengeNonce != nil {
		flow.peer.Connection().SetRemoteNodeChallengeNonce(*msgVersion.NodeChallengeNonce)
	}
	if len(peerQuantumHandshakePubKey) > 0 {
		flow.peer.Connection().SetRemotePQMLKEM1024PublicKey(peerQuantumHandshakePubKey)
	}

	return msgVersion.Address, nil
}

func validatePeerUnifiedNodeIdentity(networkName string, msgVersion *appmessage.MsgVersion, required bool) (*[32]byte, *[32]byte, error) {
	if len(msgVersion.NodePubkeyXOnly) == 0 && msgVersion.NodePowNonce == nil {
		if required {
			return nil, nil, errors.New("missing nodePubkeyXonly/nodePowNonce")
		}
		if msgVersion.NodeChallengeNonce != nil {
			return nil, nil, errors.New("nodeChallengeNonce provided without unified node identity")
		}
		return nil, nil, nil
	}

	if len(msgVersion.NodePubkeyXOnly) != 32 || msgVersion.NodePowNonce == nil {
		return nil, nil, errors.New("node identity fields are incomplete")
	}
	if required && msgVersion.NodeChallengeNonce == nil {
		return nil, nil, errors.New("missing nodeChallengeNonce")
	}

	networkCode, err := netadapter.UnifiedNodeNetworkCodeFromName(networkName)
	if err != nil {
		return nil, nil, err
	}
	var pubKeyXOnly [32]byte
	copy(pubKeyXOnly[:], msgVersion.NodePubkeyXOnly)
	if !netadapter.IsValidUnifiedNodePoWNonce(networkCode, pubKeyXOnly, *msgVersion.NodePowNonce) {
		return nil, nil, errors.New("node identity proof-of-work is invalid")
	}
	nodeID := netadapter.ComputeUnifiedNodeID(pubKeyXOnly)
	return &nodeID, &pubKeyXOnly, nil
}

func validatePeerQuantumHandshakePubKey(msgVersion *appmessage.MsgVersion, required bool) ([]byte, error) {
	if len(msgVersion.PQMLKEM1024PubKey) == 0 {
		if required {
			return nil, errors.New("missing pqMlKem1024Pubkey")
		}
		return nil, nil
	}
	if len(msgVersion.PQMLKEM1024PubKey) != netadapter.QuantumHandshakeMLKEM1024PublicKeySize {
		return nil, errors.Errorf(
			"pqMlKem1024Pubkey length must be %d",
			netadapter.QuantumHandshakeMLKEM1024PublicKeySize,
		)
	}
	return append([]byte(nil), msgVersion.PQMLKEM1024PubKey...), nil
}

func isCompatiblePeerNetwork(localNetwork, remoteNetwork string) bool {
	return localNetwork == remoteNetwork
}
