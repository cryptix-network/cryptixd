package addressexchange

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/app/protocol/common"
	peerpkg "github.com/cryptix-network/cryptixd/app/protocol/peer"
	"github.com/cryptix-network/cryptixd/app/protocol/protocolerrors"
	"github.com/cryptix-network/cryptixd/infrastructure/network/addressmanager"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
)

// ReceiveAddressesContext is the interface for the context needed for the ReceiveAddresses flow.
type ReceiveAddressesContext interface {
	AddressManager() *addressmanager.AddressManager
	IsPayloadHfActive() bool
	IsAntiFraudRuntimeEnabled() bool
}

const maxUniqueAddressesAccepted = 1024

// ReceiveAddresses asks a peer for more addresses if needed.
func ReceiveAddresses(context ReceiveAddressesContext, incomingRoute *router.Route, outgoingRoute *router.Route,
	peer *peerpkg.Peer) error {
	enforceAntiFraud := context.IsPayloadHfActive() && context.IsAntiFraudRuntimeEnabled()
	if enforceAntiFraud && peer.UnifiedNodeID() == nil {
		return protocolerrors.Errorf(true, "received addresses from peer without verified unified node ID after hardfork")
	}

	subnetworkID := peer.SubnetworkID()
	msgGetAddresses := appmessage.NewMsgRequestAddresses(false, subnetworkID)
	err := outgoingRoute.Enqueue(msgGetAddresses)
	if err != nil {
		return err
	}

	message, err := incomingRoute.DequeueWithTimeout(common.DefaultTimeout)
	if err != nil {
		return err
	}

	msgAddresses := message.(*appmessage.MsgAddresses)
	if len(msgAddresses.AddressList) > addressmanager.GetAddressesMax {
		return protocolerrors.Errorf(true, "address count exceeded %d", addressmanager.GetAddressesMax)
	}
	unique := make(map[string]*appmessage.NetAddress, len(msgAddresses.AddressList))
	for _, addr := range msgAddresses.AddressList {
		if addr == nil {
			continue
		}
		key := addr.TCPAddress().String()
		if _, exists := unique[key]; exists {
			continue
		}
		unique[key] = addr
		if len(unique) > maxUniqueAddressesAccepted {
			return protocolerrors.Errorf(true, "unique address count exceeded %d", maxUniqueAddressesAccepted)
		}
	}
	deduped := make([]*appmessage.NetAddress, 0, len(unique))
	for _, addr := range unique {
		deduped = append(deduped, addr)
	}
	return context.AddressManager().AddAddresses(deduped...)
}
