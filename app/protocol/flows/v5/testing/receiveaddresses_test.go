package testing

import (
	"github.com/cryptix-network/cryptixd/app/protocol/flows/v5/addressexchange"
	"testing"
	"time"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	peerpkg "github.com/cryptix-network/cryptixd/app/protocol/peer"
	"github.com/cryptix-network/cryptixd/domain/consensus"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/testutils"
	"github.com/cryptix-network/cryptixd/infrastructure/network/addressmanager"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
)

type fakeReceiveAddressesContext struct{}

func (f fakeReceiveAddressesContext) AddressManager() *addressmanager.AddressManager {
	return nil
}

func (f fakeReceiveAddressesContext) IsPayloadHfActive() bool {
	return false
}

func (f fakeReceiveAddressesContext) IsAntiFraudRuntimeEnabled() bool {
	return false
}

type fakeReceiveAddressesHFContext struct{}

func (f fakeReceiveAddressesHFContext) AddressManager() *addressmanager.AddressManager {
	return nil
}

func (f fakeReceiveAddressesHFContext) IsPayloadHfActive() bool {
	return true
}

func (f fakeReceiveAddressesHFContext) IsAntiFraudRuntimeEnabled() bool {
	return true
}

func TestReceiveAddressesErrors(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		incomingRoute := router.NewRoute("incoming")
		outgoingRoute := router.NewRoute("outgoing")
		peer := peerpkg.New(nil)
		errChan := make(chan error)
		go func() {
			errChan <- addressexchange.ReceiveAddresses(fakeReceiveAddressesContext{}, incomingRoute, outgoingRoute, peer)
		}()

		_, err := outgoingRoute.DequeueWithTimeout(time.Second)
		if err != nil {
			t.Fatalf("DequeueWithTimeout: %+v", err)
		}

		// Sending addressmanager.GetAddressesMax+1 addresses should trigger a ban
		err = incomingRoute.Enqueue(appmessage.NewMsgAddresses(make([]*appmessage.NetAddress,
			addressmanager.GetAddressesMax+1)))
		if err != nil {
			t.Fatalf("Enqueue: %+v", err)
		}

		select {
		case err := <-errChan:
			checkFlowError(t, err, true, true, "address count exceeded")
		case <-time.After(time.Second):
			t.Fatalf("timed out after %s", time.Second)
		}
	})
}

func TestReceiveAddressesRejectsMissingUnifiedNodeIDAfterHF(t *testing.T) {
	incomingRoute := router.NewRoute("incoming")
	outgoingRoute := router.NewRoute("outgoing")
	peer := peerpkg.New(nil)

	err := addressexchange.ReceiveAddresses(fakeReceiveAddressesHFContext{}, incomingRoute, outgoingRoute, peer)
	checkFlowError(t, err, true, true, "without verified unified node ID after hardfork")
}
