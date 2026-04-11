package hfa

import (
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
)

// IgnoreMessages drains unsupported HFA gossip payloads so peers are not disconnected
// when they send valid-but-not-yet-implemented messages.
func IgnoreMessages(incomingRoute *router.Route) error {
	for {
		_, err := incomingRoute.Dequeue()
		if err != nil {
			return err
		}
	}
}
