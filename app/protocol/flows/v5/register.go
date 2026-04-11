package v5

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/app/protocol/common"
	"github.com/cryptix-network/cryptixd/app/protocol/flowcontext"
	"github.com/cryptix-network/cryptixd/app/protocol/flows/v5/addressexchange"
	"github.com/cryptix-network/cryptixd/app/protocol/flows/v5/antifraud"
	"github.com/cryptix-network/cryptixd/app/protocol/flows/v5/blockrelay"
	"github.com/cryptix-network/cryptixd/app/protocol/flows/v5/hfa"
	"github.com/cryptix-network/cryptixd/app/protocol/flows/v5/ping"
	"github.com/cryptix-network/cryptixd/app/protocol/flows/v5/rejects"
	"github.com/cryptix-network/cryptixd/app/protocol/flows/v5/strongnodeclaims"
	"github.com/cryptix-network/cryptixd/app/protocol/flows/v5/transactionrelay"
	peerpkg "github.com/cryptix-network/cryptixd/app/protocol/peer"
	routerpkg "github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
)

type protocolManager interface {
	RegisterFlow(name string, router *routerpkg.Router, messageTypes []appmessage.MessageCommand, isStopping *uint32,
		errChan chan error, initializeFunc common.FlowInitializeFunc) *common.Flow
	RegisterOneTimeFlow(name string, router *routerpkg.Router, messageTypes []appmessage.MessageCommand,
		isStopping *uint32, stopChan chan error, initializeFunc common.FlowInitializeFunc) *common.Flow
	RegisterFlowWithCapacity(name string, capacity int, router *routerpkg.Router,
		messageTypes []appmessage.MessageCommand, isStopping *uint32,
		errChan chan error, initializeFunc common.FlowInitializeFunc) *common.Flow
	Context() *flowcontext.FlowContext
}

// Register is used in order to register all the protocol flows to the given router.
func Register(m protocolManager, router *routerpkg.Router, errChan chan error, isStopping *uint32) (flows []*common.Flow) {
	flows = registerAddressFlows(m, router, isStopping, errChan)
	flows = append(flows, registerBlockRelayFlows(m, router, isStopping, errChan)...)
	flows = append(flows, registerPingFlows(m, router, isStopping, errChan)...)
	flows = append(flows, registerTransactionRelayFlow(m, router, isStopping, errChan)...)
	flows = append(flows, registerHFACompatibilityFlows(m, router, isStopping, errChan)...)
	flows = append(flows, registerRejectsFlow(m, router, isStopping, errChan)...)
	flows = append(flows, registerAntiFraudFlows(m, router, isStopping, errChan)...)
	flows = append(flows, registerStrongNodeFlows(m, router, isStopping, errChan)...)

	return flows
}

// RegisterRestricted registers only RESTRICTED_AF-allowed flows.
func RegisterRestricted(m protocolManager, router *routerpkg.Router, errChan chan error, isStopping *uint32) (flows []*common.Flow) {
	flows = registerPingFlows(m, router, isStopping, errChan)
	flows = append(flows, registerHFACompatibilityFlows(m, router, isStopping, errChan)...)
	flows = append(flows, registerAntiFraudFlows(m, router, isStopping, errChan)...)
	return flows
}

func registerAddressFlows(m protocolManager, router *routerpkg.Router, isStopping *uint32, errChan chan error) []*common.Flow {
	outgoingRoute := router.OutgoingRoute()

	return []*common.Flow{
		m.RegisterFlow("SendAddresses", router, []appmessage.MessageCommand{appmessage.CmdRequestAddresses}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return addressexchange.SendAddresses(m.Context(), incomingRoute, outgoingRoute)
			},
		),

		m.RegisterOneTimeFlow("ReceiveAddresses", router, []appmessage.MessageCommand{appmessage.CmdAddresses}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return addressexchange.ReceiveAddresses(m.Context(), incomingRoute, outgoingRoute, peer)
			},
		),
	}
}

func registerBlockRelayFlows(m protocolManager, router *routerpkg.Router, isStopping *uint32, errChan chan error) []*common.Flow {
	outgoingRoute := router.OutgoingRoute()

	return []*common.Flow{
		m.RegisterOneTimeFlow("SendVirtualSelectedParentInv", router, []appmessage.MessageCommand{},
			isStopping, errChan, func(route *routerpkg.Route, peer *peerpkg.Peer) error {
				return blockrelay.SendVirtualSelectedParentInv(m.Context(), outgoingRoute, peer)
			}),

		m.RegisterFlow("HandleRelayInvs", router, []appmessage.MessageCommand{
			appmessage.CmdInvRelayBlock, appmessage.CmdBlock, appmessage.CmdBlockLocator,
		},
			isStopping, errChan, func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return blockrelay.HandleRelayInvs(m.Context(), incomingRoute,
					outgoingRoute, peer)
			},
		),

		m.RegisterFlow("HandleIBD", router, []appmessage.MessageCommand{
			appmessage.CmdDoneHeaders, appmessage.CmdUnexpectedPruningPoint, appmessage.CmdPruningPointUTXOSetChunk,
			appmessage.CmdBlockHeaders, appmessage.CmdIBDBlockLocatorHighestHash, appmessage.CmdBlockWithTrustedDataV4,
			appmessage.CmdDoneBlocksWithTrustedData, appmessage.CmdIBDBlockLocatorHighestHashNotFound,
			appmessage.CmdDonePruningPointUTXOSetChunks, appmessage.CmdIBDBlock, appmessage.CmdPruningPoints,
			appmessage.CmdPruningPointProof,
			appmessage.CmdTrustedData,
			appmessage.CmdIBDChainBlockLocator,
		},
			isStopping, errChan, func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return blockrelay.HandleIBD(m.Context(), incomingRoute,
					outgoingRoute, peer)
			},
		),

		m.RegisterFlow("HandleRelayBlockRequests", router, []appmessage.MessageCommand{appmessage.CmdRequestRelayBlocks}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return blockrelay.HandleRelayBlockRequests(m.Context(), incomingRoute, outgoingRoute, peer)
			},
		),

		m.RegisterFlow("HandleRequestBlockLocator", router,
			[]appmessage.MessageCommand{appmessage.CmdRequestBlockLocator}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return blockrelay.HandleRequestBlockLocator(m.Context(), incomingRoute, outgoingRoute)
			},
		),

		m.RegisterFlow("HandleRequestHeaders", router,
			[]appmessage.MessageCommand{appmessage.CmdRequestHeaders, appmessage.CmdRequestNextHeaders}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return blockrelay.HandleRequestHeaders(m.Context(), incomingRoute, outgoingRoute, peer)
			},
		),

		m.RegisterFlow("HandleIBDBlockRequests", router,
			[]appmessage.MessageCommand{appmessage.CmdRequestIBDBlocks}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return blockrelay.HandleIBDBlockRequests(m.Context(), incomingRoute, outgoingRoute)
			},
		),

		m.RegisterFlow("HandleRequestPruningPointUTXOSet", router,
			[]appmessage.MessageCommand{appmessage.CmdRequestPruningPointUTXOSet,
				appmessage.CmdRequestNextPruningPointUTXOSetChunk}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return blockrelay.HandleRequestPruningPointUTXOSet(m.Context(), incomingRoute, outgoingRoute)
			},
		),

		m.RegisterFlow("HandlePruningPointAndItsAnticoneRequests", router,
			[]appmessage.MessageCommand{appmessage.CmdRequestPruningPointAndItsAnticone, appmessage.CmdRequestNextPruningPointAndItsAnticoneBlocks}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return blockrelay.HandlePruningPointAndItsAnticoneRequests(m.Context(), incomingRoute, outgoingRoute, peer)
			},
		),

		m.RegisterFlow("HandleIBDBlockLocator", router,
			[]appmessage.MessageCommand{appmessage.CmdIBDBlockLocator}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return blockrelay.HandleIBDBlockLocator(m.Context(), incomingRoute, outgoingRoute, peer)
			},
		),

		m.RegisterFlow("HandleRequestIBDChainBlockLocator", router,
			[]appmessage.MessageCommand{appmessage.CmdRequestIBDChainBlockLocator}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return blockrelay.HandleRequestIBDChainBlockLocator(m.Context(), incomingRoute, outgoingRoute)
			},
		),

		m.RegisterFlow("HandleRequestAnticone", router,
			[]appmessage.MessageCommand{appmessage.CmdRequestAnticone}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return blockrelay.HandleRequestAnticone(m.Context(), incomingRoute, outgoingRoute, peer)
			},
		),

		m.RegisterFlow("HandlePruningPointProofRequests", router,
			[]appmessage.MessageCommand{appmessage.CmdRequestPruningPointProof}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return blockrelay.HandlePruningPointProofRequests(m.Context(), incomingRoute, outgoingRoute, peer)
			},
		),
	}
}

func registerPingFlows(m protocolManager, router *routerpkg.Router, isStopping *uint32, errChan chan error) []*common.Flow {
	outgoingRoute := router.OutgoingRoute()

	return []*common.Flow{
		m.RegisterFlow("ReceivePings", router, []appmessage.MessageCommand{appmessage.CmdPing}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return ping.ReceivePings(m.Context(), incomingRoute, outgoingRoute)
			},
		),

		m.RegisterFlow("SendPings", router, []appmessage.MessageCommand{appmessage.CmdPong}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return ping.SendPings(m.Context(), incomingRoute, outgoingRoute, peer)
			},
		),
	}
}

func registerTransactionRelayFlow(m protocolManager, router *routerpkg.Router, isStopping *uint32, errChan chan error) []*common.Flow {
	outgoingRoute := router.OutgoingRoute()

	return []*common.Flow{
		m.RegisterFlowWithCapacity("HandleRelayedTransactions", 10_000, router,
			[]appmessage.MessageCommand{appmessage.CmdInvTransaction, appmessage.CmdTx, appmessage.CmdTransactionNotFound}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return transactionrelay.HandleRelayedTransactions(m.Context(), incomingRoute, outgoingRoute)
			},
		),
		m.RegisterFlow("HandleRequestTransactions", router,
			[]appmessage.MessageCommand{appmessage.CmdRequestTransactions}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return transactionrelay.HandleRequestedTransactions(m.Context(), incomingRoute, outgoingRoute)
			},
		),
	}
}

func registerHFACompatibilityFlows(m protocolManager, router *routerpkg.Router, isStopping *uint32, errChan chan error) []*common.Flow {
	return []*common.Flow{
		m.RegisterFlowWithCapacity("IgnoreHFAPayloads", 4096, router,
			[]appmessage.MessageCommand{
				appmessage.CmdRequestFastIntents,
				appmessage.CmdFastIntent,
				appmessage.CmdFastMicroblock,
			},
			isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return hfa.IgnoreMessages(incomingRoute)
			},
		),
	}
}

func registerRejectsFlow(m protocolManager, router *routerpkg.Router, isStopping *uint32, errChan chan error) []*common.Flow {
	outgoingRoute := router.OutgoingRoute()

	return []*common.Flow{
		m.RegisterFlow("HandleRejects", router,
			[]appmessage.MessageCommand{appmessage.CmdReject}, isStopping, errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return rejects.HandleRejects(m.Context(), incomingRoute, outgoingRoute)
			},
		),
	}
}

func registerStrongNodeFlows(m protocolManager, router *routerpkg.Router, isStopping *uint32, errChan chan error) []*common.Flow {
	flows := make([]*common.Flow, 0, 1)
	flows = append(flows, m.RegisterFlowWithCapacity("HandleBlockProducerClaims", 2048, router,
		[]appmessage.MessageCommand{appmessage.CmdBlockProducerClaimV1},
		isStopping,
		errChan,
		func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
			return strongnodeclaims.HandleBlockProducerClaims(m.Context(), incomingRoute, peer)
		},
	))
	return flows
}

func registerAntiFraudFlows(m protocolManager, router *routerpkg.Router, isStopping *uint32, errChan chan error) []*common.Flow {
	outgoingRoute := router.OutgoingRoute()

	return []*common.Flow{
		m.RegisterFlow("HandleAntiFraudSnapshotRequests", router,
			[]appmessage.MessageCommand{appmessage.CmdRequestAntiFraudSnapshotV1},
			isStopping,
			errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return antifraud.HandleSnapshotRequests(m.Context(), incomingRoute, outgoingRoute)
			},
		),
		m.RegisterFlow("SyncAntiFraudSnapshots", router,
			[]appmessage.MessageCommand{appmessage.CmdAntiFraudSnapshotV1},
			isStopping,
			errChan,
			func(incomingRoute *routerpkg.Route, peer *peerpkg.Peer) error {
				return antifraud.SyncSnapshots(m.Context(), incomingRoute, outgoingRoute, peer)
			},
		),
	}
}
