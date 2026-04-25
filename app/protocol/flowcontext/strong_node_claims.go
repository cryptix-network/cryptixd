package flowcontext

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	peerpkg "github.com/cryptix-network/cryptixd/app/protocol/peer"
	"github.com/cryptix-network/cryptixd/app/protocol/protocolerrors"
	"github.com/cryptix-network/cryptixd/app/protocol/strongnodeclaims"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter"
	"time"
)

const (
	blockProducerClaimWaitTimeout  = 3 * time.Second
	blockProducerClaimWaitInterval = 50 * time.Millisecond
)

func (f *FlowContext) isStrongNodeClaimsP2PEnabled() bool {
	return f.strongNodeClaims != nil && f.strongNodeClaims.ShouldAdvertiseServiceBit(f.IsPayloadHfActive())
}

func (f *FlowContext) HasValidBlockProducerClaim(blockHash *externalapi.DomainHash) bool {
	if !f.isStrongNodeClaimsP2PEnabled() || blockHash == nil {
		return true
	}
	key := *blockHash.ByteArray()
	for _, nodeID := range f.strongNodeClaims.ClaimNodeIDsForBlock(key) {
		if !f.ConnectionManager().IsUnifiedNodeIDBanned(nodeID) {
			return true
		}
	}
	return false
}

func (f *FlowContext) WaitForValidBlockProducerClaim(blockHash *externalapi.DomainHash) bool {
	if !f.isStrongNodeClaimsP2PEnabled() || blockHash == nil {
		return true
	}
	deadline := time.Now().Add(blockProducerClaimWaitTimeout)
	for {
		if f.HasValidBlockProducerClaim(blockHash) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(blockProducerClaimWaitInterval)
	}
}

func (f *FlowContext) BlockProducerClaimsForBlock(blockHash *externalapi.DomainHash) []*appmessage.MsgBlockProducerClaimV1 {
	if !f.isStrongNodeClaimsP2PEnabled() || blockHash == nil {
		return nil
	}
	key := *blockHash.ByteArray()
	claims := f.strongNodeClaims.ClaimMessagesForBlock(key)
	filtered := make([]*appmessage.MsgBlockProducerClaimV1, 0, len(claims))
	for _, claim := range claims {
		if claim == nil || len(claim.NodePubkeyXOnly) != 32 {
			continue
		}
		var pubKey [32]byte
		copy(pubKey[:], claim.NodePubkeyXOnly)
		nodeID := netadapter.ComputeUnifiedNodeID(pubKey)
		if f.ConnectionManager().IsUnifiedNodeIDBanned(nodeID) {
			continue
		}
		filtered = append(filtered, claim)
	}
	return filtered
}

func (f *FlowContext) BroadcastBlockProducerClaimsForBlock(blockHash *externalapi.DomainHash) error {
	for _, claim := range f.BlockProducerClaimsForBlock(blockHash) {
		if err := f.broadcastBlockProducerClaim(claim, nil); err != nil {
			return err
		}
	}
	return nil
}

// HandleBlockProducerClaim validates, ingests and relays claimant messages.
func (f *FlowContext) HandleBlockProducerClaim(peer *peerpkg.Peer, message *appmessage.MsgBlockProducerClaimV1) error {
	if f.strongNodeClaims == nil || !f.strongNodeClaims.Enabled() {
		return nil
	}
	if err := f.refreshStrongNodeClaimsWindow(); err != nil {
		log.Warnf("failed refreshing strong-node claim window before ingest: %s", err)
	}

	known := false
	if len(message.BlockHash) == 32 {
		if blockHash, err := externalapi.NewDomainHashFromByteSlice(message.BlockHash); err == nil {
			if blockInfo, infoErr := f.Domain().Consensus().GetBlockInfo(blockHash); infoErr == nil {
				known = blockInfo.Exists
			}
		}
	}

	outcome := f.strongNodeClaims.IngestClaim(message, f.IsPayloadHfActive(), known)
	switch outcome.Status {
	case strongnodeclaims.IngestIgnored, strongnodeclaims.IngestDropped:
		return nil
	case strongnodeclaims.IngestAccepted:
		f.strongNodeClaims.MaybeFlush()
		return f.broadcastBlockProducerClaim(message, peer)
	case strongnodeclaims.IngestStrike:
		if outcome.NodeID != nil && f.ConnectionManager().IsUnifiedNodeIDBanned(*outcome.NodeID) {
			return protocolerrors.New(true, "claim references externally banned unified node ID")
		}
		return protocolerrors.Errorf(true, "invalid block producer claim: %s", outcome.Reason)
	default:
		return nil
	}
}

func (f *FlowContext) broadcastBlockProducerClaim(message *appmessage.MsgBlockProducerClaimV1, sourcePeer *peerpkg.Peer) error {
	if message == nil || !f.isStrongNodeClaimsP2PEnabled() {
		return nil
	}

	targets := make([]*netadapter.NetConnection, 0, len(f.Peers()))
	peers := f.Peers()
	for _, peer := range peers {
		if peer == nil || peer.AntiFraudRestricted() {
			continue
		}
		if sourcePeer != nil && peer.ID().IsEqual(sourcePeer.ID()) {
			continue
		}
		if peer.Services()&appmessage.SFNodeStrongNodeClaims == 0 {
			continue
		}
		targets = append(targets, peer.Connection())
	}
	if len(targets) == 0 {
		return nil
	}
	return f.NetAdapter().P2PBroadcast(targets, message)
}

// BroadcastLocalBlockProducerClaim signs, ingests and relays the local claimant for a locally submitted block.
func (f *FlowContext) BroadcastLocalBlockProducerClaim(blockHash *externalapi.DomainHash) {
	if !f.isStrongNodeClaimsP2PEnabled() || blockHash == nil {
		return
	}
	claim, err := f.NetAdapter().BuildBlockProducerClaim(f.Config().ActiveNetParams.Name, blockHash)
	if err != nil {
		log.Warnf("failed building local block producer claim for %s: %s", blockHash, err)
		return
	}
	outcome := f.strongNodeClaims.IngestClaim(claim, f.IsPayloadHfActive(), true)
	if outcome.Status == strongnodeclaims.IngestStrike {
		log.Warnf("failed ingesting local block producer claim for %s: %s", blockHash, outcome.Reason)
		return
	}
	f.strongNodeClaims.MaybeFlush()
	if err := f.broadcastBlockProducerClaim(claim, nil); err != nil {
		log.Debugf("failed relaying local block producer claim for %s: %s", blockHash, err)
	}
}

func (f *FlowContext) refreshStrongNodeClaimsWindow() error {
	if f.strongNodeClaims == nil || !f.strongNodeClaims.Enabled() {
		return nil
	}
	consensus := f.Domain().Consensus()
	sink, err := consensus.GetVirtualSelectedParent()
	if err != nil {
		return err
	}

	previousSink, hasPrevious := f.strongNodeClaims.LastSink()
	switch {
	case !hasPrevious:
		f.strongNodeClaims.ApplyChainPathUpdate(
			&externalapi.SelectedChainPath{Added: []*externalapi.DomainHash{sink}},
			sink,
			f.IsPayloadHfActive(),
		)
	case !sink.Equal(previousSink):
		chainPath, pathErr := consensus.GetVirtualSelectedParentChainFromBlock(previousSink)
		if pathErr != nil {
			return pathErr
		}
		f.strongNodeClaims.ApplyChainPathUpdate(chainPath, sink, f.IsPayloadHfActive())
	}

	f.strongNodeClaims.MaybeFlush()
	return nil
}
