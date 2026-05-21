package blockrelay

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"sort"
	"sync/atomic"
	"time"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	peerpkg "github.com/cryptix-network/cryptixd/app/protocol/peer"
	"github.com/cryptix-network/cryptixd/domain"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/infrastructure/config"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
	"github.com/pkg/errors"
)

const (
	atomicP2PAuditInitialDelay = 10 * time.Second
	atomicP2PAuditInterval     = 60 * time.Second
	atomicP2PAuditTimeout      = 15 * time.Second
	atomicP2PAuditDeferredLog  = 5 * time.Minute
	atomicP2PAuditDAALag       = uint64(60)
	atomicP2PAuditMaxWalk      = 512
	atomicP2PAuditMinSample    = 4
	atomicP2PAuditMaxSample    = 12
)

var atomicP2PAuditPolicyLogged uint32
var atomicP2PAuditDeferredLogUnixNano int64

type AtomicStateAuditContext interface {
	Domain() domain.Domain
	Config() *config.Config
	IsIBDRunning() bool
	IsPayloadHfActive() bool
	Peers() []*peerpkg.Peer
	ShutdownChan() <-chan struct{}
}

type atomicStateAuditFlow struct {
	AtomicStateAuditContext
	incomingRoute *router.Route
	outgoingRoute *router.Route
	peer          *peerpkg.Peer
	nextRequestID uint32
}

type atomicAuditAnchor struct {
	blockHash *externalapi.DomainHash
	daaScore  uint64
	stateHash [externalapi.DomainHashSize]byte
}

type scoredAuditPeer struct {
	peer  *peerpkg.Peer
	score uint64
}

// AuditAtomicState actively checks a small deterministic P2P peer sample against
// the local canonical Atomic state hash. It uses only P2P messages; RPC is not
// required for this audit path.
func AuditAtomicState(context AtomicStateAuditContext, incomingRoute *router.Route,
	outgoingRoute *router.Route, peer *peerpkg.Peer) error {

	flow := &atomicStateAuditFlow{
		AtomicStateAuditContext: context,
		incomingRoute:           incomingRoute,
		outgoingRoute:           outgoingRoute,
		peer:                    peer,
		nextRequestID:           1,
	}
	return flow.start()
}

func (flow *atomicStateAuditFlow) start() error {
	flow.logPolicyOnce()

	timer := time.NewTimer(atomicP2PAuditInitialDelay)
	defer timer.Stop()

	for {
		select {
		case <-flow.ShutdownChan():
			return nil
		case <-timer.C:
			if flow.auditEnabled() {
				if err := flow.runAudit(); err != nil {
					return err
				}
			}
			timer.Reset(atomicP2PAuditInterval)
		}
	}
}

func (flow *atomicStateAuditFlow) logPolicyOnce() {
	if !atomic.CompareAndSwapUint32(&atomicP2PAuditPolicyLogged, 0, 1) {
		return
	}

	cfg := flow.Config()
	switch {
	case cfg.DisableDNSSeed && cfg.AtomicBootstrapAllowPeerFallback:
		log.Infof("[atomic-bootstrap:p2p] Go Atomic audit enabled: peer-only P2P fallback, min_sources=%d, interval=%s, RPC not required",
			flow.minSources(), atomicP2PAuditInterval)
	case cfg.DisableDNSSeed:
		log.Infof("[atomic-bootstrap:p2p] Go Atomic audit disabled: --nodnsseed was used without --atomic-bootstrap-allow-peer-fallback")
	default:
		log.Infof("[atomic-bootstrap:p2p] Go Atomic audit enabled: seed-connected peer mode, min_sources=%d, interval=%s, RPC not required",
			flow.minSources(), atomicP2PAuditInterval)
	}
}

func (flow *atomicStateAuditFlow) auditEnabled() bool {
	cfg := flow.Config()
	return !cfg.DisableDNSSeed || cfg.AtomicBootstrapAllowPeerFallback
}

func (flow *atomicStateAuditFlow) runAudit() error {
	activePeers := flow.Peers()
	minSources := flow.minSources()
	if len(activePeers) < minSources {
		if flow.isFirstPeer(activePeers) {
			log.Infof("[atomic-bootstrap:p2p] healthy-state audit skipped: active peer sources %d/%d",
				len(activePeers), minSources)
		}
		return nil
	}

	anchor, reason, err := flow.currentAnchor()
	if err != nil {
		log.Infof("[atomic-bootstrap:p2p] healthy-state audit skipped: %s", err)
		return nil
	}
	if anchor == nil {
		if flow.isFirstPeer(activePeers) && shouldLogAtomicP2PAuditDeferred() {
			log.Infof("[atomic-bootstrap:p2p] healthy-state audit deferred: %s", reason)
		}
		return nil
	}

	sampleLimit := flow.sampleLimit(minSources)
	if !flow.isSelectedPeer(activePeers, anchor.blockHash, sampleLimit) {
		return nil
	}

	response, err := flow.requestAtomicTokenStateHash(anchor)
	if errors.Is(err, router.ErrTimeout) {
		log.Infof("[atomic-bootstrap:p2p] healthy-state audit skipped at DAA-rendezvous block %s (daa=%d): peer %s did not respond within %s",
			anchor.blockHash, anchor.daaScore, flow.peer, atomicP2PAuditTimeout)
		return nil
	}
	if err != nil {
		return err
	}

	if !response.BlockHash.Equal(anchor.blockHash) || response.AnchorDAAScore != anchor.daaScore {
		log.Infof("[atomic-bootstrap:p2p] healthy-state audit skipped: peer %s answered for different anchor block=%s daa=%d",
			flow.peer, response.BlockHash, response.AnchorDAAScore)
		return nil
	}
	if !response.HasState {
		log.Infof("[atomic-bootstrap:p2p] healthy-state audit skipped at DAA-rendezvous block %s (daa=%d): peer %s has no Atomic state for this anchor yet",
			anchor.blockHash, anchor.daaScore, flow.peer)
		return nil
	}
	if len(response.StateHash) != externalapi.DomainHashSize {
		log.Warnf("[atomic-bootstrap:p2p] healthy-state audit rejected peer %s at DAA-rendezvous block %s (daa=%d): invalid state hash size %d",
			flow.peer, anchor.blockHash, anchor.daaScore, len(response.StateHash))
		return nil
	}

	localHash := anchor.stateHash[:]
	if !bytes.Equal(localHash, response.StateHash) {
		log.Warnf("[atomic-bootstrap:p2p] healthy-state audit mismatch at DAA-rendezvous block %s (daa=%d) with peer %s: local state hash %s differs from peer state hash %s",
			anchor.blockHash, anchor.daaScore, flow.peer, hex.EncodeToString(localHash), hex.EncodeToString(response.StateHash))
		return nil
	}

	log.Infof("[atomic-bootstrap:p2p] healthy-state audit passed at DAA-rendezvous block %s (daa=%d) with peer %s: state hash %s",
		anchor.blockHash, anchor.daaScore, flow.peer, hex.EncodeToString(localHash))
	return nil
}

func (flow *atomicStateAuditFlow) currentAnchor() (*atomicAuditAnchor, string, error) {
	if !flow.IsPayloadHfActive() {
		return nil, "payload hardfork is not active yet", nil
	}
	if flow.IsIBDRunning() {
		return nil, "P2P IBD is running", nil
	}

	consensus := flow.Domain().Consensus()
	sinkHash, err := consensus.GetVirtualSelectedParent()
	if err != nil {
		return nil, "", err
	}
	finalityHash, err := consensus.GetVirtualFinalityPoint()
	if err != nil {
		return nil, "", err
	}

	targetDAA := uint64(0)
	finalityHeader, err := consensus.GetBlockHeader(finalityHash)
	if err != nil {
		return nil, "", err
	}
	sinkHeader, err := consensus.GetBlockHeader(sinkHash)
	if err != nil {
		return nil, "", err
	}
	finalityDepth := flow.Config().ActiveNetParams.FinalityDepth()
	if sinkHeader.BlueScore() < finalityHeader.BlueScore() {
		return nil, fmt.Sprintf("virtual finality point is ahead of the selected sink: sink_blue_score=%d finality_blue_score=%d",
			sinkHeader.BlueScore(), finalityHeader.BlueScore()), nil
	}
	finalityDistance := sinkHeader.BlueScore() - finalityHeader.BlueScore()
	if finalityDistance < finalityDepth {
		return nil, fmt.Sprintf("virtual finality point is not finality-safe yet: blue_score_distance=%d/%d",
			finalityDistance, finalityDepth), nil
	}
	if finalityHeader.DAAScore() > atomicP2PAuditDAALag {
		targetDAA = finalityHeader.DAAScore() - atomicP2PAuditDAALag
	}

	isFinalityOnSelectedChain, err := consensus.IsInSelectedParentChainOf(finalityHash, sinkHash)
	if err != nil {
		return nil, "", err
	}
	if !isFinalityOnSelectedChain {
		return nil, "virtual finality point is not on the selected chain yet", nil
	}

	currentHash := finalityHash
	for i := 0; i < atomicP2PAuditMaxWalk; i++ {
		header, err := consensus.GetBlockHeader(currentHash)
		if err != nil {
			return nil, "", err
		}
		if header.DAAScore() <= targetDAA {
			stateHash, hasState, err := consensus.GetAtomicTokenStateHash(currentHash)
			if err != nil {
				return nil, "", err
			}
			if !hasState {
				_, reason, availabilityErr := consensus.GetAtomicTokenStateHashAvailability(currentHash)
				if availabilityErr != nil {
					return nil, "", availabilityErr
				}
				if reason == "" {
					reason = "unknown reason"
				}
				return nil, "local Atomic token checkpoint is unavailable for the finality-stable DAA-rendezvous anchor: " + reason, nil
			}
			return &atomicAuditAnchor{
				blockHash: currentHash,
				daaScore:  header.DAAScore(),
				stateHash: stateHash,
			}, "", nil
		}

		blockInfo, err := consensus.GetBlockInfo(currentHash)
		if err != nil {
			return nil, "", err
		}
		if blockInfo.SelectedParent == nil || blockInfo.SelectedParent.Equal(currentHash) {
			break
		}
		currentHash = blockInfo.SelectedParent
	}

	return nil, "could not resolve a retained selected-chain block at the configured DAA lag", nil
}

func shouldLogAtomicP2PAuditDeferred() bool {
	now := time.Now()
	nowUnixNano := now.UnixNano()
	for {
		lastUnixNano := atomic.LoadInt64(&atomicP2PAuditDeferredLogUnixNano)
		if lastUnixNano != 0 && now.Sub(time.Unix(0, lastUnixNano)) < atomicP2PAuditDeferredLog {
			return false
		}
		if atomic.CompareAndSwapInt64(&atomicP2PAuditDeferredLogUnixNano, lastUnixNano, nowUnixNano) {
			return true
		}
	}
}

func (flow *atomicStateAuditFlow) requestAtomicTokenStateHash(anchor *atomicAuditAnchor) (*appmessage.MsgAtomicTokenStateHash, error) {
	requestID := flow.allocateRequestID()
	request := appmessage.NewMsgRequestAtomicTokenStateHash(anchor.blockHash, anchor.daaScore)
	request.SetRequestID(requestID)

	if err := flow.outgoingRoute.Enqueue(request); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(atomicP2PAuditTimeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, errors.WithStack(router.ErrTimeout)
		}

		message, err := flow.incomingRoute.DequeueWithTimeout(remaining)
		if err != nil {
			return nil, err
		}
		response, ok := message.(*appmessage.MsgAtomicTokenStateHash)
		if !ok {
			return nil, errors.Errorf("unexpected Atomic audit response message: %s", message.Command())
		}
		if response.ResponseID() != requestID {
			log.Debugf("[atomic-bootstrap:p2p] ignoring stale Atomic audit response from %s with response_id=%d, expected=%d",
				flow.peer, response.ResponseID(), requestID)
			continue
		}
		return response, nil
	}
}

func (flow *atomicStateAuditFlow) allocateRequestID() uint32 {
	requestID := flow.nextRequestID
	flow.nextRequestID++
	if flow.nextRequestID == 0 {
		flow.nextRequestID = 1
	}
	return requestID
}

func (flow *atomicStateAuditFlow) minSources() int {
	minSources := int(flow.Config().AtomicBootstrapPeerQuorumMinSources)
	if minSources < 1 {
		return 1
	}
	return minSources
}

func (flow *atomicStateAuditFlow) sampleLimit(minSources int) int {
	limit := minSources*2 + 1
	if limit < atomicP2PAuditMinSample {
		limit = atomicP2PAuditMinSample
	}
	if limit > atomicP2PAuditMaxSample {
		limit = atomicP2PAuditMaxSample
	}
	if limit < minSources {
		limit = minSources
	}
	return limit
}

func (flow *atomicStateAuditFlow) isSelectedPeer(peers []*peerpkg.Peer, anchor *externalapi.DomainHash, sampleLimit int) bool {
	if len(peers) <= sampleLimit {
		return true
	}

	scoredPeers := make([]scoredAuditPeer, 0, len(peers))
	for _, peer := range peers {
		scoredPeers = append(scoredPeers, scoredAuditPeer{
			peer:  peer,
			score: auditPeerScore(anchor, peer),
		})
	}
	sort.Slice(scoredPeers, func(i, j int) bool {
		if scoredPeers[i].score == scoredPeers[j].score {
			return scoredPeers[i].peer.Address() < scoredPeers[j].peer.Address()
		}
		return scoredPeers[i].score < scoredPeers[j].score
	})

	for i := 0; i < sampleLimit; i++ {
		if scoredPeers[i].peer == flow.peer {
			return true
		}
	}
	return false
}

func (flow *atomicStateAuditFlow) isFirstPeer(peers []*peerpkg.Peer) bool {
	if len(peers) == 0 {
		return false
	}
	first := peers[0]
	for _, peer := range peers[1:] {
		if peer.Address() < first.Address() {
			first = peer
		}
	}
	return first == flow.peer
}

func auditPeerScore(anchor *externalapi.DomainHash, peer *peerpkg.Peer) uint64 {
	hasher := fnv.New64a()
	_, _ = hasher.Write(anchor.ByteSlice())
	_, _ = hasher.Write([]byte(peer.ID().String()))
	_, _ = hasher.Write([]byte(peer.Address()))
	return hasher.Sum64()
}
