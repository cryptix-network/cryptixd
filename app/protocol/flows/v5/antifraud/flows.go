package antifraud

import (
	"errors"
	"time"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	peerpkg "github.com/cryptix-network/cryptixd/app/protocol/peer"
	"github.com/cryptix-network/cryptixd/infrastructure/network/connmanager"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
)

const (
	snapshotRequestInterval = 20 * time.Second
	snapshotRequestTimeout  = 5 * time.Second
	modeRecheckInterval     = 1 * time.Second
	modeMismatchThreshold   = 5
	hardforkProtocolVersion = uint32(8)
)

func shouldDisconnectOnConsecutiveMismatch(streak *int, mismatch bool) bool {
	if streak == nil {
		return false
	}
	if !mismatch {
		*streak = 0
		return false
	}
	*streak++
	return *streak >= modeMismatchThreshold
}

// HandleSnapshotRequestsContext is the context required for serving anti-fraud snapshots to peers.
type HandleSnapshotRequestsContext interface {
	ConnectionManager() *connmanager.ConnectionManager
}

// HandleSnapshotRequests serves anti-fraud snapshots to requesting peers.
func HandleSnapshotRequests(context HandleSnapshotRequestsContext, incomingRoute *router.Route, outgoingRoute *router.Route) error {
	for {
		_, err := incomingRoute.Dequeue()
		if err != nil {
			return err
		}

		snapshot := context.ConnectionManager().AntiFraudSnapshotForPeer()
		if snapshot == nil {
			continue
		}
		if err := outgoingRoute.Enqueue(snapshot); err != nil {
			return err
		}
	}
}

// SyncSnapshotsContext is the context required for peer fallback anti-fraud snapshot sync.
type SyncSnapshotsContext interface {
	ShutdownChan() <-chan struct{}
	ConnectionManager() *connmanager.ConnectionManager
	IsPayloadHfActive() bool
}

// SyncSnapshots requests peer snapshots while peer-fallback is required and ingests valid responses.
func SyncSnapshots(context SyncSnapshotsContext, incomingRoute *router.Route, outgoingRoute *router.Route, peer *peerpkg.Peer) error {
	modeTicker := time.NewTicker(modeRecheckInterval)
	requestTicker := time.NewTicker(snapshotRequestInterval)
	protocolMismatchStreak := 0
	serviceMismatchStreak := 0
	modeMismatchStreak := 0
	defer modeTicker.Stop()
	defer requestTicker.Stop()

	for {
		select {
		case <-context.ShutdownChan():
			return nil
		case <-modeTicker.C:
			if !context.IsPayloadHfActive() {
				protocolMismatchStreak = 0
				serviceMismatchStreak = 0
				modeMismatchStreak = 0
				continue
			}
			protocolMismatch := peer.ProtocolVersion() < hardforkProtocolVersion
			if shouldDisconnectOnConsecutiveMismatch(&protocolMismatchStreak, protocolMismatch) {
				log.Warnf("Peer %s still uses pre-HF protocol version %d; reconnecting to enforce v%d+", peer, peer.ProtocolVersion(), hardforkProtocolVersion)
				peer.Connection().Disconnect()
				return nil
			}
			if protocolMismatch {
				serviceMismatchStreak = 0
				modeMismatchStreak = 0
				continue
			}
			missingStrongNodeClaimsService := peer.Services()&appmessage.SFNodeStrongNodeClaims == 0
			if shouldDisconnectOnConsecutiveMismatch(&serviceMismatchStreak, missingStrongNodeClaimsService) {
				log.Warnf("Peer %s is missing mandatory strong-node-claims service bit after hardfork; reconnecting to renegotiate post-HF capabilities", peer)
				peer.Connection().Disconnect()
				return nil
			}
			if missingStrongNodeClaimsService {
				modeMismatchStreak = 0
				continue
			}
			if !context.ConnectionManager().IsAntiFraudRuntimeEnabled() {
				modeMismatchStreak = 0
				continue
			}
			currentMode := context.ConnectionManager().AntiFraudModeForPeerHashes(peer.AntiFraudHashes())
			modeMismatch := (peer.AntiFraudRestricted() && currentMode == connmanager.AntiFraudModeFull) ||
				(!peer.AntiFraudRestricted() && currentMode == connmanager.AntiFraudModeRestricted)
			if !shouldDisconnectOnConsecutiveMismatch(&modeMismatchStreak, modeMismatch) {
				continue
			}
			if peer.AntiFraudRestricted() && currentMode == connmanager.AntiFraudModeFull {
				log.Infof("Peer %s anti-fraud overlap became valid; reconnecting to upgrade from RESTRICTED_AF to FULL", peer)
				peer.Connection().Disconnect()
				return nil
			}
			log.Warnf("Peer %s lost anti-fraud hash overlap; reconnecting to enforce RESTRICTED_AF", peer)
			peer.Connection().Disconnect()
			return nil
		case <-requestTicker.C:
			if !context.ConnectionManager().IsAntiFraudRuntimeEnabled() || !context.ConnectionManager().IsAntiFraudPeerFallbackRequired() {
				continue
			}

			if err := outgoingRoute.Enqueue(appmessage.NewMsgRequestAntiFraudSnapshotV1()); err != nil {
				return err
			}

			message, err := incomingRoute.DequeueWithTimeout(snapshotRequestTimeout)
			if err != nil {
				// Timeout is expected frequently during fallback probing.
				if errors.Is(err, router.ErrTimeout) {
					continue
				}
				return err
			}

			snapshotMessage, ok := message.(*appmessage.MsgAntiFraudSnapshotV1)
			if !ok {
				continue
			}
			if !context.ConnectionManager().IsAntiFraudRuntimeEnabled() {
				continue
			}

			peerID := ""
			if peer != nil && peer.ID() != nil {
				peerID = peer.ID().String()
			}
			ingestResult, ingestErr := context.ConnectionManager().IngestPeerAntiFraudSnapshot(peerID, snapshotMessage)
			if ingestErr != nil {
				log.Warnf("Ignoring anti-fraud snapshot from peer %s: %s", peer, ingestErr)
				continue
			}
			if ingestResult == nil {
				continue
			}

			// Keep peer hash window current based on verified snapshot messages so
			// mode rechecks don't rely on stale handshake-only hashes.
			currentHashes := peer.AntiFraudHashes()
			updatedHashes := context.ConnectionManager().AdvancePeerAntiFraudHashWindow(currentHashes, ingestResult.RootHash)
			if len(updatedHashes) == len(currentHashes) {
				same := true
				for i := range updatedHashes {
					if updatedHashes[i] != currentHashes[i] {
						same = false
						break
					}
				}
				if !same {
					peer.SetAntiFraudHashes(updatedHashes)
				}
			} else {
				peer.SetAntiFraudHashes(updatedHashes)
			}
		}
	}
}
