package consensusstatemanager

import (
	"encoding/hex"
	"time"

	"github.com/cryptix-network/cryptixd/domain/consensus/database"
	"github.com/cryptix-network/cryptixd/domain/consensus/model"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
)

const (
	atomicConsensusStatusLogInterval      = 30 * time.Second
	atomicConsensusActiveStateLogInterval = 5 * time.Second
)

type atomicConsensusStateSummary struct {
	root     [externalapi.DomainHashSize]byte
	rootOnly bool
	assets   int
	balances int
	nonces   int
	anchors  int
	vaults   int
}

func summarizeAtomicConsensusState(state *atomicstate.State) atomicConsensusStateSummary {
	summary := atomicConsensusStateSummary{}
	if state == nil {
		return summary
	}
	summary.root = state.CanonicalHash()
	summary.rootOnly = state.IsRootOnly()
	if !summary.rootOnly {
		summary.assets = len(state.Assets)
		summary.balances = len(state.Balances)
		summary.nonces = len(state.NextNonces)
		summary.anchors = len(state.AnchorCounts)
		summary.vaults = len(state.LiquidityVaultOutpoints)
	}
	return summary
}

func (summary atomicConsensusStateSummary) hasTokenState() bool {
	return summary.assets != 0 || summary.balances != 0 || summary.nonces != 0 || summary.vaults != 0
}

func (summary atomicConsensusStateSummary) countsChanged(other atomicConsensusStateSummary) bool {
	return summary.rootOnly != other.rootOnly ||
		summary.assets != other.assets ||
		summary.balances != other.balances ||
		summary.nonces != other.nonces ||
		summary.anchors != other.anchors ||
		summary.vaults != other.vaults
}

func (summary atomicConsensusStateSummary) rootHex() string {
	return hex.EncodeToString(summary.root[:])
}

func (csm *consensusStateManager) logAtomicStartupState() error {
	stagingArea := model.NewStagingArea()
	daaScore, err := csm.daaBlocksStore.DAAScore(csm.databaseContext, stagingArea, model.VirtualBlockHash)
	if err != nil {
		if database.IsNotFoundError(err) {
			atomicLog.Infof("Atomic consensus startup state is not initialized yet: runtime=not_ready live_correct=false")
			return nil
		}
		return err
	}

	atomicState, err := csm.atomicStateStore.Get(csm.databaseContext, stagingArea, model.VirtualBlockHash)
	if err != nil {
		if database.IsNotFoundError(err) {
			atomicLog.Warnf("Atomic consensus startup state is missing for virtual block: runtime=not_ready live_correct=false daa=%d hf_active=%t",
				daaScore, daaScore >= csm.payloadHfActivationDAAScore)
			return nil
		}
		return err
	}

	csm.logAtomicStateSummary(stagingArea, "startup", true, daaScore, atomicState, nil)
	return nil
}

func (csm *consensusStateManager) logAtomicVirtualState(
	stagingArea *model.StagingArea,
	reason string,
	virtualUTXODiff externalapi.UTXODiff,
) {
	daaScore, err := csm.daaBlocksStore.DAAScore(csm.databaseContext, stagingArea, model.VirtualBlockHash)
	if err != nil {
		atomicLog.Warnf("Cannot read Atomic virtual DAA score for status log: %s", err)
		return
	}
	atomicState, err := csm.atomicStateStore.Get(csm.databaseContext, stagingArea, model.VirtualBlockHash)
	if err != nil {
		atomicLog.Warnf("Cannot read Atomic virtual consensus state for status log: %s", err)
		return
	}
	force := !csm.hasAtomicConsensusLogState
	csm.logAtomicStateSummary(stagingArea, reason, force, daaScore, atomicState, virtualUTXODiff)
}

func (csm *consensusStateManager) logAtomicStateSummary(
	stagingArea *model.StagingArea,
	reason string,
	force bool,
	daaScore uint64,
	atomicState *atomicstate.State,
	virtualUTXODiff externalapi.UTXODiff,
) {
	summary := summarizeAtomicConsensusState(atomicState)
	now := time.Now()
	interval := atomicConsensusStatusLogInterval
	if summary.hasTokenState() && summary.root != csm.lastAtomicConsensusLogState.root {
		interval = atomicConsensusActiveStateLogInterval
	}
	countsChanged := !csm.hasAtomicConsensusLogState || summary.countsChanged(csm.lastAtomicConsensusLogState)
	intervalElapsed := csm.lastAtomicConsensusLogTime.IsZero() || now.Sub(csm.lastAtomicConsensusLogTime) >= interval
	if !force && !countsChanged && !intervalElapsed {
		return
	}

	selectedParent, err := csm.virtualSelectedParent(stagingArea)
	if err != nil {
		selectedParent = nil
	}
	virtualParents, err := csm.dagTopologyManager.Parents(stagingArea, model.VirtualBlockHash)
	if err != nil {
		virtualParents = nil
	}

	addedUTXOs := 0
	removedUTXOs := 0
	if virtualUTXODiff != nil {
		addedUTXOs = virtualUTXODiff.ToAdd().Len()
		removedUTXOs = virtualUTXODiff.ToRemove().Len()
	}

	atomicLog.Infof("Atomic consensus state: runtime=healthy live_correct=true reason=%s daa=%d hf_active=%t root=%s root_only=%t "+
		"assets=%d balances=%d nonces=%d anchors=%d vaults=%d selected_parent=%s parents=%d utxo_add=%d utxo_remove=%d",
		reason,
		daaScore,
		daaScore >= csm.payloadHfActivationDAAScore,
		summary.rootHex(),
		summary.rootOnly,
		summary.assets,
		summary.balances,
		summary.nonces,
		summary.anchors,
		summary.vaults,
		selectedParent,
		len(virtualParents),
		addedUTXOs,
		removedUTXOs,
	)

	csm.lastAtomicConsensusLogTime = now
	csm.lastAtomicConsensusLogState = summary
	csm.hasAtomicConsensusLogState = true
}
