package consensus

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"

	"github.com/cryptix-network/cryptixd/domain/consensus/database"
	"github.com/cryptix-network/cryptixd/domain/consensus/model"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/util/staging"
	"github.com/pkg/errors"
)

type startupRepairPlan struct {
	SchemaVersion            uint32   `json:"schemaVersion"`
	Enabled                  *bool    `json:"enabled,omitempty"`
	Name                     string   `json:"name,omitempty"`
	TriggerBlocks            []string `json:"triggerBlocks,omitempty"`
	RequireTriggerBlock      *bool    `json:"requireTriggerBlock,omitempty"`
	TargetBlockHash          string   `json:"targetBlockHash,omitempty"`
	TargetDAA                *uint64  `json:"targetDaa,omitempty"`
	CutoffDAA                *uint64  `json:"cutoffDaa,omitempty"`
	MarkRemovedDisqualified  *bool    `json:"markRemovedDisqualified,omitempty"`
	CleanupRemovedBlockData  *bool    `json:"cleanupRemovedBlockData,omitempty"`
	CleanupAtomicAboveTarget *bool    `json:"cleanupAtomicAboveTarget,omitempty"`
	ScanBodyDescendants      *bool    `json:"scanBodyDescendants,omitempty"`
	DryRun                   bool     `json:"dryRun,omitempty"`
}

func loadStartupRepairPlan(path string) (*startupRepairPlan, error) {
	planBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read startup repair plan %q", path)
	}

	decoder := json.NewDecoder(bytes.NewReader(planBytes))
	decoder.DisallowUnknownFields()

	plan := &startupRepairPlan{}
	if err := decoder.Decode(plan); err != nil {
		return nil, errors.Wrapf(err, "failed to parse startup repair plan %q", path)
	}
	if err := plan.validate(); err != nil {
		return nil, errors.Wrapf(err, "invalid startup repair plan %q", path)
	}
	return plan, nil
}

func (plan *startupRepairPlan) validate() error {
	if plan.SchemaVersion != 1 {
		return errors.Errorf("schemaVersion must be 1")
	}
	if plan.TargetDAA != nil && plan.CutoffDAA != nil && *plan.TargetDAA != *plan.CutoffDAA {
		return errors.Errorf("targetDaa and cutoffDaa both set to different values")
	}
	if strings.TrimSpace(plan.TargetBlockHash) != "" && plan.targetDAA() != nil {
		return errors.Errorf("set either targetBlockHash or targetDaa/cutoffDaa, not both")
	}
	if strings.TrimSpace(plan.TargetBlockHash) == "" && plan.targetDAA() == nil {
		return errors.Errorf("missing targetBlockHash or targetDaa")
	}
	if plan.requireTriggerBlock() && len(plan.TriggerBlocks) == 0 {
		return errors.Errorf("requireTriggerBlock is true but triggerBlocks is empty")
	}
	return nil
}

func (plan *startupRepairPlan) enabled() bool {
	return plan.Enabled == nil || *plan.Enabled
}

func (plan *startupRepairPlan) requireTriggerBlock() bool {
	if plan.RequireTriggerBlock != nil {
		return *plan.RequireTriggerBlock
	}
	return len(plan.TriggerBlocks) > 0
}

func (plan *startupRepairPlan) markRemovedDisqualified() bool {
	return plan.MarkRemovedDisqualified == nil || *plan.MarkRemovedDisqualified
}

func (plan *startupRepairPlan) cleanupRemovedBlockData() bool {
	return plan.CleanupRemovedBlockData == nil || *plan.CleanupRemovedBlockData
}

func (plan *startupRepairPlan) cleanupAtomicAboveTarget() bool {
	return plan.CleanupAtomicAboveTarget == nil || *plan.CleanupAtomicAboveTarget
}

func (plan *startupRepairPlan) scanBodyDescendants() bool {
	return plan.ScanBodyDescendants != nil && *plan.ScanBodyDescendants
}

func (plan *startupRepairPlan) targetDAA() *uint64 {
	if plan.TargetDAA != nil {
		return plan.TargetDAA
	}
	return plan.CutoffDAA
}

func (plan *startupRepairPlan) label() string {
	if strings.TrimSpace(plan.Name) != "" {
		return plan.Name
	}
	return "unnamed"
}

func (s *consensus) applyStartupRepairPlanAtStartup() error {
	if strings.TrimSpace(s.startupRepairPlanPath) == "" {
		return nil
	}

	plan, err := loadStartupRepairPlan(s.startupRepairPlanPath)
	if err != nil {
		return err
	}
	if !plan.enabled() {
		log.Infof("Startup DB repair plan %q is disabled; skipping", plan.label())
		return nil
	}

	readStagingArea := model.NewStagingArea()
	triggerHash, triggerMatched, err := s.startupRepairTriggerMatched(readStagingArea, plan)
	if err != nil {
		return err
	}
	if plan.requireTriggerBlock() && !triggerMatched {
		log.Infof("Startup DB repair plan %q skipped: none of the configured trigger blocks exists locally", plan.label())
		return nil
	}

	currentTip, err := s.headersSelectedTipStore.HeadersSelectedTip(s.databaseContext, readStagingArea)
	if err != nil {
		if errors.Is(err, database.ErrNotFound) {
			return nil
		}
		return err
	}

	currentTipHeader, err := s.blockHeaderStore.BlockHeader(s.databaseContext, readStagingArea, currentTip)
	if err != nil {
		return err
	}

	targetHash, targetDAA, removed, err := s.selectedChainRepairTarget(readStagingArea, currentTip, plan)
	if err != nil {
		return err
	}
	virtualDAA, err := s.daaBlocksStore.DAAScore(s.databaseContext, readStagingArea, model.VirtualBlockHash)
	if err != nil {
		return err
	}
	virtualNeedsRepair := virtualDAA > targetDAA
	if len(removed) == 0 && !virtualNeedsRepair {
		log.Infof("Startup DB repair plan %q no-op: selected tip is already at or before target %s (daa=%d)",
			plan.label(), targetHash, targetDAA)
		return nil
	}

	triggerText := "<not-required>"
	if triggerMatched {
		triggerText = triggerHash.String()
	}
	if len(removed) > 0 {
		log.Warnf("Startup DB repair plan %q: rewinding selected chain from %s (daa=%d) to %s (daa=%d), removing %d selected-chain block(s), trigger=%s",
			plan.label(), currentTip, currentTipHeader.DAAScore(), targetHash, targetDAA, len(removed), triggerText)
	} else {
		log.Warnf("Startup DB repair plan %q: selected chain is already capped at %s (daa=%d), but virtual DAA is %d; repairing virtual state, trigger=%s",
			plan.label(), targetHash, targetDAA, virtualDAA, triggerText)
	}

	var staleDescendants []*externalapi.DomainHash
	if plan.scanBodyDescendants() {
		staleDescendants, err = s.startupRepairBodyDescendantsAboveTarget(readStagingArea, targetHash, targetDAA, removed)
		if err != nil {
			return err
		}
		if len(staleDescendants) > 0 {
			log.Warnf("Startup DB repair plan %q: also removing %d local body descendant/side-branch block(s) above DAA %d",
				plan.label(), len(staleDescendants), targetDAA)
		}
	} else {
		log.Infof("Startup DB repair plan %q: body-descendant scan disabled; repairing selected chain and virtual state only",
			plan.label())
	}

	if plan.DryRun {
		log.Warnf("Startup DB repair plan %q dry-run: no database changes were written", plan.label())
		return nil
	}

	rewindStagingArea := model.NewStagingArea()
	err = s.headersSelectedChainStore.Stage(s.databaseContext, rewindStagingArea, &externalapi.SelectedChainPath{Removed: removed})
	if err != nil {
		return err
	}
	s.headersSelectedTipStore.Stage(rewindStagingArea, targetHash)
	s.consensusStateStore.StageTips(rewindStagingArea, []*externalapi.DomainHash{targetHash})
	err = staging.CommitAllChanges(s.databaseContext, rewindStagingArea)
	if err != nil {
		return err
	}
	log.Infof("Startup DB repair plan %q: selected chain/tips staged at %s (daa=%d); rebuilding virtual state",
		plan.label(), targetHash, targetDAA)

	err = s.stageStartupRepairVirtualState(targetHash)
	if err != nil {
		return err
	}
	log.Infof("Startup DB repair plan %q: virtual UTXO/Atomic state rebuilt at %s (daa=%d)",
		plan.label(), targetHash, targetDAA)

	if plan.markRemovedDisqualified() {
		statusStagingArea := model.NewStagingArea()
		for _, blockHash := range removed {
			s.blockStatusStore.Stage(statusStagingArea, blockHash, externalapi.StatusDisqualifiedFromChain)
		}
		for _, blockHash := range staleDescendants {
			s.blockStatusStore.Stage(statusStagingArea, blockHash, externalapi.StatusDisqualifiedFromChain)
		}
		err = staging.CommitAllChanges(s.databaseContext, statusStagingArea)
		if err != nil {
			return err
		}
	}

	if plan.cleanupRemovedBlockData() {
		cleanupStagingArea := model.NewStagingArea()
		blocksToCleanup := append(append([]*externalapi.DomainHash{}, removed...), staleDescendants...)
		for _, blockHash := range blocksToCleanup {
			s.blockStore.Delete(cleanupStagingArea, blockHash)
			s.acceptanceDataStore.Delete(cleanupStagingArea, blockHash)
			s.atomicStateStore.Delete(cleanupStagingArea, blockHash)
			s.multisetStore.Delete(cleanupStagingArea, blockHash)
			s.utxoDiffStore.Delete(cleanupStagingArea, blockHash)
			s.daaBlocksStore.Delete(cleanupStagingArea, blockHash)
		}
		err = staging.CommitAllChanges(s.databaseContext, cleanupStagingArea)
		if err != nil {
			return err
		}
	}

	if plan.cleanupAtomicAboveTarget() {
		atomicCleanupStagingArea := model.NewStagingArea()
		deletedAboveTarget, deletedOrphans, err := s.atomicStateStore.DeleteEntriesAboveDAA(
			s.databaseContext, atomicCleanupStagingArea, s.blockHeaderStore, targetDAA)
		if err != nil {
			return err
		}
		err = staging.CommitAllChanges(s.databaseContext, atomicCleanupStagingArea)
		if err != nil {
			return err
		}
		log.Warnf("Startup DB repair plan %q: cleaned Atomic state snapshots above DAA %d: deleted_above_target=%d deleted_orphans=%d",
			plan.label(), targetDAA, deletedAboveTarget, deletedOrphans)
	}

	log.Warnf("Startup DB repair plan %q completed: selected chain and virtual state are now capped at %s (daa=%d)",
		plan.label(), targetHash, targetDAA)
	return nil
}

func (s *consensus) stageStartupRepairVirtualState(targetHash *externalapi.DomainHash) error {
	virtualStagingArea := model.NewStagingArea()

	s.consensusStateStore.StageTips(virtualStagingArea, []*externalapi.DomainHash{targetHash})

	restoredPathBlocks, err := s.stageStartupRepairDiffPathForRestore(virtualStagingArea, targetHash)
	if err != nil {
		return err
	}
	if restoredPathBlocks > 0 {
		log.Warnf("Startup DB repair: temporarily restored %d disqualified UTXO diff-path block(s) so the target state can be rebuilt",
			restoredPathBlocks)
	}

	err = s.dagTopologyManagers[0].SetParents(virtualStagingArea, model.VirtualBlockHash, []*externalapi.DomainHash{targetHash})
	if err != nil {
		return err
	}

	err = s.ghostdagManagers[0].GHOSTDAG(virtualStagingArea, model.VirtualBlockHash)
	if err != nil {
		return err
	}

	_, err = s.difficultyManager.StageDAADataAndReturnRequiredDifficulty(virtualStagingArea, model.VirtualBlockHash, false)
	if err != nil {
		return err
	}

	virtualUTXODiff, virtualAcceptanceData, virtualMultiset, virtualAtomicState, err :=
		s.consensusStateManager.CalculatePastUTXOAndAcceptanceDataAndAtomicState(virtualStagingArea, model.VirtualBlockHash)
	if err != nil {
		return err
	}

	s.acceptanceDataStore.Stage(virtualStagingArea, model.VirtualBlockHash, virtualAcceptanceData)
	s.multisetStore.Stage(virtualStagingArea, model.VirtualBlockHash, virtualMultiset)
	s.atomicStateStore.Stage(virtualStagingArea, model.VirtualBlockHash, virtualAtomicState)
	s.consensusStateStore.StageVirtualUTXODiff(virtualStagingArea, virtualUTXODiff)

	targetUTXODiff, err := s.utxoDiffStore.UTXODiff(s.databaseContext, virtualStagingArea, targetHash)
	if err != nil {
		return err
	}
	targetToVirtualDiff, err := virtualUTXODiff.DiffFrom(targetUTXODiff)
	if err != nil {
		return err
	}
	s.utxoDiffStore.Stage(virtualStagingArea, targetHash, targetToVirtualDiff, model.VirtualBlockHash)

	return staging.CommitAllChanges(s.databaseContext, virtualStagingArea)
}

func (s *consensus) stageStartupRepairDiffPathForRestore(
	stagingArea *model.StagingArea,
	targetHash *externalapi.DomainHash) (int, error) {

	restored := 0
	visited := make(map[externalapi.DomainHash]struct{})
	nextBlockHash := targetHash
	for {
		if _, ok := visited[*nextBlockHash]; ok {
			return restored, errors.Errorf("cycle in UTXO diff path while repairing from %s at %s", targetHash, nextBlockHash)
		}
		visited[*nextBlockHash] = struct{}{}

		status, err := s.blockStatusStore.Get(s.databaseContext, stagingArea, nextBlockHash)
		if err != nil {
			return restored, err
		}
		if status == externalapi.StatusDisqualifiedFromChain {
			s.blockStatusStore.Stage(stagingArea, nextBlockHash, externalapi.StatusUTXOValid)
			restored++
		}

		exists, err := s.utxoDiffStore.HasUTXODiffChild(s.databaseContext, stagingArea, nextBlockHash)
		if err != nil {
			return restored, err
		}
		if !exists {
			return restored, nil
		}

		nextBlockHash, err = s.utxoDiffStore.UTXODiffChild(s.databaseContext, stagingArea, nextBlockHash)
		if err != nil {
			return restored, err
		}
		if nextBlockHash == nil || nextBlockHash.Equal(model.VirtualBlockHash) {
			return restored, nil
		}
	}
}

func (s *consensus) startupRepairBodyDescendantsAboveTarget(
	stagingArea *model.StagingArea,
	targetHash *externalapi.DomainHash,
	targetDAA uint64,
	selectedChainRemoved []*externalapi.DomainHash) ([]*externalapi.DomainHash, error) {

	removedSet := make(map[externalapi.DomainHash]struct{}, len(selectedChainRemoved))
	for _, hash := range selectedChainRemoved {
		removedSet[*hash] = struct{}{}
	}

	dagTopologyManager := s.dagTopologyManagers[0]
	queue, err := dagTopologyManager.Children(stagingArea, targetHash)
	if err != nil {
		return nil, err
	}
	visited := make(map[externalapi.DomainHash]struct{}, len(queue))
	stale := make([]*externalapi.DomainHash, 0)

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if _, ok := visited[*current]; ok {
			continue
		}
		visited[*current] = struct{}{}

		children, err := dagTopologyManager.Children(stagingArea, current)
		if err != nil {
			return nil, err
		}
		queue = append(queue, children...)

		if _, ok := removedSet[*current]; ok {
			continue
		}

		exists, err := s.blockStatusStore.Exists(s.databaseContext, stagingArea, current)
		if err != nil {
			return nil, err
		}
		if !exists {
			continue
		}
		status, err := s.blockStatusStore.Get(s.databaseContext, stagingArea, current)
		if err != nil {
			return nil, err
		}
		if status == externalapi.StatusHeaderOnly || status == externalapi.StatusDisqualifiedFromChain || status == externalapi.StatusInvalid {
			continue
		}

		header, err := s.blockHeaderStore.BlockHeader(s.databaseContext, stagingArea, current)
		if err != nil {
			return nil, err
		}
		if header.DAAScore() > targetDAA {
			stale = append(stale, current)
		}
	}

	return stale, nil
}

func (s *consensus) startupRepairTriggerMatched(
	stagingArea *model.StagingArea,
	plan *startupRepairPlan) (*externalapi.DomainHash, bool, error) {

	for _, blockHashString := range plan.TriggerBlocks {
		blockHash, err := externalapi.NewDomainHashFromString(strings.TrimSpace(blockHashString))
		if err != nil {
			return nil, false, err
		}
		exists, err := s.blockStatusStore.Exists(s.databaseContext, stagingArea, blockHash)
		if err != nil {
			return nil, false, err
		}
		if exists {
			return blockHash, true, nil
		}
	}
	return nil, false, nil
}

func (s *consensus) selectedChainRepairTarget(
	stagingArea *model.StagingArea,
	currentTip *externalapi.DomainHash,
	plan *startupRepairPlan) (*externalapi.DomainHash, uint64, []*externalapi.DomainHash, error) {

	currentIndex, err := s.headersSelectedChainStore.GetIndexByHash(s.databaseContext, stagingArea, currentTip)
	if err != nil {
		return nil, 0, nil, err
	}

	if strings.TrimSpace(plan.TargetBlockHash) != "" {
		targetHash, err := externalapi.NewDomainHashFromString(strings.TrimSpace(plan.TargetBlockHash))
		if err != nil {
			return nil, 0, nil, err
		}
		targetIndex, err := s.headersSelectedChainStore.GetIndexByHash(s.databaseContext, stagingArea, targetHash)
		if err != nil {
			return nil, 0, nil, errors.Wrapf(err, "targetBlockHash %s is not in the local selected chain", targetHash)
		}
		if targetIndex > currentIndex {
			return nil, 0, nil, errors.Errorf("targetBlockHash %s is ahead of current selected tip %s", targetHash, currentTip)
		}
		targetHeader, err := s.blockHeaderStore.BlockHeader(s.databaseContext, stagingArea, targetHash)
		if err != nil {
			return nil, 0, nil, err
		}
		removed, err := s.selectedChainRemovedAfterIndex(stagingArea, currentIndex, targetIndex)
		if err != nil {
			return nil, 0, nil, err
		}
		return targetHash, targetHeader.DAAScore(), removed, nil
	}

	targetDAA := *plan.targetDAA()
	return s.selectedChainRepairTargetByDAA(stagingArea, currentIndex, targetDAA)
}

func (s *consensus) selectedChainRepairTargetByDAA(
	stagingArea *model.StagingArea,
	currentIndex uint64,
	targetDAA uint64) (*externalapi.DomainHash, uint64, []*externalapi.DomainHash, error) {

	var targetHash *externalapi.DomainHash
	var targetIndex uint64
	var actualTargetDAA uint64
	for index := currentIndex; ; index-- {
		blockHash, err := s.headersSelectedChainStore.GetHashByIndex(s.databaseContext, stagingArea, index)
		if err != nil {
			return nil, 0, nil, err
		}
		header, err := s.blockHeaderStore.BlockHeader(s.databaseContext, stagingArea, blockHash)
		if err != nil {
			return nil, 0, nil, err
		}
		if header.DAAScore() <= targetDAA {
			targetHash = blockHash
			targetIndex = index
			actualTargetDAA = header.DAAScore()
			break
		}
		if index == 0 {
			return nil, 0, nil, errors.Errorf("could not find selected-chain target at or below DAA %d", targetDAA)
		}
	}

	removed, err := s.selectedChainRemovedAfterIndex(stagingArea, currentIndex, targetIndex)
	if err != nil {
		return nil, 0, nil, err
	}
	return targetHash, actualTargetDAA, removed, nil
}

func (s *consensus) selectedChainRemovedAfterIndex(
	stagingArea *model.StagingArea,
	currentIndex uint64,
	targetIndex uint64) ([]*externalapi.DomainHash, error) {

	removed := make([]*externalapi.DomainHash, 0, currentIndex-targetIndex)
	for index := currentIndex; index > targetIndex; index-- {
		blockHash, err := s.headersSelectedChainStore.GetHashByIndex(s.databaseContext, stagingArea, index)
		if err != nil {
			return nil, err
		}
		removed = append(removed, blockHash)
	}
	return removed, nil
}
