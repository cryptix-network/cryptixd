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
	SchemaVersion           uint32   `json:"schemaVersion"`
	Enabled                 *bool    `json:"enabled,omitempty"`
	Name                    string   `json:"name,omitempty"`
	TriggerBlocks           []string `json:"triggerBlocks,omitempty"`
	RequireTriggerBlock     *bool    `json:"requireTriggerBlock,omitempty"`
	TargetBlockHash         string   `json:"targetBlockHash,omitempty"`
	TargetDAA               *uint64  `json:"targetDaa,omitempty"`
	CutoffDAA               *uint64  `json:"cutoffDaa,omitempty"`
	MarkRemovedDisqualified *bool    `json:"markRemovedDisqualified,omitempty"`
	CleanupRemovedBlockData *bool    `json:"cleanupRemovedBlockData,omitempty"`
	DryRun                  bool     `json:"dryRun,omitempty"`
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
	if len(removed) == 0 {
		log.Infof("Startup DB repair plan %q no-op: selected tip is already at or before target %s (daa=%d)",
			plan.label(), targetHash, targetDAA)
		return nil
	}

	triggerText := "<not-required>"
	if triggerMatched {
		triggerText = triggerHash.String()
	}
	log.Warnf("Startup DB repair plan %q: rewinding selected chain from %s (daa=%d) to %s (daa=%d), removing %d selected-chain block(s), trigger=%s",
		plan.label(), currentTip, currentTipHeader.DAAScore(), targetHash, targetDAA, len(removed), triggerText)

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
	if plan.markRemovedDisqualified() {
		for _, blockHash := range removed {
			s.blockStatusStore.Stage(rewindStagingArea, blockHash, externalapi.StatusDisqualifiedFromChain)
		}
	}
	err = staging.CommitAllChanges(s.databaseContext, rewindStagingArea)
	if err != nil {
		return err
	}

	_, _, err = s.resolveVirtualChunkNoLock(0)
	if err != nil {
		return err
	}

	if plan.cleanupRemovedBlockData() {
		cleanupStagingArea := model.NewStagingArea()
		for _, blockHash := range removed {
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

	log.Warnf("Startup DB repair plan %q completed: selected chain and virtual state are now capped at %s (daa=%d)",
		plan.label(), targetHash, targetDAA)
	return nil
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
