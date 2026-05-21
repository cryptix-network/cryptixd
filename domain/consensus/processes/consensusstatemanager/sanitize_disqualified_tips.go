package consensusstatemanager

import (
	"github.com/cryptix-network/cryptixd/domain/consensus/model"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
)

func (csm *consensusStateManager) sanitizeDisqualifiedTips(
	stagingArea *model.StagingArea) ([]*externalapi.DomainHash, error) {

	currentTips, err := csm.consensusStateStore.Tips(stagingArea, csm.databaseContext)
	if err != nil {
		return nil, err
	}

	sanitizedTips := make([]*externalapi.DomainHash, 0, len(currentTips))
	seen := make(map[externalapi.DomainHash]struct{}, len(currentTips))

	appendTip := func(tip *externalapi.DomainHash) {
		if _, ok := seen[*tip]; ok {
			return
		}
		seen[*tip] = struct{}{}
		sanitizedTips = append(sanitizedTips, tip)
	}

	for _, tip := range currentTips {
		tipStatus, err := csm.blockStatusStore.Get(csm.databaseContext, stagingArea, tip)
		if err != nil {
			return nil, err
		}
		if tipStatus != externalapi.StatusDisqualifiedFromChain {
			appendTip(tip)
			continue
		}

		replacementParents, err := csm.tipReplacementParentsAfterDisqualification(stagingArea, tip)
		if err != nil {
			return nil, err
		}
		for _, parent := range replacementParents {
			appendTip(parent)
		}
	}

	return sanitizedTips, nil
}

func (csm *consensusStateManager) tipReplacementParentsAfterDisqualification(
	stagingArea *model.StagingArea, disqualifiedTip *externalapi.DomainHash) ([]*externalapi.DomainHash, error) {

	parents, err := csm.dagTopologyManager.Parents(stagingArea, disqualifiedTip)
	if err != nil {
		return nil, err
	}

	replacements := make([]*externalapi.DomainHash, 0, len(parents))
	for _, parent := range parents {
		parentStatus, err := csm.blockStatusStore.Get(csm.databaseContext, stagingArea, parent)
		if err != nil {
			return nil, err
		}
		if parentStatus == externalapi.StatusDisqualifiedFromChain {
			continue
		}

		shouldRestoreParent, err := csm.allBodyChildrenDisqualified(stagingArea, parent)
		if err != nil {
			return nil, err
		}
		if shouldRestoreParent {
			replacements = append(replacements, parent)
		}
	}

	return replacements, nil
}

func (csm *consensusStateManager) allBodyChildrenDisqualified(
	stagingArea *model.StagingArea, parent *externalapi.DomainHash) (bool, error) {

	children, err := csm.dagTopologyManager.Children(stagingArea, parent)
	if err != nil {
		return false, err
	}

	for _, child := range children {
		if child.Equal(model.VirtualBlockHash) {
			continue
		}

		childStatus, err := csm.blockStatusStore.Get(csm.databaseContext, stagingArea, child)
		if err != nil {
			return false, err
		}
		if childStatus == externalapi.StatusHeaderOnly {
			continue
		}
		if childStatus != externalapi.StatusDisqualifiedFromChain {
			return false, nil
		}
	}

	return true, nil
}
