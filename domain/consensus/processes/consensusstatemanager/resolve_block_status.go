package consensusstatemanager

import (
	"fmt"

	"github.com/cryptix-network/cryptixd/util/staging"

	"github.com/cryptix-network/cryptixd/domain/consensus/model"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/ruleerrors"
	"github.com/cryptix-network/cryptixd/infrastructure/db/database"
	"github.com/cryptix-network/cryptixd/infrastructure/logger"
	"github.com/pkg/errors"
)

func (csm *consensusStateManager) resolveBlockStatus(stagingArea *model.StagingArea, blockHash *externalapi.DomainHash,
	useSeparateStagingAreaPerBlock bool) (externalapi.BlockStatus, *model.UTXODiffReversalData, error) {

	onEnd := logger.LogAndMeasureExecutionTime(log, fmt.Sprintf("resolveBlockStatus for %s", blockHash))
	defer onEnd()

	log.Debugf("Getting a list of all blocks in the selected "+
		"parent chain of %s that have no yet resolved their status", blockHash)
	unverifiedBlocks, err := csm.getUnverifiedChainBlocks(stagingArea, blockHash)
	if err != nil {
		return 0, nil, err
	}
	log.Debugf("Got %d unverified blocks in the selected parent "+
		"chain of %s: %s", len(unverifiedBlocks), blockHash, unverifiedBlocks)

	// If there's no unverified blocks in the given block's chain - this means the given block already has a
	// UTXO-verified status, and therefore it should be retrieved from the store and returned
	if len(unverifiedBlocks) == 0 {
		log.Debugf("There are not unverified blocks in %s's selected parent chain. "+
			"This means that the block already has a UTXO-verified status.", blockHash)
		status, err := csm.blockStatusStore.Get(csm.databaseContext, stagingArea, blockHash)
		if err != nil {
			return 0, nil, err
		}
		log.Debugf("Block %s's status resolved to: %s", blockHash, status)
		return status, nil, nil
	}

	log.Debugf("Finding the status of the selected parent of %s", blockHash)
	selectedParentHash, selectedParentStatus, selectedParentUTXOSet, err := csm.selectedParentInfo(stagingArea, unverifiedBlocks)
	if err != nil {
		return 0, nil, err
	}
	log.Debugf("The status of the selected parent of %s is: %s", blockHash, selectedParentStatus)

	log.Debugf("Resolving the unverified blocks' status in reverse order (past to present)")
	var blockStatus externalapi.BlockStatus

	previousBlockHash := selectedParentHash
	previousBlockUTXOSet := selectedParentUTXOSet
	var oneBeforeLastResolvedBlockUTXOSet externalapi.UTXODiff
	var oneBeforeLastResolvedBlockHash *externalapi.DomainHash
	loggedDisqualifiedParentPropagation := false

	for i := len(unverifiedBlocks) - 1; i >= 0; i-- {
		unverifiedBlockHash := unverifiedBlocks[i]

		stagingAreaForCurrentBlock := stagingArea
		isResolveTip := i == 0
		useSeparateStagingArea := useSeparateStagingAreaPerBlock && !isResolveTip
		if useSeparateStagingArea {
			stagingAreaForCurrentBlock = model.NewStagingArea()
		}

		if selectedParentStatus == externalapi.StatusDisqualifiedFromChain {
			if !loggedDisqualifiedParentPropagation {
				log.Warnf("Disqualifying selected-chain block(s) because selected parent is already disqualified: first_child=%s disqualified_parent=%s remaining_unverified=%d/%d",
					unverifiedBlockHash, previousBlockHash, i+1, len(unverifiedBlocks))
				loggedDisqualifiedParentPropagation = true
			}
			blockStatus = externalapi.StatusDisqualifiedFromChain
		} else {
			oneBeforeLastResolvedBlockUTXOSet = previousBlockUTXOSet
			oneBeforeLastResolvedBlockHash = previousBlockHash

			blockStatus, previousBlockUTXOSet, err = csm.resolveSingleBlockStatus(
				stagingAreaForCurrentBlock, unverifiedBlockHash, previousBlockHash, previousBlockUTXOSet, isResolveTip)
			if err != nil {
				return 0, nil, err
			}
		}

		csm.blockStatusStore.Stage(stagingAreaForCurrentBlock, unverifiedBlockHash, blockStatus)
		selectedParentStatus = blockStatus
		log.Debugf("Block %s status resolved to `%s`, finished %d/%d of unverified blocks",
			unverifiedBlockHash, blockStatus, len(unverifiedBlocks)-i, len(unverifiedBlocks))

		if useSeparateStagingArea {
			err := staging.CommitAllChanges(csm.databaseContext, stagingAreaForCurrentBlock)
			if err != nil {
				return 0, nil, err
			}
		}
		previousBlockHash = unverifiedBlockHash
	}

	var reversalData *model.UTXODiffReversalData
	if blockStatus == externalapi.StatusUTXOValid && len(unverifiedBlocks) > 1 {
		log.Debugf("Preparing data for reversing the UTXODiff")
		// During resolveSingleBlockStatus, all unverifiedBlocks (excluding the tip) were assigned their selectedParent
		// as their UTXODiffChild.
		// Now that the whole chain has been resolved - we can reverse the UTXODiffs, to create shorter UTXODiffChild paths.
		// However, we can't do this right now, because the tip of the chain is not yet committed, so we prepare the
		// needed data (tip's selectedParent and selectedParent's UTXODiff)
		selectedParentUTXODiff, err := previousBlockUTXOSet.DiffFrom(oneBeforeLastResolvedBlockUTXOSet)
		if err != nil {
			return 0, nil, err
		}

		reversalData = &model.UTXODiffReversalData{
			SelectedParentHash:     oneBeforeLastResolvedBlockHash,
			SelectedParentUTXODiff: selectedParentUTXODiff,
		}
	}

	return blockStatus, reversalData, nil
}

// selectedParentInfo returns the hash and status of the selectedParent of the last block in the unverifiedBlocks
// chain, in addition, if the status is UTXOValid, it return it's pastUTXOSet
func (csm *consensusStateManager) selectedParentInfo(
	stagingArea *model.StagingArea, unverifiedBlocks []*externalapi.DomainHash) (
	*externalapi.DomainHash, externalapi.BlockStatus, externalapi.UTXODiff, error) {

	log.Tracef("findSelectedParentStatus start")
	defer log.Tracef("findSelectedParentStatus end")

	lastUnverifiedBlock := unverifiedBlocks[len(unverifiedBlocks)-1]
	if lastUnverifiedBlock.Equal(csm.genesisHash) {
		log.Debugf("the most recent unverified block is the genesis block, "+
			"which by definition has status: %s", externalapi.StatusUTXOValid)
		utxoDiff, err := csm.utxoDiffStore.UTXODiff(csm.databaseContext, stagingArea, lastUnverifiedBlock)
		if err != nil {
			return nil, 0, nil, err
		}
		return lastUnverifiedBlock, externalapi.StatusUTXOValid, utxoDiff, nil
	}
	lastUnverifiedBlockGHOSTDAGData, err := csm.ghostdagDataStore.Get(csm.databaseContext, stagingArea, lastUnverifiedBlock, false)
	if err != nil {
		return nil, 0, nil, err
	}
	selectedParent := lastUnverifiedBlockGHOSTDAGData.SelectedParent()
	selectedParentStatus, err := csm.blockStatusStore.Get(csm.databaseContext, stagingArea, selectedParent)
	if err != nil {
		return nil, 0, nil, err
	}
	if selectedParentStatus != externalapi.StatusUTXOValid {
		return selectedParent, selectedParentStatus, nil, nil
	}

	selectedParentUTXOSet, err := csm.restorePastUTXO(stagingArea, selectedParent)
	if err != nil {
		return nil, 0, nil, err
	}
	return selectedParent, selectedParentStatus, selectedParentUTXOSet, nil
}

func (csm *consensusStateManager) getUnverifiedChainBlocks(stagingArea *model.StagingArea,
	blockHash *externalapi.DomainHash) ([]*externalapi.DomainHash, error) {

	log.Tracef("getUnverifiedChainBlocks start for block %s", blockHash)
	defer log.Tracef("getUnverifiedChainBlocks end for block %s", blockHash)

	var unverifiedBlocks []*externalapi.DomainHash
	currentHash := blockHash
	for {
		log.Tracef("Getting status for block %s", currentHash)
		currentBlockStatus, err := csm.blockStatusStore.Get(csm.databaseContext, stagingArea, currentHash)
		if err != nil {
			return nil, err
		}
		if currentBlockStatus != externalapi.StatusUTXOPendingVerification {
			if currentBlockStatus == externalapi.StatusUTXOValid {
				hasValidDiffPath, err := csm.hasUTXODiffPathToVirtualRoot(stagingArea, currentHash)
				if err != nil {
					return nil, err
				}
				if !hasValidDiffPath {
					log.Warnf("Block %s is marked UTXO-valid but its UTXO diff path to the virtual root is incomplete; revalidating it to repair local diff state", currentHash)
					unverifiedBlocks = append(unverifiedBlocks, currentHash)

					currentBlockGHOSTDAGData, err := csm.ghostdagDataStore.Get(csm.databaseContext, stagingArea, currentHash, false)
					if err != nil {
						return nil, err
					}
					if currentBlockGHOSTDAGData.SelectedParent() == nil {
						log.Tracef("Genesis block reached while repairing UTXO diff path. Returning all the "+
							"unverified blocks prior to it: %s", unverifiedBlocks)
						return unverifiedBlocks, nil
					}
					currentHash = currentBlockGHOSTDAGData.SelectedParent()
					continue
				}
			}

			log.Tracef("Block %s has status %s. Returning all the "+
				"unverified blocks prior to it: %s", currentHash, currentBlockStatus, unverifiedBlocks)
			return unverifiedBlocks, nil
		}

		log.Tracef("Block %s is unverified. Adding it to the unverified block collection", currentHash)
		unverifiedBlocks = append(unverifiedBlocks, currentHash)

		currentBlockGHOSTDAGData, err := csm.ghostdagDataStore.Get(csm.databaseContext, stagingArea, currentHash, false)
		if err != nil {
			return nil, err
		}

		if currentBlockGHOSTDAGData.SelectedParent() == nil {
			log.Tracef("Genesis block reached. Returning all the "+
				"unverified blocks prior to it: %s", unverifiedBlocks)
			return unverifiedBlocks, nil
		}

		currentHash = currentBlockGHOSTDAGData.SelectedParent()
	}
}

func (csm *consensusStateManager) hasUTXODiffPathToVirtualRoot(
	stagingArea *model.StagingArea, blockHash *externalapi.DomainHash) (bool, error) {

	virtualRoot, err := csm.virtualSelectedParent(stagingArea)
	if err != nil {
		if database.IsNotFoundError(err) {
			return true, nil
		}
		return false, err
	}

	currentHash := blockHash
	visited := make(map[externalapi.DomainHash]struct{})
	for {
		if _, ok := visited[*currentHash]; ok {
			log.Warnf("Detected a cycle in the UTXO diff child path while checking block %s", blockHash)
			return false, nil
		}
		visited[*currentHash] = struct{}{}

		_, err := csm.utxoDiffStore.UTXODiff(csm.databaseContext, stagingArea, currentHash)
		if err != nil {
			if database.IsNotFoundError(err) {
				return false, nil
			}
			return false, err
		}

		hasChild, err := csm.utxoDiffStore.HasUTXODiffChild(csm.databaseContext, stagingArea, currentHash)
		if err != nil {
			return false, err
		}
		if currentHash.Equal(virtualRoot) {
			return !hasChild, nil
		}
		if !hasChild {
			return false, nil
		}

		currentHash, err = csm.utxoDiffStore.UTXODiffChild(csm.databaseContext, stagingArea, currentHash)
		if err != nil {
			if database.IsNotFoundError(err) {
				return false, nil
			}
			return false, err
		}
		if currentHash == nil {
			return false, nil
		}
	}
}

func (csm *consensusStateManager) resolveSingleBlockStatus(stagingArea *model.StagingArea,
	blockHash, selectedParentHash *externalapi.DomainHash, selectedParentPastUTXOSet externalapi.UTXODiff, isResolveTip bool) (
	externalapi.BlockStatus, externalapi.UTXODiff, error) {

	onEnd := logger.LogAndMeasureExecutionTime(log, fmt.Sprintf("resolveSingleBlockStatus for %s", blockHash))
	defer onEnd()

	log.Tracef("Calculating pastUTXO and acceptance data and multiset for block %s", blockHash)
	pastUTXOSet, acceptanceData, multiset, atomicState, err := csm.calculatePastUTXOAndAcceptanceDataWithSelectedParentUTXOAndAtomicState(
		stagingArea, blockHash, selectedParentPastUTXOSet)
	if err != nil {
		return 0, nil, err
	}

	log.Tracef("Staging the calculated acceptance data of block %s", blockHash)
	csm.acceptanceDataStore.Stage(stagingArea, blockHash, acceptanceData)

	block, err := csm.blockStore.Block(csm.databaseContext, stagingArea, blockHash)
	if err != nil {
		return 0, nil, err
	}

	log.Tracef("verifying the UTXO of block %s", blockHash)
	err = csm.verifyUTXO(stagingArea, block, blockHash, pastUTXOSet, acceptanceData, multiset, atomicState)
	if err != nil {
		var ruleErr ruleerrors.RuleError
		if errors.As(err, &ruleErr) {
			log.Warnf("Disqualifying block after UTXO/Atomic verification failed: block=%s selected_parent=%s daa=%d blue_score=%d txs=%d non_coinbase_txs=%d payload_txs=%d utxo_commitment=%s reason=%s",
				blockHash,
				selectedParentHash,
				block.Header.DAAScore(),
				block.Header.BlueScore(),
				len(block.Transactions),
				nonCoinbaseTransactionCount(block),
				payloadTransactionCount(block),
				block.Header.UTXOCommitment(),
				err)
			return externalapi.StatusDisqualifiedFromChain, nil, nil
		}
		return 0, nil, err
	}
	log.Debugf("UTXO verification for block %s passed", blockHash)

	log.Tracef("Staging the multiset of block %s", blockHash)
	csm.multisetStore.Stage(stagingArea, blockHash, multiset)

	log.Tracef("Staging the Atomic state of block %s", blockHash)
	csm.atomicStateStore.Stage(stagingArea, blockHash, atomicState)

	if csm.genesisHash.Equal(blockHash) {
		log.Tracef("Staging the utxoDiff of genesis")
		csm.stageDiff(stagingArea, blockHash, pastUTXOSet, nil)
		return externalapi.StatusUTXOValid, nil, nil
	}

	oldSelectedTip, err := csm.virtualSelectedParent(stagingArea)
	if err != nil {
		return 0, nil, err
	}

	if isResolveTip {
		oldSelectedTipUTXOSet, err := csm.restorePastUTXO(stagingArea, oldSelectedTip)
		if err != nil {
			return 0, nil, err
		}
		isNewSelectedTip, err := csm.isNewSelectedTip(stagingArea, blockHash, oldSelectedTip)
		if err != nil {
			return 0, nil, err
		}

		if isNewSelectedTip {
			log.Debugf("Block %s is the new selected tip, therefore setting it as old selected tip's diffChild", blockHash)

			updatedOldSelectedTipUTXOSet, err := pastUTXOSet.DiffFrom(oldSelectedTipUTXOSet)
			if err != nil {
				return 0, nil, err
			}
			log.Debugf("Setting the old selected tip's (%s) diffChild to be the new selected tip (%s)",
				oldSelectedTip, blockHash)
			csm.stageDiff(stagingArea, oldSelectedTip, updatedOldSelectedTipUTXOSet, blockHash)

			log.Tracef("Staging the utxoDiff of block %s, with virtual as diffChild", blockHash)
			csm.stageDiff(stagingArea, blockHash, pastUTXOSet, nil)
		} else {
			log.Debugf("Block %s is the tip of currently resolved chain, but not the new selected tip,"+
				"therefore setting it's utxoDiffChild to be the current selectedTip %s", blockHash, oldSelectedTip)
			utxoDiff, err := oldSelectedTipUTXOSet.DiffFrom(pastUTXOSet)
			if err != nil {
				return 0, nil, err
			}
			csm.stageDiff(stagingArea, blockHash, utxoDiff, oldSelectedTip)
		}
	} else {
		// If the block is not the tip of the currently resolved chain, we set it's diffChild to be the selectedParent,
		// this is a temporary measure to ensure there's a restore path to all blocks at all times.
		// Later down the process, the diff will be reversed in reverseUTXODiffs.
		log.Debugf("Block %s is not the new selected tip, and is not the tip of the currently verified chain, "+
			"therefore temporarily setting selectedParent as it's diffChild", blockHash)
		utxoDiff, err := selectedParentPastUTXOSet.DiffFrom(pastUTXOSet)
		if err != nil {
			return 0, nil, err
		}

		csm.stageDiff(stagingArea, blockHash, utxoDiff, selectedParentHash)
	}

	return externalapi.StatusUTXOValid, pastUTXOSet, nil
}

func nonCoinbaseTransactionCount(block *externalapi.DomainBlock) int {
	if block == nil || len(block.Transactions) == 0 {
		return 0
	}
	return len(block.Transactions) - 1
}

func payloadTransactionCount(block *externalapi.DomainBlock) int {
	if block == nil {
		return 0
	}
	payloadTransactions := 0
	for _, transaction := range block.Transactions {
		if len(transaction.Payload) > 0 {
			payloadTransactions++
		}
	}
	return payloadTransactions
}

func (csm *consensusStateManager) isNewSelectedTip(stagingArea *model.StagingArea,
	blockHash, oldSelectedTip *externalapi.DomainHash) (bool, error) {

	newSelectedTip, err := csm.ghostdagManager.ChooseSelectedParent(stagingArea, blockHash, oldSelectedTip)
	if err != nil {
		return false, err
	}

	return blockHash.Equal(newSelectedTip), nil
}

func (csm *consensusStateManager) virtualSelectedParent(stagingArea *model.StagingArea) (*externalapi.DomainHash, error) {
	virtualGHOSTDAGData, err := csm.ghostdagDataStore.Get(csm.databaseContext, stagingArea, model.VirtualBlockHash, false)
	if err != nil {
		return nil, err
	}

	return virtualGHOSTDAGData.SelectedParent(), nil
}
