package consensus

import (
	"fmt"

	"github.com/cryptix-network/cryptixd/domain/consensus/database"
	"github.com/cryptix-network/cryptixd/domain/consensus/model"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/transactionhelper"
)

type atomicTokenReplayRef struct {
	transaction         *externalapi.DomainTransaction
	sourceBlockHash     *externalapi.DomainHash
	sourceDAAScore      uint64
	sourceTime          uint64
	missingInputEntries int
}

type atomicTokenReplayRefKey struct {
	sourceBlockHash externalapi.DomainHash
	txIndex         uint32
}

type atomicTokenReplayStats struct {
	chainBlocks         int
	acceptanceEntries   int
	acceptedTxs         int
	catPayloads         int
	catApplied          int
	catNoops            int
	missingInputEntries int
}

const (
	atomicTokenReplayYieldInterval = 50
	atomicTokenReplayLogInterval   = 5000
)

type atomicTokenReplayCache struct {
	blockHash            externalapi.DomainHash
	state                *atomicstate.State
	processedCAT         map[externalapi.DomainTransactionID]struct{}
	processedCATComplete bool
}

func (s *consensus) atomicTokenIndexHashByReplay(stagingArea *model.StagingArea,
	blockHash *externalapi.DomainHash) ([externalapi.DomainHashSize]byte, bool, string, error) {

	if stateHash, ok, reason, state, err := s.atomicTokenIndexHashFromStoredState(stagingArea, blockHash); err != nil {
		return [externalapi.DomainHashSize]byte{}, false, "", err
	} else if ok {
		log.Infof("[atomic-bootstrap:p2p] Go Atomic token stored-state hash at block %s: hash=%x assets=%d balances=%d nonces=%d anchors=%d",
			blockHash,
			stateHash,
			len(state.Assets),
			len(state.Balances),
			len(state.NextNonces),
			len(state.AnchorCounts),
		)
		if s.atomicTokenReplayCache != nil {
			s.atomicTokenReplayCache.blockHash = *blockHash
			s.atomicTokenReplayCache.state = state.Clone()
			s.atomicTokenReplayCache.processedCAT = nil
			s.atomicTokenReplayCache.processedCATComplete = false
		}
		return stateHash, true, "", nil
	} else if reason != "" {
		log.Debugf("[atomic-bootstrap:p2p] Go Atomic token stored-state hash unavailable at block %s: %s; falling back to retained replay",
			blockHash, reason)
	}

	replayBlocks, baseState, processedCAT, reason, err := s.selectedChainTokenReplayPlanToBlock(stagingArea, blockHash)
	if err != nil || baseState == nil {
		return [externalapi.DomainHashSize]byte{}, false, reason, err
	}

	state := baseState.Clone()
	stats := atomicTokenReplayStats{chainBlocks: len(replayBlocks)}
	if stats.chainBlocks >= atomicTokenReplayLogInterval {
		log.Infof("[atomic-bootstrap:p2p] Go Atomic token replay starting for block %s: replay_blocks=%d",
			blockHash, stats.chainBlocks)
	}

	for blockIndex, acceptingBlockHash := range replayBlocks {
		hasBlock, err := s.blockStore.HasBlock(s.databaseContext, stagingArea, acceptingBlockHash)
		if err != nil {
			return [externalapi.DomainHashSize]byte{}, false, "", err
		}
		if !hasBlock {
			return [externalapi.DomainHashSize]byte{}, false,
				fmt.Sprintf("retained block body is unavailable for selected-chain block %s", acceptingBlockHash), nil
		}

		acceptingHeader, err := s.blockHeaderStore.BlockHeader(s.databaseContext, stagingArea, acceptingBlockHash)
		if err != nil {
			return [externalapi.DomainHashSize]byte{}, false, "", err
		}
		acceptanceData, err := s.acceptanceDataStore.Get(s.databaseContext, stagingArea, acceptingBlockHash)
		if err != nil {
			if database.IsNotFoundError(err) {
				if acceptingBlockHash.Equal(s.genesisHash) {
					continue
				}
				return [externalapi.DomainHashSize]byte{}, false,
					fmt.Sprintf("retained acceptance data is unavailable for selected-chain block %s", acceptingBlockHash), nil
			}
			return [externalapi.DomainHashSize]byte{}, false, "", err
		}

		refs, err := s.atomicTokenReplayRefs(stagingArea, acceptanceData)
		if err != nil {
			return [externalapi.DomainHashSize]byte{}, false, "", err
		}
		stats.acceptanceEntries += len(acceptanceData)
		stats.acceptedTxs += len(refs)
		for _, ref := range refs {
			stats.missingInputEntries += ref.missingInputEntries
			tx := ref.transaction
			if transactionhelper.IsCoinBase(tx) {
				continue
			}

			txID := *consensushashing.TransactionID(tx)
			isCATPayload := false
			if acceptingHeader.DAAScore() >= s.payloadHfActivationDAAScore &&
				subnetworks.IsPayload(tx.SubnetworkID) &&
				len(tx.Payload) > 0 {
				parsedPayload, parseErr := atomicstate.ParsePayload(tx.Payload)
				if parseErr != nil || parsedPayload != nil {
					isCATPayload = true
					stats.catPayloads++
					if _, exists := processedCAT[txID]; exists {
						continue
					}
					processedCAT[txID] = struct{}{}
				}
			}

			creationContext := atomicstate.NewCreationContext(ref.sourceBlockHash, ref.sourceDAAScore, ref.sourceTime)
			err := atomicstate.ValidateAndApplyTransactionWithCreationContext(
				tx,
				acceptingHeader.DAAScore(),
				s.payloadHfActivationDAAScore,
				creationContext,
				state,
			)
			if err != nil {
				if isCATPayload {
					stats.catNoops++
					// Rust's token index records malformed/no-op accepted CAT payloads as processed
					// but still applies the owner-anchor UTXO delta for that transaction.
					if anchorErr := atomicstate.ApplyAnchorDeltasForTransaction(tx, state); anchorErr != nil {
						return [externalapi.DomainHashSize]byte{}, false, "", anchorErr
					}
					continue
				}
				return [externalapi.DomainHashSize]byte{}, false, "", err
			}
			if isCATPayload {
				stats.catApplied++
			}
		}

		if (blockIndex+1)%atomicTokenReplayYieldInterval == 0 {
			s.lock.Unlock()
			s.lock.Lock()
		}
		if (blockIndex+1)%atomicTokenReplayLogInterval == 0 {
			log.Infof("[atomic-bootstrap:p2p] Go Atomic token replay progress for block %s: %d/%d block(s)",
				blockHash, blockIndex+1, stats.chainBlocks)
		}
	}

	stateHash, ok, reason, err := s.atomicTokenStateHashWithRecoveredMetadata(stagingArea, blockHash, state)
	if err != nil {
		return [externalapi.DomainHashSize]byte{}, false, "", err
	}
	if !ok {
		return [externalapi.DomainHashSize]byte{}, false, reason, nil
	}
	log.Infof("[atomic-bootstrap:p2p] Go Atomic token replay hash at block %s: hash=%x chain_blocks=%d acceptance_entries=%d accepted_txs=%d cat_payloads=%d cat_applied=%d cat_noops=%d missing_input_entries=%d assets=%d balances=%d nonces=%d anchors=%d",
		blockHash,
		stateHash,
		stats.chainBlocks,
		stats.acceptanceEntries,
		stats.acceptedTxs,
		stats.catPayloads,
		stats.catApplied,
		stats.catNoops,
		stats.missingInputEntries,
		len(state.Assets),
		len(state.Balances),
		len(state.NextNonces),
		len(state.AnchorCounts),
	)
	if s.atomicTokenReplayCache != nil {
		s.atomicTokenReplayCache.blockHash = *blockHash
		s.atomicTokenReplayCache.state = state.Clone()
		s.atomicTokenReplayCache.processedCAT = cloneProcessedCAT(processedCAT)
		s.atomicTokenReplayCache.processedCATComplete = true
	}
	return stateHash, true, "", nil
}

func (s *consensus) atomicTokenIndexHashFromStoredState(stagingArea *model.StagingArea,
	blockHash *externalapi.DomainHash) ([externalapi.DomainHashSize]byte, bool, string, *atomicstate.State, error) {

	state, err := s.atomicStateStore.Get(s.databaseContext, stagingArea, blockHash)
	if err != nil {
		if database.IsNotFoundError(err) {
			return [externalapi.DomainHashSize]byte{}, false, "missing stored Atomic state", nil, nil
		}
		return [externalapi.DomainHashSize]byte{}, false, "", nil, err
	}
	if state == nil || state.IsRootOnly() {
		return [externalapi.DomainHashSize]byte{}, false, "stored Atomic state is root-only", nil, nil
	}
	state = state.Clone()
	stateHash, ok, reason, err := s.atomicTokenStateHashWithRecoveredMetadata(stagingArea, blockHash, state)
	if err != nil || !ok {
		return [externalapi.DomainHashSize]byte{}, false, reason, nil, err
	}
	return stateHash, true, "", state, nil
}

func (s *consensus) selectedChainTokenReplayPlanToBlock(stagingArea *model.StagingArea,
	blockHash *externalapi.DomainHash) ([]*externalapi.DomainHash, *atomicstate.State,
	map[externalapi.DomainTransactionID]struct{}, string, error) {

	if replayBlocks, baseState, processedCAT, ok, err := s.selectedChainTokenReplayPlanFromCache(stagingArea, blockHash); err != nil {
		return nil, nil, nil, "", err
	} else if ok {
		return replayBlocks, baseState, processedCAT, "", nil
	}

	var reversed []*externalapi.DomainHash
	currentHash := blockHash
	for currentHash != nil {
		reversed = append(reversed, currentHash)

		if currentHash.Equal(s.genesisHash) {
			break
		}
		ghostdagData, err := s.ghostdagDataStores[0].Get(s.databaseContext, stagingArea, currentHash, false)
		if err != nil {
			if database.IsNotFoundError(err) {
				return nil, nil, nil, fmt.Sprintf("selected-parent data is unavailable for block %s", currentHash), nil
			}
			return nil, nil, nil, "", err
		}
		currentHash = ghostdagData.SelectedParent()
	}

	if len(reversed) == 0 || !reversed[len(reversed)-1].Equal(s.genesisHash) {
		return nil, nil, nil, fmt.Sprintf("selected chain for block %s does not reach genesis in retained data", blockHash), nil
	}

	replayBlocks := make([]*externalapi.DomainHash, 0, len(reversed))
	for i := len(reversed) - 1; i >= 0; i-- {
		replayBlocks = append(replayBlocks, reversed[i])
	}
	return replayBlocks, atomicstate.NewState(), make(map[externalapi.DomainTransactionID]struct{}), "", nil
}

func (s *consensus) selectedChainTokenReplayPlanFromCache(stagingArea *model.StagingArea,
	blockHash *externalapi.DomainHash) ([]*externalapi.DomainHash, *atomicstate.State,
	map[externalapi.DomainTransactionID]struct{}, bool, error) {

	cache := s.atomicTokenReplayCache
	if cache == nil || cache.state == nil || !cache.processedCATComplete {
		return nil, nil, nil, false, nil
	}

	var reversed []*externalapi.DomainHash
	currentHash := blockHash
	for currentHash != nil {
		if currentHash.Equal(&cache.blockHash) {
			replayBlocks := make([]*externalapi.DomainHash, 0, len(reversed))
			for i := len(reversed) - 1; i >= 0; i-- {
				replayBlocks = append(replayBlocks, reversed[i])
			}
			return replayBlocks, cache.state.Clone(), cloneProcessedCAT(cache.processedCAT), true, nil
		}

		reversed = append(reversed, currentHash)
		if currentHash.Equal(s.genesisHash) {
			break
		}

		ghostdagData, err := s.ghostdagDataStores[0].Get(s.databaseContext, stagingArea, currentHash, false)
		if err != nil {
			if database.IsNotFoundError(err) {
				return nil, nil, nil, false, nil
			}
			return nil, nil, nil, false, err
		}
		currentHash = ghostdagData.SelectedParent()
	}
	return nil, nil, nil, false, nil
}

func cloneProcessedCAT(in map[externalapi.DomainTransactionID]struct{}) map[externalapi.DomainTransactionID]struct{} {
	out := make(map[externalapi.DomainTransactionID]struct{}, len(in))
	for txID := range in {
		out[txID] = struct{}{}
	}
	return out
}

func (s *consensus) atomicTokenReplayRefs(stagingArea *model.StagingArea,
	acceptanceData externalapi.AcceptanceData) ([]atomicTokenReplayRef, error) {

	seen := make(map[externalapi.DomainTransactionID]atomicTokenReplayRefKey)
	refs := make([]atomicTokenReplayRef, 0)

	for _, blockAcceptanceData := range acceptanceData {
		if blockAcceptanceData == nil || blockAcceptanceData.BlockHash == nil {
			continue
		}
		sourceHeader, err := s.blockHeaderStore.BlockHeader(s.databaseContext, stagingArea, blockAcceptanceData.BlockHash)
		if err != nil {
			return nil, err
		}
		sourceTime := uint64(0)
		if sourceHeader.TimeInMilliseconds() > 0 {
			sourceTime = uint64(sourceHeader.TimeInMilliseconds())
		}

		for txIndex, transactionAcceptanceData := range blockAcceptanceData.TransactionAcceptanceData {
			if transactionAcceptanceData == nil ||
				!transactionAcceptanceData.IsAccepted ||
				transactionAcceptanceData.Transaction == nil {
				continue
			}

			tx := transactionAcceptanceData.Transaction.Clone()
			missingInputEntries := 0
			for i := range tx.Inputs {
				if i < len(transactionAcceptanceData.TransactionInputUTXOEntries) {
					tx.Inputs[i].UTXOEntry = transactionAcceptanceData.TransactionInputUTXOEntries[i]
				} else {
					missingInputEntries++
				}
			}

			txID := *consensushashing.TransactionID(tx)
			key := atomicTokenReplayRefKey{sourceBlockHash: *blockAcceptanceData.BlockHash, txIndex: uint32(txIndex)}
			if previous, exists := seen[txID]; exists {
				if previous == key {
					continue
				}
				continue
			}
			seen[txID] = key

			refs = append(refs, atomicTokenReplayRef{
				transaction:         tx,
				sourceBlockHash:     blockAcceptanceData.BlockHash,
				sourceDAAScore:      sourceHeader.DAAScore(),
				sourceTime:          sourceTime,
				missingInputEntries: missingInputEntries,
			})
		}
	}
	return refs, nil
}
