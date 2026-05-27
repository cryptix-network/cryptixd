package consensus

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cryptix-network/cryptixd/domain/consensus/database"
	"github.com/cryptix-network/cryptixd/domain/consensus/model"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
)

const atomicTokenMetadataRecoveryMaxWalk = 250_000

var atomicTokenMetadataCacheBucket = database.MakeBucket([]byte("atomic-token-metadata-cache-v2"))

func (s *consensus) atomicTokenStateHashWithRecoveredMetadata(stagingArea *model.StagingArea,
	blockHash *externalapi.DomainHash, state *atomicstate.State) ([externalapi.DomainHashSize]byte, bool, string, error) {

	if stateHash, ok := state.P2PTokenAuditHash(); ok {
		return stateHash, true, "", nil
	}
	return [externalapi.DomainHashSize]byte{}, false, state.P2PTokenAuditHashUnavailableReason(), nil
}

func (s *consensus) loadAtomicTokenMetadataCache(assetID [externalapi.DomainHashSize]byte) (
	atomicstate.AssetPermanentMetadata, bool, error) {

	data, err := s.databaseContext.Get(atomicTokenMetadataCacheKey(assetID))
	if err != nil {
		if database.IsNotFoundError(err) {
			return atomicstate.AssetPermanentMetadata{}, false, nil
		}
		return atomicstate.AssetPermanentMetadata{}, false, err
	}
	var metadata atomicstate.AssetPermanentMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return atomicstate.AssetPermanentMetadata{}, false, fmt.Errorf("failed decoding persisted Atomic token metadata cache for asset `%x`: %w", assetID, err)
	}
	return metadata, true, nil
}

func (s *consensus) persistAtomicTokenMetadataCache(assetID [externalapi.DomainHashSize]byte, metadata atomicstate.AssetPermanentMetadata) error {
	data, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed encoding Atomic token metadata cache for asset `%x`: %w", assetID, err)
	}
	if err := s.databaseContext.Put(atomicTokenMetadataCacheKey(assetID), data); err != nil {
		return fmt.Errorf("failed persisting Atomic token metadata cache for asset `%x`: %w", assetID, err)
	}
	return nil
}

func atomicTokenMetadataCacheKey(assetID [externalapi.DomainHashSize]byte) model.DBKey {
	return atomicTokenMetadataCacheBucket.Key(assetID[:])
}

func (s *consensus) atomicTokenStateHashAvailabilityWithRecoveredMetadata(stagingArea *model.StagingArea,
	blockHash *externalapi.DomainHash, state *atomicstate.State) (bool, string, error) {

	_, ok, reason, err := s.atomicTokenStateHashWithRecoveredMetadata(stagingArea, blockHash, state)
	return ok, reason, err
}

func (s *consensus) atomicStateWithRecoveredAnchorCounts(stagingArea *model.StagingArea,
	blockHash *externalapi.DomainHash, state *atomicstate.State) (*atomicstate.State, error) {

	if state == nil || state.IsRootOnly() || blockHash == nil {
		return state, nil
	}
	if s.atomicTokenAnchorCountCache == nil {
		s.atomicTokenAnchorCountCache = make(map[[externalapi.DomainHashSize]byte]map[[externalapi.DomainHashSize]byte]uint64)
	}
	blockKey := *blockHash.ByteArray()
	if cached, ok := s.atomicTokenAnchorCountCache[blockKey]; ok {
		if anchorCountsEqual(state.AnchorCounts, cached) {
			return state, nil
		}
		state.AnchorCounts = cloneAnchorCounts(cached)
		return state, nil
	}

	iterator, err := s.consensusStateManager.RestorePastUTXOSetIterator(stagingArea, blockHash)
	if err != nil {
		log.Warnf("[atomic-bootstrap:p2p] Atomic token anchor-count recovery unavailable for audit anchor %s: %s", blockHash, err)
		return state, nil
	}
	reconstructed, err := atomicAnchorCountsFromUTXOIterator(iterator)
	closeErr := iterator.Close()
	if err != nil {
		if closeErr != nil {
			return nil, closeErr
		}
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}

	s.atomicTokenAnchorCountCache[blockKey] = cloneAnchorCounts(reconstructed)
	if anchorCountsEqual(state.AnchorCounts, reconstructed) {
		return state, nil
	}

	replayAnchorOwners := len(state.AnchorCounts)
	state.AnchorCounts = reconstructed
	log.Infof("[atomic-bootstrap:p2p] recovered Atomic token anchor counts from UTXO set for audit anchor %s: replay_anchor_owners=%d recovered_anchor_owners=%d",
		blockHash, replayAnchorOwners, len(state.AnchorCounts))
	return state, nil
}

func atomicAnchorCountsFromUTXOIterator(iterator externalapi.ReadOnlyUTXOSetIterator) (map[[externalapi.DomainHashSize]byte]uint64, error) {
	reconstructed := make(map[[externalapi.DomainHashSize]byte]uint64)
	for ok := iterator.First(); ok; ok = iterator.Next() {
		_, utxoEntry, getErr := iterator.Get()
		if getErr != nil {
			return nil, getErr
		}
		if utxoEntry.IsCoinbase() {
			continue
		}
		ownerID, ok := atomicstate.OwnerIDFromScript(utxoEntry.ScriptPublicKey())
		if !ok {
			continue
		}
		if reconstructed[ownerID] == ^uint64(0) {
			return nil, fmt.Errorf("Atomic anchor count overflow for owner `%x`", ownerID)
		}
		reconstructed[ownerID]++
	}
	return reconstructed, nil
}

func cloneAnchorCounts(source map[[externalapi.DomainHashSize]byte]uint64) map[[externalapi.DomainHashSize]byte]uint64 {
	clone := make(map[[externalapi.DomainHashSize]byte]uint64, len(source))
	for ownerID, count := range source {
		if count != 0 {
			clone[ownerID] = count
		}
	}
	return clone
}

func anchorCountsEqual(left, right map[[externalapi.DomainHashSize]byte]uint64) bool {
	leftNonZero := 0
	for ownerID, count := range left {
		if count == 0 {
			continue
		}
		leftNonZero++
		if right[ownerID] != count {
			return false
		}
	}
	rightNonZero := 0
	for _, count := range right {
		if count != 0 {
			rightNonZero++
		}
	}
	return leftNonZero == rightNonZero
}

func (s *consensus) recoverAtomicTokenMetadataFromRetainedAcceptanceData(stagingArea *model.StagingArea,
	anchorHash *externalapi.DomainHash, missing map[[externalapi.DomainHashSize]byte]struct{}) (
	map[[externalapi.DomainHashSize]byte]atomicstate.AssetPermanentMetadata, string, error) {

	recovered := make(map[[externalapi.DomainHashSize]byte]atomicstate.AssetPermanentMetadata, len(missing))
	currentHash := anchorHash
	walked := 0
	var stopReason string

	for currentHash != nil && walked < atomicTokenMetadataRecoveryMaxWalk && len(missing) != 0 {
		acceptanceData, err := s.acceptanceDataStore.Get(s.databaseContext, stagingArea, currentHash)
		if err != nil {
			if database.IsNotFoundError(err) {
				stopReason = fmt.Sprintf("retained acceptance data ended at selected-chain block %s after %d block(s); older block data is pruned", currentHash, walked)
				break
			}
			return nil, "", err
		}

		for _, blockAcceptanceData := range acceptanceData {
			if blockAcceptanceData == nil || blockAcceptanceData.BlockHash == nil {
				continue
			}
			blockHeader, headerErr := s.blockHeaderStore.BlockHeader(s.databaseContext, stagingArea, blockAcceptanceData.BlockHash)
			if headerErr != nil {
				if database.IsNotFoundError(headerErr) {
					continue
				}
				return nil, "", headerErr
			}
			creationContext := atomicstate.NewCreationContext(
				blockAcceptanceData.BlockHash,
				blockHeader.DAAScore(),
				uint64(blockHeader.TimeInMilliseconds()),
			)
			for _, transactionAcceptanceData := range blockAcceptanceData.TransactionAcceptanceData {
				if transactionAcceptanceData == nil || !transactionAcceptanceData.IsAccepted || transactionAcceptanceData.Transaction == nil {
					continue
				}
				tx := transactionAcceptanceData.Transaction.Clone()
				for i := range tx.Inputs {
					if i < len(transactionAcceptanceData.TransactionInputUTXOEntries) {
						tx.Inputs[i].UTXOEntry = transactionAcceptanceData.TransactionInputUTXOEntries[i]
					}
				}
				assetID, metadata, ok, err := atomicstate.AssetPermanentMetadataFromCreationTransaction(
					tx,
					creationContext,
				)
				if err != nil {
					return nil, "", err
				}
				if !ok {
					continue
				}
				if _, needed := missing[assetID]; !needed {
					continue
				}
				recovered[assetID] = metadata
				delete(missing, assetID)
				if len(missing) == 0 {
					break
				}
			}
			if len(missing) == 0 {
				break
			}
		}

		if currentHash.Equal(s.genesisHash) {
			break
		}
		ghostdagData, err := s.ghostdagDataStores[0].Get(s.databaseContext, stagingArea, currentHash, false)
		if err != nil {
			if database.IsNotFoundError(err) {
				stopReason = fmt.Sprintf("selected-parent metadata ended at block %s after %d block(s); older DAG data is pruned", currentHash, walked)
				break
			}
			return nil, "", err
		}
		currentHash = ghostdagData.SelectedParent()
		walked++
	}

	if len(missing) == 0 {
		log.Infof("[atomic-bootstrap:p2p] recovered Atomic token creation metadata for %d legacy asset(s) from retained acceptance data", len(recovered))
		return recovered, "", nil
	}

	missingAssets := make([]string, 0, len(missing))
	for assetID := range missing {
		missingAssets = append(missingAssets, fmt.Sprintf("%x", assetID))
	}
	if stopReason == "" {
		stopReason = fmt.Sprintf("searched %d selected-chain block(s) without finding the creation transaction", walked)
	}
	return recovered, fmt.Sprintf("legacy Atomic token metadata unavailable for asset(s) %s: %s", strings.Join(missingAssets, ","), stopReason), nil
}
