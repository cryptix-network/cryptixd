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

	state, err := s.atomicStateWithRecoveredAnchorCounts(stagingArea, blockHash, state)
	if err != nil {
		return [externalapi.DomainHashSize]byte{}, false, "", err
	}

	if stateHash, ok := state.TokenIndexHash(); ok {
		return stateHash, true, "", nil
	}

	neededAssetIDs := atomicstate.AssetsRequiringPermanentMetadata(state)
	if len(neededAssetIDs) == 0 {
		return [externalapi.DomainHashSize]byte{}, false, state.TokenIndexHashUnavailableReason(), nil
	}

	metadata := make(map[[externalapi.DomainHashSize]byte]atomicstate.AssetPermanentMetadata, len(neededAssetIDs))
	missing := make(map[[externalapi.DomainHashSize]byte]struct{}, len(neededAssetIDs))
	if s.atomicTokenMetadataCache == nil {
		s.atomicTokenMetadataCache = make(map[[externalapi.DomainHashSize]byte]atomicstate.AssetPermanentMetadata)
	}
	if s.atomicTokenMetadataMissCache == nil {
		s.atomicTokenMetadataMissCache = make(map[[externalapi.DomainHashSize]byte]string)
	}
	for _, assetID := range neededAssetIDs {
		if cached, ok := s.atomicTokenMetadataCache[assetID]; ok {
			metadata[assetID] = cached
			continue
		}
		cached, ok, err := s.loadAtomicTokenMetadataCache(assetID)
		if err != nil {
			return [externalapi.DomainHashSize]byte{}, false, "", err
		}
		if ok {
			s.atomicTokenMetadataCache[assetID] = cached
			metadata[assetID] = cached
			continue
		}
		if reason, ok := s.atomicTokenMetadataMissCache[assetID]; ok {
			return [externalapi.DomainHashSize]byte{}, false, reason, nil
		}
		missing[assetID] = struct{}{}
	}

	if len(missing) != 0 {
		recovered, reason, err := s.recoverAtomicTokenMetadataFromRetainedAcceptanceData(stagingArea, blockHash, missing)
		if err != nil {
			return [externalapi.DomainHashSize]byte{}, false, "", err
		}
		for assetID, value := range recovered {
			s.atomicTokenMetadataCache[assetID] = value
			metadata[assetID] = value
			if err := s.persistAtomicTokenMetadataCache(assetID, value); err != nil {
				return [externalapi.DomainHashSize]byte{}, false, "", err
			}
			delete(missing, assetID)
		}
		if len(missing) != 0 {
			if reason == "" {
				reason = "creation transaction metadata is not available in retained block data"
			}
			for assetID := range missing {
				s.atomicTokenMetadataMissCache[assetID] = reason
			}
			return [externalapi.DomainHashSize]byte{}, false, reason, nil
		}
	}

	stateHash, ok := state.TokenIndexHashWithAssetMetadata(metadata)
	if !ok {
		return [externalapi.DomainHashSize]byte{}, false, state.TokenIndexHashUnavailableReasonWithAssetMetadata(metadata), nil
	}
	return stateHash, true, "", nil
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
		recovered := state.Clone()
		recovered.AnchorCounts = cloneAnchorCounts(cached)
		return recovered, nil
	}

	iterator, err := s.consensusStateManager.RestorePastUTXOSetIterator(stagingArea, blockHash)
	if err != nil {
		log.Warnf("[atomic-bootstrap:p2p] Atomic token anchor-count recovery unavailable for audit anchor %s: %s", blockHash, err)
		return state, nil
	}
	reconstructed := make(map[[externalapi.DomainHashSize]byte]uint64)
	for ok := iterator.First(); ok; ok = iterator.Next() {
		_, utxoEntry, getErr := iterator.Get()
		if getErr != nil {
			closeErr := iterator.Close()
			if closeErr != nil {
				return nil, closeErr
			}
			return nil, getErr
		}
		ownerID, ok := atomicstate.OwnerIDFromScript(utxoEntry.ScriptPublicKey())
		if !ok {
			continue
		}
		if reconstructed[ownerID] == ^uint64(0) {
			closeErr := iterator.Close()
			if closeErr != nil {
				return nil, closeErr
			}
			return nil, fmt.Errorf("Atomic anchor count overflow for owner `%x` at audit anchor %s", ownerID, blockHash)
		}
		reconstructed[ownerID]++
	}
	if err := iterator.Close(); err != nil {
		return nil, err
	}

	s.atomicTokenAnchorCountCache[blockKey] = cloneAnchorCounts(reconstructed)
	if anchorCountsEqual(state.AnchorCounts, reconstructed) {
		return state, nil
	}

	recovered := state.Clone()
	recovered.AnchorCounts = reconstructed
	log.Debugf("[atomic-bootstrap:p2p] recovered Atomic token anchor counts from retained UTXO set for audit anchor %s: stored_anchor_owners=%d recovered_anchor_owners=%d",
		blockHash, len(state.AnchorCounts), len(recovered.AnchorCounts))
	return recovered, nil
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
				assetID, metadata, ok, err := atomicstate.AssetPermanentMetadataFromCreationTransaction(
					transactionAcceptanceData.Transaction,
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
