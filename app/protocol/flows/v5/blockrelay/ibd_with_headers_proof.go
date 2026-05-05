package blockrelay

import (
	"bytes"
	"fmt"
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/app/protocol/common"
	"github.com/cryptix-network/cryptixd/app/protocol/protocolerrors"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/ruleerrors"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/pkg/errors"
	"time"
)

func (flow *handleIBDFlow) ibdWithHeadersProof(
	syncerHeaderSelectedTipHash, relayBlockHash *externalapi.DomainHash, highBlockDAAScore uint64) error {
	err := flow.Domain().InitStagingConsensusWithoutGenesis()
	if err != nil {
		return err
	}

	err = flow.downloadHeadersAndPruningUTXOSet(syncerHeaderSelectedTipHash, relayBlockHash, highBlockDAAScore)
	if err != nil {
		if !flow.IsRecoverableError(err) {
			return err
		}

		log.Infof("IBD with pruning proof from %s was unsuccessful. Deleting the staging consensus. (%s)", flow.peer, err)
		deleteStagingConsensusErr := flow.Domain().DeleteStagingConsensus()
		if deleteStagingConsensusErr != nil {
			return deleteStagingConsensusErr
		}

		return err
	}

	log.Infof("Header download stage of IBD with pruning proof completed successfully from %s. "+
		"Committing the staging consensus and deleting the previous obsolete one if such exists.", flow.peer)
	err = flow.Domain().CommitStagingConsensus()
	if err != nil {
		return err
	}

	err = flow.OnPruningPointUTXOSetOverride()
	if err != nil {
		return err
	}

	return nil
}

func (flow *handleIBDFlow) shouldSyncAndShouldDownloadHeadersProof(
	relayBlock *externalapi.DomainBlock,
	highestKnownSyncerChainHash *externalapi.DomainHash) (shouldDownload, shouldSync bool, err error) {

	var highestSharedBlockFound, isPruningPointInSharedBlockChain bool
	if highestKnownSyncerChainHash != nil {
		blockInfo, err := flow.Domain().Consensus().GetBlockInfo(highestKnownSyncerChainHash)
		if err != nil {
			return false, false, err
		}

		highestSharedBlockFound = blockInfo.HasBody()
		pruningPoint, err := flow.Domain().Consensus().PruningPoint()
		if err != nil {
			return false, false, err
		}

		isPruningPointInSharedBlockChain, err = flow.Domain().Consensus().IsInSelectedParentChainOf(
			pruningPoint, highestKnownSyncerChainHash)
		if err != nil {
			return false, false, err
		}
	}
	// Note: in the case where `highestSharedBlockFound == true && isPruningPointInSharedBlockChain == false`
	// we might have here info which is relevant to finality conflict decisions. This should be taken into
	// account when we improve this aspect.
	if !highestSharedBlockFound || !isPruningPointInSharedBlockChain {
		hasMoreBlueWorkThanSelectedTipAndPruningDepthMoreBlueScore, err := flow.checkIfHighHashHasMoreBlueWorkThanSelectedTipAndPruningDepthMoreBlueScore(relayBlock)
		if err != nil {
			return false, false, err
		}

		if hasMoreBlueWorkThanSelectedTipAndPruningDepthMoreBlueScore {
			return true, true, nil
		}

		if highestKnownSyncerChainHash == nil {
			log.Infof("Stopping IBD since IBD from this node will cause a finality conflict")
			return false, false, nil
		}

		return false, true, nil
	}

	return false, true, nil
}

func (flow *handleIBDFlow) checkIfHighHashHasMoreBlueWorkThanSelectedTipAndPruningDepthMoreBlueScore(relayBlock *externalapi.DomainBlock) (bool, error) {
	virtualSelectedParent, err := flow.Domain().Consensus().GetVirtualSelectedParent()
	if err != nil {
		return false, err
	}

	virtualSelectedTipInfo, err := flow.Domain().Consensus().GetBlockInfo(virtualSelectedParent)
	if err != nil {
		return false, err
	}

	if relayBlock.Header.BlueScore() < virtualSelectedTipInfo.BlueScore+flow.Config().NetParams().PruningDepth() {
		return false, nil
	}

	return relayBlock.Header.BlueWork().Cmp(virtualSelectedTipInfo.BlueWork) > 0, nil
}

func (flow *handleIBDFlow) syncAndValidatePruningPointProof() (*externalapi.DomainHash, uint64, error) {
	log.Infof("Downloading the pruning point proof from %s", flow.peer)
	err := flow.outgoingRoute.Enqueue(appmessage.NewMsgRequestPruningPointProof())
	if err != nil {
		return nil, 0, err
	}
	message, err := flow.incomingRoute.DequeueWithTimeout(10 * time.Minute)
	if err != nil {
		return nil, 0, err
	}
	pruningPointProofMessage, ok := message.(*appmessage.MsgPruningPointProof)
	if !ok {
		return nil, 0, protocolerrors.Errorf(true, "received unexpected message type. "+
			"expected: %s, got: %s", appmessage.CmdPruningPointProof, message.Command())
	}
	pruningPointProof := appmessage.MsgPruningPointProofToDomainPruningPointProof(pruningPointProofMessage)
	err = flow.Domain().Consensus().ValidatePruningPointProof(pruningPointProof)
	if err != nil {
		if errors.As(err, &ruleerrors.RuleError{}) {
			return nil, 0, protocolerrors.Wrapf(true, err, "pruning point proof validation failed")
		}
		return nil, 0, err
	}

	err = flow.Domain().StagingConsensus().ApplyPruningPointProof(pruningPointProof)
	if err != nil {
		return nil, 0, err
	}

	proofPruningPointHeader := pruningPointProof.Headers[0][len(pruningPointProof.Headers[0])-1]
	return consensushashing.HeaderHash(proofPruningPointHeader), proofPruningPointHeader.DAAScore(), nil
}

func (flow *handleIBDFlow) downloadHeadersAndPruningUTXOSet(
	syncerHeaderSelectedTipHash, relayBlockHash *externalapi.DomainHash,
	highBlockDAAScore uint64) error {

	proofPruningPoint, proofPruningPointDAAScore, err := flow.syncAndValidatePruningPointProof()
	if err != nil {
		return err
	}

	err = flow.syncPruningPointsAndPruningPointAnticone(proofPruningPoint, proofPruningPointDAAScore)
	if err != nil {
		return err
	}

	// TODO: Remove this condition once there's more proper way to check finality violation
	// in the headers proof.
	if proofPruningPoint.Equal(flow.Config().NetParams().GenesisHash) {
		return protocolerrors.Errorf(true, "the genesis pruning point violates finality")
	}

	err = flow.syncPruningPointFutureHeaders(flow.Domain().StagingConsensus(),
		syncerHeaderSelectedTipHash, proofPruningPoint, relayBlockHash, highBlockDAAScore)
	if err != nil {
		return err
	}

	log.Infof("Headers downloaded from peer %s", flow.peer)

	relayBlockInfo, err := flow.Domain().StagingConsensus().GetBlockInfo(relayBlockHash)
	if err != nil {
		return err
	}

	if !relayBlockInfo.Exists {
		return protocolerrors.Errorf(true, "the triggering IBD block was not sent")
	}

	err = flow.validatePruningPointFutureHeaderTimestamps()
	if err != nil {
		return err
	}

	log.Debugf("Syncing the current pruning point UTXO set")
	syncedPruningPointUTXOSetSuccessfully, err := flow.syncPruningPointUTXOSet(flow.Domain().StagingConsensus(), proofPruningPoint)
	if err != nil {
		return err
	}
	if !syncedPruningPointUTXOSetSuccessfully {
		log.Debugf("Aborting IBD because the pruning point UTXO set failed to sync")
		return nil
	}
	log.Debugf("Finished syncing the current pruning point UTXO set")
	return nil
}

func (flow *handleIBDFlow) syncPruningPointsAndPruningPointAnticone(proofPruningPoint *externalapi.DomainHash, proofPruningPointDAAScore uint64) error {
	log.Infof("Downloading the past pruning points and the pruning point anticone from %s", flow.peer)
	err := flow.outgoingRoute.Enqueue(appmessage.NewMsgRequestPruningPointAndItsAnticone())
	if err != nil {
		return err
	}

	err = flow.validateAndInsertPruningPoints(proofPruningPoint)
	if err != nil {
		return err
	}

	message, err := flow.incomingRoute.DequeueWithTimeout(common.DefaultTimeout)
	if err != nil {
		return err
	}

	msgTrustedData, ok := message.(*appmessage.MsgTrustedData)
	if !ok {
		return protocolerrors.Errorf(true, "received unexpected message type. "+
			"expected: %s, got: %s", appmessage.CmdTrustedData, message.Command())
	}

	err = flow.receivePruningPointTrustedAtomicState(flow.Domain().StagingConsensus(), msgTrustedData, proofPruningPoint, proofPruningPointDAAScore)
	if err != nil {
		return err
	}

	pruningPointWithMetaData, done, err := flow.receiveBlockWithTrustedData()
	if err != nil {
		return err
	}

	if done {
		return protocolerrors.Errorf(true, "got `done` message before receiving the pruning point")
	}

	if !pruningPointWithMetaData.Block.Header.BlockHash().Equal(proofPruningPoint) {
		return protocolerrors.Errorf(true, "first block with trusted data is not the pruning point")
	}

	err = flow.processBlockWithTrustedData(flow.Domain().StagingConsensus(), pruningPointWithMetaData, msgTrustedData)
	if err != nil {
		return err
	}

	i := 0
	for ; ; i++ {
		blockWithTrustedData, done, err := flow.receiveBlockWithTrustedData()
		if err != nil {
			return err
		}

		if done {
			break
		}

		err = flow.processBlockWithTrustedData(flow.Domain().StagingConsensus(), blockWithTrustedData, msgTrustedData)
		if err != nil {
			return err
		}

		// We're using i+2 because we want to check if the next block will belong to the next batch, but we already downloaded
		// the pruning point outside the loop so we use i+2 instead of i+1.
		if (i+2)%ibdBatchSize == 0 {
			log.Infof("Downloaded %d blocks from the pruning point anticone", i+1)
			err := flow.outgoingRoute.Enqueue(appmessage.NewMsgRequestNextPruningPointAndItsAnticoneBlocks())
			if err != nil {
				return err
			}
		}
	}

	log.Infof("Finished downloading pruning point and its anticone from %s. Total blocks downloaded: %d", flow.peer, i+1)
	return nil
}

func (flow *handleIBDFlow) receivePruningPointTrustedAtomicState(consensus externalapi.Consensus,
	msgTrustedData *appmessage.MsgTrustedData, proofPruningPoint *externalapi.DomainHash, proofPruningPointDAAScore uint64) error {

	if proofPruningPointDAAScore < flow.Config().NetParams().PayloadHfActivationDAAScore {
		if len(msgTrustedData.AtomicConsensusStateHash) != 0 || len(msgTrustedData.AtomicConsensusState) != 0 ||
			msgTrustedData.AtomicConsensusStateByteLength != 0 || msgTrustedData.AtomicConsensusStateChunkCount != 0 {
			log.Debugf("Ignoring pre-payload-HF pruning point Atomic trusted data from peer %s; consensus reconstructs it from the imported UTXO set", flow.peer)
		}
		return nil
	}

	if len(msgTrustedData.AtomicConsensusStateHash) == 0 && len(msgTrustedData.AtomicConsensusState) == 0 &&
		msgTrustedData.AtomicConsensusStateByteLength == 0 && msgTrustedData.AtomicConsensusStateChunkCount == 0 {
		return protocolerrors.Errorf(true, "post-payload-HF trusted data is missing pruning point Atomic state metadata")
	}

	stateHash, err := trustedAtomicStateHashFromBytes(msgTrustedData.AtomicConsensusStateHash)
	if err != nil {
		return err
	}

	var stateBytes []byte
	if len(msgTrustedData.AtomicConsensusState) != 0 {
		stateBytes = append([]byte(nil), msgTrustedData.AtomicConsensusState...)
		if len(stateBytes) > maxImportedAtomicStateBytes {
			return protocolerrors.Errorf(true, "inline pruning point Atomic state is too large")
		}
	} else {
		stateBytes, err = flow.receiveTrustedAtomicStateChunks(
			stateHash,
			msgTrustedData.AtomicConsensusStateByteLength,
			msgTrustedData.AtomicConsensusStateChunkCount)
		if err != nil {
			return err
		}
	}

	if err := importTrustedAtomicState(consensus, stateBytes, stateHash); err != nil {
		return err
	}

	log.Debugf("Imported pruning point Atomic trusted state for %s from %s", proofPruningPoint, flow.peer)
	return nil
}

func trustedAtomicStateHashFromBytes(hashBytes []byte) ([externalapi.DomainHashSize]byte, error) {
	if len(hashBytes) != externalapi.DomainHashSize {
		return [externalapi.DomainHashSize]byte{}, protocolerrors.Errorf(true,
			"invalid pruning point Atomic state hash length: expected %d, got %d",
			externalapi.DomainHashSize, len(hashBytes))
	}

	var stateHash [externalapi.DomainHashSize]byte
	copy(stateHash[:], hashBytes)
	return stateHash, nil
}

func importTrustedAtomicState(consensus externalapi.Consensus, stateBytes []byte, expectedStateHash [externalapi.DomainHashSize]byte) error {
	stateHash := atomicstate.HashCanonicalBytes(stateBytes)
	if stateHash != expectedStateHash {
		return protocolerrors.Errorf(true, "pruning point Atomic state hash mismatch")
	}

	err := consensus.AppendImportedPruningPointAtomicState(stateBytes)
	if err != nil {
		return protocolerrors.Wrapf(true, err, "invalid pruning point Atomic state")
	}
	return nil
}

func (flow *handleIBDFlow) receiveTrustedAtomicStateChunks(
	stateHash [externalapi.DomainHashSize]byte, totalBytes, totalChunks uint64) ([]byte, error) {

	if err := validateTrustedAtomicStateMetadata(totalBytes, totalChunks); err != nil {
		return nil, err
	}

	stateBytes := make([]byte, 0)
	for expectedChunkIndex := uint64(0); expectedChunkIndex < totalChunks; expectedChunkIndex++ {
		message, err := flow.incomingRoute.DequeueWithTimeout(common.DefaultTimeout)
		if err != nil {
			return nil, err
		}

		chunk, ok := message.(*appmessage.MsgTrustedAtomicStateChunk)
		if !ok {
			return nil, protocolerrors.Errorf(true, "received unexpected message type. "+
				"expected: %s, got: %s", appmessage.CmdTrustedAtomicStateChunk, message.Command())
		}

		err = validateTrustedAtomicStateChunk(chunk, stateHash, expectedChunkIndex, totalChunks, totalBytes, uint64(len(stateBytes)))
		if err != nil {
			return nil, err
		}
		stateBytes = append(stateBytes, chunk.Chunk...)

		downloadedChunks := expectedChunkIndex + 1
		if downloadedChunks%ibdBatchSize == 0 && downloadedChunks < totalChunks {
			log.Infof("Downloaded %d pruning point Atomic state chunks from %s", downloadedChunks, flow.peer)
			err := flow.outgoingRoute.Enqueue(appmessage.NewMsgRequestNextPruningPointAtomicStateChunk())
			if err != nil {
				return nil, err
			}
		}
	}

	if uint64(len(stateBytes)) != totalBytes {
		return nil, protocolerrors.Errorf(true,
			"pruning point Atomic state size mismatch: expected %d, got %d", totalBytes, len(stateBytes))
	}

	log.Infof("Finished receiving pruning point Atomic state from %s: %d bytes in %d chunks", flow.peer, totalBytes, totalChunks)
	return stateBytes, nil
}

func validateTrustedAtomicStateMetadata(totalBytes, totalChunks uint64) error {
	if totalBytes == 0 || totalChunks == 0 {
		return protocolerrors.Errorf(true, "chunked pruning point Atomic state must declare non-zero bytes and chunks")
	}
	if totalBytes > maxImportedAtomicStateBytes {
		return protocolerrors.Errorf(true, "chunked pruning point Atomic state size %d exceeds transfer limit %d",
			totalBytes, maxImportedAtomicStateBytes)
	}

	expectedChunks := trustedAtomicStateChunkCount(totalBytes)
	if totalChunks != expectedChunks {
		return protocolerrors.Errorf(true,
			"chunked pruning point Atomic state metadata mismatch: expected %d chunks for %d bytes, got %d",
			expectedChunks, totalBytes, totalChunks)
	}
	return nil
}

func validateTrustedAtomicStateChunk(chunk *appmessage.MsgTrustedAtomicStateChunk, stateHash [externalapi.DomainHashSize]byte,
	expectedChunkIndex, totalChunks, totalBytes, assembledLen uint64) error {

	if !bytes.Equal(chunk.StateHash, stateHash[:]) {
		return protocolerrors.Errorf(true, "pruning point Atomic state chunk hash label mismatch")
	}
	if chunk.ChunkIndex != expectedChunkIndex {
		return protocolerrors.Errorf(true, "unexpected pruning point Atomic state chunk index: expected %d, got %d",
			expectedChunkIndex, chunk.ChunkIndex)
	}
	if chunk.TotalChunks != totalChunks || chunk.TotalBytes != totalBytes {
		return protocolerrors.Errorf(true, "pruning point Atomic state chunk metadata changed mid-stream")
	}
	if len(chunk.Chunk) == 0 {
		return protocolerrors.Errorf(true, "pruning point Atomic state chunk must not be empty")
	}
	if len(chunk.Chunk) > trustedAtomicStateChunkSize {
		return protocolerrors.Errorf(true, "pruning point Atomic state chunk %d size %d exceeds max %d",
			expectedChunkIndex, len(chunk.Chunk), trustedAtomicStateChunkSize)
	}

	remaining := totalBytes - assembledLen
	expectedLen := remaining
	if expectedLen > trustedAtomicStateChunkSize {
		expectedLen = trustedAtomicStateChunkSize
	}
	if uint64(len(chunk.Chunk)) != expectedLen {
		return protocolerrors.Errorf(true, "pruning point Atomic state chunk %d invalid size: expected %d, got %d",
			expectedChunkIndex, expectedLen, len(chunk.Chunk))
	}

	return nil
}

func (flow *handleIBDFlow) processBlockWithTrustedData(
	consensus externalapi.Consensus, block *appmessage.MsgBlockWithTrustedDataV4, data *appmessage.MsgTrustedData) error {
	if block == nil || block.Block == nil {
		return protocolerrors.Errorf(true, "received block with trusted data missing block payload")
	}
	if data == nil {
		return protocolerrors.Errorf(true, "received block with trusted data before trusted data payload")
	}

	blockWithTrustedData := &externalapi.BlockWithTrustedData{
		Block:        appmessage.MsgBlockToDomainBlock(block.Block),
		DAAWindow:    make([]*externalapi.TrustedDataDataDAAHeader, 0, len(block.DAAWindowIndices)),
		GHOSTDAGData: make([]*externalapi.BlockGHOSTDAGDataHashPair, 0, len(block.GHOSTDAGDataIndices)),
	}

	for _, index := range block.DAAWindowIndices {
		if index >= uint64(len(data.DAAWindow)) {
			return protocolerrors.Errorf(true, "received invalid DAA window index %d (trusted window size %d)", index, len(data.DAAWindow))
		}
		blockWithTrustedData.DAAWindow = append(blockWithTrustedData.DAAWindow, appmessage.TrustedDataDataDAABlockV4ToTrustedDataDataDAAHeader(data.DAAWindow[index]))
	}

	for _, index := range block.GHOSTDAGDataIndices {
		if index >= uint64(len(data.GHOSTDAGData)) {
			return protocolerrors.Errorf(true, "received invalid GHOSTDAG index %d (trusted data size %d)", index, len(data.GHOSTDAGData))
		}
		blockWithTrustedData.GHOSTDAGData = append(blockWithTrustedData.GHOSTDAGData, appmessage.GHOSTDAGHashPairToDomainGHOSTDAGHashPair(data.GHOSTDAGData[index]))
	}
	if len(blockWithTrustedData.GHOSTDAGData) == 0 {
		return protocolerrors.Errorf(true, "received block with trusted data without GHOSTDAG indices")
	}

	err := consensus.ValidateAndInsertBlockWithTrustedData(blockWithTrustedData, false)
	if err != nil {
		if errors.As(err, &ruleerrors.RuleError{}) {
			return protocolerrors.Wrapf(true, err, "failed validating block with trusted data")
		}
		return err
	}
	return nil
}

func (flow *handleIBDFlow) receiveBlockWithTrustedData() (*appmessage.MsgBlockWithTrustedDataV4, bool, error) {
	message, err := flow.incomingRoute.DequeueWithTimeout(common.DefaultTimeout)
	if err != nil {
		return nil, false, err
	}

	switch downCastedMessage := message.(type) {
	case *appmessage.MsgBlockWithTrustedDataV4:
		return downCastedMessage, false, nil
	case *appmessage.MsgDoneBlocksWithTrustedData:
		return nil, true, nil
	default:
		return nil, false,
			protocolerrors.Errorf(true, "received unexpected message type. "+
				"expected: %s or %s, got: %s",
				(&appmessage.MsgBlockWithTrustedData{}).Command(),
				(&appmessage.MsgDoneBlocksWithTrustedData{}).Command(),
				downCastedMessage.Command())
	}
}

func (flow *handleIBDFlow) receivePruningPoints() (*appmessage.MsgPruningPoints, error) {
	message, err := flow.incomingRoute.DequeueWithTimeout(common.DefaultTimeout)
	if err != nil {
		return nil, err
	}

	msgPruningPoints, ok := message.(*appmessage.MsgPruningPoints)
	if !ok {
		return nil,
			protocolerrors.Errorf(true, "received unexpected message type. "+
				"expected: %s, got: %s", appmessage.CmdPruningPoints, message.Command())
	}

	return msgPruningPoints, nil
}

func (flow *handleIBDFlow) validateAndInsertPruningPoints(proofPruningPoint *externalapi.DomainHash) error {
	currentPruningPoint, err := flow.Domain().Consensus().PruningPoint()
	if err != nil {
		return err
	}

	if currentPruningPoint.Equal(proofPruningPoint) {
		return protocolerrors.Errorf(true, "the proposed pruning point is the same as the current pruning point")
	}

	pruningPoints, err := flow.receivePruningPoints()
	if err != nil {
		return err
	}

	headers := make([]externalapi.BlockHeader, len(pruningPoints.Headers))
	for i, header := range pruningPoints.Headers {
		headers[i] = appmessage.BlockHeaderToDomainBlockHeader(header)
	}

	arePruningPointsViolatingFinality, err := flow.Domain().Consensus().ArePruningPointsViolatingFinality(headers)
	if err != nil {
		return err
	}

	if arePruningPointsViolatingFinality {
		// TODO: Find a better way to deal with finality conflicts.
		return protocolerrors.Errorf(false, "pruning points are violating finality")
	}

	lastPruningPoint := consensushashing.HeaderHash(headers[len(headers)-1])
	if !lastPruningPoint.Equal(proofPruningPoint) {
		return protocolerrors.Errorf(true, "the proof pruning point is not equal to the last pruning "+
			"point in the list")
	}

	err = flow.Domain().StagingConsensus().ImportPruningPoints(headers)
	if err != nil {
		return err
	}

	return nil
}

func (flow *handleIBDFlow) syncPruningPointUTXOSet(consensus externalapi.Consensus,
	pruningPoint *externalapi.DomainHash) (bool, error) {

	log.Infof("Checking if the suggested pruning point %s is compatible to the node DAG", pruningPoint)
	isValid, err := flow.Domain().StagingConsensus().IsValidPruningPoint(pruningPoint)
	if err != nil {
		return false, err
	}

	if !isValid {
		return false, protocolerrors.Errorf(true, "invalid pruning point %s", pruningPoint)
	}

	log.Info("Fetching the pruning point UTXO set")
	isSuccessful, err := flow.fetchMissingUTXOSet(consensus, pruningPoint)
	if err != nil {
		log.Infof("An error occurred while fetching the pruning point UTXO set. Stopping IBD. (%s)", err)
		return false, err
	}

	if !isSuccessful {
		log.Infof("Couldn't successfully fetch the pruning point UTXO set. Stopping IBD.")
		return false, nil
	}

	log.Info("Fetched the new pruning point UTXO set")
	return true, nil
}

func (flow *handleIBDFlow) fetchMissingUTXOSet(consensus externalapi.Consensus, pruningPointHash *externalapi.DomainHash) (succeed bool, err error) {
	defer func() {
		err := flow.Domain().StagingConsensus().ClearImportedPruningPointData()
		if err != nil {
			panic(fmt.Sprintf("failed to clear imported pruning point data: %s", err))
		}
	}()

	err = flow.outgoingRoute.Enqueue(appmessage.NewMsgRequestPruningPointUTXOSet(pruningPointHash))
	if err != nil {
		return false, err
	}

	receivedAll, err := flow.receiveAndInsertPruningPointUTXOSet(consensus, pruningPointHash)
	if err != nil {
		return false, err
	}
	if !receivedAll {
		return false, nil
	}

	err = flow.Domain().StagingConsensus().ValidateAndInsertImportedPruningPoint(pruningPointHash)
	if err != nil {
		// TODO: Find a better way to deal with finality conflicts.
		if errors.Is(err, ruleerrors.ErrSuggestedPruningViolatesFinality) {
			return false, nil
		}
		return false, protocolerrors.ConvertToBanningProtocolErrorIfRuleError(err, "error with pruning point UTXO set")
	}

	return true, nil
}
