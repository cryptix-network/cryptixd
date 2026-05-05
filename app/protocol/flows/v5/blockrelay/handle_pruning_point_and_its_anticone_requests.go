package blockrelay

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	peerpkg "github.com/cryptix-network/cryptixd/app/protocol/peer"
	"github.com/cryptix-network/cryptixd/app/protocol/protocolerrors"
	"github.com/cryptix-network/cryptixd/domain"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
	"github.com/cryptix-network/cryptixd/infrastructure/config"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
	"sync/atomic"
)

// PruningPointAndItsAnticoneRequestsContext is the interface for the context needed for the HandlePruningPointAndItsAnticoneRequests flow.
type PruningPointAndItsAnticoneRequestsContext interface {
	Domain() domain.Domain
	Config() *config.Config
}

var isBusy uint32

// HandlePruningPointAndItsAnticoneRequests listens to appmessage.MsgRequestPruningPointAndItsAnticone messages and sends
// the pruning point and its anticone to the requesting peer.
func HandlePruningPointAndItsAnticoneRequests(context PruningPointAndItsAnticoneRequestsContext, incomingRoute *router.Route,
	outgoingRoute *router.Route, peer *peerpkg.Peer) error {

	for {
		err := func() error {
			_, err := incomingRoute.Dequeue()
			if err != nil {
				return err
			}

			if !atomic.CompareAndSwapUint32(&isBusy, 0, 1) {
				return protocolerrors.Errorf(false, "node is busy with other pruning point anticone requests")
			}
			defer atomic.StoreUint32(&isBusy, 0)

			log.Debugf("Got request for pruning point and its anticone from %s", peer)

			pruningPointHeaders, err := context.Domain().Consensus().PruningPointHeaders()
			if err != nil {
				return err
			}

			msgPruningPointHeaders := make([]*appmessage.MsgBlockHeader, len(pruningPointHeaders))
			for i, header := range pruningPointHeaders {
				msgPruningPointHeaders[i] = appmessage.DomainBlockHeaderToBlockHeader(header)
			}

			err = outgoingRoute.Enqueue(appmessage.NewMsgPruningPoints(msgPruningPointHeaders))
			if err != nil {
				return err
			}

			pointAndItsAnticone, err := context.Domain().Consensus().PruningPointAndItsAnticone()
			if err != nil {
				return err
			}
			if len(pointAndItsAnticone) == 0 {
				return protocolerrors.Errorf(false, "pruning point and its anticone is empty")
			}

			windowSize := context.Config().NetParams().DifficultyAdjustmentWindowSize
			daaWindowBlocks := make([]*externalapi.TrustedDataDataDAAHeader, 0, windowSize)
			daaWindowHashesToIndex := make(map[externalapi.DomainHash]int, windowSize)
			trustedDataDAABlockIndexes := make(map[externalapi.DomainHash][]uint64)

			ghostdagData := make([]*externalapi.BlockGHOSTDAGDataHashPair, 0)
			ghostdagDataHashToIndex := make(map[externalapi.DomainHash]int)
			trustedDataGHOSTDAGDataIndexes := make(map[externalapi.DomainHash][]uint64)
			for _, blockHash := range pointAndItsAnticone {
				blockDAAWindowHashes, err := context.Domain().Consensus().BlockDAAWindowHashes(blockHash)
				if err != nil {
					return err
				}

				trustedDataDAABlockIndexes[*blockHash] = make([]uint64, 0, windowSize)
				for i, daaBlockHash := range blockDAAWindowHashes {
					index, exists := daaWindowHashesToIndex[*daaBlockHash]
					if !exists {
						trustedDataDataDAAHeader, err := context.Domain().Consensus().TrustedDataDataDAAHeader(blockHash, daaBlockHash, uint64(i))
						if err != nil {
							return err
						}
						daaWindowBlocks = append(daaWindowBlocks, trustedDataDataDAAHeader)
						index = len(daaWindowBlocks) - 1
						daaWindowHashesToIndex[*daaBlockHash] = index
					}

					trustedDataDAABlockIndexes[*blockHash] = append(trustedDataDAABlockIndexes[*blockHash], uint64(index))
				}

				ghostdagDataBlockHashes, err := context.Domain().Consensus().TrustedBlockAssociatedGHOSTDAGDataBlockHashes(blockHash)
				if err != nil {
					return err
				}

				trustedDataGHOSTDAGDataIndexes[*blockHash] = make([]uint64, 0, context.Config().NetParams().K)
				for _, ghostdagDataBlockHash := range ghostdagDataBlockHashes {
					index, exists := ghostdagDataHashToIndex[*ghostdagDataBlockHash]
					if !exists {
						data, err := context.Domain().Consensus().TrustedGHOSTDAGData(ghostdagDataBlockHash)
						if err != nil {
							return err
						}
						ghostdagData = append(ghostdagData, &externalapi.BlockGHOSTDAGDataHashPair{
							Hash:         ghostdagDataBlockHash,
							GHOSTDAGData: data,
						})
						index = len(ghostdagData) - 1
						ghostdagDataHashToIndex[*ghostdagDataBlockHash] = index
					}

					trustedDataGHOSTDAGDataIndexes[*blockHash] = append(trustedDataGHOSTDAGDataIndexes[*blockHash], uint64(index))
				}
			}

			msgTrustedData := appmessage.DomainTrustedDataToTrustedData(daaWindowBlocks, ghostdagData)
			atomicStateBytes, atomicStateHash, err := pruningPointAtomicStateForTrustedData(context, pointAndItsAnticone[0])
			if err != nil {
				return err
			}
			if len(atomicStateBytes) != 0 {
				msgTrustedData.AtomicConsensusStateHash = append([]byte(nil), atomicStateHash[:]...)
				msgTrustedData.AtomicConsensusStateByteLength = uint64(len(atomicStateBytes))
				msgTrustedData.AtomicConsensusStateChunkCount = trustedAtomicStateChunkCount(uint64(len(atomicStateBytes)))
			}

			err = outgoingRoute.Enqueue(msgTrustedData)
			if err != nil {
				return err
			}

			if len(atomicStateBytes) != 0 {
				err = sendTrustedAtomicStateChunks(incomingRoute, outgoingRoute, atomicStateHash, atomicStateBytes)
				if err != nil {
					return err
				}
			}

			for i, blockHash := range pointAndItsAnticone {
				block, found, err := context.Domain().Consensus().GetBlock(blockHash)
				if err != nil {
					return err
				}

				if !found {
					return protocolerrors.Errorf(false, "pruning point anticone block %s not found", blockHash)
				}

				err = outgoingRoute.Enqueue(appmessage.DomainBlockWithTrustedDataToBlockWithTrustedDataV4(block, trustedDataDAABlockIndexes[*blockHash], trustedDataGHOSTDAGDataIndexes[*blockHash]))
				if err != nil {
					return err
				}

				if (i+1)%ibdBatchSize == 0 {
					// No timeout here, as we don't care if the syncee takes its time computing,
					// since it only blocks this dedicated flow
					message, err := incomingRoute.Dequeue()
					if err != nil {
						return err
					}
					if _, ok := message.(*appmessage.MsgRequestNextPruningPointAndItsAnticoneBlocks); !ok {
						return protocolerrors.Errorf(true, "received unexpected message type. "+
							"expected: %s, got: %s", appmessage.CmdRequestNextPruningPointAndItsAnticoneBlocks, message.Command())
					}
				}
			}

			err = outgoingRoute.Enqueue(appmessage.NewMsgDoneBlocksWithTrustedData())
			if err != nil {
				return err
			}

			log.Debugf("Sent pruning point and its anticone to %s", peer)
			return nil
		}()
		if err != nil {
			return err
		}
	}
}

func pruningPointAtomicStateForTrustedData(context PruningPointAndItsAnticoneRequestsContext,
	pruningPoint *externalapi.DomainHash) ([]byte, [externalapi.DomainHashSize]byte, error) {

	header, err := context.Domain().Consensus().GetBlockHeader(pruningPoint)
	if err != nil {
		return nil, [externalapi.DomainHashSize]byte{}, err
	}
	if header.DAAScore() < context.Config().NetParams().PayloadHfActivationDAAScore {
		return nil, [externalapi.DomainHashSize]byte{}, nil
	}

	atomicStateBytes, err := context.Domain().Consensus().GetPruningPointAtomicState(pruningPoint)
	if err != nil {
		return nil, [externalapi.DomainHashSize]byte{}, err
	}
	if len(atomicStateBytes) == 0 {
		return nil, [externalapi.DomainHashSize]byte{},
			protocolerrors.Errorf(false, "post-payload-HF pruning point Atomic state is empty")
	}
	if uint64(len(atomicStateBytes)) > maxImportedAtomicStateBytes {
		return nil, [externalapi.DomainHashSize]byte{},
			protocolerrors.Errorf(false, "post-payload-HF pruning point Atomic state is too large: %d bytes", len(atomicStateBytes))
	}

	return atomicStateBytes, atomicstate.HashCanonicalBytes(atomicStateBytes), nil
}

func sendTrustedAtomicStateChunks(incomingRoute *router.Route, outgoingRoute *router.Route,
	stateHash [externalapi.DomainHashSize]byte, stateBytes []byte) error {

	totalBytes := uint64(len(stateBytes))
	totalChunks := trustedAtomicStateChunkCount(totalBytes)
	for chunkIndex, offset := uint64(0), 0; offset < len(stateBytes); chunkIndex++ {
		chunkEnd := offset + trustedAtomicStateChunkSize
		if chunkEnd > len(stateBytes) {
			chunkEnd = len(stateBytes)
		}

		err := outgoingRoute.Enqueue(appmessage.NewMsgTrustedAtomicStateChunk(
			stateHash[:],
			chunkIndex,
			totalChunks,
			totalBytes,
			stateBytes[offset:chunkEnd],
		))
		if err != nil {
			return err
		}

		offset = chunkEnd
		downloadedChunks := chunkIndex + 1
		if downloadedChunks%ibdBatchSize == 0 && downloadedChunks < totalChunks {
			message, err := incomingRoute.Dequeue()
			if err != nil {
				return err
			}
			if _, ok := message.(*appmessage.MsgRequestNextPruningPointAtomicStateChunk); !ok {
				return protocolerrors.Errorf(true, "received unexpected message type. "+
					"expected: %s, got: %s", appmessage.CmdRequestNextPruningPointAtomicStateChunk, message.Command())
			}
		}
	}

	log.Debugf("Finished sending pruning point Atomic state in %d chunks", totalChunks)
	return nil
}
