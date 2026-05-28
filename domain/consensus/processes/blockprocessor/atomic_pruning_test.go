package blockprocessor_test

import (
	"encoding/binary"
	"math"
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/testapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/testutils"
	"github.com/cryptix-network/cryptixd/domain/dagconfig"
	"github.com/pkg/errors"
)

func TestAtomicPruningPostHFFirstPruningKeepsFullAtomicState(t *testing.T) {
	consensusConfig := atomicPruningTestConfig(0, false)
	factory := consensus.NewFactory()
	tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestAtomicPruningPostHFFirstPruningKeepsFullAtomicState")
	if err != nil {
		t.Fatalf("NewTestConsensus: %+v", err)
	}
	defer teardown(false)

	mineEmptyBlocks(t, tc, consensusConfig.PruningDepth()+2)
	pruningPoint := waitForPruningPointPastGenesis(t, tc)
	emptyState := assertPruningPointAtomicState(t, tc, pruningPoint)
	if len(emptyState.Assets) != 0 || len(emptyState.Balances) != 0 || len(emptyState.NextNonces) != 0 {
		t.Fatalf("first post-HF pruning point should preserve the full empty token state, got assets=%d balances=%d nonces=%d",
			len(emptyState.Assets), len(emptyState.Balances), len(emptyState.NextNonces))
	}

	tokenBlock := mineAssetCreateBlock(t, tc, 1)
	tokenHeader, err := tc.GetBlockHeader(tokenBlock)
	if err != nil {
		t.Fatalf("GetBlockHeader(tokenBlock): %+v", err)
	}
	pruningPoint = waitForPruningPointAtOrAfterBlueScore(t, tc, tokenHeader.BlueScore())
	tokenState := assertPruningPointAtomicState(t, tc, pruningPoint)
	if len(tokenState.Assets) == 0 {
		t.Fatalf("post-token pruning point should carry a materialized Atomic asset state")
	}
}

func TestAtomicPruningSurvivesPruningsBeforeHFThenPostHFPruning(t *testing.T) {
	const payloadHFActivationDAA = 20
	consensusConfig := atomicPruningTestConfig(payloadHFActivationDAA, false)
	factory := consensus.NewFactory()
	tc, teardown, err := factory.NewTestConsensus(consensusConfig, "TestAtomicPruningSurvivesPruningsBeforeHFThenPostHFPruning")
	if err != nil {
		t.Fatalf("NewTestConsensus: %+v", err)
	}
	defer teardown(false)

	mineEmptyBlocks(t, tc, consensusConfig.PruningDepth()+2)
	preHFPruningPoint := waitForPruningPointPastGenesis(t, tc)
	preHFHeader, err := tc.GetBlockHeader(preHFPruningPoint)
	if err != nil {
		t.Fatalf("GetBlockHeader(preHFPruningPoint): %+v", err)
	}
	if preHFHeader.DAAScore() >= payloadHFActivationDAA {
		t.Fatalf("test setup expected a pre-HF pruning point, got daa=%d activation=%d",
			preHFHeader.DAAScore(), payloadHFActivationDAA)
	}
	assertPruningPointAtomicState(t, tc, preHFPruningPoint)

	mineUntilVirtualDAA(t, tc, payloadHFActivationDAA)
	tokenBlock := mineAssetCreateBlock(t, tc, 1)
	tokenHeader, err := tc.GetBlockHeader(tokenBlock)
	if err != nil {
		t.Fatalf("GetBlockHeader(tokenBlock): %+v", err)
	}
	postHFPruningPoint := waitForPruningPointAtOrAfterBlueScore(t, tc, tokenHeader.BlueScore())
	postHFHeader, err := tc.GetBlockHeader(postHFPruningPoint)
	if err != nil {
		t.Fatalf("GetBlockHeader(postHFPruningPoint): %+v", err)
	}
	if postHFHeader.DAAScore() < payloadHFActivationDAA {
		t.Fatalf("test setup expected a post-HF pruning point, got daa=%d activation=%d",
			postHFHeader.DAAScore(), payloadHFActivationDAA)
	}
	postHFState := assertPruningPointAtomicState(t, tc, postHFPruningPoint)
	if len(postHFState.Assets) == 0 {
		t.Fatalf("post-HF pruning point after token create should carry Atomic asset state")
	}
}

func TestAtomicPruningSyncImportsFullAtomicStateFromPrunedPeer(t *testing.T) {
	consensusConfig := atomicPruningTestConfig(0, false)
	factory := consensus.NewFactory()
	source, teardownSource, err := factory.NewTestConsensus(consensusConfig, "TestAtomicPruningSyncImportsFullAtomicStateFromPrunedPeerSource")
	if err != nil {
		t.Fatalf("NewTestConsensus(source): %+v", err)
	}
	defer teardownSource(false)

	tokenBlock := mineAssetCreateBlock(t, source, 1)
	tokenHeader, err := source.GetBlockHeader(tokenBlock)
	if err != nil {
		t.Fatalf("GetBlockHeader(tokenBlock): %+v", err)
	}
	pruningPoint := waitForPruningPointAtOrAfterBlueScore(t, source, tokenHeader.BlueScore())
	sourceState := assertPruningPointAtomicState(t, source, pruningPoint)
	if len(sourceState.Assets) == 0 {
		t.Fatalf("source pruning point should include a materialized Atomic asset state")
	}
	sourceStateHash := sourceState.CanonicalHash()

	target := importPrunedConsensusFromSource(t, factory, consensusConfig, source, pruningPoint)
	targetState := assertPruningPointAtomicState(t, target, pruningPoint)
	if targetState.CanonicalHash() != sourceStateHash {
		t.Fatalf("imported pruning point Atomic state mismatch: got %x want %x",
			targetState.CanonicalHash(), sourceStateHash)
	}
	if len(targetState.Assets) != len(sourceState.Assets) ||
		len(targetState.Balances) != len(sourceState.Balances) ||
		len(targetState.NextNonces) != len(sourceState.NextNonces) {
		t.Fatalf("imported Atomic state counts mismatch: got assets=%d balances=%d nonces=%d; want assets=%d balances=%d nonces=%d",
			len(targetState.Assets), len(targetState.Balances), len(targetState.NextNonces),
			len(sourceState.Assets), len(sourceState.Balances), len(sourceState.NextNonces))
	}

	tips, err := target.Tips()
	if err != nil {
		t.Fatalf("Tips(target): %+v", err)
	}
	nextTip, _, err := target.AddBlock(tips, nil, nil)
	if err != nil {
		t.Fatalf("target failed to extend after pruning import: %+v", err)
	}
	valid, reason, err := target.IsStoredBlockUTXOCommitmentValid(nextTip)
	if err != nil {
		t.Fatalf("IsStoredBlockUTXOCommitmentValid: %+v", err)
	}
	if !valid {
		t.Fatalf("target built an invalid UTXO/Atomic commitment after pruning import: %s", reason)
	}
}

func atomicPruningTestConfig(payloadHFActivationDAAScore uint64, skipAddingGenesis bool) *consensus.Config {
	params := dagconfig.SimnetParams
	params.SkipProofOfWork = true
	params.BlockCoinbaseMaturity = 0
	params.K = 0
	params.MergeSetSizeLimit = 1
	params.MaxBlockParents = 4
	params.FinalityDuration = 2 * params.TargetTimePerBlock
	params.PruningProofM = 1
	params.PayloadHfActivationDAAScore = payloadHFActivationDAAScore
	return &consensus.Config{
		Params:                          params,
		EnableSanityCheckPruningUTXOSet: true,
		SkipAddingGenesis:               skipAddingGenesis,
	}
}

func mineEmptyBlocks(t *testing.T, tc testapi.TestConsensus, count uint64) {
	t.Helper()
	for i := uint64(0); i < count; i++ {
		tips, err := tc.Tips()
		if err != nil {
			t.Fatalf("Tips: %+v", err)
		}
		if _, _, err := tc.AddBlock(tips, nil, nil); err != nil {
			t.Fatalf("AddBlock(%d): %+v", i, err)
		}
	}
}

func mineAssetCreateBlock(t *testing.T, tc testapi.TestConsensus, nonce uint64) *externalapi.DomainHash {
	t.Helper()
	tx, err := createReadyAtomicTransactionFromConsensusFunding(tc, 10_000, createCATCreateAssetWithMintPayload(nonce))
	if err != nil {
		t.Fatalf("create atomic funding tx: %+v", err)
	}
	tips, err := tc.Tips()
	if err != nil {
		t.Fatalf("Tips: %+v", err)
	}
	blockHash, _, err := tc.AddBlock(tips, nil, []*externalapi.DomainTransaction{tx})
	if err != nil {
		t.Fatalf("AddBlock(token create): %+v", err)
	}
	valid, reason, err := tc.IsStoredBlockUTXOCommitmentValid(blockHash)
	if err != nil {
		t.Fatalf("IsStoredBlockUTXOCommitmentValid(token create): %+v", err)
	}
	if !valid {
		t.Fatalf("token create block stored invalid UTXO/Atomic commitment: %s", reason)
	}
	if _, ok, err := tc.GetAtomicTokenStateHash(blockHash); err != nil {
		t.Fatalf("GetAtomicTokenStateHash(token create): %+v", err)
	} else if !ok {
		t.Fatalf("token create block has no Atomic token state hash")
	}
	return blockHash
}

func waitForPruningPointPastGenesis(t *testing.T, tc testapi.TestConsensus) *externalapi.DomainHash {
	t.Helper()
	for i := 0; i < 1000; i++ {
		pruningPoint, err := tc.PruningPoint()
		if err != nil {
			t.Fatalf("PruningPoint: %+v", err)
		}
		if !pruningPoint.Equal(tc.DAGParams().GenesisHash) {
			return pruningPoint
		}
		mineEmptyBlocks(t, tc, 1)
	}
	t.Fatalf("pruning point did not move past genesis")
	return nil
}

func waitForPruningPointAtOrAfterBlueScore(t *testing.T, tc testapi.TestConsensus, blueScore uint64) *externalapi.DomainHash {
	t.Helper()
	for i := 0; i < 2000; i++ {
		pruningPoint, err := tc.PruningPoint()
		if err != nil {
			t.Fatalf("PruningPoint: %+v", err)
		}
		header, err := tc.GetBlockHeader(pruningPoint)
		if err != nil {
			t.Fatalf("GetBlockHeader(pruningPoint): %+v", err)
		}
		if header.BlueScore() >= blueScore {
			return pruningPoint
		}
		mineEmptyBlocks(t, tc, 1)
	}
	t.Fatalf("pruning point did not reach blue score %d", blueScore)
	return nil
}

func mineUntilVirtualDAA(t *testing.T, tc testapi.TestConsensus, daaScore uint64) {
	t.Helper()
	for i := 0; i < 2000; i++ {
		virtualDAA, err := tc.GetVirtualDAAScore()
		if err != nil {
			t.Fatalf("GetVirtualDAAScore: %+v", err)
		}
		if virtualDAA >= daaScore {
			return
		}
		mineEmptyBlocks(t, tc, 1)
	}
	t.Fatalf("virtual DAA did not reach %d", daaScore)
}

func assertPruningPointAtomicState(t *testing.T, tc testapi.TestConsensus, pruningPoint *externalapi.DomainHash) *atomicstate.State {
	t.Helper()
	stateBytes, err := tc.GetPruningPointAtomicState(pruningPoint)
	if err != nil {
		t.Fatalf("GetPruningPointAtomicState(%s): %+v", pruningPoint, err)
	}
	state, err := atomicstate.FromCanonicalBytes(stateBytes)
	if err != nil {
		t.Fatalf("FromCanonicalBytes(pruning point %s): %+v", pruningPoint, err)
	}
	if state.IsRootOnly() {
		t.Fatalf("pruning point %s returned a root-only Atomic state; sync requires full materialized bytes", pruningPoint)
	}
	stateHash := state.CanonicalHash()
	storedHash, err := tc.GetPruningPointAtomicStateHash(pruningPoint)
	if err != nil {
		t.Fatalf("GetPruningPointAtomicStateHash(%s): %+v", pruningPoint, err)
	}
	if storedHash != stateHash {
		t.Fatalf("pruning point Atomic state hash mismatch: bytes hash=%x stored hash=%x", stateHash, storedHash)
	}
	return state
}

func importPrunedConsensusFromSource(
	t *testing.T,
	factory consensus.Factory,
	consensusConfig *consensus.Config,
	source testapi.TestConsensus,
	pruningPoint *externalapi.DomainHash,
) testapi.TestConsensus {
	t.Helper()

	proof, err := source.BuildPruningPointProof()
	if err != nil {
		t.Fatalf("BuildPruningPointProof: %+v", err)
	}

	validator, teardownValidator, err := factory.NewTestConsensus(consensusConfig, "TestAtomicPruningSyncImportsFullAtomicStateFromPrunedPeerValidator")
	if err != nil {
		t.Fatalf("NewTestConsensus(validator): %+v", err)
	}
	defer teardownValidator(false)
	if err := validator.ValidatePruningPointProof(proof); err != nil {
		t.Fatalf("ValidatePruningPointProof: %+v", err)
	}

	stagingConfig := *consensusConfig
	stagingConfig.SkipAddingGenesis = true
	target, teardownTarget, err := factory.NewTestConsensus(&stagingConfig, "TestAtomicPruningSyncImportsFullAtomicStateFromPrunedPeerTarget")
	if err != nil {
		t.Fatalf("NewTestConsensus(target): %+v", err)
	}
	t.Cleanup(func() { teardownTarget(false) })

	if err := target.ApplyPruningPointProof(proof); err != nil {
		t.Fatalf("ApplyPruningPointProof: %+v", err)
	}
	pruningPointHeaders, err := source.PruningPointHeaders()
	if err != nil {
		t.Fatalf("PruningPointHeaders: %+v", err)
	}
	if err := target.ImportPruningPoints(pruningPointHeaders); err != nil {
		t.Fatalf("ImportPruningPoints: %+v", err)
	}
	importTrustedBlocks(t, source, target)
	importMissingHeaders(t, source, target, pruningPoint)

	stateBytes, err := source.GetPruningPointAtomicState(pruningPoint)
	if err != nil {
		t.Fatalf("source GetPruningPointAtomicState: %+v", err)
	}
	if err := target.AppendImportedPruningPointAtomicState(stateBytes); err != nil {
		t.Fatalf("AppendImportedPruningPointAtomicState: %+v", err)
	}
	importPruningPointUTXOs(t, source, target, pruningPoint)

	if err := target.ValidateAndInsertImportedPruningPoint(pruningPoint); err != nil {
		t.Fatalf("ValidateAndInsertImportedPruningPoint: %+v", err)
	}
	return target
}

func importTrustedBlocks(t *testing.T, source, target testapi.TestConsensus) {
	t.Helper()
	pruningPointAndAnticone, err := source.PruningPointAndItsAnticone()
	if err != nil {
		t.Fatalf("PruningPointAndItsAnticone: %+v", err)
	}
	for _, blockHash := range pruningPointAndAnticone {
		block, _, err := source.GetBlock(blockHash)
		if err != nil {
			t.Fatalf("GetBlock(%s): %+v", blockHash, err)
		}
		blockDAAWindowHashes, err := source.BlockDAAWindowHashes(blockHash)
		if err != nil {
			t.Fatalf("BlockDAAWindowHashes(%s): %+v", blockHash, err)
		}
		ghostdagDataBlockHashes, err := source.TrustedBlockAssociatedGHOSTDAGDataBlockHashes(blockHash)
		if err != nil {
			t.Fatalf("TrustedBlockAssociatedGHOSTDAGDataBlockHashes(%s): %+v", blockHash, err)
		}

		blockWithTrustedData := &externalapi.BlockWithTrustedData{
			Block:        block,
			DAAWindow:    make([]*externalapi.TrustedDataDataDAAHeader, 0, len(blockDAAWindowHashes)),
			GHOSTDAGData: make([]*externalapi.BlockGHOSTDAGDataHashPair, 0, len(ghostdagDataBlockHashes)),
		}
		for i, daaBlockHash := range blockDAAWindowHashes {
			daaHeader, err := source.TrustedDataDataDAAHeader(blockHash, daaBlockHash, uint64(i))
			if err != nil {
				t.Fatalf("TrustedDataDataDAAHeader(%s): %+v", daaBlockHash, err)
			}
			blockWithTrustedData.DAAWindow = append(blockWithTrustedData.DAAWindow, daaHeader)
		}
		for _, ghostdagDataBlockHash := range ghostdagDataBlockHashes {
			data, err := source.TrustedGHOSTDAGData(ghostdagDataBlockHash)
			if err != nil {
				t.Fatalf("TrustedGHOSTDAGData(%s): %+v", ghostdagDataBlockHash, err)
			}
			blockWithTrustedData.GHOSTDAGData = append(blockWithTrustedData.GHOSTDAGData, &externalapi.BlockGHOSTDAGDataHashPair{
				Hash:         ghostdagDataBlockHash,
				GHOSTDAGData: data,
			})
		}
		if err := target.ValidateAndInsertBlockWithTrustedData(blockWithTrustedData, false); err != nil {
			t.Fatalf("ValidateAndInsertBlockWithTrustedData(%s): %+v", blockHash, err)
		}
	}
}

func importMissingHeaders(t *testing.T, source, target testapi.TestConsensus, pruningPoint *externalapi.DomainHash) {
	t.Helper()
	sourceSelectedParent, err := source.GetVirtualSelectedParent()
	if err != nil {
		t.Fatalf("GetVirtualSelectedParent(source): %+v", err)
	}
	missingHeaderHashes, _, err := source.GetHashesBetween(pruningPoint, sourceSelectedParent, math.MaxUint64)
	if err != nil {
		t.Fatalf("GetHashesBetween: %+v", err)
	}
	for i, blockHash := range missingHeaderHashes {
		blockInfo, err := target.GetBlockInfo(blockHash)
		if err != nil {
			t.Fatalf("target GetBlockInfo(%s): %+v", blockHash, err)
		}
		if blockInfo.Exists {
			continue
		}
		header, err := source.GetBlockHeader(blockHash)
		if err != nil {
			t.Fatalf("source GetBlockHeader(%s): %+v", blockHash, err)
		}
		if err := target.ValidateAndInsertBlock(&externalapi.DomainBlock{Header: header}, false); err != nil {
			t.Fatalf("ValidateAndInsertBlock header %d %s: %+v", i, blockHash, err)
		}
	}
}

func importPruningPointUTXOs(t *testing.T, source, target testapi.TestConsensus, pruningPoint *externalapi.DomainHash) {
	t.Helper()
	var fromOutpoint *externalapi.DomainOutpoint
	const step = 100_000
	for {
		pairs, err := source.GetPruningPointUTXOs(pruningPoint, fromOutpoint, step)
		if err != nil {
			t.Fatalf("GetPruningPointUTXOs: %+v", err)
		}
		if len(pairs) == 0 {
			t.Fatalf("GetPruningPointUTXOs returned an empty chunk")
		}
		if err := target.AppendImportedPruningPointUTXOs(pairs); err != nil {
			t.Fatalf("AppendImportedPruningPointUTXOs: %+v", err)
		}
		fromOutpoint = pairs[len(pairs)-1].Outpoint
		if len(pairs) < step {
			break
		}
	}
}

func createReadyAtomicTransactionFromConsensusFunding(
	tc testapi.TestConsensus,
	fee uint64,
	payload []byte,
) (*externalapi.DomainTransaction, error) {
	tips, err := tc.Tips()
	if err != nil {
		return nil, err
	}
	if _, _, err := tc.AddBlock(tips, nil, nil); err != nil {
		return nil, errors.Wrap(err, "AddBlock maturity spacer")
	}
	tips, err = tc.Tips()
	if err != nil {
		return nil, err
	}
	fundingBlockHash, _, err := tc.AddBlock(tips, nil, nil)
	if err != nil {
		return nil, errors.Wrap(err, "AddBlock funding")
	}
	fundingBlock, _, err := tc.GetBlock(fundingBlockHash)
	if err != nil {
		return nil, errors.Wrap(err, "GetBlock funding")
	}
	tx, err := testutils.CreateTransaction(fundingBlock.Transactions[0], fee)
	if err != nil {
		return nil, err
	}
	tx.SubnetworkID = subnetworks.SubnetworkIDPayload
	tx.Payload = append([]byte(nil), payload...)
	tx.Mass = 1_000
	return tx, nil
}

func createCATCreateAssetWithMintPayload(nonce uint64) []byte {
	payload := createCATPayloadHeader(4, nonce)
	payload = append(payload, 1, 0, 1)
	payload = appendCATUint128(payload, 10_000)
	var mintAuthorityOwnerID [externalapi.DomainHashSize]byte
	mintAuthorityOwnerID[0] = 0x55
	payload = append(payload, mintAuthorityOwnerID[:]...)
	payload = append(payload, 1, 1)
	payload = appendUint16LE(payload, 0)
	payload = append(payload, 'P', 'P')
	payload = appendCATUint128(payload, 1)
	var initialMintToOwnerID [externalapi.DomainHashSize]byte
	initialMintToOwnerID[0] = 0x66
	payload = append(payload, initialMintToOwnerID[:]...)
	return payload
}

func createCATPayloadHeader(opcode byte, nonce uint64) []byte {
	payload := make([]byte, 16)
	copy(payload, []byte("CAT"))
	payload[3] = 1
	payload[4] = opcode
	binary.LittleEndian.PutUint16(payload[6:8], 0)
	binary.LittleEndian.PutUint64(payload[8:16], nonce)
	return payload
}

func appendUint16LE(payload []byte, value uint16) []byte {
	var encoded [2]byte
	binary.LittleEndian.PutUint16(encoded[:], value)
	return append(payload, encoded[:]...)
}

func appendCATUint128(payload []byte, value uint64) []byte {
	var encoded [16]byte
	binary.LittleEndian.PutUint64(encoded[:8], value)
	return append(payload, encoded[:]...)
}
