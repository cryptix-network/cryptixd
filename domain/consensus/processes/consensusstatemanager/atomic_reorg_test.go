package consensusstatemanager_test

import (
	"encoding/binary"
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus"
	"github.com/cryptix-network/cryptixd/domain/consensus/model"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/testapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/testutils"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/transactionhelper"
)

func TestAtomicReorgPrefersSelectedBranchState(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		tc, teardown, err := consensus.NewFactory().NewTestConsensus(consensusConfig, "TestAtomicReorgPrefersSelectedBranchState")
		if err != nil {
			t.Fatalf("Error setting up consensus: %+v", err)
		}
		defer teardown(false)

		coinbaseData := atomicReorgCoinbaseData()
		spacerHash, _, err := tc.AddBlock([]*externalapi.DomainHash{consensusConfig.GenesisHash}, coinbaseData, nil)
		if err != nil {
			t.Fatalf("AddBlock reward spacer: %+v", err)
		}
		fundingAHash, _, err := tc.AddBlock([]*externalapi.DomainHash{spacerHash}, coinbaseData, nil)
		if err != nil {
			t.Fatalf("AddBlock funding A: %+v", err)
		}
		fundingBHash, _, err := tc.AddBlock([]*externalapi.DomainHash{fundingAHash}, coinbaseData, nil)
		if err != nil {
			t.Fatalf("AddBlock funding B: %+v", err)
		}
		forkBase := fundingBHash

		createA := atomicReorgCreateAssetTxFromBlock(t, tc, fundingAHash, 10_000, 1, 'A', 'a')
		createB := atomicReorgCreateAssetTxFromBlock(t, tc, fundingBHash, 10_000, 1, 'B', 'b')

		branchAHash, _, err := tc.AddBlock([]*externalapi.DomainHash{forkBase}, coinbaseData, []*externalapi.DomainTransaction{createA})
		if err != nil {
			t.Fatalf("AddBlock branch A: %+v", err)
		}
		branchAStateHash, ok, err := tc.GetAtomicTokenStateHash(branchAHash)
		if err != nil {
			t.Fatalf("GetAtomicTokenStateHash branch A: %+v", err)
		}
		if !ok {
			t.Fatalf("branch A must have an Atomic token state hash")
		}

		branchBTip, _, err := tc.AddBlock([]*externalapi.DomainHash{forkBase}, coinbaseData, []*externalapi.DomainTransaction{createB})
		if err != nil {
			t.Fatalf("AddBlock branch B: %+v", err)
		}
		for i := 0; i < 3; i++ {
			branchBTip, _, err = tc.AddBlock([]*externalapi.DomainHash{branchBTip}, coinbaseData, nil)
			if err != nil {
				t.Fatalf("Extend branch B %d: %+v", i, err)
			}
		}

		selectedParent, err := tc.GetVirtualSelectedParent()
		if err != nil {
			t.Fatalf("GetVirtualSelectedParent: %+v", err)
		}
		if !selectedParent.Equal(branchBTip) {
			t.Fatalf("expected branch B tip to win the reorg: got %s want %s", selectedParent, branchBTip)
		}

		branchBStateHash, ok, err := tc.GetAtomicTokenStateHash(selectedParent)
		if err != nil {
			t.Fatalf("GetAtomicTokenStateHash selected branch B: %+v", err)
		}
		if !ok {
			t.Fatalf("selected branch B must have an Atomic token state hash")
		}
		if branchBStateHash == branchAStateHash {
			t.Fatalf("Atomic token state hash did not switch after reorg: %x", branchBStateHash)
		}

		valid, reason, err := tc.IsStoredBlockUTXOCommitmentValid(selectedParent)
		if err != nil {
			t.Fatalf("IsStoredBlockUTXOCommitmentValid: %+v", err)
		}
		if !valid {
			t.Fatalf("selected branch B stored UTXO/Atomic commitment is invalid: %s", reason)
		}
	})
}

func TestBuildBlockTemplateDuringAtomicReorgResolution(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		consensusConfig.BlockCoinbaseMaturity = 0
		consensusConfig.PayloadHfActivationDAAScore = 0

		tc, teardown, err := consensus.NewFactory().NewTestConsensus(consensusConfig, "TestBuildBlockTemplateDuringAtomicReorgResolution")
		if err != nil {
			t.Fatalf("Error setting up consensus: %+v", err)
		}
		defer teardown(false)

		coinbaseData := atomicReorgCoinbaseData()
		spacerHash, _, err := tc.AddBlock([]*externalapi.DomainHash{consensusConfig.GenesisHash}, coinbaseData, nil)
		if err != nil {
			t.Fatalf("AddBlock reward spacer: %+v", err)
		}
		fundingAHash, _, err := tc.AddBlock([]*externalapi.DomainHash{spacerHash}, coinbaseData, nil)
		if err != nil {
			t.Fatalf("AddBlock funding A: %+v", err)
		}
		fundingBHash, _, err := tc.AddBlock([]*externalapi.DomainHash{fundingAHash}, coinbaseData, nil)
		if err != nil {
			t.Fatalf("AddBlock funding B: %+v", err)
		}
		fundingCHash, _, err := tc.AddBlock([]*externalapi.DomainHash{fundingBHash}, coinbaseData, nil)
		if err != nil {
			t.Fatalf("AddBlock funding C: %+v", err)
		}
		forkBase := fundingCHash

		createA := atomicReorgCreateAssetTxFromBlock(t, tc, fundingAHash, 10_000, 1, 'C', 'c')
		createB := atomicReorgCreateAssetTxFromBlock(t, tc, fundingBHash, 10_000, 1, 'D', 'd')
		createDuringReorg := atomicReorgCreateAssetTxFromBlock(t, tc, fundingCHash, 10_000, 2, 'E', 'e')

		_, _, err = tc.AddBlock([]*externalapi.DomainHash{forkBase}, coinbaseData, []*externalapi.DomainTransaction{createA})
		if err != nil {
			t.Fatalf("AddBlock initial Atomic branch: %+v", err)
		}

		reorgBlock, _, err := tc.BuildBlockWithParents([]*externalapi.DomainHash{forkBase}, coinbaseData, []*externalapi.DomainTransaction{createB})
		if err != nil {
			t.Fatalf("BuildBlockWithParents reorg root: %+v", err)
		}
		reorgTip := consensushashing.BlockHash(reorgBlock)
		if err := tc.ValidateAndInsertBlock(reorgBlock, false); err != nil {
			t.Fatalf("ValidateAndInsertBlock pending reorg root: %+v", err)
		}
		for i := 0; i < 7; i++ {
			block, _, err := tc.BuildBlockWithParents([]*externalapi.DomainHash{reorgTip}, coinbaseData, nil)
			if err != nil {
				t.Fatalf("BuildBlockWithParents pending reorg extension %d: %+v", i, err)
			}
			reorgTip = consensushashing.BlockHash(block)
			if err := tc.ValidateAndInsertBlock(block, false); err != nil {
				t.Fatalf("ValidateAndInsertBlock pending reorg extension %d: %+v", i, err)
			}
		}

		_, isCompletelyResolved, err := tc.ResolveVirtualWithMaxParam(1)
		if err != nil {
			t.Fatalf("ResolveVirtual first chunk: %+v", err)
		}
		if isCompletelyResolved {
			t.Fatalf("test setup expected a partially resolved Atomic reorg after the first chunk")
		}

		emptyCoinbase := atomicReorgCoinbaseData()
		blockTemplate, err := tc.BuildBlockTemplate(emptyCoinbase, []*externalapi.DomainTransaction{createDuringReorg})
		if err != nil {
			t.Fatalf("BuildBlockTemplate with new Atomic tx during Atomic reorg resolution: %+v", err)
		}
		templateHash := consensushashing.BlockHash(blockTemplate.Block)

		if err := tc.ValidateAndInsertBlock(blockTemplate.Block, true); err != nil {
			t.Fatalf("new Atomic block must remain valid while Atomic reorg resolution is incomplete: %+v", err)
		}

		for !isCompletelyResolved {
			_, isCompletelyResolved, err = tc.ResolveVirtualWithMaxParam(1)
			if err != nil {
				t.Fatalf("ResolveVirtual completion: %+v", err)
			}
		}

		selectedParent, err := tc.GetVirtualSelectedParent()
		if err != nil {
			t.Fatalf("GetVirtualSelectedParent: %+v", err)
		}
		if _, ok, err := tc.GetAtomicTokenStateHash(selectedParent); err != nil {
			t.Fatalf("GetAtomicTokenStateHash selected parent: %+v", err)
		} else if !ok {
			t.Fatalf("selected parent must have an Atomic token state hash after Atomic reorg resolution")
		}
		valid, reason, err := tc.IsStoredBlockUTXOCommitmentValid(selectedParent)
		if err != nil {
			t.Fatalf("IsStoredBlockUTXOCommitmentValid: %+v", err)
		}
		if !valid {
			t.Fatalf("selected parent stored UTXO/Atomic commitment is invalid after Atomic reorg resolution: %s", reason)
		}
		status, err := tc.BlockStatusStore().Get(tc.DatabaseContext(), model.NewStagingArea(), templateHash)
		if err != nil {
			t.Fatalf("BlockStatusStore.Get mined Atomic template: %+v", err)
		}
		if status == externalapi.StatusDisqualifiedFromChain || status == externalapi.StatusInvalid {
			t.Fatalf("new Atomic block during reorg must not be rejected, got status %s", status)
		}
		createDuringReorgID := consensushashing.TransactionID(createDuringReorg)
		if !atomicReorgVirtualAcceptanceContainsAcceptedTx(t, tc, createDuringReorgID) {
			t.Fatalf("new Atomic transaction mined during reorg was not accepted into the resolved virtual state")
		}
	})
}

func atomicReorgCreateAssetTxFromBlock(
	t *testing.T,
	tc testapi.TestConsensus,
	fundingBlockHash *externalapi.DomainHash,
	fee uint64,
	nonce uint64,
	symbol byte,
	name byte,
) *externalapi.DomainTransaction {
	fundingBlock, _, err := tc.GetBlock(fundingBlockHash)
	if err != nil {
		t.Fatalf("GetBlock funding %s: %+v", fundingBlockHash, err)
	}
	tx, err := testutils.CreateTransaction(fundingBlock.Transactions[transactionhelper.CoinbaseTransactionIndex], fee)
	if err != nil {
		t.Fatalf("CreateTransaction from funding %s: %+v", fundingBlockHash, err)
	}
	tx.SubnetworkID = subnetworks.SubnetworkIDPayload
	tx.Payload = atomicReorgCreateAssetWithMintPayload(nonce, symbol, name)
	tx.Mass = 1_000
	return tx
}

func atomicReorgCoinbaseData() *externalapi.DomainCoinbaseData {
	scriptPublicKey, _ := testutils.OpTrueScript()
	return &externalapi.DomainCoinbaseData{ScriptPublicKey: scriptPublicKey}
}

func atomicReorgVirtualAcceptanceContainsAcceptedTx(
	t *testing.T,
	tc testapi.TestConsensus,
	transactionID *externalapi.DomainTransactionID,
) bool {
	acceptanceData, err := tc.AcceptanceDataStore().Get(tc.DatabaseContext(), model.NewStagingArea(), model.VirtualBlockHash)
	if err != nil {
		t.Fatalf("reading virtual acceptance data: %+v", err)
	}
	for _, blockAcceptanceData := range acceptanceData {
		for _, transactionAcceptanceData := range blockAcceptanceData.TransactionAcceptanceData {
			if transactionAcceptanceData.Transaction == nil {
				continue
			}
			if consensushashing.TransactionID(transactionAcceptanceData.Transaction).Equal(transactionID) {
				return transactionAcceptanceData.IsAccepted
			}
		}
	}
	return false
}

func atomicReorgCreateAssetWithMintPayload(nonce uint64, symbol byte, name byte) []byte {
	payload := atomicReorgCATPayloadHeader(4, nonce)
	payload = append(payload, 1, 0, 1)
	payload = atomicReorgAppendCATUint128(payload, 10_000)
	var mintAuthorityOwnerID [externalapi.DomainHashSize]byte
	mintAuthorityOwnerID[0] = 0x55
	payload = append(payload, mintAuthorityOwnerID[:]...)
	payload = append(payload, 1, 1)
	payload = atomicReorgAppendUint16LE(payload, 0)
	payload = append(payload, symbol, name)
	payload = atomicReorgAppendCATUint128(payload, 1)
	var initialMintToOwnerID [externalapi.DomainHashSize]byte
	initialMintToOwnerID[0] = 0x66
	return append(payload, initialMintToOwnerID[:]...)
}

func atomicReorgCATPayloadHeader(opcode byte, nonce uint64) []byte {
	payload := make([]byte, 16)
	copy(payload, []byte("CAT"))
	payload[3] = 1
	payload[4] = opcode
	binary.LittleEndian.PutUint16(payload[6:8], 0)
	binary.LittleEndian.PutUint64(payload[8:16], nonce)
	return payload
}

func atomicReorgAppendUint16LE(payload []byte, value uint16) []byte {
	var encoded [2]byte
	binary.LittleEndian.PutUint16(encoded[:], value)
	return append(payload, encoded[:]...)
}

func atomicReorgAppendCATUint128(payload []byte, value uint64) []byte {
	var encoded [16]byte
	binary.LittleEndian.PutUint64(encoded[:8], value)
	return append(payload, encoded[:]...)
}
