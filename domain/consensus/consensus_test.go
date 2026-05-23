package consensus_test

import (
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus"
	"github.com/cryptix-network/cryptixd/domain/consensus/model"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/ruleerrors"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/testutils"
	"github.com/cryptix-network/cryptixd/util/staging"
	"github.com/pkg/errors"
)

func TestConsensus_GetBlockInfo(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		factory := consensus.NewFactory()
		consensus, teardown, err := factory.NewTestConsensus(consensusConfig, "TestConsensus_GetBlockInfo")
		if err != nil {
			t.Fatalf("Error setting up consensus: %+v", err)
		}
		defer teardown(false)

		invalidBlock, _, err := consensus.BuildBlockWithParents([]*externalapi.DomainHash{consensusConfig.GenesisHash}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		newHeader := invalidBlock.Header.ToMutable()
		newHeader.SetTimeInMilliseconds(0)
		invalidBlock.Header = newHeader.ToImmutable()
		err = consensus.ValidateAndInsertBlock(invalidBlock, true)
		if !errors.Is(err, ruleerrors.ErrTimeTooOld) {
			t.Fatalf("Expected block to be invalid with err: %v, instead found: %v", ruleerrors.ErrTimeTooOld, err)
		}

		info, err := consensus.GetBlockInfo(consensushashing.BlockHash(invalidBlock))
		if err != nil {
			t.Fatalf("Failed to get block info: %v", err)
		}

		if !info.Exists {
			t.Fatal("The block is missing")
		}
		if info.BlockStatus != externalapi.StatusInvalid {
			t.Fatalf("Expected block status: %s, instead got: %s", externalapi.StatusInvalid, info.BlockStatus)
		}

		emptyCoinbase := externalapi.DomainCoinbaseData{
			ScriptPublicKey: &externalapi.ScriptPublicKey{
				Script:  nil,
				Version: 0,
			},
		}
		validBlock, err := consensus.BuildBlock(&emptyCoinbase, nil)
		if err != nil {
			t.Fatalf("consensus.BuildBlock with an empty coinbase shouldn't fail: %v", err)
		}

		err = consensus.ValidateAndInsertBlock(validBlock, true)
		if err != nil {
			t.Fatalf("consensus.ValidateAndInsertBlock with a block straight from consensus.BuildBlock should not fail: %v", err)
		}

		info, err = consensus.GetBlockInfo(consensushashing.BlockHash(validBlock))
		if err != nil {
			t.Fatalf("Failed to get block info: %v", err)
		}

		if !info.Exists {
			t.Fatal("The block is missing")
		}
		if info.BlockStatus != externalapi.StatusUTXOValid {
			t.Fatalf("Expected block status: %s, instead got: %s", externalapi.StatusUTXOValid, info.BlockStatus)
		}

	})
}

func TestConsensus_BuildBlockTemplateRefusesDisqualifiedVirtualSelectedParent(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		factory := consensus.NewFactory()
		testConsensus, teardown, err := factory.NewTestConsensus(consensusConfig, "TestConsensus_BuildBlockTemplateRefusesDisqualifiedVirtualSelectedParent")
		if err != nil {
			t.Fatalf("Error setting up consensus: %+v", err)
		}
		defer teardown(false)

		selectedParent, _, err := testConsensus.AddBlock([]*externalapi.DomainHash{consensusConfig.GenesisHash}, nil, nil)
		if err != nil {
			t.Fatalf("Error adding selected parent block: %+v", err)
		}

		stagingArea := model.NewStagingArea()
		testConsensus.BlockStatusStore().Stage(stagingArea, selectedParent, externalapi.StatusDisqualifiedFromChain)
		err = staging.CommitAllChanges(testConsensus.DatabaseContext(), stagingArea)
		if err != nil {
			t.Fatalf("Error staging disqualified selected parent: %+v", err)
		}

		emptyCoinbase := externalapi.DomainCoinbaseData{
			ScriptPublicKey: &externalapi.ScriptPublicKey{
				Script:  nil,
				Version: 0,
			},
		}
		_, err = testConsensus.BuildBlockTemplate(&emptyCoinbase, nil)
		if err == nil {
			t.Fatalf("expected BuildBlockTemplate to refuse a disqualified virtual selected parent")
		}
	})
}
