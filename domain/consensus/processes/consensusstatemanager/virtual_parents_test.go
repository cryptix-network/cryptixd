package consensusstatemanager_test

import (
	"sort"
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus"
	"github.com/cryptix-network/cryptixd/domain/consensus/model"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/testapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/testutils"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/transactionhelper"
)

func TestConsensusStateManager_pickVirtualParents(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		stagingArea := model.NewStagingArea()

		tc, teardown, err := consensus.NewFactory().NewTestConsensus(consensusConfig, "TestConsensusStateManager_pickVirtualParents")
		if err != nil {
			t.Fatalf("Error setting up tc: %+v", err)
		}
		defer teardown(false)

		getSortedVirtualParents := func(tc testapi.TestConsensus) []*externalapi.DomainHash {
			virtualRelations, err := tc.BlockRelationStore().BlockRelation(tc.DatabaseContext(), stagingArea, model.VirtualBlockHash)
			if err != nil {
				t.Fatalf("Failed getting virtual block virtualRelations: %v", err)
			}

			block, err := tc.BuildBlock(&externalapi.DomainCoinbaseData{ScriptPublicKey: &externalapi.ScriptPublicKey{Script: nil, Version: 0}}, nil)
			if err != nil {
				t.Fatalf("Consensus failed building a block: %v", err)
			}
			blockParents := block.Header.DirectParents()
			sort.Sort(testutils.NewTestGhostDAGSorter(stagingArea, virtualRelations.Parents, tc, t))
			sort.Sort(testutils.NewTestGhostDAGSorter(stagingArea, blockParents, tc, t))
			if !externalapi.HashesEqual(virtualRelations.Parents, blockParents) {
				t.Fatalf("Block relations and BuildBlock return different parents for virtual, %s != %s", virtualRelations.Parents, blockParents)
			}
			return virtualRelations.Parents
		}

		// We build 2*consensusConfig.MaxBlockParents each one with blueWork higher than the other.
		parents := make([]*externalapi.DomainHash, 0, consensusConfig.MaxBlockParents)
		for i := 0; i < 2*int(consensusConfig.MaxBlockParents); i++ {
			lastBlock := consensusConfig.GenesisHash
			for j := 0; j <= i; j++ {
				lastBlock, _, err = tc.AddBlock([]*externalapi.DomainHash{lastBlock}, nil, nil)
				if err != nil {
					t.Fatalf("Failed Adding block to tc: %+v", err)
				}
			}
			parents = append(parents, lastBlock)
		}

		virtualParents := getSortedVirtualParents(tc)
		sort.Sort(testutils.NewTestGhostDAGSorter(stagingArea, parents, tc, t))

		// Make sure the first half of the blocks are with highest blueWork
		// we use (max+1)/2 because the first "half" is rounded up, so `(dividend + (divisor - 1)) / divisor` = `(max + (2-1))/2` = `(max+1)/2`
		for i := 0; i < int(consensusConfig.MaxBlockParents+1)/2; i++ {
			if !virtualParents[i].Equal(parents[i]) {
				t.Fatalf("Expected block at %d to be equal, instead found %s != %s", i, virtualParents[i], parents[i])
			}
		}

		// Make sure the second half is the candidates with lowest blueWork
		end := len(parents) - int(consensusConfig.MaxBlockParents)/2
		for i := (consensusConfig.MaxBlockParents + 1) / 2; i < consensusConfig.MaxBlockParents; i++ {
			if !virtualParents[i].Equal(parents[end]) {
				t.Fatalf("Expected block at %d to be equal, instead found %s != %s", i, virtualParents[i], parents[end])
			}
			end++
		}
		if end != len(parents) {
			t.Fatalf("Expected %d==%d", end, len(parents))
		}

		// Clear all tips.
		var virtualSelectedParent *externalapi.DomainHash
		for {
			block, err := tc.BuildBlock(&externalapi.DomainCoinbaseData{ScriptPublicKey: &externalapi.ScriptPublicKey{Script: nil, Version: 0}, ExtraData: nil}, nil)
			if err != nil {
				t.Fatalf("Failed building a block: %v", err)
			}
			err = tc.ValidateAndInsertBlock(block, true)
			if err != nil {
				t.Fatalf("Failed Inserting block to tc: %v", err)
			}
			virtualSelectedParent = consensushashing.BlockHash(block)
			if len(block.Header.DirectParents()) == 1 {
				break
			}
		}
		// build exactly consensusConfig.MaxBlockParents
		parents = make([]*externalapi.DomainHash, 0, consensusConfig.MaxBlockParents)
		for i := 0; i < int(consensusConfig.MaxBlockParents); i++ {
			block, _, err := tc.AddBlock([]*externalapi.DomainHash{virtualSelectedParent}, nil, nil)
			if err != nil {
				t.Fatalf("Failed Adding block to tc: %+v", err)
			}
			parents = append(parents, block)
		}

		sort.Sort(testutils.NewTestGhostDAGSorter(stagingArea, parents, tc, t))
		virtualParents = getSortedVirtualParents(tc)
		if !externalapi.HashesEqual(virtualParents, parents) {
			t.Fatalf("Expected VirtualParents and parents to be equal, instead: %s != %s", virtualParents, parents)
		}
	})
}

func TestConsensusStateManager_pickVirtualParentsSkipsDisqualifiedTips(t *testing.T) {
	testutils.ForAllNets(t, true, func(t *testing.T, consensusConfig *consensus.Config) {
		stagingArea := model.NewStagingArea()
		consensusConfig.BlockCoinbaseMaturity = 0

		tc, teardown, err := consensus.NewFactory().NewTestConsensus(consensusConfig, "TestConsensusStateManager_pickVirtualParentsSkipsDisqualifiedTips")
		if err != nil {
			t.Fatalf("Error setting up tc: %+v", err)
		}
		defer teardown(false)

		firstBlockHash, _, err := tc.AddBlock([]*externalapi.DomainHash{consensusConfig.GenesisHash}, nil, nil)
		if err != nil {
			t.Fatalf("Failed adding first block: %+v", err)
		}
		fundingBlockHash, _, err := tc.AddBlock([]*externalapi.DomainHash{firstBlockHash}, nil, nil)
		if err != nil {
			t.Fatalf("Failed adding funding block: %+v", err)
		}
		fundingBlock, _, err := tc.GetBlock(fundingBlockHash)
		if err != nil {
			t.Fatalf("Failed getting funding block: %+v", err)
		}
		spendingTransaction, err := testutils.CreateTransaction(fundingBlock.Transactions[transactionhelper.CoinbaseTransactionIndex], 1)
		if err != nil {
			t.Fatalf("Failed creating spending transaction: %+v", err)
		}
		goodBlockHash, _, err := tc.AddBlock([]*externalapi.DomainHash{fundingBlockHash}, nil, []*externalapi.DomainTransaction{spendingTransaction})
		if err != nil {
			t.Fatalf("Failed adding good block: %+v", err)
		}

		disqualifiedTip, _, err := tc.AddBlock([]*externalapi.DomainHash{goodBlockHash}, nil, []*externalapi.DomainTransaction{spendingTransaction})
		if err != nil {
			t.Fatalf("Failed adding disqualified candidate block body: %+v", err)
		}
		disqualifiedStatus, err := tc.BlockStatusStore().Get(tc.DatabaseContext(), stagingArea, disqualifiedTip)
		if err != nil {
			t.Fatalf("Failed getting disqualified candidate status: %+v", err)
		}
		if disqualifiedStatus != externalapi.StatusDisqualifiedFromChain {
			t.Fatalf("Expected disqualified candidate status %s, got %s", externalapi.StatusDisqualifiedFromChain, disqualifiedStatus)
		}

		validTip, _, err := tc.AddBlock([]*externalapi.DomainHash{goodBlockHash}, nil, nil)
		if err != nil {
			t.Fatalf("Failed adding valid sibling tip: %+v", err)
		}
		validStatus, err := tc.BlockStatusStore().Get(tc.DatabaseContext(), stagingArea, validTip)
		if err != nil {
			t.Fatalf("Failed getting valid tip status: %+v", err)
		}
		if validStatus != externalapi.StatusUTXOValid {
			t.Fatalf("Expected valid tip status %s, got %s", externalapi.StatusUTXOValid, validStatus)
		}

		tips, err := tc.ConsensusStateStore().Tips(stagingArea, tc.DatabaseContext())
		if err != nil {
			t.Fatalf("Failed getting consensus tips: %+v", err)
		}
		for _, tip := range tips {
			if tip.Equal(disqualifiedTip) {
				t.Fatalf("Disqualified tip %s must be pruned from consensus tips; tips: %s", disqualifiedTip, tips)
			}
		}

		virtualRelations, err := tc.BlockRelationStore().BlockRelation(tc.DatabaseContext(), stagingArea, model.VirtualBlockHash)
		if err != nil {
			t.Fatalf("Failed getting virtual parents: %+v", err)
		}
		for _, parent := range virtualRelations.Parents {
			if parent.Equal(disqualifiedTip) {
				t.Fatalf("Disqualified tip %s must not be a virtual parent; virtual parents: %s", disqualifiedTip, virtualRelations.Parents)
			}
		}
	})
}
