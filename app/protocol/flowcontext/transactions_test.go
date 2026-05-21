package flowcontext

import (
	"testing"
	"time"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/miningmanager"
	miningmanagerapi "github.com/cryptix-network/cryptixd/domain/miningmanager/model"
)

type fakeMiningManager struct {
	clearCalls int
}

func (m *fakeMiningManager) GetBlockTemplate(*externalapi.DomainCoinbaseData) (*externalapi.DomainBlock, bool, error) {
	panic("not implemented")
}

func (m *fakeMiningManager) ClearBlockTemplate() {
	m.clearCalls++
}

func (m *fakeMiningManager) GetBlockTemplateBuilder() miningmanagerapi.BlockTemplateBuilder {
	panic("not implemented")
}

func (m *fakeMiningManager) GetTransaction(*externalapi.DomainTransactionID, bool, bool) (*externalapi.DomainTransaction, bool, bool) {
	panic("not implemented")
}

func (m *fakeMiningManager) GetTransactionsByAddresses(bool, bool) (
	map[string]*externalapi.DomainTransaction,
	map[string]*externalapi.DomainTransaction,
	map[string]*externalapi.DomainTransaction,
	map[string]*externalapi.DomainTransaction,
	error,
) {
	panic("not implemented")
}

func (m *fakeMiningManager) AllTransactions(bool, bool) ([]*externalapi.DomainTransaction, []*externalapi.DomainTransaction) {
	panic("not implemented")
}

func (m *fakeMiningManager) TransactionCount(bool, bool) int {
	return 0
}

func (m *fakeMiningManager) HandleNewBlockTransactions([]*externalapi.DomainTransaction) ([]*externalapi.DomainTransaction, error) {
	panic("not implemented")
}

func (m *fakeMiningManager) HandleAcceptedTransactions([]*externalapi.DomainTransaction) ([]*externalapi.DomainTransaction, error) {
	panic("not implemented")
}

func (m *fakeMiningManager) ValidateAndInsertTransaction(*externalapi.DomainTransaction, bool, bool) ([]*externalapi.DomainTransaction, error) {
	panic("not implemented")
}

func (m *fakeMiningManager) RevalidateHighPriorityTransactions() ([]*externalapi.DomainTransaction, error) {
	panic("not implemented")
}

func (m *fakeMiningManager) RevalidateOrphanTransactions() ([]*externalapi.DomainTransaction, error) {
	return nil, nil
}

func (m *fakeMiningManager) ExpireLowPriorityTransactions() (int, int, error) {
	return 0, 0, nil
}

type testDomain struct {
	mining miningmanager.MiningManager
}

func (d *testDomain) MiningManager() miningmanager.MiningManager {
	return d.mining
}

func (d *testDomain) Consensus() externalapi.Consensus {
	panic("not implemented")
}

func (d *testDomain) StagingConsensus() externalapi.Consensus {
	panic("not implemented")
}

func (d *testDomain) InitStagingConsensusWithoutGenesis() error {
	panic("not implemented")
}

func (d *testDomain) CommitStagingConsensus() error {
	panic("not implemented")
}

func (d *testDomain) DeleteStagingConsensus() error {
	panic("not implemented")
}

func (d *testDomain) ConsensusEventsChannel() chan externalapi.ConsensusEvent {
	panic("not implemented")
}

func TestOnTransactionAddedToMempoolClearsTemplateAndCallsHandler(t *testing.T) {
	mining := &fakeMiningManager{}
	ctx := &FlowContext{
		domain:                           &testDomain{mining: mining},
		lastTransactionIDPropagationTime: time.Now(),
	}

	handlerCalls := 0
	ctx.SetOnTransactionAddedToMempoolHandler(func() {
		handlerCalls++
	})

	ctx.OnTransactionAddedToMempool()

	if mining.clearCalls != 1 {
		t.Fatalf("expected ClearBlockTemplate to be called once, got %d", mining.clearCalls)
	}
	if handlerCalls != 1 {
		t.Fatalf("expected transaction-added handler to be called once, got %d", handlerCalls)
	}
}

func TestExpandTransactionIDsWithMempoolParentsOrdersParentsBeforeChildren(t *testing.T) {
	parentID := testTransactionID(1)
	childID := testTransactionID(2)
	grandChildID := testTransactionID(3)

	transactions := map[externalapi.DomainTransactionID]*externalapi.DomainTransaction{
		*parentID: {
			Inputs: []*externalapi.DomainTransactionInput{},
		},
		*childID: {
			Inputs: []*externalapi.DomainTransactionInput{{
				PreviousOutpoint: externalapi.DomainOutpoint{TransactionID: *parentID, Index: 0},
			}},
		},
		*grandChildID: {
			Inputs: []*externalapi.DomainTransactionInput{{
				PreviousOutpoint: externalapi.DomainOutpoint{TransactionID: *childID, Index: 0},
			}},
		},
	}

	expanded := expandTransactionIDsWithMempoolParents(
		[]*externalapi.DomainTransactionID{grandChildID},
		func(transactionID *externalapi.DomainTransactionID) (*externalapi.DomainTransaction, bool) {
			transaction, ok := transactions[*transactionID]
			return transaction, ok
		})

	assertTransactionIDOrder(t, expanded, []*externalapi.DomainTransactionID{parentID, childID, grandChildID})
}

func TestExpandTransactionIDsWithMempoolParentsSkipsUnknownParents(t *testing.T) {
	missingParentID := testTransactionID(1)
	childID := testTransactionID(2)
	transactions := map[externalapi.DomainTransactionID]*externalapi.DomainTransaction{
		*childID: {
			Inputs: []*externalapi.DomainTransactionInput{{
				PreviousOutpoint: externalapi.DomainOutpoint{TransactionID: *missingParentID, Index: 0},
			}},
		},
	}

	expanded := expandTransactionIDsWithMempoolParents(
		[]*externalapi.DomainTransactionID{childID},
		func(transactionID *externalapi.DomainTransactionID) (*externalapi.DomainTransaction, bool) {
			transaction, ok := transactions[*transactionID]
			return transaction, ok
		})

	assertTransactionIDOrder(t, expanded, []*externalapi.DomainTransactionID{childID})
}

func testTransactionID(tag byte) *externalapi.DomainTransactionID {
	var bytes [externalapi.DomainHashSize]byte
	bytes[externalapi.DomainHashSize-1] = tag
	return externalapi.NewDomainTransactionIDFromByteArray(&bytes)
}

func assertTransactionIDOrder(t *testing.T, actual []*externalapi.DomainTransactionID, expected []*externalapi.DomainTransactionID) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("expected %d transaction IDs, got %d", len(expected), len(actual))
	}
	for i := range expected {
		if !actual[i].Equal(expected[i]) {
			t.Fatalf("expected transaction ID %s at index %d, got %s", expected[i], i, actual[i])
		}
	}
}
