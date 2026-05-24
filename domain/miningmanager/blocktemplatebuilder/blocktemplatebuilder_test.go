package blocktemplatebuilder

import (
	"errors"
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/ruleerrors"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
)

func TestSplitTemplateInvalidTransactionsKeepsMissingInputsInMempool(t *testing.T) {
	missingInputTx := testTemplateTx(1)
	permanentlyInvalidTx := testTemplateTx(2)

	missingRuleError := testRuleError(t, ruleerrors.NewErrMissingTxOut([]*externalapi.DomainOutpoint{
		externalapi.NewDomainOutpoint(testTransactionID(3), 0),
	}))
	permanentRuleError := ruleerrors.ErrNoTxInputs
	invalidTxsErr := &ruleerrors.ErrInvalidTransactionsInNewBlock{InvalidTransactions: []ruleerrors.InvalidTransaction{
		{Transaction: missingInputTx, Error: missingRuleError},
		{Transaction: permanentlyInvalidTx, Error: &permanentRuleError},
	}}
	excludedMissingInputTxs := map[externalapi.DomainTransactionID]struct{}{}

	removableInvalidTxs, missingInputTxs := splitTemplateInvalidTransactions(invalidTxsErr, excludedMissingInputTxs)

	missingInputTxID := consensushashing.TransactionID(missingInputTx)
	if _, ok := excludedMissingInputTxs[*missingInputTxID]; !ok {
		t.Fatalf("expected missing-input transaction %s to be excluded only from the current template attempt", missingInputTxID)
	}
	if len(missingInputTxs) != 1 || missingInputTxs[0] != missingInputTxID.String() {
		t.Fatalf("expected missing-input transaction log list to contain %s, got %v", missingInputTxID, missingInputTxs)
	}
	if len(removableInvalidTxs.InvalidTransactions) != 1 {
		t.Fatalf("expected only permanently invalid transaction to be removable, got %d", len(removableInvalidTxs.InvalidTransactions))
	}
	if removableInvalidTxs.InvalidTransactions[0].Transaction != permanentlyInvalidTx {
		t.Fatalf("missing-input transaction was classified as removable from mempool")
	}
}

func TestCountPayloadCandidateTransactionsIgnoresExcludedTransactions(t *testing.T) {
	payloadCandidate := &candidateTx{DomainTransaction: testPayloadTemplateTx(1)}
	regularCandidate := &candidateTx{DomainTransaction: testTemplateTx(2)}

	if count := countPayloadCandidateTransactions([]*candidateTx{payloadCandidate, regularCandidate}); count != 1 {
		t.Fatalf("expected 1 payload candidate, got %d", count)
	}
}

func testRuleError(t *testing.T, err error) *ruleerrors.RuleError {
	t.Helper()

	ruleError := &ruleerrors.RuleError{}
	if !errors.As(err, ruleError) {
		t.Fatalf("expected RuleError, got %v", err)
	}
	return ruleError
}

func testTemplateTx(tag byte) *externalapi.DomainTransaction {
	return &externalapi.DomainTransaction{
		Version: 0,
		Inputs: []*externalapi.DomainTransactionInput{{
			PreviousOutpoint: *externalapi.NewDomainOutpoint(testTransactionID(tag), uint32(tag)),
			Sequence:         uint64(tag),
		}},
		Outputs: []*externalapi.DomainTransactionOutput{{
			Value:           uint64(tag) + 1,
			ScriptPublicKey: &externalapi.ScriptPublicKey{Script: []byte{tag}, Version: 0},
		}},
		SubnetworkID: subnetworks.SubnetworkIDNative,
	}
}

func testPayloadTemplateTx(tag byte) *externalapi.DomainTransaction {
	tx := testTemplateTx(tag)
	tx.SubnetworkID = subnetworks.SubnetworkIDPayload
	tx.Payload = []byte{tag}
	return tx
}

func testTransactionID(tag byte) *externalapi.DomainTransactionID {
	var bytes [externalapi.DomainHashSize]byte
	bytes[0] = tag
	return externalapi.NewDomainTransactionIDFromByteArray(&bytes)
}
