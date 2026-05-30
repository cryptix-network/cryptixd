package blocktemplatebuilder

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/ruleerrors"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/constants"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/txscript"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/utxo"
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

func TestOrderAtomicCandidateTransactionsOrdersSameOwnerNonceChain(t *testing.T) {
	var assetID [externalapi.DomainHashSize]byte
	assetID[0] = 0xAA
	nonceTwo := testCATCandidate(1, 0xA1, testTemplateCATTransferPayload(assetID, 2))
	nonceOne := testCATCandidate(2, 0xA1, testTemplateCATTransferPayload(assetID, 1))
	candidates := []*candidateTx{nonceTwo, nonceOne}

	orderAtomicCandidateTransactions(candidates)

	assertCandidateOrder(t, candidates, nonceOne, nonceTwo)
}

func TestOrderAtomicCandidateTransactionsOrdersLiquidityPoolNonceAcrossOwners(t *testing.T) {
	var assetID [externalapi.DomainHashSize]byte
	assetID[0] = 0xBB
	poolNonceTwo := testCATCandidate(1, 0xB1, testTemplateCATBuyPayload(assetID, 1, 2))
	poolNonceOne := testCATCandidate(2, 0xB2, testTemplateCATBuyPayload(assetID, 1, 1))
	candidates := []*candidateTx{poolNonceTwo, poolNonceOne}

	orderAtomicCandidateTransactions(candidates)

	assertCandidateOrder(t, candidates, poolNonceOne, poolNonceTwo)
}

func TestOrderAtomicCandidateTransactionsPlacesCreateBeforeReference(t *testing.T) {
	create := testCATCandidate(1, 0xC1, testTemplateCATCreateAssetPayload(1))
	assetID := *consensushashing.TransactionID(create.DomainTransaction).ByteArray()
	transfer := testCATCandidate(2, 0xC2, testTemplateCATTransferPayload(assetID, 1))
	candidates := []*candidateTx{transfer, create}

	orderAtomicCandidateTransactions(candidates)

	assertCandidateOrder(t, candidates, create, transfer)
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

func testCATCandidate(tag byte, ownerSeed byte, payload []byte) *candidateTx {
	tx := testTemplateTx(tag)
	tx.SubnetworkID = subnetworks.SubnetworkIDPayload
	tx.Payload = payload
	tx.Fee = 1
	tx.Mass = 1
	tx.Inputs[0].UTXOEntry = utxo.NewUTXOEntry(1, testTemplateOwnerScript(ownerSeed), false, 0)
	return &candidateTx{DomainTransaction: tx}
}

func testTemplateOwnerScript(seed byte) *externalapi.ScriptPublicKey {
	script := make([]byte, 34)
	script[0] = txscript.OpData32
	for i := 1; i <= 32; i++ {
		script[i] = seed
	}
	script[33] = txscript.OpCheckSig
	return &externalapi.ScriptPublicKey{Script: script, Version: constants.MaxScriptPublicKeyVersion}
}

func testTemplateCATTransferPayload(assetID [externalapi.DomainHashSize]byte, nonce uint64) []byte {
	payload := testTemplateCATPayloadHeader(1, nonce)
	payload = append(payload, assetID[:]...)
	var toOwnerID [externalapi.DomainHashSize]byte
	toOwnerID[0] = 0x77
	payload = append(payload, toOwnerID[:]...)
	return appendTemplateCATUint128(payload, 1)
}

func testTemplateCATCreateAssetPayload(nonce uint64) []byte {
	payload := testTemplateCATPayloadHeader(0, nonce)
	payload = append(payload, 1, 0, 0)
	payload = appendTemplateCATUint128(payload, 0)
	var mintAuthorityOwnerID [externalapi.DomainHashSize]byte
	mintAuthorityOwnerID[0] = 0x55
	payload = append(payload, mintAuthorityOwnerID[:]...)
	payload = append(payload, 1, 1)
	payload = appendTemplateUint16LE(payload, 0)
	payload = append(payload, 'A', 'A')
	return payload
}

func testTemplateCATBuyPayload(assetID [externalapi.DomainHashSize]byte, nonce uint64, expectedPoolNonce uint64) []byte {
	payload := testTemplateCATPayloadHeader(6, nonce)
	payload = append(payload, assetID[:]...)
	payload = appendTemplateUint64LE(payload, expectedPoolNonce)
	payload = appendTemplateUint64LE(payload, 1)
	return appendTemplateCATUint128(payload, 1)
}

func testTemplateCATPayloadHeader(opcode byte, nonce uint64) []byte {
	payload := make([]byte, 16)
	copy(payload, []byte("CAT"))
	payload[3] = 1
	payload[4] = opcode
	binary.LittleEndian.PutUint16(payload[6:8], 0)
	binary.LittleEndian.PutUint64(payload[8:16], nonce)
	return payload
}

func appendTemplateUint16LE(payload []byte, value uint16) []byte {
	var encoded [2]byte
	binary.LittleEndian.PutUint16(encoded[:], value)
	return append(payload, encoded[:]...)
}

func appendTemplateUint64LE(payload []byte, value uint64) []byte {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	return append(payload, encoded[:]...)
}

func appendTemplateCATUint128(payload []byte, value uint64) []byte {
	var encoded [16]byte
	binary.LittleEndian.PutUint64(encoded[:8], value)
	return append(payload, encoded[:]...)
}

func assertCandidateOrder(t *testing.T, got []*candidateTx, want ...*candidateTx) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("candidate count got %d want %d", len(got), len(want))
	}
	for i := range want {
		gotID := consensushashing.TransactionID(got[i].DomainTransaction)
		wantID := consensushashing.TransactionID(want[i].DomainTransaction)
		if !gotID.Equal(wantID) {
			t.Fatalf("candidate %d got %s want %s", i, gotID, wantID)
		}
	}
}
