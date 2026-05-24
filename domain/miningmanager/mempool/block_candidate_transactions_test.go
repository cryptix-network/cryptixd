package mempool

import (
	"encoding/binary"
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/constants"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/utxo"
	"github.com/cryptix-network/cryptixd/domain/dagconfig"
	mempoolmodel "github.com/cryptix-network/cryptixd/domain/miningmanager/mempool/model"
)

func TestBlockCandidateTransactionsKeepsPayloadTransactionsOutOfNativeSpamFilter(t *testing.T) {
	mp := &mempool{config: DefaultConfig(&dagconfig.SimnetParams)}
	mp.transactionsPool = newTransactionsPool(mp)

	payloadTx := lowFeeManyOutputTransaction(1, subnetworks.SubnetworkIDPayload, []byte{'C', 'A', 'T', 1})
	nativeTx := lowFeeManyOutputTransaction(2, subnetworks.SubnetworkIDNative, nil)

	for _, tx := range []*externalapi.DomainTransaction{payloadTx, nativeTx} {
		txID := consensushashing.TransactionID(tx)
		mp.transactionsPool.allTransactions[*txID] = mempoolmodel.NewMempoolTransaction(
			tx,
			mempoolmodel.IDToTransactionMap{},
			false,
			0,
		)
	}

	candidates := mp.BlockCandidateTransactions()
	if len(candidates) != 1 {
		t.Fatalf("expected only the payload/CAT transaction to survive candidate filtering, got %d", len(candidates))
	}
	if *consensushashing.TransactionID(candidates[0]) != *consensushashing.TransactionID(payloadTx) {
		t.Fatalf("payload/CAT transaction was filtered out of block candidates")
	}
}

func TestBlockCandidateTransactionsMixedCrossParityFixture(t *testing.T) {
	mp := &mempool{config: DefaultConfig(&dagconfig.SimnetParams)}
	mp.transactionsPool = newTransactionsPool(mp)
	mp.orphansPool = newOrphansPool(mp)

	var assetID [externalapi.DomainHashSize]byte
	assetID[0] = 0x42
	readyTxs := []*externalapi.DomainTransaction{
		mixedFixtureTransaction(1, subnetworks.SubnetworkIDNative, nil),
		mixedFixtureTransaction(2, subnetworks.SubnetworkIDNative, nil),
		mixedFixtureTransaction(3, subnetworks.SubnetworkIDNative, nil),
		mixedFixtureTransaction(4, subnetworks.SubnetworkIDNative, nil),
		mixedFixtureTransaction(10, subnetworks.SubnetworkIDPayload, []byte("MSG:alpha")),
		mixedFixtureTransaction(11, subnetworks.SubnetworkIDPayload, []byte("MSG:beta")),
		mixedFixtureTransaction(20, subnetworks.SubnetworkIDPayload, testCATCreateAssetPayload(1)),
		mixedFixtureTransaction(21, subnetworks.SubnetworkIDPayload, testCATMintPayload(assetID, 2)),
		mixedFixtureTransaction(22, subnetworks.SubnetworkIDPayload, testCATTransferPayload(assetID, 3)),
		mixedFixtureTransaction(23, subnetworks.SubnetworkIDPayload, testCATBuyPayload(assetID, 4, 100)),
		mixedFixtureTransaction(24, subnetworks.SubnetworkIDPayload, testCATSellPayload(assetID, 5, 101)),
	}

	for _, tx := range readyTxs {
		txID := consensushashing.TransactionID(tx)
		mp.transactionsPool.allTransactions[*txID] = mempoolmodel.NewMempoolTransaction(
			tx,
			mempoolmodel.IDToTransactionMap{},
			false,
			0,
		)
	}

	orphanTx := mixedFixtureTransaction(90, subnetworks.SubnetworkIDPayload, testCATBuyPayload(assetID, 6, 102))
	orphanID := consensushashing.TransactionID(orphanTx)
	orphan := mempoolmodel.NewOrphanTransaction(orphanTx, false, 0)
	mp.orphansPool.allOrphans[*orphanID] = orphan
	for _, input := range orphanTx.Inputs {
		mp.orphansPool.orphansByPreviousOutpoint[input.PreviousOutpoint] = orphan
	}

	candidates := mp.BlockCandidateTransactions()
	assertCrossParityCandidateShape(t, candidates, 4, 7, orphanID)
}

func lowFeeManyOutputTransaction(index uint32, subnetworkID externalapi.DomainSubnetworkID, payload []byte) *externalapi.DomainTransaction {
	scriptPublicKey := &externalapi.ScriptPublicKey{Script: []byte{0x51}, Version: 0}
	prevOutPoint := externalapi.DomainOutpoint{TransactionID: externalapi.DomainTransactionID{}, Index: index}
	txInput := &externalapi.DomainTransactionInput{
		PreviousOutpoint: prevOutPoint,
		Sequence:         constants.MaxTxInSequenceNum,
		UTXOEntry:        utxo.NewUTXOEntry(constants.SompiPerCryptix, scriptPublicKey, false, 1),
	}
	outputs := make([]*externalapi.DomainTransactionOutput, 0, 5)
	for i := 0; i < 5; i++ {
		outputs = append(outputs, &externalapi.DomainTransactionOutput{
			Value:           10_000,
			ScriptPublicKey: scriptPublicKey,
		})
	}
	return &externalapi.DomainTransaction{
		Version:      constants.MaxTransactionVersion,
		Inputs:       []*externalapi.DomainTransactionInput{txInput},
		Outputs:      outputs,
		SubnetworkID: subnetworkID,
		Gas:          0,
		Fee:          1,
		Mass:         1,
		Payload:      payload,
	}
}

func mixedFixtureTransaction(index uint32, subnetworkID externalapi.DomainSubnetworkID, payload []byte) *externalapi.DomainTransaction {
	scriptPublicKey := &externalapi.ScriptPublicKey{Script: []byte{0x51}, Version: 0}
	prevOutPoint := externalapi.DomainOutpoint{TransactionID: externalapi.DomainTransactionID{}, Index: index}
	txInput := &externalapi.DomainTransactionInput{
		PreviousOutpoint: prevOutPoint,
		Sequence:         constants.MaxTxInSequenceNum,
		UTXOEntry:        utxo.NewUTXOEntry(constants.SompiPerCryptix, scriptPublicKey, false, 1),
	}
	return &externalapi.DomainTransaction{
		Version:      constants.MaxTransactionVersion,
		Inputs:       []*externalapi.DomainTransactionInput{txInput},
		Outputs:      []*externalapi.DomainTransactionOutput{{Value: constants.SompiPerCryptix - 10_000, ScriptPublicKey: scriptPublicKey}},
		SubnetworkID: subnetworkID,
		Gas:          0,
		Fee:          10_000,
		Mass:         1,
		Payload:      payload,
	}
}

func assertCrossParityCandidateShape(
	t *testing.T,
	candidates []*externalapi.DomainTransaction,
	expectedNative int,
	expectedPayload int,
	excludedOrphanID *externalapi.DomainTransactionID,
) {
	t.Helper()
	if len(candidates) != expectedNative+expectedPayload {
		t.Fatalf("cross-parity candidate count: expected %d, got %d", expectedNative+expectedPayload, len(candidates))
	}
	nativeCount := 0
	payloadCount := 0
	for _, tx := range candidates {
		if *consensushashing.TransactionID(tx) == *excludedOrphanID {
			t.Fatalf("orphan CAT entered block candidates")
		}
		if tx.SubnetworkID == subnetworks.SubnetworkIDPayload {
			payloadCount++
		} else if tx.SubnetworkID == subnetworks.SubnetworkIDNative {
			nativeCount++
		} else {
			t.Fatalf("unexpected subnetwork %s in cross-parity fixture", tx.SubnetworkID)
		}
	}
	if nativeCount != expectedNative || payloadCount != expectedPayload {
		t.Fatalf("cross-parity candidate shape: native=%d payload=%d, expected native=%d payload=%d",
			nativeCount, payloadCount, expectedNative, expectedPayload)
	}
}

func testCATCreateAssetPayload(nonce uint64) []byte {
	payload := testCATPayloadHeader(0, nonce)
	payload = append(payload, 1, 0, 0)
	payload = appendCATUint128ForCandidate(payload, 0)
	var mintAuthorityOwnerID [externalapi.DomainHashSize]byte
	mintAuthorityOwnerID[0] = 0x55
	payload = append(payload, mintAuthorityOwnerID[:]...)
	payload = append(payload, 1, 1)
	payload = appendUint16LEForCandidate(payload, 0)
	payload = append(payload, 'A', 'A')
	return payload
}

func testCATMintPayload(assetID [externalapi.DomainHashSize]byte, nonce uint64) []byte {
	payload := testCATPayloadHeader(2, nonce)
	payload = append(payload, assetID[:]...)
	var toOwnerID [externalapi.DomainHashSize]byte
	toOwnerID[0] = 0x66
	payload = append(payload, toOwnerID[:]...)
	return appendCATUint128ForCandidate(payload, 1)
}

func testCATTransferPayload(assetID [externalapi.DomainHashSize]byte, nonce uint64) []byte {
	payload := testCATPayloadHeader(1, nonce)
	payload = append(payload, assetID[:]...)
	var toOwnerID [externalapi.DomainHashSize]byte
	toOwnerID[0] = 0x77
	payload = append(payload, toOwnerID[:]...)
	return appendCATUint128ForCandidate(payload, 1)
}

func testCATBuyPayload(assetID [externalapi.DomainHashSize]byte, nonce uint64, expectedPoolNonce uint64) []byte {
	payload := testCATPayloadHeader(6, nonce)
	payload = append(payload, assetID[:]...)
	payload = appendUint64LEForCandidate(payload, expectedPoolNonce)
	payload = appendUint64LEForCandidate(payload, 1)
	return appendCATUint128ForCandidate(payload, 1)
}

func testCATSellPayload(assetID [externalapi.DomainHashSize]byte, nonce uint64, expectedPoolNonce uint64) []byte {
	payload := testCATPayloadHeader(7, nonce)
	payload = append(payload, assetID[:]...)
	payload = appendUint64LEForCandidate(payload, expectedPoolNonce)
	payload = appendCATUint128ForCandidate(payload, 1)
	payload = appendUint64LEForCandidate(payload, 1)
	return appendUint16LEForCandidate(payload, 1)
}

func testCATPayloadHeader(opcode byte, nonce uint64) []byte {
	payload := make([]byte, 16)
	copy(payload, []byte("CAT"))
	payload[3] = 1
	payload[4] = opcode
	binary.LittleEndian.PutUint16(payload[6:8], 0)
	binary.LittleEndian.PutUint64(payload[8:16], nonce)
	return payload
}

func appendUint16LEForCandidate(payload []byte, value uint16) []byte {
	var encoded [2]byte
	binary.LittleEndian.PutUint16(encoded[:], value)
	return append(payload, encoded[:]...)
}

func appendUint64LEForCandidate(payload []byte, value uint64) []byte {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	return append(payload, encoded[:]...)
}

func appendCATUint128ForCandidate(payload []byte, value uint64) []byte {
	var encoded [16]byte
	binary.LittleEndian.PutUint64(encoded[:8], value)
	return append(payload, encoded[:]...)
}
