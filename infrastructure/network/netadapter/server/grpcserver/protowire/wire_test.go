package protowire

import (
	"bytes"
	"errors"
	"testing"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
)

func TestToAppMessageUnknownPayload(t *testing.T) {
	message := &CryptixdMessage{}
	_, err := message.ToAppMessage()
	if !errors.Is(err, ErrUnknownMessagePayload) {
		t.Fatalf("expected ErrUnknownMessagePayload, got %v", err)
	}
}

func TestRequestFastIntentsRoundTrip(t *testing.T) {
	intentID1 := testDomainHash(t, 0x11)
	intentID2 := testDomainHash(t, 0x22)
	input := &appmessage.MsgRequestFastIntents{IntentIDs: []*externalapi.DomainHash{intentID1, intentID2}}

	protoMessage, err := FromAppMessage(input)
	if err != nil {
		t.Fatalf("FromAppMessage failed: %v", err)
	}

	appMsg, err := protoMessage.ToAppMessage()
	if err != nil {
		t.Fatalf("ToAppMessage failed: %v", err)
	}

	got, ok := appMsg.(*appmessage.MsgRequestFastIntents)
	if !ok {
		t.Fatalf("unexpected message type %T", appMsg)
	}
	if len(got.IntentIDs) != 2 {
		t.Fatalf("expected 2 intent IDs, got %d", len(got.IntentIDs))
	}
	if !bytes.Equal(got.IntentIDs[0].ByteSlice(), intentID1.ByteSlice()) {
		t.Fatalf("intent ID 0 mismatch")
	}
	if !bytes.Equal(got.IntentIDs[1].ByteSlice(), intentID2.ByteSlice()) {
		t.Fatalf("intent ID 1 mismatch")
	}
}

func TestFastIntentRoundTrip(t *testing.T) {
	intentID := testDomainHash(t, 0x33)
	input := &appmessage.MsgFastIntent{
		IntentID: intentID,
		BaseTransaction: &appmessage.MsgTx{
			Version:      7,
			TxIn:         []*appmessage.TxIn{},
			TxOut:        []*appmessage.TxOut{},
			LockTime:     99,
			SubnetworkID: subnetworks.SubnetworkIDNative,
			Gas:          55,
			Payload:      []byte{0xAB, 0xCD},
			Mass:         88,
		},
		IntentNonce:       101,
		ClientCreatedAtMs: 202,
		MaxFee:            303,
	}

	protoMessage, err := FromAppMessage(input)
	if err != nil {
		t.Fatalf("FromAppMessage failed: %v", err)
	}

	appMsg, err := protoMessage.ToAppMessage()
	if err != nil {
		t.Fatalf("ToAppMessage failed: %v", err)
	}

	got, ok := appMsg.(*appmessage.MsgFastIntent)
	if !ok {
		t.Fatalf("unexpected message type %T", appMsg)
	}
	if !bytes.Equal(got.IntentID.ByteSlice(), intentID.ByteSlice()) {
		t.Fatalf("intent ID mismatch")
	}
	if got.IntentNonce != input.IntentNonce || got.ClientCreatedAtMs != input.ClientCreatedAtMs || got.MaxFee != input.MaxFee {
		t.Fatalf("fast intent metadata mismatch")
	}
	if got.BaseTransaction == nil {
		t.Fatalf("base transaction is nil")
	}
	if got.BaseTransaction.Mass != input.BaseTransaction.Mass {
		t.Fatalf("base transaction mass mismatch: got %d, want %d", got.BaseTransaction.Mass, input.BaseTransaction.Mass)
	}
	if !bytes.Equal(got.BaseTransaction.Payload, input.BaseTransaction.Payload) {
		t.Fatalf("base transaction payload mismatch")
	}
}

func TestFastMicroblockRoundTrip(t *testing.T) {
	intentID1 := testDomainHash(t, 0x44)
	intentID2 := testDomainHash(t, 0x55)
	input := &appmessage.MsgFastMicroblock{
		MicroblockTimeMs: 777,
		IntentIDs:        []*externalapi.DomainHash{intentID1, intentID2},
	}

	protoMessage, err := FromAppMessage(input)
	if err != nil {
		t.Fatalf("FromAppMessage failed: %v", err)
	}

	appMsg, err := protoMessage.ToAppMessage()
	if err != nil {
		t.Fatalf("ToAppMessage failed: %v", err)
	}

	got, ok := appMsg.(*appmessage.MsgFastMicroblock)
	if !ok {
		t.Fatalf("unexpected message type %T", appMsg)
	}
	if got.MicroblockTimeMs != input.MicroblockTimeMs {
		t.Fatalf("microblock time mismatch")
	}
	if len(got.IntentIDs) != 2 {
		t.Fatalf("expected 2 intent IDs, got %d", len(got.IntentIDs))
	}
	if !bytes.Equal(got.IntentIDs[0].ByteSlice(), intentID1.ByteSlice()) {
		t.Fatalf("intent ID 0 mismatch")
	}
	if !bytes.Equal(got.IntentIDs[1].ByteSlice(), intentID2.ByteSlice()) {
		t.Fatalf("intent ID 1 mismatch")
	}
}

func TestTrustedDataAtomicMetadataRoundTrip(t *testing.T) {
	input := &appmessage.MsgTrustedData{
		DAAWindow:                      []*appmessage.TrustedDataDAAHeader{},
		GHOSTDAGData:                   []*appmessage.BlockGHOSTDAGDataHashPair{},
		AtomicConsensusState:           []byte{0x01, 0x02},
		AtomicConsensusStateHash:       bytes.Repeat([]byte{0xAA}, externalapi.DomainHashSize),
		AtomicConsensusStateByteLength: 123,
		AtomicConsensusStateChunkCount: 4,
	}

	protoMessage, err := FromAppMessage(input)
	if err != nil {
		t.Fatalf("FromAppMessage failed: %v", err)
	}

	appMsg, err := protoMessage.ToAppMessage()
	if err != nil {
		t.Fatalf("ToAppMessage failed: %v", err)
	}

	got, ok := appMsg.(*appmessage.MsgTrustedData)
	if !ok {
		t.Fatalf("unexpected message type %T", appMsg)
	}
	if !bytes.Equal(got.AtomicConsensusState, input.AtomicConsensusState) {
		t.Fatalf("atomic consensus state mismatch")
	}
	if !bytes.Equal(got.AtomicConsensusStateHash, input.AtomicConsensusStateHash) {
		t.Fatalf("atomic consensus state hash mismatch")
	}
	if got.AtomicConsensusStateByteLength != input.AtomicConsensusStateByteLength ||
		got.AtomicConsensusStateChunkCount != input.AtomicConsensusStateChunkCount {
		t.Fatalf("atomic consensus state metadata mismatch")
	}
}

func TestTrustedAtomicStateChunkRoundTrip(t *testing.T) {
	input := appmessage.NewMsgTrustedAtomicStateChunk(
		bytes.Repeat([]byte{0xBB}, externalapi.DomainHashSize),
		2,
		9,
		4097,
		[]byte{0xCA, 0xFE},
	)

	protoMessage, err := FromAppMessage(input)
	if err != nil {
		t.Fatalf("FromAppMessage failed: %v", err)
	}

	appMsg, err := protoMessage.ToAppMessage()
	if err != nil {
		t.Fatalf("ToAppMessage failed: %v", err)
	}

	got, ok := appMsg.(*appmessage.MsgTrustedAtomicStateChunk)
	if !ok {
		t.Fatalf("unexpected message type %T", appMsg)
	}
	if !bytes.Equal(got.StateHash, input.StateHash) {
		t.Fatalf("state hash mismatch")
	}
	if got.ChunkIndex != input.ChunkIndex || got.TotalChunks != input.TotalChunks || got.TotalBytes != input.TotalBytes {
		t.Fatalf("chunk metadata mismatch")
	}
	if !bytes.Equal(got.Chunk, input.Chunk) {
		t.Fatalf("chunk bytes mismatch")
	}
}

func TestRequestNextPruningPointAtomicStateChunkRoundTrip(t *testing.T) {
	input := appmessage.NewMsgRequestNextPruningPointAtomicStateChunk()

	protoMessage, err := FromAppMessage(input)
	if err != nil {
		t.Fatalf("FromAppMessage failed: %v", err)
	}

	appMsg, err := protoMessage.ToAppMessage()
	if err != nil {
		t.Fatalf("ToAppMessage failed: %v", err)
	}

	if _, ok := appMsg.(*appmessage.MsgRequestNextPruningPointAtomicStateChunk); !ok {
		t.Fatalf("unexpected message type %T", appMsg)
	}
}

func TestEnvelopeIDsRoundTrip(t *testing.T) {
	input := appmessage.NewMsgRequestAntiFraudSnapshotV1()
	input.SetRequestID(123)
	input.SetResponseID(456)

	protoMessage, err := FromAppMessage(input)
	if err != nil {
		t.Fatalf("FromAppMessage failed: %v", err)
	}
	if protoMessage.RequestId != 123 {
		t.Fatalf("request ID mismatch: got %d, want %d", protoMessage.RequestId, 123)
	}
	if protoMessage.ResponseId != 456 {
		t.Fatalf("response ID mismatch: got %d, want %d", protoMessage.ResponseId, 456)
	}

	appMsg, err := protoMessage.ToAppMessage()
	if err != nil {
		t.Fatalf("ToAppMessage failed: %v", err)
	}
	got, ok := appMsg.(*appmessage.MsgRequestAntiFraudSnapshotV1)
	if !ok {
		t.Fatalf("unexpected message type %T", appMsg)
	}
	if got.RequestID() != 123 {
		t.Fatalf("request ID mismatch after roundtrip: got %d, want %d", got.RequestID(), 123)
	}
	if got.ResponseID() != 456 {
		t.Fatalf("response ID mismatch after roundtrip: got %d, want %d", got.ResponseID(), 456)
	}
}

func testDomainHash(t *testing.T, b byte) *externalapi.DomainHash {
	t.Helper()

	bytes := make([]byte, externalapi.DomainHashSize)
	for i := range bytes {
		bytes[i] = b
	}

	hash, err := externalapi.NewDomainHashFromByteSlice(bytes)
	if err != nil {
		t.Fatalf("NewDomainHashFromByteSlice failed: %v", err)
	}

	return hash
}
