package txmass

import (
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
)

func TestPayloadSubnetworkMassDelta(t *testing.T) {
	const (
		payloadLen              = 256
		massPerTxByte           = uint64(1)
		massPerScriptPubKeyByte = uint64(0)
		massPerSigOp            = uint64(0)
		payloadWeightMultiplier = uint64(4)
	)

	calculator := NewCalculator(
		massPerTxByte,
		massPerScriptPubKeyByte,
		massPerSigOp,
		payloadWeightMultiplier,
	)

	nativeTx := testTransaction(subnetworks.SubnetworkIDNative, payloadLen)
	payloadTx := testTransaction(subnetworks.SubnetworkIDPayload, payloadLen)

	nativeMass := calculator.CalculateTransactionMass(nativeTx)
	payloadMass := calculator.CalculateTransactionMass(payloadTx)

	expectedDelta := uint64(payloadLen) * (payloadWeightMultiplier - 1) * massPerTxByte
	if payloadMass-nativeMass != expectedDelta {
		t.Fatalf("expected payload mass delta %d, got %d", expectedDelta, payloadMass-nativeMass)
	}
}

func TestPayloadMultiplierOneHasNoDelta(t *testing.T) {
	calculator := NewCalculator(1, 0, 0, 1)

	nativeTx := testTransaction(subnetworks.SubnetworkIDNative, 64)
	payloadTx := testTransaction(subnetworks.SubnetworkIDPayload, 64)

	nativeMass := calculator.CalculateTransactionMass(nativeTx)
	payloadMass := calculator.CalculateTransactionMass(payloadTx)

	if payloadMass != nativeMass {
		t.Fatalf("expected equal mass with payload multiplier 1, got payload=%d native=%d", payloadMass, nativeMass)
	}
}

func testTransaction(subnetworkID externalapi.DomainSubnetworkID, payloadLen int) *externalapi.DomainTransaction {
	payload := make([]byte, payloadLen)

	return &externalapi.DomainTransaction{
		Version: 0,
		Inputs: []*externalapi.DomainTransactionInput{
			{
				PreviousOutpoint: externalapi.DomainOutpoint{
					TransactionID: externalapi.DomainTransactionID{},
					Index:         0,
				},
				SignatureScript: []byte{},
				Sequence:        0,
				SigOpCount:      0,
			},
		},
		Outputs: []*externalapi.DomainTransactionOutput{
			{
				Value:           1,
				ScriptPublicKey: &externalapi.ScriptPublicKey{Version: 0, Script: []byte{}},
			},
		},
		LockTime:     0,
		SubnetworkID: subnetworkID,
		Gas:          0,
		Payload:      payload,
	}
}
