package mempool

import (
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
