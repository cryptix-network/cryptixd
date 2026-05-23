package mempool

import (
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/consensushashing"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/constants"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/subnetworks"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/utxo"
	mempoolmodel "github.com/cryptix-network/cryptixd/domain/miningmanager/mempool/model"
)

func TestMempoolUTXOSetAddChildRemovesSpentParentOutput(t *testing.T) {
	mempoolUTXOs := newMempoolUTXOSet(nil)
	scriptPublicKey := &externalapi.ScriptPublicKey{Script: []byte{0x51}, Version: 0}
	parentInputEntry := utxo.NewUTXOEntry(constants.SompiPerCryptix, scriptPublicKey, false, 1)

	parentTransaction := &externalapi.DomainTransaction{
		Version: constants.MaxTransactionVersion,
		Inputs: []*externalapi.DomainTransactionInput{{
			PreviousOutpoint: mempoolUTXOSetTestOutpoint(1, 0),
			Sequence:         constants.MaxTxInSequenceNum,
			UTXOEntry:        parentInputEntry,
		}},
		Outputs: []*externalapi.DomainTransactionOutput{{
			Value:           5_000,
			ScriptPublicKey: scriptPublicKey,
		}},
		SubnetworkID: subnetworks.SubnetworkIDNative,
		Fee:          1,
		Mass:         1,
	}
	parent := mempoolmodel.NewMempoolTransaction(
		parentTransaction,
		mempoolmodel.IDToTransactionMap{},
		false,
		0,
	)
	mempoolUTXOs.addTransaction(parent)

	parentOutput := externalapi.DomainOutpoint{
		TransactionID: *consensushashing.TransactionID(parentTransaction),
		Index:         0,
	}
	parentOutputEntry, ok := mempoolUTXOs.poolUnspentOutputs[parentOutput]
	if !ok {
		t.Fatalf("expected parent output to be available in mempool UTXO set")
	}

	childTransaction := &externalapi.DomainTransaction{
		Version: constants.MaxTransactionVersion,
		Inputs: []*externalapi.DomainTransactionInput{{
			PreviousOutpoint: parentOutput,
			Sequence:         constants.MaxTxInSequenceNum,
			UTXOEntry:        parentOutputEntry,
		}},
		Outputs: []*externalapi.DomainTransactionOutput{{
			Value:           4_000,
			ScriptPublicKey: scriptPublicKey,
		}},
		SubnetworkID: subnetworks.SubnetworkIDNative,
		Fee:          1,
		Mass:         1,
	}
	child := mempoolmodel.NewMempoolTransaction(
		childTransaction,
		mempoolmodel.IDToTransactionMap{*consensushashing.TransactionID(parentTransaction): parent},
		false,
		0,
	)
	mempoolUTXOs.addTransaction(child)

	if _, ok := mempoolUTXOs.poolUnspentOutputs[parentOutput]; ok {
		t.Fatalf("spent parent output remained available in mempool UTXO set")
	}

	childOutput := externalapi.DomainOutpoint{
		TransactionID: *consensushashing.TransactionID(childTransaction),
		Index:         0,
	}
	if _, ok := mempoolUTXOs.poolUnspentOutputs[childOutput]; !ok {
		t.Fatalf("expected child output to be available in mempool UTXO set")
	}
}

func mempoolUTXOSetTestOutpoint(seed byte, index uint32) externalapi.DomainOutpoint {
	var bytes [externalapi.DomainHashSize]byte
	bytes[0] = seed
	return externalapi.DomainOutpoint{
		TransactionID: *externalapi.NewDomainTransactionIDFromByteArray(&bytes),
		Index:         index,
	}
}
