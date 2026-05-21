package consensusstatemanager

import (
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/constants"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/txscript"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/utxo"
)

func TestAtomicAnchorStateFromUTXOIteratorSkipsCoinbaseAnchors(t *testing.T) {
	ownerScript := testAtomicOwnerScript(0x51)
	ownerID, ok := atomicstate.OwnerIDFromScript(ownerScript)
	if !ok {
		t.Fatal("test owner script did not derive an owner ID")
	}

	iterator := &testReadOnlyUTXOSetIterator{entries: []externalapi.OutpointAndUTXOEntryPair{
		{
			Outpoint:  externalapi.NewDomainOutpoint(externalapi.NewDomainTransactionIDFromByteArray(&[externalapi.DomainHashSize]byte{0x01}), 0),
			UTXOEntry: utxo.NewUTXOEntry(10, ownerScript, false, 1),
		},
		{
			Outpoint:  externalapi.NewDomainOutpoint(externalapi.NewDomainTransactionIDFromByteArray(&[externalapi.DomainHashSize]byte{0x02}), 0),
			UTXOEntry: utxo.NewUTXOEntry(20, ownerScript, true, 2),
		},
	}}

	state, err := atomicAnchorStateFromUTXOIterator(iterator)
	if err != nil {
		t.Fatalf("atomicAnchorStateFromUTXOIterator: %v", err)
	}
	if got := state.AnchorCounts[ownerID]; got != 1 {
		t.Fatalf("coinbase anchor counted unexpectedly: got %d want 1", got)
	}
}

type testReadOnlyUTXOSetIterator struct {
	entries []externalapi.OutpointAndUTXOEntryPair
	index   int
	valid   bool
}

func (i *testReadOnlyUTXOSetIterator) First() bool {
	i.index = 0
	i.valid = len(i.entries) > 0
	return i.valid
}

func (i *testReadOnlyUTXOSetIterator) Next() bool {
	if !i.valid {
		return false
	}
	i.index++
	i.valid = i.index < len(i.entries)
	return i.valid
}

func (i *testReadOnlyUTXOSetIterator) Get() (*externalapi.DomainOutpoint, externalapi.UTXOEntry, error) {
	entry := i.entries[i.index]
	return entry.Outpoint, entry.UTXOEntry, nil
}

func (i *testReadOnlyUTXOSetIterator) Close() error {
	return nil
}

func testAtomicOwnerScript(seed byte) *externalapi.ScriptPublicKey {
	script := make([]byte, 34)
	script[0] = txscript.OpData32
	for i := 1; i <= 32; i++ {
		script[i] = seed
	}
	script[33] = txscript.OpCheckSig
	return &externalapi.ScriptPublicKey{Script: script, Version: constants.MaxScriptPublicKeyVersion}
}
