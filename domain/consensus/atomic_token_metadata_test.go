package consensus

import (
	"testing"

	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/constants"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/txscript"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/utxo"
)

type testUTXOIterator struct {
	entries []externalapi.UTXOEntry
	index   int
}

func (it *testUTXOIterator) First() bool {
	it.index = 0
	return len(it.entries) > 0
}

func (it *testUTXOIterator) Next() bool {
	it.index++
	return it.index < len(it.entries)
}

func (it *testUTXOIterator) Get() (*externalapi.DomainOutpoint, externalapi.UTXOEntry, error) {
	return nil, it.entries[it.index], nil
}

func (it *testUTXOIterator) Close() error {
	return nil
}

func TestAtomicAnchorCountsFromUTXOIteratorSkipsCoinbase(t *testing.T) {
	script := testAtomicOwnerScript(0x11)
	ownerID, ok := atomicstate.OwnerIDFromScript(script)
	if !ok {
		t.Fatalf("test owner script did not produce an Atomic owner id")
	}

	counts, err := atomicAnchorCountsFromUTXOIterator(&testUTXOIterator{entries: []externalapi.UTXOEntry{
		utxo.NewUTXOEntry(1, script, true, 0),
		utxo.NewUTXOEntry(1, script, true, 0),
		utxo.NewUTXOEntry(1, script, false, 0),
	}})
	if err != nil {
		t.Fatalf("unexpected error reconstructing anchor counts: %v", err)
	}
	if got := counts[ownerID]; got != 1 {
		t.Fatalf("expected only the non-coinbase owner UTXO to be counted, got %d", got)
	}
}

func testAtomicOwnerScript(fill byte) *externalapi.ScriptPublicKey {
	script := make([]byte, 34)
	script[0] = txscript.OpData32
	for i := 1; i <= 32; i++ {
		script[i] = fill
	}
	script[33] = txscript.OpCheckSig
	return &externalapi.ScriptPublicKey{
		Version: constants.MaxScriptPublicKeyVersion,
		Script:  script,
	}
}
