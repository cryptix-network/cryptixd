package pruningstore

import (
	"bytes"
	"testing"

	consensusdatabase "github.com/cryptix-network/cryptixd/domain/consensus/database"
	"github.com/cryptix-network/cryptixd/domain/consensus/model"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
	"github.com/cryptix-network/cryptixd/infrastructure/db/database/ldb"
)

func TestImportedPruningPointAtomicStatePreservesFullStateBytes(t *testing.T) {
	store, dbContext, teardown := newTestPruningStore(t)
	defer teardown()

	stateBytes := atomicstate.NewState().CanonicalBytes()
	dbTx, err := dbContext.Begin()
	if err != nil {
		t.Fatalf("Begin: %+v", err)
	}
	defer dbTx.RollbackUnlessClosed()

	err = store.UpdateImportedPruningPointAtomicState(dbTx, stateBytes)
	if err != nil {
		t.Fatalf("UpdateImportedPruningPointAtomicState: %+v", err)
	}
	err = dbTx.Commit()
	if err != nil {
		t.Fatalf("Commit: %+v", err)
	}

	gotStateBytes, err := store.ImportedPruningPointAtomicState(dbContext)
	if err != nil {
		t.Fatalf("ImportedPruningPointAtomicState: %+v", err)
	}
	if !bytes.Equal(gotStateBytes, stateBytes) {
		t.Fatalf("full Atomic state bytes were not preserved")
	}

	gotHash, err := store.ImportedPruningPointAtomicStateHash(dbContext)
	if err != nil {
		t.Fatalf("ImportedPruningPointAtomicStateHash: %+v", err)
	}
	if wantHash := atomicstate.HashCanonicalBytes(stateBytes); gotHash != wantHash {
		t.Fatalf("hash mismatch\n got: %x\nwant: %x", gotHash, wantHash)
	}
}

func TestImportedPruningPointAtomicStateHashOnlyFallback(t *testing.T) {
	store, dbContext, teardown := newTestPruningStore(t)
	defer teardown()

	var stateHash [externalapi.DomainHashSize]byte
	for i := range stateHash {
		stateHash[i] = byte(i + 1)
	}

	dbTx, err := dbContext.Begin()
	if err != nil {
		t.Fatalf("Begin: %+v", err)
	}
	defer dbTx.RollbackUnlessClosed()

	err = store.UpdateImportedPruningPointAtomicStateHash(dbTx, stateHash)
	if err != nil {
		t.Fatalf("UpdateImportedPruningPointAtomicStateHash: %+v", err)
	}
	err = dbTx.Commit()
	if err != nil {
		t.Fatalf("Commit: %+v", err)
	}

	gotStateBytes, err := store.ImportedPruningPointAtomicState(dbContext)
	if err != nil {
		t.Fatalf("ImportedPruningPointAtomicState: %+v", err)
	}
	gotState, err := atomicstate.FromCanonicalBytes(gotStateBytes)
	if err != nil {
		t.Fatalf("FromCanonicalBytes: %+v", err)
	}
	if !gotState.IsRootOnly() {
		t.Fatalf("expected hash-only import to decode as root-only state")
	}
	if gotHash := gotState.CanonicalHash(); gotHash != stateHash {
		t.Fatalf("root-only hash mismatch\n got: %x\nwant: %x", gotHash, stateHash)
	}
}

func newTestPruningStore(t *testing.T) (model.PruningStore, model.DBManager, func()) {
	t.Helper()

	db, err := ldb.NewLevelDB(t.TempDir(), 8)
	if err != nil {
		t.Fatalf("NewLevelDB: %+v", err)
	}

	return New(consensusdatabase.MakeBucket(nil), 10, false), consensusdatabase.New(db), func() {
		err := db.Close()
		if err != nil {
			t.Fatalf("Close: %+v", err)
		}
	}
}
