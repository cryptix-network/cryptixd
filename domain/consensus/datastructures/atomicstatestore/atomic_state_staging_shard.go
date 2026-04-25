package atomicstatestore

import (
	"github.com/cryptix-network/cryptixd/domain/consensus/model"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
)

type atomicStateStagingShard struct {
	store    *atomicStateStore
	toAdd    map[externalapi.DomainHash]*atomicstate.State
	toDelete map[externalapi.DomainHash]struct{}
}

func (ass *atomicStateStore) stagingShard(stagingArea *model.StagingArea) *atomicStateStagingShard {
	return stagingArea.GetOrCreateShard(ass.shardID, func() model.StagingShard {
		return &atomicStateStagingShard{
			store:    ass,
			toAdd:    make(map[externalapi.DomainHash]*atomicstate.State),
			toDelete: make(map[externalapi.DomainHash]struct{}),
		}
	}).(*atomicStateStagingShard)
}

func (asss *atomicStateStagingShard) Commit(dbTx model.DBTransaction) error {
	for hash, state := range asss.toAdd {
		err := dbTx.Put(asss.store.hashAsKey(&hash), state.CanonicalBytes())
		if err != nil {
			return err
		}
		asss.store.cache.Add(&hash, state.Clone())
	}

	for hash := range asss.toDelete {
		err := dbTx.Delete(asss.store.hashAsKey(&hash))
		if err != nil {
			return err
		}
		asss.store.cache.Remove(&hash)
	}

	return nil
}

func (asss *atomicStateStagingShard) isStaged() bool {
	return len(asss.toAdd) != 0 || len(asss.toDelete) != 0
}
