package atomicstatestore

import (
	"github.com/cryptix-network/cryptixd/domain/consensus/model"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/lrucache"
	"github.com/cryptix-network/cryptixd/util/staging"
)

var bucketName = []byte("atomic-states")

// atomicStateStore represents a store of consensus Atomic states.
type atomicStateStore struct {
	shardID model.StagingShardID
	cache   *lrucache.LRUCache
	bucket  model.DBBucket
}

// New instantiates a new AtomicStateStore.
func New(prefixBucket model.DBBucket, cacheSize int, preallocate bool) model.AtomicStateStore {
	return &atomicStateStore{
		shardID: staging.GenerateShardingID(),
		cache:   lrucache.New(cacheSize, preallocate),
		bucket:  prefixBucket.Bucket(bucketName),
	}
}

// Stage stages the given Atomic state for the given blockHash.
func (ass *atomicStateStore) Stage(stagingArea *model.StagingArea, blockHash *externalapi.DomainHash, state *atomicstate.State) {
	stagingShard := ass.stagingShard(stagingArea)
	stagingShard.toAdd[*blockHash] = state.Clone()
}

func (ass *atomicStateStore) IsStaged(stagingArea *model.StagingArea) bool {
	return ass.stagingShard(stagingArea).isStaged()
}

// Get gets the Atomic state associated with the given blockHash.
func (ass *atomicStateStore) Get(dbContext model.DBReader, stagingArea *model.StagingArea,
	blockHash *externalapi.DomainHash) (*atomicstate.State, error) {

	stagingShard := ass.stagingShard(stagingArea)

	if state, ok := stagingShard.toAdd[*blockHash]; ok {
		return state.Clone(), nil
	}

	if state, ok := ass.cache.Get(blockHash); ok {
		return state.(*atomicstate.State).Clone(), nil
	}

	stateBytes, err := dbContext.Get(ass.hashAsKey(blockHash))
	if err != nil {
		return nil, err
	}

	state, err := atomicstate.FromCanonicalBytes(stateBytes)
	if err != nil {
		return nil, err
	}
	ass.cache.Add(blockHash, state)
	return state.Clone(), nil
}

// Delete deletes the Atomic state associated with the given blockHash.
func (ass *atomicStateStore) Delete(stagingArea *model.StagingArea, blockHash *externalapi.DomainHash) {
	stagingShard := ass.stagingShard(stagingArea)

	if _, ok := stagingShard.toAdd[*blockHash]; ok {
		delete(stagingShard.toAdd, *blockHash)
		return
	}
	stagingShard.toDelete[*blockHash] = struct{}{}
}

func (ass *atomicStateStore) hashAsKey(hash *externalapi.DomainHash) model.DBKey {
	return ass.bucket.Key(hash.ByteSlice())
}
