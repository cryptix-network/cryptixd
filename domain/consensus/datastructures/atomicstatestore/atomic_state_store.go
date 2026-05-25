package atomicstatestore

import (
	"github.com/cryptix-network/cryptixd/domain/consensus/database"
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

func (ass *atomicStateStore) DeleteEntriesAboveDAA(
	dbContext model.DBReader,
	stagingArea *model.StagingArea,
	blockHeaderStore model.BlockHeaderStore,
	targetDAA uint64) (deletedAboveTarget int, deletedOrphans int, err error) {

	cursor, err := dbContext.Cursor(ass.bucket)
	if err != nil {
		return 0, 0, err
	}
	defer cursor.Close()

	for ok := cursor.First(); ok; ok = cursor.Next() {
		key, err := cursor.Key()
		if err != nil {
			return deletedAboveTarget, deletedOrphans, err
		}

		blockHash, err := externalapi.NewDomainHashFromByteSlice(key.Suffix())
		if err != nil {
			return deletedAboveTarget, deletedOrphans, err
		}
		if blockHash.Equal(model.VirtualBlockHash) {
			continue
		}

		header, err := blockHeaderStore.BlockHeader(dbContext, stagingArea, blockHash)
		if err != nil {
			if database.IsNotFoundError(err) {
				ass.Delete(stagingArea, blockHash)
				deletedOrphans++
				continue
			}
			return deletedAboveTarget, deletedOrphans, err
		}

		if header.DAAScore() > targetDAA {
			ass.Delete(stagingArea, blockHash)
			deletedAboveTarget++
		}
	}

	return deletedAboveTarget, deletedOrphans, nil
}

func (ass *atomicStateStore) hashAsKey(hash *externalapi.DomainHash) model.DBKey {
	return ass.bucket.Key(hash.ByteSlice())
}
