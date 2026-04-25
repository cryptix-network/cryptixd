package model

import (
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/domain/consensus/utils/atomicstate"
)

// AtomicStateStore represents a store of consensus Atomic states.
type AtomicStateStore interface {
	Store
	Stage(stagingArea *StagingArea, blockHash *externalapi.DomainHash, state *atomicstate.State)
	IsStaged(stagingArea *StagingArea) bool
	Get(dbContext DBReader, stagingArea *StagingArea, blockHash *externalapi.DomainHash) (*atomicstate.State, error)
	Delete(stagingArea *StagingArea, blockHash *externalapi.DomainHash)
}
