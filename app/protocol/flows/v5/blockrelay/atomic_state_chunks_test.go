package blockrelay

import (
	"testing"
	"time"

	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/cryptix-network/cryptixd/domain/consensus/model/externalapi"
	"github.com/cryptix-network/cryptixd/infrastructure/network/netadapter/router"
)

func TestDrainTrustedAtomicStateChunksConsumesChunkWithoutRequestingMore(t *testing.T) {
	incomingRoute := router.NewRoute("incoming")
	outgoingRoute := router.NewRoute("outgoing")
	flow := &handleIBDFlow{incomingRoute: incomingRoute, outgoingRoute: outgoingRoute}

	stateHash := [externalapi.DomainHashSize]byte{1, 2, 3}
	chunk := []byte{4, 5, 6}
	err := incomingRoute.Enqueue(appmessage.NewMsgTrustedAtomicStateChunk(
		stateHash[:], 0, 1, uint64(len(chunk)), chunk))
	if err != nil {
		t.Fatalf("Enqueue: %+v", err)
	}

	err = flow.drainTrustedAtomicStateChunks(stateHash, uint64(len(chunk)), 1)
	if err != nil {
		t.Fatalf("drainTrustedAtomicStateChunks: %+v", err)
	}

	_, err = outgoingRoute.DequeueWithTimeout(10 * time.Millisecond)
	if err == nil {
		t.Fatalf("drainTrustedAtomicStateChunks unexpectedly requested more chunks")
	}
}

func TestDrainTrustedAtomicStateChunksRejectsInvalidMetadata(t *testing.T) {
	flow := &handleIBDFlow{
		incomingRoute: router.NewRoute("incoming"),
		outgoingRoute: router.NewRoute("outgoing"),
	}

	stateHash := [externalapi.DomainHashSize]byte{1, 2, 3}
	err := flow.drainTrustedAtomicStateChunks(stateHash, 2, 2)
	if err == nil {
		t.Fatalf("drainTrustedAtomicStateChunks accepted invalid metadata")
	}
}
