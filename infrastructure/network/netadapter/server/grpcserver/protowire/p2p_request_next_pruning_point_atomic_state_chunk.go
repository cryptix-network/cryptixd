package protowire

import (
	"github.com/cryptix-network/cryptixd/app/appmessage"
	"github.com/pkg/errors"
)

func (x *CryptixdMessage_RequestNextPruningPointAtomicStateChunk) toAppMessage() (appmessage.Message, error) {
	if x == nil {
		return nil, errors.Wrapf(errorNil, "CryptixdMessage_RequestNextPruningPointAtomicStateChunk is nil")
	}
	return &appmessage.MsgRequestNextPruningPointAtomicStateChunk{}, nil
}

func (x *CryptixdMessage_RequestNextPruningPointAtomicStateChunk) fromAppMessage(_ *appmessage.MsgRequestNextPruningPointAtomicStateChunk) error {
	x.RequestNextPruningPointAtomicStateChunk = &RequestNextPruningPointAtomicStateChunkMessage{}
	return nil
}
